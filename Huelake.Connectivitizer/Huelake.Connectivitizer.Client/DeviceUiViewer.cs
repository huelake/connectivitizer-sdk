using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Huelake.Connectivitizer.Client;

/// <summary>What a device says about the screen it brings (<c>/.cz/ui.json</c>, docs/device-ui).</summary>
public sealed record DeviceUiManifest(string Name, string Entry, string? Version);

/// <summary>What the page is told about its device and the session to it (<c>connectivitizer.device</c>).</summary>
public sealed record DeviceUiSessionInfo(string DeviceName, bool Direct, bool EndToEndEncrypted);

/// <summary>The device answered, but not with a screen this viewer can show.</summary>
public sealed class DeviceUiException(string message) : Exception(message);

/// <summary>
/// Shows a device's own screen (docs/device-ui) in a browser on this machine, for <c>cz ui</c>: a web server
/// on the loopback address that passes the page's requests and WebSockets through the session to one device
/// service. The session and its keys stay in this process; the browser only ever talks to 127.0.0.1.
///
/// The local server is not for anyone but the browser this viewer was opened in:
/// <list type="bullet">
/// <item>it listens on the loopback address only, on a port the system picks;</item>
/// <item>every request needs a secret of this run. The address to open carries it once and trades it for a
/// cookie that is not sent along with requests from other sites;</item>
/// <item><c>Host</c> has to be this server's own address (a foreign name pointing at 127.0.0.1 is refused),
/// and a request that says it comes from another site (<c>Origin</c>, <c>Sec-Fetch-Site</c>) is refused;</item>
/// <item>the device's page may load nothing from the network but its own device (Content-Security-Policy),
/// as in the app, and cannot set cookies.</item>
/// </list>
/// End-to-end encryption ends in this process; the last step to the browser is loopback on the same machine.
/// </summary>
public sealed class DeviceUiViewer : IAsyncDisposable
{
    /// <summary>The largest page a device may bring, as in the app.</summary>
    public const int MaxPageBytes = 2 * 1024 * 1024;

    private const int MaxHeadBytes = 64 * 1024;
    private const int MaxManifestBytes = 64 * 1024;
    private const string CookieName = "cz_ui";
    private const string HostPrefix = "/.cz-host/";
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(2);

    /// <summary>Request headers that are about this server, not about the device, or that would break the framing.</summary>
    private static readonly HashSet<string> DroppedRequestHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Host", "Cookie", "Connection", "Keep-Alive", "Proxy-Connection", "Accept-Encoding", "Origin", "Referer",
        "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User",
    };

    /// <summary>Response headers the device does not get to set here: cookies, and how this server frames and guards the page.</summary>
    private static readonly HashSet<string> DroppedResponseHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Connection", "Keep-Alive", "Set-Cookie", "Content-Security-Policy", "Content-Security-Policy-Report-Only",
        "X-Frame-Options", "Cache-Control", "Referrer-Policy", "X-Content-Type-Options",
    };

    // What the page knows from the app (docs/device-ui, "The bridge"). Requests with a path already reach the
    // device: this server is the page's origin. Only the object itself has to be added.
    private const string Shim = """
        <script>
        (function () {
          var bridge = {
            fetch: function (path, init) { return fetch(path, init); },
            webSocket: function (path, protocols) {
              var url = new URL(path, location.href);
              url.protocol = 'ws:';
              var socket = protocols === undefined ? new WebSocket(url) : new WebSocket(url, protocols);
              socket.binaryType = 'arraybuffer';
              return socket;
            },
            device: null,
            host: { name: 'cz', platform: 'desktop' },
            close: function () { window.close(); },
            setTheme: function (theme) {
              var meta = document.querySelector('meta[name="theme-color"]');
              if (!theme || typeof theme.background !== 'string') { if (meta) meta.remove(); return; }
              if (!meta) { meta = document.createElement('meta'); meta.name = 'theme-color'; document.head.appendChild(meta); }
              meta.content = theme.background;
            }
          };
          bridge.ready = fetch('/.cz-host/hello').then(function (r) { return r.json(); }).then(function (hello) {
            bridge.device = hello.device;
            return hello.device;
          });
          window.connectivitizer = bridge;
        })();
        </script>
        """;

    private readonly Func<CancellationToken, Task<Stream>> _openStream;
    private readonly DeviceUiManifest _manifest;
    private readonly DeviceUiSessionInfo _info;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _acceptLoop;
    private readonly string _token;
    private readonly string _authority;

    /// <param name="openStream">Opens a stream to the device service, as <c>TunnelSession.OpenStreamAsync</c> does.</param>
    /// <param name="manifest">The device's manifest, from <see cref="ReadManifestAsync"/>.</param>
    /// <param name="info">What the page is told about its device and the session.</param>
    public DeviceUiViewer(Func<CancellationToken, Task<Stream>> openStream, DeviceUiManifest manifest, DeviceUiSessionInfo info)
    {
        _openStream = openStream;
        _manifest = manifest;
        _info = info;
        _token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        LocalEndPoint = (IPEndPoint)_listener.LocalEndpoint;
        _authority = $"127.0.0.1:{LocalEndPoint.Port}";
        _acceptLoop = Task.Run(AcceptLoopAsync);
    }

    /// <summary>Where the server listens: always the loopback address.</summary>
    public IPEndPoint LocalEndPoint { get; }

    /// <summary>The address to open in the browser. It carries this run's secret; nothing else is accepted first.</summary>
    public Uri LaunchUrl => new($"http://{_authority}{HostPrefix}open?t={_token}");

    /// <summary>
    /// Asks the device for its manifest. Throws <see cref="DeviceUiException"/> when the device brings no screen
    /// or its manifest cannot be used.
    /// </summary>
    public static async Task<DeviceUiManifest> ReadManifestAsync(Func<CancellationToken, Task<Stream>> openStream, CancellationToken cancellationToken = default)
    {
        await using Stream device = await openStream(cancellationToken).ConfigureAwait(false);
        await device.WriteAsync(Encoding.ASCII.GetBytes("GET /.cz/ui.json HTTP/1.1\r\nHost: device\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"), cancellationToken).ConfigureAwait(false);
        await device.FlushAsync(cancellationToken).ConfigureAwait(false);

        (HttpHead head, byte[] rest) = await ReadHeadAsync(device, cancellationToken).ConfigureAwait(false) ?? throw new DeviceUiException("The device closed the connection without an answer.");
        int status = head.Status;
        if (status == 404)
        {
            throw new DeviceUiException("This device brings no screen of its own (no /.cz/ui.json on this service).");
        }
        if (status != 200)
        {
            throw new DeviceUiException($"The device answered {status} for /.cz/ui.json.");
        }
        byte[] body = await ReadBodyAsync(device, head, rest, MaxManifestBytes, cancellationToken).ConfigureAwait(false)
            ?? throw new DeviceUiException("The device's manifest is larger than a manifest may be.");

        try
        {
            using JsonDocument document = JsonDocument.Parse(body);
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new DeviceUiException("The device's manifest is not a JSON object.");
            }
            string name = Text(root, "name") is { Length: > 0 } given ? given.Trim() : "Device";
            if (name.Length > 60)
            {
                name = name[..60];
            }
            string entry = Text(root, "entry") is { Length: > 0 } path ? path : "/.cz/ui.html";
            // A path on the same service and nothing else: no scheme, no host, no way out of the device.
            if (!entry.StartsWith('/') || entry.StartsWith("//", StringComparison.Ordinal) || entry.Contains('\\') || entry.Contains("://", StringComparison.Ordinal)
                || entry.Any(character => char.IsControl(character) || char.IsWhiteSpace(character)) || entry.StartsWith(HostPrefix, StringComparison.OrdinalIgnoreCase))
            {
                throw new DeviceUiException("The manifest's entry has to be a path on the device, such as /.cz/ui.html.");
            }
            return new DeviceUiManifest(name, entry, Text(root, "version"));
        }
        catch (JsonException)
        {
            throw new DeviceUiException("The device's manifest is not valid JSON.");
        }

        static string? Text(JsonElement root, string member) =>
            root.TryGetProperty(member, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                TcpClient client = await _listener.AcceptTcpClientAsync(_stop.Token).ConfigureAwait(false);
                _ = Task.Run(() => ServeAsync(client));
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
        {
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                client.NoDelay = true;
                NetworkStream browser = client.GetStream();
                (HttpHead head, byte[] rest)? read = await ReadHeadAsync(browser, _stop.Token).ConfigureAwait(false);
                if (read is null)
                {
                    return;
                }
                (HttpHead request, byte[] rest) = read.Value;

                if (Refusal(request) is { } refusal)
                {
                    await WriteAnswerAsync(browser, 403, "Forbidden", "text/plain; charset=utf-8", Encoding.UTF8.GetBytes(refusal), null).ConfigureAwait(false);
                    return;
                }

                string path = request.Target;
                string pathOnly = path.Split('?', 2)[0];
                if (pathOnly == HostPrefix + "open")
                {
                    // The secret has just been checked (Refusal): trade it for the cookie and leave the address bar clean.
                    await WriteAnswerAsync(browser, 302, "Found", "text/plain; charset=utf-8", [],
                        $"Location: {_manifest.Entry}\r\nSet-Cookie: {CookieName}={_token}; Path=/; HttpOnly; SameSite=Strict\r\n").ConfigureAwait(false);
                    return;
                }
                if (pathOnly == HostPrefix + "hello")
                {
                    await WriteAnswerAsync(browser, 200, "OK", "application/json", HelloJson(), null).ConfigureAwait(false);
                    return;
                }
                if (pathOnly.StartsWith(HostPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    await WriteAnswerAsync(browser, 404, "Not Found", "text/plain; charset=utf-8", [], null).ConfigureAwait(false);
                    return;
                }

                await ProxyAsync(browser, request, rest).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException or Sessions.TunnelException)
            {
                // The browser sees its connection close; why a session ended is reported by the session itself.
            }
        }
    }

    /// <summary>Why a request is not answered, or null when it is this viewer's own browser asking.</summary>
    private string? Refusal(HttpHead request)
    {
        // A page on another site can make the browser send requests here; it cannot make them look like ours.
        if (!string.Equals(request.Header("Host"), _authority, StringComparison.OrdinalIgnoreCase))
        {
            return "This address is not served here.";
        }
        if (request.Header("Origin") is { } origin && !string.Equals(origin, $"http://{_authority}", StringComparison.OrdinalIgnoreCase))
        {
            return "Requests from other sites are not accepted.";
        }
        if (string.Equals(request.Header("Sec-Fetch-Site"), "cross-site", StringComparison.OrdinalIgnoreCase))
        {
            return "Requests from other sites are not accepted.";
        }

        string pathOnly = request.Target.Split('?', 2)[0];
        string? presented = pathOnly == HostPrefix + "open"
            ? request.Target.Split('?', 2) is [_, var query] ? query.Split('&').FirstOrDefault(part => part.StartsWith("t=", StringComparison.Ordinal))?[2..] : null
            : CookieValue(request.Header("Cookie"));
        if (presented is null || !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(presented), Encoding.ASCII.GetBytes(_token)))
        {
            return "Open the address that cz printed: this page belongs to the browser it was opened in.";
        }
        return null;
    }

    private static string? CookieValue(string? header)
    {
        if (header is null)
        {
            return null;
        }
        foreach (string part in header.Split(';'))
        {
            string trimmed = part.Trim();
            if (trimmed.StartsWith(CookieName + "=", StringComparison.Ordinal))
            {
                return trimmed[(CookieName.Length + 1)..];
            }
        }
        return null;
    }

    private byte[] HelloJson()
    {
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteStartObject("device");
            json.WriteString("name", _info.DeviceName);
            json.WriteString("title", _manifest.Name);
            json.WriteString("path", _info.Direct ? "direct" : "relayed");
            json.WriteBoolean("endToEndEncrypted", _info.EndToEndEncrypted);
            json.WriteEndObject();
            json.WriteStartObject("host");
            json.WriteString("name", "cz");
            json.WriteString("platform", "desktop");
            json.WriteEndObject();
            json.WriteEndObject();
        }
        return buffer.ToArray();
    }

    private async Task ProxyAsync(NetworkStream browser, HttpHead request, byte[] rest)
    {
        bool upgrade = request.Header("Upgrade") is { } wanted && wanted.Equals("websocket", StringComparison.OrdinalIgnoreCase);
        string pathOnly = request.Target.Split('?', 2)[0];
        bool entry = !upgrade && request.Method == "GET" && pathOnly == _manifest.Entry;

        await using Stream device = await _openStream(_stop.Token).ConfigureAwait(false);

        var head = new StringBuilder();
        head.Append(request.Method).Append(' ').Append(request.Target).Append(" HTTP/1.1\r\n");
        head.Append("Host: ").Append(_info.DeviceName).Append("\r\n");
        foreach ((string name, string value) in request.Headers)
        {
            if (!DroppedRequestHeaders.Contains(name))
            {
                head.Append(name).Append(": ").Append(value).Append("\r\n");
            }
        }
        // Uncompressed, as the SDKs ask for it: the page is handed on as it comes.
        head.Append("Accept-Encoding: identity\r\n");
        head.Append(upgrade ? "Connection: Upgrade\r\n" : "Connection: close\r\n");
        head.Append("\r\n");
        await device.WriteAsync(Encoding.Latin1.GetBytes(head.ToString()), _stop.Token).ConfigureAwait(false);
        if (rest.Length > 0)
        {
            await device.WriteAsync(rest, _stop.Token).ConfigureAwait(false);
        }
        await device.FlushAsync(_stop.Token).ConfigureAwait(false);

        // What the browser still sends (the rest of a body, WebSocket frames) goes on to the device.
        Task up = CopyAsync(browser, device, null);

        (HttpHead head, byte[] rest)? answered = await ReadHeadAsync(device, _stop.Token).ConfigureAwait(false);
        if (answered is null)
        {
            await WriteAnswerAsync(browser, 502, "Bad Gateway", "text/plain; charset=utf-8", "The device closed the connection without an answer."u8.ToArray(), null).ConfigureAwait(false);
            return;
        }
        (HttpHead response, byte[] body) = answered.Value;

        if (upgrade && response.Status == 101)
        {
            await browser.WriteAsync(response.Raw, _stop.Token).ConfigureAwait(false);
            if (body.Length > 0)
            {
                await browser.WriteAsync(body, _stop.Token).ConfigureAwait(false);
            }
            Task down = CopyAsync(device, browser, null);
            await Task.WhenAny(up, down).ConfigureAwait(false);
            return;
        }

        if (entry && response.Status == 200)
        {
            byte[]? page = await ReadBodyAsync(device, response, body, MaxPageBytes, _stop.Token).ConfigureAwait(false);
            if (page is null)
            {
                await WriteAnswerAsync(browser, 502, "Bad Gateway", "text/plain; charset=utf-8", "The device's page is larger than 2 MB, which is the most a device's screen may be."u8.ToArray(), null).ConfigureAwait(false);
                return;
            }
            string type = response.Header("Content-Type") ?? "text/html; charset=utf-8";
            await WriteAnswerAsync(browser, 200, "OK", type, WithShim(page), PageHeaders()).ConfigureAwait(false);
            return;
        }

        var answer = new StringBuilder();
        answer.Append("HTTP/1.1 ").Append(response.Status.ToString(CultureInfo.InvariantCulture)).Append(' ').Append(response.Reason).Append("\r\n");
        foreach ((string name, string value) in response.Headers)
        {
            if (!DroppedResponseHeaders.Contains(name))
            {
                answer.Append(name).Append(": ").Append(value).Append("\r\n");
            }
        }
        answer.Append(CommonHeaders()).Append("\r\n");
        await browser.WriteAsync(Encoding.Latin1.GetBytes(answer.ToString()), _stop.Token).ConfigureAwait(false);

        long? length = long.TryParse(response.Header("Content-Length"), NumberStyles.None, CultureInfo.InvariantCulture, out long parsed) ? parsed : null;
        if (request.Method == "HEAD" || response.Status is 204 or 304)
        {
            length = 0;
        }
        long sent = Math.Min(body.Length, length ?? long.MaxValue);
        if (sent > 0)
        {
            await browser.WriteAsync(body.AsMemory(0, (int)sent), _stop.Token).ConfigureAwait(false);
        }
        await CopyAsync(device, browser, length - sent).ConfigureAwait(false);
        await browser.FlushAsync(_stop.Token).ConfigureAwait(false);
    }

    private string CommonHeaders() => "Connection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\n";

    /// <summary>The page may talk to its device (this server) and to nothing else, and nobody may frame it.</summary>
    private string PageHeaders() =>
        $"Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' data: blob:; font-src data:; connect-src 'self' ws://{_authority}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nX-Frame-Options: DENY\r\n";

    /// <summary>The page with <c>window.connectivitizer</c> defined before any of its own scripts run.</summary>
    internal static byte[] WithShim(byte[] page)
    {
        string html = Encoding.UTF8.GetString(page);
        int head = html.IndexOf("<head", StringComparison.OrdinalIgnoreCase);
        int insertAt = 0;
        if (head >= 0 && html.IndexOf('>', head) is var close and >= 0)
        {
            insertAt = close + 1;
        }
        else if (html.IndexOf("<html", StringComparison.OrdinalIgnoreCase) is var root and >= 0 && html.IndexOf('>', root) is var rootClose and >= 0)
        {
            insertAt = rootClose + 1;
        }
        else if (html.StartsWith("<!doctype", StringComparison.OrdinalIgnoreCase) && html.IndexOf('>') is var doctypeClose and >= 0)
        {
            insertAt = doctypeClose + 1;
        }
        return Encoding.UTF8.GetBytes(html.Insert(insertAt, Shim));
    }

    private async Task WriteAnswerAsync(Stream browser, int status, string reason, string contentType, byte[] body, string? extraHeaders)
    {
        string head = $"HTTP/1.1 {status} {reason}\r\nContent-Type: {contentType}\r\nContent-Length: {body.Length}\r\n{extraHeaders}{CommonHeaders()}\r\n";
        await browser.WriteAsync(Encoding.Latin1.GetBytes(head), _stop.Token).ConfigureAwait(false);
        await browser.WriteAsync(body, _stop.Token).ConfigureAwait(false);
        await browser.FlushAsync(_stop.Token).ConfigureAwait(false);
    }

    /// <summary>Copies until the source ends, <paramref name="limit"/> bytes are through, or nothing moved for too long.</summary>
    private async Task CopyAsync(Stream from, Stream to, long? limit)
    {
        byte[] buffer = new byte[32 * 1024];
        long left = limit ?? long.MaxValue;
        try
        {
            while (left > 0)
            {
                using var idle = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                idle.CancelAfter(IdleTimeout);
                int read = await from.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, left)), idle.Token).ConfigureAwait(false);
                if (read == 0)
                {
                    return;
                }
                await to.WriteAsync(buffer.AsMemory(0, read), _stop.Token).ConfigureAwait(false);
                await to.FlushAsync(_stop.Token).ConfigureAwait(false);
                left -= read;
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
        }
    }

    // ---------------------------------------------------------------- a little HTTP/1.1

    private sealed class HttpHead
    {
        public required byte[] Raw { get; init; }
        public required string[] StartLine { get; init; }
        public required List<(string Name, string Value)> Headers { get; init; }

        public string Method => StartLine[0];
        public string Target => StartLine[1];
        public int Status => int.TryParse(StartLine[1], NumberStyles.None, CultureInfo.InvariantCulture, out int status) ? status : 0;
        public string Reason => StartLine.Length > 2 ? StartLine[2] : "";

        public string? Header(string name)
        {
            foreach ((string candidate, string value) in Headers)
            {
                if (candidate.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    return value;
                }
            }
            return null;
        }
    }

    /// <summary>Reads a request's or a response's head. Null when the other side closed first; what was read beyond the head is returned with it.</summary>
    private static async Task<(HttpHead Head, byte[] Remainder)?> ReadHeadAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[4096];
        int filled = 0;
        while (true)
        {
            int end = buffer.AsSpan(0, filled).IndexOf("\r\n\r\n"u8);
            if (end >= 0)
            {
                byte[] raw = buffer[..(end + 4)];
                string[] lines = Encoding.Latin1.GetString(raw, 0, end).Split("\r\n");
                string[] start = lines[0].Split(' ', 3);
                if (start.Length < 2)
                {
                    throw new IOException("Not HTTP.");
                }
                var headers = new List<(string, string)>();
                foreach (string line in lines.Skip(1))
                {
                    int colon = line.IndexOf(':');
                    if (colon > 0)
                    {
                        headers.Add((line[..colon].Trim(), line[(colon + 1)..].Trim()));
                    }
                }
                return (new HttpHead { Raw = raw, StartLine = start, Headers = headers }, buffer[(end + 4)..filled]);
            }
            if (filled == buffer.Length)
            {
                if (buffer.Length >= MaxHeadBytes)
                {
                    throw new IOException("The headers are too large.");
                }
                Array.Resize(ref buffer, buffer.Length * 2);
            }
            int read = await stream.ReadAsync(buffer.AsMemory(filled), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return null;
            }
            filled += read;
        }
    }

    /// <summary>Reads a whole body (by its length, in chunks, or to the end). Null when it is larger than <paramref name="limit"/>.</summary>
    private static async Task<byte[]?> ReadBodyAsync(Stream stream, HttpHead head, byte[] rest, int limit, CancellationToken cancellationToken)
    {
        using var raw = new MemoryStream();
        raw.Write(rest);
        bool chunked = head.Header("Transfer-Encoding") is { } encoding && encoding.Contains("chunked", StringComparison.OrdinalIgnoreCase);
        long? length = !chunked && long.TryParse(head.Header("Content-Length"), NumberStyles.None, CultureInfo.InvariantCulture, out long parsed) ? parsed : null;
        if (length > limit)
        {
            return null;
        }
        // A chunked body is a little larger than what it carries; it is measured again once decoded.
        long most = length ?? (chunked ? (long)limit * 2 + 4096 : limit);
        byte[] buffer = new byte[32 * 1024];
        while (length is null || raw.Length < length)
        {
            if (chunked && EndsChunks(raw))
            {
                break;
            }
            int read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            raw.Write(buffer, 0, read);
            if (raw.Length > most)
            {
                return null;
            }
        }

        byte[] body = raw.ToArray();
        if (length is { } exact && body.Length > exact)
        {
            body = body[..(int)exact];
        }
        if (chunked)
        {
            body = Dechunk(body);
        }
        return body.Length > limit ? null : body;

        static bool EndsChunks(MemoryStream stream) => stream.Length >= 5 && stream.GetBuffer().AsSpan(0, (int)stream.Length).EndsWith("0\r\n\r\n"u8);
    }

    private static byte[] Dechunk(byte[] chunked)
    {
        using var body = new MemoryStream();
        int position = 0;
        while (position < chunked.Length)
        {
            int lineEnd = chunked.AsSpan(position).IndexOf("\r\n"u8);
            if (lineEnd < 0)
            {
                break;
            }
            string sizeText = Encoding.ASCII.GetString(chunked, position, lineEnd).Split(';')[0].Trim();
            if (!int.TryParse(sizeText, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int size) || size < 0)
            {
                throw new IOException("The device's answer is not chunked the way it says.");
            }
            position += lineEnd + 2;
            if (size == 0)
            {
                break;
            }
            int take = Math.Min(size, chunked.Length - position);
            body.Write(chunked, position, take);
            position += take + 2;
        }
        return body.ToArray();
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        _listener.Stop();
        try
        {
            await _acceptLoop.ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
        {
        }
        _stop.Dispose();
    }
}
