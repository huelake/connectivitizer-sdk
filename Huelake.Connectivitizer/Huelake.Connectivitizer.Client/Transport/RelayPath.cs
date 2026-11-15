using System.Net;
using System.Net.WebSockets;
using System.Text.Json;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.Transport;

/// <summary>Thrown when a path to the peer cannot be established. <see cref="ErrorCode"/> is one of <see cref="ErrorCodes"/>.</summary>
public sealed class PathException(string errorCode, string message, Exception? innerException = null) : IOException(message, innerException)
{
    public string ErrorCode { get; } = errorCode;
}

/// <summary>
/// The relayed path: a WebSocket to the Connectivitizer relay, which pairs it with the peer's
/// WebSocket and copies bytes between the two. Everything written to <see cref="Stream"/> passes
/// through Connectivitizer infrastructure, which is why the end-to-end TLS layer is run on top of it.
/// </summary>
internal sealed class RelayPath : IAsyncDisposable
{
    private const int MaxMessage = 32 * 1024;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);

    private readonly ClientWebSocket _socket;
    private readonly SemaphoreSlim _sendLock = new(1, 1);

    private RelayPath(ClientWebSocket socket)
    {
        _socket = socket;
        Stream = new RelayStream(this);
    }

    public Stream Stream { get; }

    /// <summary>Connects to the relay and waits until the peer has connected too.</summary>
    public static async Task<RelayPath> ConnectAsync(Uri relayUrl, string grantToken, string role, CancellationToken cancellationToken)
    {
        var socket = new ClientWebSocket();
        socket.Options.SetRequestHeader("Authorization", "Bearer " + grantToken);
        socket.Options.SetRequestHeader("Cz-Role", role);
        socket.Options.CollectHttpResponseDetails = true;
        socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(25);

        try
        {
            // A relay that cannot be reached must be reported, not waited for indefinitely.
            using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectTimeout.CancelAfter(ConnectTimeout);
            try
            {
                await socket.ConnectAsync(relayUrl, connectTimeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                socket.Dispose();
                throw new PathException(ErrorCodes.RelayUnreachable, $"The relay did not answer within {ConnectTimeout.TotalSeconds:F0} s ({ErrorCodes.RelayUnreachable}).");
            }
        }
        catch (WebSocketException ex)
        {
            string code = socket.HttpResponseHeaders is { } headers && headers.TryGetValue("Cz-Error", out IEnumerable<string>? values)
                ? values.FirstOrDefault() ?? ErrorCodes.RelayRejected
                : socket.HttpStatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden or HttpStatusCode.BadRequest
                    ? ErrorCodes.RelayRejected
                    : ErrorCodes.RelayUnreachable;
            socket.Dispose();
            throw new PathException(code, $"The relay did not accept the connection ({code}).", ex);
        }
        catch (Exception ex) when (ex is IOException or HttpRequestException)
        {
            socket.Dispose();
            throw new PathException(ErrorCodes.RelayUnreachable, $"The relay could not be reached ({ErrorCodes.RelayUnreachable}).", ex);
        }

        // The first message is always the relay's "paired" notice (text); anything else is a failure.
        byte[] buffer = new byte[256];
        try
        {
            ValueWebSocketReceiveResult first = await socket.ReceiveAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (first.MessageType == WebSocketMessageType.Close)
            {
                string code = string.IsNullOrEmpty(socket.CloseStatusDescription) ? ErrorCodes.RelayRejected : socket.CloseStatusDescription;
                throw new PathException(code, $"The relay closed the session before it started ({code}).");
            }

            RelayPaired? paired = first is { MessageType: WebSocketMessageType.Text, EndOfMessage: true }
                ? JsonSerializer.Deserialize(buffer.AsSpan(0, first.Count), ProtocolJsonContext.Default.RelayPaired)
                : null;
            if (paired is not { Type: "paired" })
            {
                throw new PathException(ErrorCodes.RelayRejected, "The relay did not confirm the session.");
            }
        }
        catch (Exception ex) when (ex is WebSocketException or JsonException)
        {
            socket.Dispose();
            throw new PathException(ErrorCodes.RelayUnreachable, "The connection to the relay was lost while waiting for the peer.", ex);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        return new RelayPath(socket);
    }

    /// <summary>Presents a fresh grant to the relay so it keeps forwarding past the previous lease.</summary>
    public async Task RenewLeaseAsync(string grantToken, CancellationToken cancellationToken)
    {
        byte[] message = JsonSerializer.SerializeToUtf8Bytes(new RelayLeaseRenewal { GrantToken = grantToken }, ProtocolJsonContext.Default.RelayLeaseRenewal);
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _socket.SendAsync(message, WebSocketMessageType.Text, endOfMessage: true, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_socket.State is WebSocketState.Open or WebSocketState.CloseReceived)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                await _sendLock.WaitAsync(timeout.Token).ConfigureAwait(false);
                try
                {
                    await _socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null, timeout.Token).ConfigureAwait(false);
                }
                finally
                {
                    _sendLock.Release();
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or WebSocketException or IOException or ObjectDisposedException)
            {
            }
        }
        _socket.Dispose();
    }

    private sealed class RelayStream(RelayPath path) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.IsEmpty)
            {
                return 0;
            }

            try
            {
                while (true)
                {
                    ValueWebSocketReceiveResult result = await path._socket.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                    switch (result.MessageType)
                    {
                        case WebSocketMessageType.Close:
                            // The relay ends a session it has a reason to end (lease over, revoked) with an
                            // application close code and the error code as description. Pass that on.
                            if ((int?)path._socket.CloseStatus >= 4000 && path._socket.CloseStatusDescription is { Length: > 0 } reason
                                && reason != ErrorCodes.PathClosed)
                            {
                                throw new PathException(reason, $"The relay ended the session ({reason}).");
                            }
                            return 0;
                        case WebSocketMessageType.Binary when result.Count > 0:
                            return result.Count;
                        default:
                            continue; // text messages are relay notices, not part of the byte stream
                    }
                }
            }
            catch (WebSocketException ex)
            {
                throw new IOException("The connection to the relay was lost.", ex);
            }
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await path._sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                while (!buffer.IsEmpty)
                {
                    int chunk = Math.Min(buffer.Length, MaxMessage);
                    await path._socket.SendAsync(buffer[..chunk], WebSocketMessageType.Binary, endOfMessage: true, cancellationToken).ConfigureAwait(false);
                    buffer = buffer[chunk..];
                }
            }
            catch (Exception ex) when (ex is WebSocketException or ObjectDisposedException or InvalidOperationException)
            {
                throw new IOException("The connection to the relay was lost.", ex);
            }
            finally
            {
                path._sendLock.Release();
            }
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override ValueTask DisposeAsync() => path.DisposeAsync();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                path.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
            base.Dispose(disposing);
        }
    }
}
