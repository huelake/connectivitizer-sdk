using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using Huelake.Connectivitizer.Client.Identity;
using Huelake.Connectivitizer.Client.Platform;
using Huelake.Connectivitizer.Client.Sessions;
using Huelake.Connectivitizer.Client.State;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client;

/// <summary>
/// Runs an agent from a <see cref="StateDirectory"/>: the same thing whether it is started by the
/// <c>cz</c> command line, the stand-alone agent executable or an application embedding it.
/// </summary>
public static class AgentHost
{
    public static string Version { get; } =
        typeof(AgentHost).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    /// <summary>Enrolls this machine. Generates both device keys locally and stores them in <paramref name="state"/>.</summary>
    public static async Task<DeviceRegistration> EnrollAsync(StateDirectory state, Uri apiUrl, string enrollmentToken, string name, CancellationToken cancellationToken = default)
    {
        if (state.LoadDevice() is { } existing)
        {
            throw new InvalidOperationException($"This state directory already belongs to device '{existing.Name}' ({existing.DeviceId}). Use another directory or remove it first.");
        }

        using ECDsa authKey = state.LoadOrCreateAuthKey();
        using EndpointIdentity identity = state.LoadOrCreateIdentity(name);
        EnrollResponse enrolled = await new PlatformApi(apiUrl).EnrollAsync(enrollmentToken, name, authKey, identity,
            System.Runtime.InteropServices.RuntimeInformation.OSDescription, Version, cancellationToken).ConfigureAwait(false);

        var registration = new DeviceRegistration
        {
            ApiUrl = apiUrl.ToString(),
            DeviceId = enrolled.DeviceId,
            WorkspaceId = enrolled.WorkspaceId,
            Name = enrolled.Name,
            Slug = enrolled.Slug,
        };
        state.SaveDevice(registration);
        return registration;
    }

    /// <summary>
    /// Makes this machine a device that logs in with a device key under <paramref name="name"/>.
    /// The first login under a name creates the device in the workspace; the same key and name
    /// later are that device again. Nothing is generated: the key is all the platform is given.
    /// </summary>
    public static async Task<DeviceRegistration> LoginWithDeviceKeyAsync(StateDirectory state, Uri apiUrl, string deviceKey, string name, CancellationToken cancellationToken = default)
    {
        if (state.LoadDevice() is { } existing && (existing.DeviceKey is null || existing.Name != name))
        {
            throw new InvalidOperationException($"This state directory already belongs to device '{existing.Name}' ({existing.DeviceId}). Use another directory or remove it first.");
        }

        using EndpointIdentity? identity = state.HasIdentity ? state.LoadIdentity() : null;
        TokenResponse token = await new PlatformApi(apiUrl).GetDeviceKeyTokenAsync(deviceKey, name, identity,
            System.Runtime.InteropServices.RuntimeInformation.OSDescription, Version, cancellationToken).ConfigureAwait(false);

        var registration = new DeviceRegistration
        {
            ApiUrl = apiUrl.ToString(),
            DeviceId = token.EndpointId,
            WorkspaceId = token.WorkspaceId,
            Name = name,
            Slug = token.Slug,
            DeviceKey = deviceKey,
        };
        state.SaveDevice(registration);
        return registration;
    }

    /// <summary>Creates an agent from the enrollment or device key, identity, shared keys, trust and services found in <paramref name="state"/>.</summary>
    /// <param name="direct">How to attempt direct connections; null reads <see cref="DirectSettings.FromEnvironment"/>.</param>
    public static ConnectivitizerAgent Create(StateDirectory state, Action<string>? log = null, bool allowPlatformIntroducedPeers = false, DirectSettings? direct = null)
    {
        direct ??= DirectSettings.FromEnvironment();
        DeviceRegistration registration = state.LoadDevice()
            ?? throw new InvalidOperationException($"No device is set up in '{state.Path}'. Run 'cz device enroll' or 'cz device login' first.");
        bool byKey = registration.DeviceKey is not null;
        return new ConnectivitizerAgent(new ConnectivitizerAgentOptions
        {
            ApiUrl = new Uri(registration.ApiUrl),
            DeviceId = registration.DeviceId,
            AuthKey = byKey ? null : state.LoadOrCreateAuthKey(),
            DeviceKey = registration.DeviceKey,
            DeviceName = byKey ? registration.Name : null,
            // An enrolled device always has a certificate; one that logs in with a device key has one only if it was created.
            Identity = byKey && !state.HasIdentity ? null : state.LoadIdentity(),
            SharedKeys = state.LoadSharedKeys(),
            Trust = state.OpenTrustStore(),
            Services = state.LoadServices(),
            AllowPlatformIntroducedPeers = allowPlatformIntroducedPeers,
            AgentVersion = Version,
            Log = log,
            DisableDirect = direct.Transports == DirectTransports.None,
            DirectTransports = direct.Transports,
            TcpListenPort = direct.TcpListenPort,
            PublicTcpEndpoints = direct.PublicTcpEndpoints,
        });
    }
}

/// <summary>
/// How an endpoint attempts direct connections, as the command line tools and examples configure it.
/// </summary>
public sealed record DirectSettings
{
    /// <summary><c>CZ_DIRECT</c>: <c>all</c> (default), <c>udp</c>, <c>tcp</c> or <c>none</c>.</summary>
    public DirectTransports Transports { get; init; } = DirectTransports.All;

    /// <summary><c>CZ_TCP_PORT</c>: see <see cref="ConnectivitizerClientOptions.TcpListenPort"/>.</summary>
    public int TcpListenPort { get; init; }

    /// <summary><c>CZ_PUBLIC_TCP</c>: comma separated <c>host:port</c>, see <see cref="ConnectivitizerClientOptions.PublicTcpEndpoints"/>.</summary>
    public IReadOnlyList<string> PublicTcpEndpoints { get; init; } = [];

    public static DirectSettings FromEnvironment() => Parse(
        Environment.GetEnvironmentVariable("CZ_DIRECT"),
        Environment.GetEnvironmentVariable("CZ_TCP_PORT"),
        Environment.GetEnvironmentVariable("CZ_PUBLIC_TCP"));

    /// <summary>Builds settings from their text forms; a null or empty value leaves the default.</summary>
    public static DirectSettings Parse(string? transports, string? tcpPort, string? publicTcp)
    {
        var settings = new DirectSettings();
        if (!string.IsNullOrWhiteSpace(transports))
        {
            settings = settings with
            {
                Transports = transports.Trim().ToLowerInvariant() switch
                {
                    "all" => DirectTransports.All,
                    "udp" => DirectTransports.Udp,
                    "tcp" => DirectTransports.Tcp,
                    "none" => DirectTransports.None,
                    _ => throw new FormatException($"'{transports}' is not one of all, udp, tcp, none."),
                },
            };
        }
        if (!string.IsNullOrWhiteSpace(tcpPort))
        {
            if (!int.TryParse(tcpPort, out int port) || port is < -1 or > 65535)
            {
                throw new FormatException($"'{tcpPort}' is not a TCP port (0 for any free port, -1 to never listen).");
            }
            settings = settings with { TcpListenPort = port };
        }
        if (!string.IsNullOrWhiteSpace(publicTcp))
        {
            string[] endpoints = publicTcp.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (string endpoint in endpoints)
            {
                StateDirectory.ParseTarget(endpoint);
            }
            settings = settings with { PublicTcpEndpoints = endpoints };
        }
        return settings;
    }
}

/// <summary>
/// Makes one service of a session available on a local TCP port, so that programs in any language
/// can use it with their ordinary HTTP, WebSocket or TCP client.
/// </summary>
public sealed class LocalPortForward : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly TunnelSession _session;
    private readonly string _service;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _acceptLoop;

    public LocalPortForward(TunnelSession session, string service, IPEndPoint listenOn)
    {
        _session = session;
        _service = service;
        _listener = new TcpListener(listenOn);
        _listener.Start();
        LocalEndPoint = (IPEndPoint)_listener.LocalEndpoint;
        _acceptLoop = Task.Run(AcceptLoopAsync);
    }

    /// <summary>The address local programs connect to.</summary>
    public IPEndPoint LocalEndPoint { get; }

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                TcpClient client = await _listener.AcceptTcpClientAsync(_stop.Token).ConfigureAwait(false);
                _ = Task.Run(() => ForwardAsync(client));
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
        {
        }
    }

    private async Task ForwardAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                client.NoDelay = true;
                await using Stream remote = await _session.OpenStreamAsync(_service, _stop.Token).ConfigureAwait(false);
                NetworkStream local = client.GetStream();
                Task up = local.CopyToAsync(remote, _stop.Token);
                Task down = remote.CopyToAsync(local, _stop.Token);
                await Task.WhenAny(up, down).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
            {
                // The local program sees its connection close; the reason is available from the session.
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        _listener.Stop();
        try
        {
            await _acceptLoop.ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
        }
        _stop.Dispose();
    }
}
