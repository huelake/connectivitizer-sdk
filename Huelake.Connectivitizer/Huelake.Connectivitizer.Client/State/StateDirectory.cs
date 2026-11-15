using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Huelake.Connectivitizer.Client.Identity;
using Huelake.Connectivitizer.Client.Security;
using Huelake.Connectivitizer.Client.Sessions;

namespace Huelake.Connectivitizer.Client.State;

/// <summary>What a device remembers about its enrollment.</summary>
public sealed record DeviceRegistration
{
    [JsonPropertyName("apiUrl")] public required string ApiUrl { get; init; }

    [JsonPropertyName("deviceId")] public required string DeviceId { get; init; }

    [JsonPropertyName("workspaceId")] public required string WorkspaceId { get; init; }

    [JsonPropertyName("name")] public required string Name { get; init; }

    [JsonPropertyName("slug")] public string? Slug { get; init; }

    /// <summary>Set for a device that logs in with a device key (<c>czd_…</c>) instead of a login key of its own.</summary>
    [JsonPropertyName("deviceKey")] public string? DeviceKey { get; init; }
}

/// <summary>A service the device exposes. This is local configuration; the target never leaves the device.</summary>
public sealed record ServiceEntry
{
    [JsonPropertyName("name")] public required string Name { get; init; }

    /// <summary><c>host:port</c> of the local application.</summary>
    [JsonPropertyName("target")] public required string Target { get; init; }

    [JsonPropertyName("protocol")] public string Protocol { get; init; } = "tcp";

    /// <summary>
    /// Who may use the service: identity fingerprints, and <c>key:&lt;name&gt;</c> for peers that
    /// authenticate with that shared key. Null allows every peer the device trusts.
    /// </summary>
    [JsonPropertyName("allow")] public List<string>? Allow { get; init; }

    /// <summary>
    /// The owner's local consent to compatibility mode for this service: the platform's gateway
    /// may connect to it on behalf of applications that cannot run the end-to-end stack, and can
    /// read that traffic. Off unless switched on here, on the device - the platform cannot set it.
    /// </summary>
    [JsonPropertyName("compatibility")] public bool Compatibility { get; init; }
}

internal sealed record SharedKeyEntry
{
    [JsonPropertyName("name")] public required string Name { get; init; }

    [JsonPropertyName("key")] public required string Key { get; init; }
}

internal sealed record SharedKeysFile
{
    [JsonPropertyName("keys")] public List<SharedKeyEntry> Keys { get; init; } = [];
}

internal sealed record ServicesFile
{
    [JsonPropertyName("services")] public List<ServiceEntry> Services { get; init; } = [];
}

/// <summary>
/// The directory in which an endpoint keeps its keys, its trust store and its configuration.
/// Everything in it stays on the endpoint; the private keys in particular are never transmitted.
/// </summary>
public sealed class StateDirectory
{
    private const string IdentityCertificateFile = "identity.cert.pem";
    private const string IdentityKeyFile = "identity.key.pem";
    private const string AuthKeyFile = "auth.key.pem";
    private const string DeviceFile = "device.json";
    private const string ServicesFileName = "services.json";
    private const string TrustFileName = "trust.json";
    private const string PairingsFileName = "pairings.json";
    private const string SharedKeysFileName = "sharedkeys.json";

    public StateDirectory(string? path = null)
    {
        Path = System.IO.Path.GetFullPath(path ?? DefaultPath());
        Directory.CreateDirectory(Path);
        RestrictToOwner(Path, isDirectory: true);
    }

    public string Path { get; }

    /// <summary><c>CONNECTIVITIZER_HOME</c>, else the per-user application data folder.</summary>
    public static string DefaultPath()
    {
        string? configured = Environment.GetEnvironmentVariable("CONNECTIVITIZER_HOME");
        return !string.IsNullOrWhiteSpace(configured)
            ? configured
            : System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.Create), "connectivitizer");
    }

    public TrustStore OpenTrustStore() => new(File(TrustFileName));

    public bool HasIdentity => System.IO.File.Exists(File(IdentityCertificateFile)) && System.IO.File.Exists(File(IdentityKeyFile));

    public EndpointIdentity LoadIdentity()
        => EndpointIdentity.FromPem(System.IO.File.ReadAllText(File(IdentityCertificateFile)), System.IO.File.ReadAllText(File(IdentityKeyFile)));

    /// <summary>Loads the endpoint's identity, creating a new one (key generated here) on first use.</summary>
    public EndpointIdentity LoadOrCreateIdentity(string name)
    {
        if (HasIdentity)
        {
            return LoadIdentity();
        }
        EndpointIdentity identity = EndpointIdentity.Create(name);
        SaveIdentity(identity);
        return identity;
    }

    public void SaveIdentity(EndpointIdentity identity)
    {
        WritePrivate(IdentityKeyFile, identity.ExportPrivateKeyPem());
        System.IO.File.WriteAllText(File(IdentityCertificateFile), identity.ExportCertificatePem());
    }

    public bool HasAuthKey => System.IO.File.Exists(File(AuthKeyFile));

    /// <summary>The key a device logs in to the platform with. Separate from the end-to-end identity.</summary>
    public ECDsa LoadOrCreateAuthKey()
    {
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        if (HasAuthKey)
        {
            key.ImportFromPem(System.IO.File.ReadAllText(File(AuthKeyFile)));
        }
        else
        {
            WritePrivate(AuthKeyFile, key.ExportPkcs8PrivateKeyPem());
        }
        return key;
    }

    public DeviceRegistration? LoadDevice()
        => System.IO.File.Exists(File(DeviceFile))
            ? JsonSerializer.Deserialize(System.IO.File.ReadAllBytes(File(DeviceFile)), ClientJsonContext.Default.DeviceRegistration)
            : null;

    /// <summary>Stored privately: for a device that logs in with a device key the file holds that key.</summary>
    public void SaveDevice(DeviceRegistration registration)
        => WritePrivate(DeviceFile, JsonSerializer.Serialize(registration, ClientJsonContext.Default.DeviceRegistration));

    /// <summary>
    /// The keys this endpoint shares with its peers, each under the name this endpoint gave it.
    /// They are secrets and stay in this directory.
    /// </summary>
    public List<SharedKey> LoadSharedKeys()
    {
        if (!System.IO.File.Exists(File(SharedKeysFileName)))
        {
            return [];
        }
        SharedKeysFile? file = JsonSerializer.Deserialize(System.IO.File.ReadAllBytes(File(SharedKeysFileName)), ClientJsonContext.Default.SharedKeysFile);
        return [.. (file?.Keys ?? []).Select(entry => SharedKey.Parse(entry.Key, entry.Name))];
    }

    public void SaveSharedKeys(IEnumerable<SharedKey> keys)
        => WritePrivate(SharedKeysFileName, JsonSerializer.Serialize(
            new SharedKeysFile { Keys = [.. keys.Select(k => new SharedKeyEntry { Name = k.Name, Key = k.Export() })] }, ClientJsonContext.Default.SharedKeysFile));

    public List<ServiceEntry> LoadServices()
        => System.IO.File.Exists(File(ServicesFileName))
            ? JsonSerializer.Deserialize(System.IO.File.ReadAllBytes(File(ServicesFileName)), ClientJsonContext.Default.ServicesFile)?.Services ?? []
            : [];

    public void SaveServices(List<ServiceEntry> services)
        => System.IO.File.WriteAllBytes(File(ServicesFileName), JsonSerializer.SerializeToUtf8Bytes(new ServicesFile { Services = services }, ClientJsonContext.Default.ServicesFile));

    /// <summary>Invitations this endpoint issued and has not completed yet. They contain secrets and stay private.</summary>
    public List<PendingPairing> LoadPendingPairings()
        => System.IO.File.Exists(File(PairingsFileName))
            ? JsonSerializer.Deserialize(System.IO.File.ReadAllBytes(File(PairingsFileName)), PairingJsonContext.Default.PendingPairingsFile)?.Pending ?? []
            : [];

    public void SavePendingPairings(List<PendingPairing> pending)
        => WritePrivate(PairingsFileName, JsonSerializer.Serialize(new PendingPairingsFile { Pending = pending }, PairingJsonContext.Default.PendingPairingsFile));

    /// <summary>Builds the directory the session layer consults from the locally declared services.</summary>
    public static LocalServiceDirectory ToDirectory(IEnumerable<ServiceEntry> services)
    {
        var directory = new LocalServiceDirectory();
        foreach (ServiceEntry service in services)
        {
            (string host, int port) = ParseTarget(service.Target);
            directory.Add(service.Name, host, port, service.Allow);
        }
        return directory;
    }

    public static (string Host, int Port) ParseTarget(string target)
    {
        int colon = target.LastIndexOf(':');
        if (colon <= 0 || !int.TryParse(target.AsSpan(colon + 1), out int port) || port is < 1 or > 65535)
        {
            throw new FormatException($"'{target}' is not a valid target; expected host:port.");
        }
        return (target[..colon].Trim('[', ']'), port);
    }

    private string File(string name) => System.IO.Path.Combine(Path, name);

    private void WritePrivate(string name, string content)
    {
        string path = File(name);
        System.IO.File.WriteAllText(path, content);
        RestrictToOwner(path, isDirectory: false);
    }

    private static void RestrictToOwner(string path, bool isDirectory)
    {
        // On Windows the per-user profile folder already limits access to the user.
        if (OperatingSystem.IsWindows())
        {
            return;
        }
        UnixFileMode mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | (isDirectory ? UnixFileMode.UserExecute : 0);
        System.IO.File.SetUnixFileMode(path, mode);
    }
}

[JsonSourceGenerationOptions(WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(TrustFile))]
[JsonSerializable(typeof(DeviceRegistration))]
[JsonSerializable(typeof(ServicesFile))]
[JsonSerializable(typeof(SharedKeysFile))]
internal sealed partial class ClientJsonContext : JsonSerializerContext;
