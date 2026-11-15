using System.Security.Cryptography;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.Platform;

/// <summary>
/// Verifies session grants on the endpoint, offline, with the control plane's published public
/// keys. An endpoint acts on a grant because its signature checks out, not because of the channel
/// it arrived on.
/// </summary>
internal sealed class GrantVerifier(PlatformApi api)
{
    private static readonly TimeSpan MinRefreshInterval = TimeSpan.FromSeconds(30);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private Dictionary<string, ECDsa> _keys = new(StringComparer.Ordinal);
    private long _lastRefresh = long.MinValue;

    public async Task<GrantValidation> ValidateAsync(string token, string audience, bool forSessionStart, CancellationToken cancellationToken)
    {
        if (!CompactJws.TryReadKeyId(token, out string keyId))
        {
            return new GrantValidation(null, ErrorCodes.GrantInvalid);
        }
        if (!_keys.ContainsKey(keyId))
        {
            await RefreshAsync(cancellationToken).ConfigureAwait(false);
        }
        return Validate(token, audience, forSessionStart);
    }

    /// <summary>Validates with the keys already known (used for in-session lease renewals, which must not block on the network).</summary>
    public GrantValidation Validate(string token, string audience, bool forSessionStart)
    {
        Dictionary<string, ECDsa> keys = _keys;
        return SessionGrantToken.Validate(token, kid => keys.GetValueOrDefault(kid), audience, DateTimeOffset.UtcNow, forSessionStart);
    }

    private async Task RefreshAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            long now = Environment.TickCount64;
            if (_lastRefresh != long.MinValue && now - _lastRefresh < (long)MinRefreshInterval.TotalMilliseconds)
            {
                return;
            }
            _lastRefresh = now;
            _keys = await api.GetGrantKeysAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (PlatformException)
        {
            // Without keys the grant simply does not validate; the caller reports GRANT_INVALID.
        }
        finally
        {
            _gate.Release();
        }
    }
}

/// <summary>What this implementation supports, announced to the control plane and to peers.</summary>
internal static class LocalCapabilities
{
    /// <summary>
    /// What an endpoint announces: the end-to-end layers it is configured for (a certificate, shared
    /// keys, or both) and the direct transports its options leave switched on.
    /// </summary>
    public static string[] For(bool disableDirect, DirectTransports transports, bool certificate = true, bool sharedKey = false)
    {
        List<string> capabilities = [Capabilities.MuxYamux, Capabilities.PathRelayWs];
        if (certificate)
        {
            capabilities.Insert(0, Capabilities.E2eTls13);
        }
        if (sharedKey)
        {
            capabilities.Add(Capabilities.E2eSharedKey);
        }
        if (!disableDirect && transports.HasFlag(DirectTransports.Tcp))
        {
            capabilities.Add(Capabilities.PathTcp);
        }
        if (!disableDirect && transports.HasFlag(DirectTransports.Udp))
        {
            capabilities.Add(Capabilities.PathUdpKcp);
        }
        return [.. capabilities];
    }
}
