using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Huelake.Connectivitizer.Client.Identity;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.Security;

/// <summary>
/// The end-to-end layer: mutual TLS 1.3 between two endpoints, run over whatever byte stream the
/// path provides (a relay WebSocket or a direct connection). Nothing between the two endpoints
/// holds a key for it.
/// </summary>
/// <remarks>
/// Peers are authenticated only by <see cref="IPeerVerifier"/>, i.e. by local trust in the
/// certificate's public key. Certificate chains, host names and revocation lists are deliberately
/// not consulted: there is no public CA involved and the platform must not be able to vouch for a key.
/// </remarks>
public static class SecureChannel
{
    private static readonly List<SslApplicationProtocol> ApplicationProtocols = [new SslApplicationProtocol(WireConstants.TunnelAlpn)];

    /// <summary>Runs the TLS handshake as the initiating endpoint (TLS client).</summary>
    public static Task<SecureStream> ConnectAsync(Stream path, EndpointIdentity local, IPeerVerifier verifier, CancellationToken cancellationToken = default)
        => HandshakeAsync(path, local, verifier, isServer: false, cancellationToken);

    /// <summary>Runs the TLS handshake as the accepting endpoint (TLS server). A client certificate is mandatory.</summary>
    public static Task<SecureStream> AcceptAsync(Stream path, EndpointIdentity local, IPeerVerifier verifier, CancellationToken cancellationToken = default)
        => HandshakeAsync(path, local, verifier, isServer: true, cancellationToken);

    private static async Task<SecureStream> HandshakeAsync(Stream path, EndpointIdentity local, IPeerVerifier verifier, bool isServer, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(local);
        ArgumentNullException.ThrowIfNull(verifier);

        var validation = new PeerValidation(verifier);
        var tls = new SslStream(path, leaveInnerStreamOpen: false);
        try
        {
            // offline: true => never touch the network or the machine store to build a chain.
            SslStreamCertificateContext certificateContext = SslStreamCertificateContext.Create(local.Certificate, additionalCertificates: null, offline: true);

            if (isServer)
            {
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificateContext = certificateContext,
                    ClientCertificateRequired = true,
                    EnabledSslProtocols = SslProtocols.Tls13,
                    ApplicationProtocols = ApplicationProtocols,
                    RemoteCertificateValidationCallback = validation.Validate,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    AllowRenegotiation = false,
                    AllowTlsResume = false,
                }, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = WireConstants.TunnelServerName,
                    ClientCertificateContext = certificateContext,
                    EnabledSslProtocols = SslProtocols.Tls13,
                    ApplicationProtocols = ApplicationProtocols,
                    RemoteCertificateValidationCallback = validation.Validate,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    AllowRenegotiation = false,
                    AllowTlsResume = false,
                }, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            await tls.DisposeAsync().ConfigureAwait(false);
            string code = validation.Verdict is { Accepted: false, ErrorCode: not null } rejected
                ? rejected.ErrorCode!
                : ErrorCodes.E2eHandshakeFailed;
            throw new SecureChannelException(code, $"The end-to-end handshake failed ({code}).", ex);
        }
        catch
        {
            await tls.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        // The callback is the only thing that authenticates the peer; never continue without its acceptance.
        if (validation.Verdict is not { Accepted: true } || validation.Peer is null
            || tls.SslProtocol != SslProtocols.Tls13
            || tls.NegotiatedApplicationProtocol != ApplicationProtocols[0])
        {
            await tls.DisposeAsync().ConfigureAwait(false);
            string code = validation.Verdict is { Accepted: false, ErrorCode: not null } rejected
                ? rejected.ErrorCode!
                : ErrorCodes.E2eProtocolMismatch;
            throw new SecureChannelException(code, $"The end-to-end channel was not established as required ({code}).");
        }

        return new SecureStream(tls, validation.Peer);
    }

    private sealed class PeerValidation(IPeerVerifier verifier)
    {
        public PeerVerdict? Verdict { get; private set; }

        public PeerIdentity? Peer { get; private set; }

        public bool Validate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            // sslPolicyErrors and chain are ignored on purpose: trust comes from the local pin only.
            if (certificate is null)
            {
                Verdict = PeerVerdict.Reject(ErrorCodes.E2ePeerNoCertificate);
                return false;
            }

            X509Certificate2 remote = certificate as X509Certificate2 ?? X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
            DateTime now = DateTime.UtcNow;
            if (now < remote.NotBefore.ToUniversalTime() || now > remote.NotAfter.ToUniversalTime())
            {
                Verdict = PeerVerdict.Reject(ErrorCodes.E2ePeerCertificateExpired);
                return false;
            }

            string fingerprint = Fingerprints.OfCertificate(remote);
            PeerVerdict verdict = verifier.Verify(remote, fingerprint);
            Verdict = verdict;
            if (!verdict.Accepted)
            {
                return false;
            }

            Peer = new PeerIdentity(fingerprint, remote.GetNameInfo(X509NameType.SimpleName, false), verdict.Trust, remote.ExportCertificatePem());
            return true;
        }
    }
}

/// <summary>An established end-to-end encrypted stream together with the identity of its remote endpoint.</summary>
public sealed class SecureStream : IAsyncDisposable
{
    internal SecureStream(Stream stream, PeerIdentity peer)
    {
        Stream = stream;
        Peer = peer;
    }

    public Stream Stream { get; }

    public PeerIdentity Peer { get; }

    public ValueTask DisposeAsync() => Stream.DisposeAsync();
}
