using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.Identity;

/// <summary>
/// The end-to-end identity of one endpoint: an ECDSA P-256 key pair and its X.509 certificate.
/// The private key is created and kept on the endpoint. Only <see cref="ExportCertificatePem"/>
/// and <see cref="Fingerprint"/> are ever meant to leave it.
/// </summary>
public sealed class EndpointIdentity : IDisposable
{
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";

    private readonly ECDsa _key;

    private EndpointIdentity(X509Certificate2 publicCertificate, ECDsa key)
    {
        _key = key;
        Fingerprint = Fingerprints.OfCertificate(publicCertificate);
        Name = publicCertificate.GetNameInfo(X509NameType.SimpleName, false);
        NotAfter = publicCertificate.NotAfter.ToUniversalTime();
        Certificate = ToTlsUsable(publicCertificate, key);
    }

    /// <summary>The certificate with its private key attached, usable by <c>SslStream</c> on every platform.</summary>
    public X509Certificate2 Certificate { get; }

    /// <summary>SHA-256 fingerprint of the public key, e.g. <c>sha256:ab12…</c>. This is what peers pin.</summary>
    public string Fingerprint { get; }

    public string Name { get; }

    public DateTime NotAfter { get; }

    /// <summary>Creates a new self-signed identity. The key never leaves this process unless explicitly exported.</summary>
    public static EndpointIdentity Create(string name, TimeSpan? validity = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        try
        {
            var subject = new X500DistinguishedNameBuilder();
            subject.AddCommonName(name);

            var request = new CertificateRequest(subject.Build(), key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid(ServerAuthOid), new Oid(ClientAuthOid) }, false));

            DateTimeOffset now = DateTimeOffset.UtcNow;
            using X509Certificate2 selfSigned = request.CreateSelfSigned(now.AddMinutes(-5), now.Add(validity ?? TimeSpan.FromDays(365)));
            X509Certificate2 publicOnly = X509CertificateLoader.LoadCertificate(selfSigned.RawData);
            return new EndpointIdentity(publicOnly, key);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    /// <summary>Loads an existing identity from a PEM certificate and a PEM (PKCS#8 or SEC1) private key.</summary>
    public static EndpointIdentity FromPem(string certificatePem, string privateKeyPem)
    {
        X509Certificate2 publicOnly = X509Certificate2.CreateFromPem(certificatePem);
        ECDsa key = ECDsa.Create();
        try
        {
            key.ImportFromPem(privateKeyPem);
            using ECDsa? certificateKey = publicOnly.GetECDsaPublicKey();
            if (certificateKey is null)
            {
                throw new CryptographicException("The certificate does not contain an ECDSA public key.");
            }
            if (!certificateKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(key.ExportSubjectPublicKeyInfo()))
            {
                throw new CryptographicException("The private key does not belong to the certificate.");
            }
            return new EndpointIdentity(publicOnly, key);
        }
        catch
        {
            key.Dispose();
            publicOnly.Dispose();
            throw;
        }
    }

    /// <summary>The public certificate in PEM form. Safe to share.</summary>
    public string ExportCertificatePem() => Certificate.ExportCertificatePem();

    /// <summary>The private key in PKCS#8 PEM form. For local storage on the endpoint only.</summary>
    public string ExportPrivateKeyPem() => _key.ExportPkcs8PrivateKeyPem();

    /// <summary>
    /// Signs <paramref name="data"/> with ECDSA P-256 / SHA-256. The signature is the fixed-size
    /// 64-byte r||s form (IEEE P1363), the same encoding JOSE ES256 uses.
    /// </summary>
    public byte[] Sign(ReadOnlySpan<byte> data) => _key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    /// <summary>Verifies a signature made by <see cref="Sign"/> against the public key of <paramref name="certificate"/>.</summary>
    public static bool Verify(X509Certificate2 certificate, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        using ECDsa? key = certificate.GetECDsaPublicKey();
        return key is not null && key.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    public void Dispose()
    {
        Certificate.Dispose();
        _key.Dispose();
    }

    private static X509Certificate2 ToTlsUsable(X509Certificate2 publicCertificate, ECDsa key)
    {
        using (publicCertificate)
        {
            X509Certificate2 withKey = publicCertificate.CopyWithPrivateKey(key);
            if (!OperatingSystem.IsWindows())
            {
                return withKey;
            }

            // SChannel cannot use the in-memory ("ephemeral") key that CopyWithPrivateKey attaches:
            // a TLS server fails outright and a TLS client silently sends no certificate.
            // Round-tripping through PKCS#12 gives the certificate a key SChannel accepts.
            using (withKey)
            {
                byte[] pkcs12 = withKey.Export(X509ContentType.Pkcs12);
                try
                {
                    return X509CertificateLoader.LoadPkcs12(pkcs12, null);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(pkcs12);
                }
            }
        }
    }
}

/// <summary>Identity fingerprints as used for pinning and in the wire protocol.</summary>
public static class Fingerprints
{
    public static string OfCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        byte[] spki = certificate.PublicKey.ExportSubjectPublicKeyInfo();
        return WireConstants.FingerprintPrefix + Convert.ToHexStringLower(SHA256.HashData(spki));
    }

    /// <summary>Normalises user input (case, surrounding whitespace) and checks the format.</summary>
    public static bool TryNormalize(string? value, out string fingerprint)
    {
        fingerprint = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string candidate = value.Trim().ToLowerInvariant();
        if (!candidate.StartsWith(WireConstants.FingerprintPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        ReadOnlySpan<char> hex = candidate.AsSpan(WireConstants.FingerprintPrefix.Length);
        if (hex.Length != 64 || hex.ContainsAnyExcept("0123456789abcdef"))
        {
            return false;
        }

        fingerprint = candidate;
        return true;
    }
}
