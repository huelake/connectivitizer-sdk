using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Huelake.Connectivitizer.Protocol;

/// <summary>
/// The one token format the protocol uses: a compact JWS signed with ES256 (ECDSA P-256 /
/// SHA-256, 64-byte r||s signature). Deliberately minimal so that relays, agents and SDKs in any
/// language can verify tokens offline with nothing but a P-256 implementation.
/// </summary>
public static class CompactJws
{
    private const string Algorithm = "ES256";

    public static string Sign(ReadOnlySpan<byte> payloadUtf8Json, ECDsa key, string keyId)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentException.ThrowIfNullOrEmpty(keyId);

        byte[] header = JsonSerializer.SerializeToUtf8Bytes(new JwsHeader(Algorithm, "JWT", keyId), ProtocolJsonContext.Default.JwsHeader);
        string signingInput = Base64Url.EncodeToString(header) + "." + Base64Url.EncodeToString(payloadUtf8Json);
        byte[] signature = key.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return signingInput + "." + Base64Url.EncodeToString(signature);
    }

    /// <summary>Reads the key id from a token's header without verifying anything, so the right key can be fetched first.</summary>
    public static bool TryReadKeyId(string? token, out string keyId)
    {
        keyId = string.Empty;
        if (string.IsNullOrEmpty(token) || token.Length > 16 * 1024)
        {
            return false;
        }

        int firstDot = token.IndexOf('.');
        if (firstDot <= 0)
        {
            return false;
        }

        try
        {
            JwsHeader? header = JsonSerializer.Deserialize(Base64Url.DecodeFromChars(token.AsSpan(0, firstDot)), ProtocolJsonContext.Default.JwsHeader);
            if (header is null || string.IsNullOrEmpty(header.Kid))
            {
                return false;
            }
            keyId = header.Kid;
            return true;
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Verifies the signature and returns the payload. <paramref name="resolveKey"/> maps the
    /// token's key id to a public key, or returns null for an unknown key.
    /// </summary>
    public static bool TryVerify(string? token, Func<string, ECDsa?> resolveKey, out byte[] payloadUtf8Json)
    {
        ArgumentNullException.ThrowIfNull(resolveKey);
        payloadUtf8Json = [];
        if (string.IsNullOrEmpty(token) || token.Length > 16 * 1024)
        {
            return false;
        }

        int firstDot = token.IndexOf('.');
        int lastDot = token.LastIndexOf('.');
        if (firstDot <= 0 || lastDot <= firstDot + 1 || lastDot == token.Length - 1)
        {
            return false;
        }

        try
        {
            byte[] headerBytes = Base64Url.DecodeFromChars(token.AsSpan(0, firstDot));
            JwsHeader? header = JsonSerializer.Deserialize(headerBytes, ProtocolJsonContext.Default.JwsHeader);
            // The algorithm is fixed. Accepting whatever the header names is how "alg" attacks work.
            if (header is not { Alg: Algorithm } || string.IsNullOrEmpty(header.Kid))
            {
                return false;
            }

            ECDsa? key = resolveKey(header.Kid);
            if (key is null)
            {
                return false;
            }

            byte[] signature = Base64Url.DecodeFromChars(token.AsSpan(lastDot + 1));
            byte[] signingInput = Encoding.ASCII.GetBytes(token, 0, lastDot);
            if (!key.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                return false;
            }

            payloadUtf8Json = Base64Url.DecodeFromChars(token.AsSpan(firstDot + 1, lastDot - firstDot - 1));
            return true;
        }
        catch (Exception ex) when (ex is FormatException or JsonException or CryptographicException)
        {
            return false;
        }
    }
}

public sealed record JwsHeader(
    [property: System.Text.Json.Serialization.JsonPropertyName("alg")] string Alg,
    [property: System.Text.Json.Serialization.JsonPropertyName("typ")] string Typ,
    [property: System.Text.Json.Serialization.JsonPropertyName("kid")] string Kid);
