using System.Buffers.Text;
using System.Security.Cryptography;

namespace Huelake.Connectivitizer.Client.Security;

/// <summary>
/// A key that two endpoints hold and nobody else does. Sessions between them are encrypted and
/// authenticated end to end with it; the platform never receives it. Whoever has the key can talk
/// to the other holders, so it is kept like a password: 32 random bytes, written
/// <c>czs_&lt;base64url&gt;</c>.
/// </summary>
public sealed class SharedKey
{
    public const string Prefix = "czs_";
    public const int Size = 32;

    private readonly byte[] _key;

    private SharedKey(string name, byte[] key)
    {
        Name = name;
        _key = key;
    }

    /// <summary>What this endpoint calls the key (for example the peer it shares it with). Never transmitted.</summary>
    public string Name { get; }

    internal ReadOnlySpan<byte> Bytes => _key;

    /// <summary>The characters of a generated key (protocol section 1.2): one case, no I and O, no 0 and 1.</summary>
    public const string ReadableAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    /// <summary>A new random key, generated readable (<see cref="GenerateText"/>).</summary>
    public static SharedKey Generate(string name = "default") => Parse(GenerateText(), name);

    /// <summary>
    /// A new random key in its text form, readable: 42 characters of <see cref="ReadableAlphabet"/> and a
    /// last <c>A</c> or <c>Q</c>, which keeps it the canonical base64url of 32 bytes. 211 bits of randomness.
    /// </summary>
    public static string GenerateText()
    {
        byte[] random = RandomNumberGenerator.GetBytes(43);
        char[] text = new char[43];
        for (int i = 0; i < 42; i++)
        {
            // 32 characters: the low five bits of a random byte pick one uniformly.
            text[i] = ReadableAlphabet[random[i] & 31];
        }
        text[42] = (random[42] & 1) == 0 ? 'A' : 'Q';
        return Prefix + new string(text);
    }

    /// <summary>Reads a key in its text form. Throws <see cref="FormatException"/> when it is not one.</summary>
    public static SharedKey Parse(string text, string name = "default")
        => TryParse(text, name, out SharedKey? key) ? key! : throw new FormatException("A shared key looks like czs_ followed by 43 characters.");

    public static bool TryParse(string? text, string name, out SharedKey? key)
    {
        key = null;
        text = text?.Trim();
        if (text is null || !text.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        byte[] bytes = new byte[Size + 4];
        if (Base64Url.DecodeFromChars(text.AsSpan(Prefix.Length), bytes, out int consumed, out int written) != System.Buffers.OperationStatus.Done
            || consumed != text.Length - Prefix.Length || written != Size)
        {
            return false;
        }
        key = new SharedKey(Normalize(name), bytes[..Size]);
        return true;
    }

    /// <summary>The text form, <c>czs_…</c>. This is the secret itself.</summary>
    public string Export() => Prefix + Base64Url.EncodeToString(_key);

    /// <summary>How a peer authenticated with this key is named in a service's allow-list.</summary>
    public string AllowListEntry => AllowListPrefix + Name;

    public const string AllowListPrefix = "key:";

    public override string ToString() => $"shared key '{Name}'";

    private static string Normalize(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return name.Trim();
    }
}
