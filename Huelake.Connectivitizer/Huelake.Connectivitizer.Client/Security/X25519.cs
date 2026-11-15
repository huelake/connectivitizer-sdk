namespace Huelake.Connectivitizer.Client.Security;

/// <summary>
/// The X25519 key agreement function of RFC 7748. .NET has no public API for it, so it is
/// implemented here; the arithmetic follows the public-domain TweetNaCl reference (field elements
/// as 16 limbs of 16 bits, a Montgomery ladder whose sequence of operations does not depend on the
/// scalar). It is checked against the test vectors of the RFC in the test project.
/// </summary>
internal static class X25519
{
    public const int KeySize = 32;

    private static readonly byte[] BasePoint = CreateBasePoint();

    /// <summary>The public key that belongs to <paramref name="privateKey"/>.</summary>
    public static byte[] PublicKey(ReadOnlySpan<byte> privateKey) => ScalarMult(privateKey, BasePoint);

    /// <summary>The shared secret of <paramref name="privateKey"/> and a peer's <paramref name="publicKey"/>.</summary>
    public static byte[] ScalarMult(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        if (privateKey.Length != KeySize || publicKey.Length != KeySize)
        {
            throw new ArgumentException("X25519 keys are 32 bytes long.");
        }

        Span<byte> z = stackalloc byte[32];
        privateKey.CopyTo(z);
        z[31] = (byte)((z[31] & 127) | 64);
        z[0] &= 248;

        Span<long> x = stackalloc long[16];
        Unpack(x, publicKey);
        Span<long> a = stackalloc long[16];
        Span<long> b = stackalloc long[16];
        Span<long> c = stackalloc long[16];
        Span<long> d = stackalloc long[16];
        Span<long> e = stackalloc long[16];
        Span<long> f = stackalloc long[16];
        x.CopyTo(b);
        a[0] = 1;
        d[0] = 1;

        for (int i = 254; i >= 0; i--)
        {
            long bit = (z[i >> 3] >> (i & 7)) & 1;
            Swap(a, b, bit);
            Swap(c, d, bit);
            Add(e, a, c);
            Subtract(a, a, c);
            Add(c, b, d);
            Subtract(b, b, d);
            Multiply(d, e, e);
            Multiply(f, a, a);
            Multiply(a, c, a);
            Multiply(c, b, e);
            Add(e, a, c);
            Subtract(a, a, c);
            Multiply(b, a, a);
            Subtract(c, d, f);
            Multiply(a, c, A24);
            Add(a, a, d);
            Multiply(c, c, a);
            Multiply(a, d, f);
            Multiply(d, b, x);
            Multiply(b, e, e);
            Swap(a, b, bit);
            Swap(c, d, bit);
        }

        Invert(c, c);
        Multiply(a, a, c);
        byte[] result = new byte[32];
        Pack(result, a);
        z.Clear();
        return result;
    }

    /// <summary>The constant (486662 - 2) / 4 = 121665 of the curve.</summary>
    private static ReadOnlySpan<long> A24 => [0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    private static byte[] CreateBasePoint()
    {
        byte[] point = new byte[32];
        point[0] = 9;
        return point;
    }

    private static void Carry(Span<long> o)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] += 1L << 16;
            long c = o[i] >> 16;
            o[i < 15 ? i + 1 : 0] += c - 1 + (i == 15 ? 37 * (c - 1) : 0);
            o[i] -= c << 16;
        }
    }

    /// <summary>Exchanges p and q when <paramref name="bit"/> is 1, without branching on it.</summary>
    private static void Swap(Span<long> p, Span<long> q, long bit)
    {
        long mask = ~(bit - 1);
        for (int i = 0; i < 16; i++)
        {
            long t = mask & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    private static void Pack(Span<byte> o, ReadOnlySpan<long> n)
    {
        Span<long> m = stackalloc long[16];
        Span<long> t = stackalloc long[16];
        n.CopyTo(t);
        Carry(t);
        Carry(t);
        Carry(t);
        for (int j = 0; j < 2; j++)
        {
            m[0] = t[0] - 0xffed;
            for (int i = 1; i < 15; i++)
            {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            long borrow = (m[15] >> 16) & 1;
            m[14] &= 0xffff;
            Swap(t, m, 1 - borrow);
        }
        for (int i = 0; i < 16; i++)
        {
            o[2 * i] = (byte)(t[i] & 0xff);
            o[(2 * i) + 1] = (byte)(t[i] >> 8);
        }
    }

    private static void Unpack(Span<long> o, ReadOnlySpan<byte> n)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] = n[2 * i] + ((long)n[(2 * i) + 1] << 8);
        }
        o[15] &= 0x7fff;
    }

    private static void Add(Span<long> o, ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] = a[i] + b[i];
        }
    }

    private static void Subtract(Span<long> o, ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] = a[i] - b[i];
        }
    }

    private static void Multiply(Span<long> o, ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        Span<long> t = stackalloc long[31];
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 16; j++)
            {
                t[i + j] += a[i] * b[j];
            }
        }
        for (int i = 0; i < 15; i++)
        {
            t[i] += 38 * t[i + 16];
        }
        t[..16].CopyTo(o);
        Carry(o);
        Carry(o);
    }

    private static void Invert(Span<long> o, ReadOnlySpan<long> value)
    {
        Span<long> input = stackalloc long[16];
        Span<long> c = stackalloc long[16];
        value.CopyTo(input);
        input.CopyTo(c);
        for (int a = 253; a >= 0; a--)
        {
            Multiply(c, c, c);
            if (a != 2 && a != 4)
            {
                Multiply(c, c, input);
            }
        }
        c.CopyTo(o);
    }
}
