package com.huelake.connectivitizer.internal

/**
 * The X25519 key agreement function of RFC 7748, because Android's JCA has none before API 33. The
 * arithmetic follows the public-domain TweetNaCl reference, as the .NET library's X25519.cs does (field
 * elements as 16 limbs of 16 bits, a Montgomery ladder whose operations do not depend on the scalar). It is
 * checked against the RFC's test vectors.
 */
internal object X25519 {
    const val KEY_SIZE = 32
    private val BASE_POINT = ByteArray(32).also { it[0] = 9 }
    private val A24 = longArrayOf(0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    fun publicKey(privateKey: ByteArray): ByteArray = scalarMult(privateKey, BASE_POINT)

    fun scalarMult(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        require(privateKey.size == KEY_SIZE && publicKey.size == KEY_SIZE) { "X25519 keys are 32 bytes long." }
        val z = privateKey.copyOf()
        z[31] = ((z[31].toInt() and 127) or 64).toByte()
        z[0] = (z[0].toInt() and 248).toByte()
        val x = LongArray(16)
        unpack(x, publicKey)
        val a = LongArray(16)
        val b = x.copyOf()
        val c = LongArray(16)
        val d = LongArray(16)
        val e = LongArray(16)
        val f = LongArray(16)
        a[0] = 1
        d[0] = 1
        for (i in 254 downTo 0) {
            val bit = ((z[i shr 3].toInt() and 0xff) shr (i and 7) and 1).toLong()
            swap(a, b, bit)
            swap(c, d, bit)
            add(e, a, c)
            sub(a, a, c)
            add(c, b, d)
            sub(b, b, d)
            mul(d, e, e)
            mul(f, a, a)
            mul(a, c, a)
            mul(c, b, e)
            add(e, a, c)
            sub(a, a, c)
            mul(b, a, a)
            sub(c, d, f)
            mul(a, c, A24)
            add(a, a, d)
            mul(c, c, a)
            mul(a, d, f)
            mul(d, b, x)
            mul(b, e, e)
            swap(a, b, bit)
            swap(c, d, bit)
        }
        invert(c, c)
        mul(a, a, c)
        val result = ByteArray(32)
        pack(result, a)
        z.fill(0)
        return result
    }

    private fun carry(o: LongArray) {
        for (i in 0 until 16) {
            o[i] += 1L shl 16
            val c = o[i] shr 16
            o[if (i < 15) i + 1 else 0] += c - 1 + (if (i == 15) 37 * (c - 1) else 0)
            o[i] -= c shl 16
        }
    }

    /** Exchanges p and q when [bit] is 1, without branching on it. */
    private fun swap(p: LongArray, q: LongArray, bit: Long) {
        val mask = (bit - 1).inv()
        for (i in 0 until 16) {
            val t = mask and (p[i] xor q[i])
            p[i] = p[i] xor t
            q[i] = q[i] xor t
        }
    }

    private fun pack(o: ByteArray, n: LongArray) {
        val m = LongArray(16)
        val t = n.copyOf()
        carry(t)
        carry(t)
        carry(t)
        for (j in 0 until 2) {
            m[0] = t[0] - 0xffed
            for (i in 1 until 15) {
                m[i] = t[i] - 0xffff - ((m[i - 1] shr 16) and 1)
                m[i - 1] = m[i - 1] and 0xffff
            }
            m[15] = t[15] - 0x7fff - ((m[14] shr 16) and 1)
            val borrow = (m[15] shr 16) and 1
            m[14] = m[14] and 0xffff
            swap(t, m, 1 - borrow)
        }
        for (i in 0 until 16) {
            o[2 * i] = (t[i] and 0xff).toByte()
            o[2 * i + 1] = (t[i] shr 8).toByte()
        }
    }

    private fun unpack(o: LongArray, n: ByteArray) {
        for (i in 0 until 16) o[i] = (n[2 * i].toLong() and 0xff) + ((n[2 * i + 1].toLong() and 0xff) shl 8)
        o[15] = o[15] and 0x7fff
    }

    private fun add(o: LongArray, a: LongArray, b: LongArray) {
        for (i in 0 until 16) o[i] = a[i] + b[i]
    }

    private fun sub(o: LongArray, a: LongArray, b: LongArray) {
        for (i in 0 until 16) o[i] = a[i] - b[i]
    }

    private fun mul(o: LongArray, a: LongArray, b: LongArray) {
        val t = LongArray(31)
        for (i in 0 until 16) for (j in 0 until 16) t[i + j] += a[i] * b[j]
        for (i in 0 until 15) t[i] += 38 * t[i + 16]
        System.arraycopy(t, 0, o, 0, 16)
        carry(o)
        carry(o)
    }

    private fun invert(o: LongArray, value: LongArray) {
        val input = value.copyOf()
        val c = input.copyOf()
        for (a in 253 downTo 0) {
            mul(c, c, c)
            if (a != 2 && a != 4) mul(c, c, input)
        }
        System.arraycopy(c, 0, o, 0, 16)
    }
}
