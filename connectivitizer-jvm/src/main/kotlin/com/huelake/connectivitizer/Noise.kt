package com.huelake.connectivitizer

import com.huelake.connectivitizer.internal.Bytes
import com.huelake.connectivitizer.internal.StreamReader
import com.huelake.connectivitizer.internal.X25519
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// The end-to-end layer for endpoints that share a key (protocol section 4a): the Noise handshake NNpsk0 with
// X25519, ChaCha20-Poly1305 and SHA-256. Each session agrees on fresh keys, so recorded traffic stays
// unreadable even if the shared key leaks later; the shared key is what authenticates the two ends to each
// other. Nothing between them holds it.

/**
 * A key that two endpoints hold and nobody else does, written `czs_` followed by 43 characters. The platform
 * never receives it. [name] is what this endpoint calls the key; it is never transmitted.
 */
class SharedKey internal constructor(val name: String, internal val bytes: ByteArray) {
    override fun toString(): String = "SharedKey(name=$name)" // never the key itself

    companion object {
        private const val PREFIX = "czs_"

        /** Reads a key in its text form. */
        @JvmStatic
        @JvmOverloads
        fun parse(text: String, name: String = "default"): SharedKey {
            val trimmed = text.trim()
            val bytes = if (trimmed.startsWith(PREFIX) && trimmed.length == PREFIX.length + 43) {
                try {
                    Bytes.base64Decode(trimmed.substring(PREFIX.length))
                } catch (e: IllegalArgumentException) {
                    null
                }
            } else {
                null
            }
            if (bytes == null || bytes.size != 32) throw ConnectivitizerException(ErrorCodes.INVALID_REQUEST, "A shared key looks like czs_ followed by 43 characters.")
            return SharedKey(name, bytes)
        }

        /** The characters of a generated key (protocol section 1.2): one case, no I and O, no 0 and 1. */
        const val READABLE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

        /**
         * A new key in its text form, from the system's secure random source, readable: 42 characters of
         * [READABLE_ALPHABET] and a last `A` or `Q`. Put the same key on both endpoints.
         */
        @JvmStatic
        fun generate(): String {
            val random = ByteArray(43).also { SecureRandom().nextBytes(it) }
            val text = StringBuilder(PREFIX)
            // 32 characters: the low five bits of a random byte pick one uniformly.
            for (i in 0 until 42) text.append(READABLE_ALPHABET[random[i].toInt() and 31])
            text.append(if (random[42].toInt() and 1 == 0) 'A' else 'Q')
            return text.toString()
        }
    }
}

internal object Noise {
    private val PROTOCOL_NAME = "Noise_NNpsk0_25519_ChaChaPoly_SHA256".toByteArray(Charsets.US_ASCII)
    const val KEY_SIZE = 32
    const val TAG_SIZE = 16
    const val HANDSHAKE_MESSAGE_SIZE = KEY_SIZE + TAG_SIZE

    /** Largest number of plaintext bytes in one message, so an endpoint with little memory needs only small buffers. */
    const val MAX_PLAINTEXT = 4096

    /** What both handshakes are bound to: this protocol, this session and this grant. */
    fun prologue(sessionId: String, grantHashHex: String): ByteArray = "cz-e2e-shared-key/1|$sessionId|$grantHashHex".toByteArray(Charsets.UTF_8)

    /** Four zero bytes, then the counter as 64-bit little-endian. */
    fun nonce(counter: Long): ByteArray = ByteArray(12).also { for (i in 0 until 8) it[4 + i] = (counter ushr (8 * i)).toByte() }

    fun hmac(key: ByteArray, data: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256"))
        doFinal(data)
    }

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun seal(key: ByteArray, counter: Long, plaintext: ByteArray, ad: ByteArray?): ByteArray = Cipher.getInstance("ChaCha20-Poly1305").run {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce(counter)))
        if (ad != null) updateAAD(ad)
        doFinal(plaintext)
    }

    /** Null when the ciphertext was not made with this key (or was altered). */
    fun open(key: ByteArray, counter: Long, ciphertext: ByteArray, ad: ByteArray?): ByteArray? = try {
        Cipher.getInstance("ChaCha20-Poly1305").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce(counter)))
            if (ad != null) updateAAD(ad)
            doFinal(ciphertext)
        }
    } catch (e: AEADBadTagException) {
        null
    }

    fun agree(privateKey: ByteArray, remotePublic: ByteArray): ByteArray {
        val shared = X25519.scalarMult(privateKey, remotePublic)
        // A peer that sends a point of small order forces a known result; such a handshake is refused.
        if (shared.all { it == 0.toByte() }) throw ConnectivitizerException(ErrorCodes.E2E_HANDSHAKE_FAILED, "The peer sent an invalid key-agreement value.")
        return shared
    }

    /**
     * `Noise_NNpsk0_25519_ChaChaPoly_SHA256` as the Noise specification (revision 34) defines it:
     *
     *     -> psk, e
     *     <- e, ee
     */
    class Handshake private constructor(prologueBytes: ByteArray, sharedKey: ByteArray) {
        private var hash = sha256(PROTOCOL_NAME)
        private var chainingKey = hash
        private var key: ByteArray? = null
        private var counter = 0L
        private var ephemeral: ByteArray? = null
        private var remotePublic: ByteArray? = null

        init {
            mixHash(prologueBytes)
            mixKeyAndHash(sharedKey)
        }

        val handshakeHash: ByteArray get() = hash.copyOf()

        fun writeFirst(payload: ByteArray = ByteArray(0)): ByteArray {
            val ephemeralPublic = X25519.publicKey(ephemeral!!)
            mixHash(ephemeralPublic)
            mixKey(ephemeralPublic)
            return ephemeralPublic + encryptAndHash(payload)
        }

        /** Processes the responder's message. Null when it was not made with the same shared key. */
        fun readSecond(message: ByteArray): ByteArray? {
            if (message.size < HANDSHAKE_MESSAGE_SIZE) return null
            val remote = message.copyOfRange(0, KEY_SIZE)
            mixHash(remote)
            mixKey(remote)
            mixKey(agree(ephemeral!!, remote))
            ephemeral!!.fill(0)
            return decryptAndHash(message.copyOfRange(KEY_SIZE, message.size))
        }

        fun writeSecond(ephemeralPrivate: ByteArray, payload: ByteArray = ByteArray(0)): ByteArray {
            val ephemeralPublic = X25519.publicKey(ephemeralPrivate)
            mixHash(ephemeralPublic)
            mixKey(ephemeralPublic)
            mixKey(agree(ephemeralPrivate, remotePublic!!))
            return ephemeralPublic + encryptAndHash(payload)
        }

        /** The transport keys: what the initiator sends, and what the responder sends. */
        fun split(): Pair<ByteArray, ByteArray> {
            val temp = hmac(chainingKey, ByteArray(0))
            val first = hmac(temp, byteArrayOf(1))
            return first to hmac(temp, first + byteArrayOf(2))
        }

        private fun mixHash(data: ByteArray) {
            hash = sha256(hash + data)
        }

        private fun mixKey(material: ByteArray) {
            val temp = hmac(chainingKey, material)
            val first = hmac(temp, byteArrayOf(1))
            chainingKey = first
            key = hmac(temp, first + byteArrayOf(2))
            counter = 0
        }

        private fun mixKeyAndHash(material: ByteArray) {
            val temp = hmac(chainingKey, material)
            val first = hmac(temp, byteArrayOf(1))
            val second = hmac(temp, first + byteArrayOf(2))
            chainingKey = first
            mixHash(second)
            key = hmac(temp, second + byteArrayOf(3))
            counter = 0
        }

        private fun encryptAndHash(plaintext: ByteArray): ByteArray {
            val ciphertext = seal(key!!, counter++, plaintext, hash)
            mixHash(ciphertext)
            return ciphertext
        }

        private fun decryptAndHash(ciphertext: ByteArray): ByteArray? {
            val plaintext = open(key!!, counter, ciphertext, hash) ?: return null
            counter++
            mixHash(ciphertext)
            return plaintext
        }

        companion object {
            fun startInitiator(prologue: ByteArray, sharedKey: ByteArray, ephemeralPrivate: ByteArray) = Handshake(prologue, sharedKey).also { it.ephemeral = ephemeralPrivate }

            /** Processes the initiator's message with one candidate key. Null when it was not made with that key. */
            fun tryStartResponder(prologue: ByteArray, sharedKey: ByteArray, first: ByteArray): Pair<Handshake, ByteArray>? {
                if (first.size < HANDSHAKE_MESSAGE_SIZE) return null
                val handshake = Handshake(prologue, sharedKey)
                val remote = first.copyOfRange(0, KEY_SIZE)
                handshake.mixHash(remote)
                handshake.mixKey(remote)
                val payload = handshake.decryptAndHash(first.copyOfRange(KEY_SIZE, first.size)) ?: return null
                handshake.remotePublic = remote
                return handshake to payload
            }
        }
    }

    class Channel(val stream: ByteStream, val keyName: String)

    private fun frame(message: ByteArray): ByteArray = Bytes.u16(message.size) + message

    private suspend fun readFrame(reader: StreamReader, maxLength: Int): ByteArray? {
        val header = reader.readExact(2) ?: return null
        val length = Bytes.readU16(header, 0)
        if (length > maxLength) throw ConnectivitizerException(ErrorCodes.E2E_HANDSHAKE_FAILED, "The peer sent a message that is too long for this protocol.")
        return if (length == 0) ByteArray(0) else reader.readExact(length)
    }

    /** Runs the handshake as the initiating endpoint. */
    suspend fun connect(path: ByteStream, key: SharedKey, prologue: ByteArray, random: (Int) -> ByteArray): Channel {
        val reader = StreamReader(path)
        try {
            val handshake = Handshake.startInitiator(prologue, key.bytes, random(KEY_SIZE))
            path.write(frame(handshake.writeFirst()))
            val second = readFrame(reader, HANDSHAKE_MESSAGE_SIZE)
            // The device answers with an empty message when none of its keys fits.
            if (second != null && second.isEmpty()) throw ConnectivitizerException(ErrorCodes.E2E_SHARED_KEY_MISMATCH, "The device does not hold this shared key.")
            if (second == null || second.size != HANDSHAKE_MESSAGE_SIZE) throw ConnectivitizerException(ErrorCodes.E2E_HANDSHAKE_FAILED, "The peer ended the end-to-end handshake.")
            handshake.readSecond(second) ?: throw ConnectivitizerException(ErrorCodes.E2E_SHARED_KEY_MISMATCH, "The device answered with a different shared key.")
            val (send, receive) = handshake.split()
            return Channel(NoiseStream(path, reader, send, receive), key.name)
        } catch (e: Throwable) {
            runCatching { path.close() }
            throw failure(e)
        }
    }

    /** Runs the handshake as the accepting endpoint, which may hold several keys; the one the initiator used is found by trying them. */
    suspend fun accept(path: ByteStream, keys: List<SharedKey>, prologue: ByteArray, random: (Int) -> ByteArray): Channel {
        val reader = StreamReader(path)
        try {
            val first = readFrame(reader, HANDSHAKE_MESSAGE_SIZE)
            if (first == null || first.size != HANDSHAKE_MESSAGE_SIZE) throw ConnectivitizerException(ErrorCodes.E2E_HANDSHAKE_FAILED, "The peer ended the end-to-end handshake.")
            for (key in keys) {
                val (handshake, _) = Handshake.tryStartResponder(prologue, key.bytes, first) ?: continue
                path.write(frame(handshake.writeSecond(random(KEY_SIZE))))
                val (initiator, responder) = handshake.split()
                return Channel(NoiseStream(path, reader, responder, initiator), key.name)
            }
            path.write(frame(ByteArray(0)))
            throw ConnectivitizerException(ErrorCodes.E2E_SHARED_KEY_MISMATCH, "The initiator used a shared key this endpoint does not hold.")
        } catch (e: Throwable) {
            runCatching { path.close() }
            throw failure(e)
        }
    }

    private fun failure(e: Throwable): Throwable =
        if (e is ConnectivitizerException || e is CancellationException) e else ConnectivitizerException(ErrorCodes.E2E_HANDSHAKE_FAILED, "The path ended during the end-to-end handshake.", e)

    /** The encrypted byte stream after the handshake: length-prefixed messages of at most [MAX_PLAINTEXT] bytes. */
    private class NoiseStream(private val path: ByteStream, private val reader: StreamReader, private val sendKey: ByteArray, private val receiveKey: ByteArray) : ByteStream {
        private var sendCounter = 0L
        private var receiveCounter = 0L
        private val writing = Mutex()

        override suspend fun read(): ByteArray? {
            while (true) {
                val header = reader.readExact(2) ?: return null
                val length = Bytes.readU16(header, 0)
                if (length < TAG_SIZE || length > MAX_PLAINTEXT + TAG_SIZE) throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The peer sent a malformed encrypted message.")
                // Cut off inside a message: the path broke, this is not an orderly end.
                val ciphertext = reader.readExact(length) ?: throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The path ended inside an encrypted message.")
                val plaintext = open(receiveKey, receiveCounter++, ciphertext, null) ?: throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "An encrypted message was altered on the way.")
                if (plaintext.isNotEmpty()) return plaintext
            }
        }

        // One writer at a time: the message counter and the order on the path must agree.
        override suspend fun write(data: ByteArray) = writing.withLock {
            var offset = 0
            while (offset < data.size) {
                val end = minOf(offset + MAX_PLAINTEXT, data.size)
                path.write(frame(seal(sendKey, sendCounter++, data.copyOfRange(offset, end), null)))
                offset = end
            }
        }

        override suspend fun end() = close()

        override suspend fun close() = path.close()
    }
}
