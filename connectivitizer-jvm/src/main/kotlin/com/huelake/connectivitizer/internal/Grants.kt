package com.huelake.connectivitizer.internal

import com.huelake.connectivitizer.ErrorCodes
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

// Session grants (protocol section 2): the control plane's signed statement that one initiator may open one
// session to one device. An endpoint acts on a grant because its signature checks out, not because of the
// channel it arrived on.

internal object ConnectionModes {
    const val DIRECT = "direct"
    const val E2E_RELAY = "e2e-relay"
    const val COMPATIBILITY = "compatibility"
}

internal object E2eMethods {
    const val TLS13 = "tls13"
    const val SHARED_KEY = "shared-key"
}

internal object Capabilities {
    const val E2E_SHARED_KEY = "e2e.shared-key"
    const val MUX_YAMUX = "mux.yamux"
    const val PATH_RELAY_WS = "path.relay-ws"
    const val PATH_UDP_KCP = "path.udp-kcp"
}

internal object Roles {
    const val INITIATOR = "initiator"
    const val DEVICE = "device"
}

/** A verified grant: the parsed JSON object, with the members the SDK reads. */
internal class Grant(val claims: Map<String, Any?>) {
    val jti: String get() = claims.string("jti")!!
    val ws: String? get() = claims.string("ws")
    val ini: Map<String, Any?> get() = claims.map("ini")!!
    val dev: Map<String, Any?> get() = claims.map("dev")!!
    val services: List<String> get() = claims.strings("svc")!!
    val modes: List<String> get() = claims.strings("modes")!!
    val relay: String? get() = claims.string("relay")
    val iat: Long get() = claims.long("iat")!!
    val lease: Long get() = claims.long("lease")!!

    /** The end-to-end layer of the session; absent means certificates. */
    val e2eMethod: String get() = claims.string("e2e") ?: E2eMethods.TLS13
}

internal sealed class GrantValidation {
    class Valid(val grant: Grant) : GrantValidation()
    class Invalid(val code: String) : GrantValidation()

    val grantOrNull: Grant? get() = (this as? Valid)?.grant
    val errorOrNull: String? get() = (this as? Invalid)?.code
}

internal object Grants {
    private const val AUDIENCE_AGENT = "cz-agent"
    private const val CLOCK_SKEW_SECONDS = 30
    private const val MAX_TOKEN_LENGTH = 16 * 1024

    private val P256: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
    }

    fun parseJwks(document: Any?): Map<String, PublicKey> {
        val keys = HashMap<String, PublicKey>()
        for (jwk in document.asMap()?.get("keys").asList() ?: emptyList()) {
            val key = jwk.asMap() ?: continue
            if (key["kty"] != "EC" || key["crv"] != "P-256") continue
            val kid = key.string("kid") ?: continue
            try {
                val x = Bytes.base64Decode(key.string("x") ?: continue)
                val y = Bytes.base64Decode(key.string("y") ?: continue)
                if (x.size != 32 || y.size != 32) continue
                keys[kid] = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, x), BigInteger(1, y)), P256))
            } catch (e: Exception) {
                // A malformed key is as good as an absent one.
            }
        }
        return keys
    }

    /** The key id a token names, without verifying anything, so the right key can be fetched first. */
    fun readKeyId(token: String): String? = try {
        Json.parse(String(Bytes.base64Decode(token.substring(0, token.indexOf('.'))), Charsets.UTF_8)).asMap()?.string("kid")?.takeIf { it.isNotEmpty() }
    } catch (e: Exception) {
        null
    }

    /** SHA-256 (lower-case hex) of a grant token: what the session bind and the shared-key handshake refer to. */
    fun hash(token: String): String = Bytes.hex(Bytes.sha256(token.toByteArray(Charsets.UTF_8)))

    /**
     * Verifies signature, audience and time of a grant token. [forSessionStart] selects which deadline applies:
     * the short start window (`exp`) or the session lease.
     */
    fun validate(token: String, keys: Map<String, PublicKey>, nowSeconds: Long, forSessionStart: Boolean): GrantValidation {
        val invalid = GrantValidation.Invalid(ErrorCodes.GRANT_INVALID)
        if (token.isEmpty() || token.length > MAX_TOKEN_LENGTH) return invalid
        val first = token.indexOf('.')
        val last = token.lastIndexOf('.')
        if (first <= 0 || last <= first + 1 || last == token.length - 1) return invalid
        val claims: Map<String, Any?>
        try {
            val header = Json.parse(String(Bytes.base64Decode(token.substring(0, first)), Charsets.UTF_8)).asMap() ?: return invalid
            // The algorithm is fixed. Accepting whatever the header names is how "alg" attacks work.
            if (header["alg"] != "ES256") return invalid
            val key = keys[header.string("kid") ?: return invalid] ?: return invalid
            val signature = Bytes.base64Decode(token.substring(last + 1))
            if (signature.size != 64) return invalid
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(key)
            verifier.update(token.substring(0, last).toByteArray(Charsets.US_ASCII))
            if (!verifier.verify(derSignature(signature))) return invalid
            claims = Json.parse(String(Bytes.base64Decode(token.substring(first + 1, last)), Charsets.UTF_8)).asMap() ?: return invalid
        } catch (e: Exception) {
            return invalid
        }
        val audience = claims["aud"].asList()
        if (claims.string("jti").isNullOrEmpty() || audience == null || AUDIENCE_AGENT !in audience || claims.map("ini") == null || claims.map("dev") == null ||
            claims["svc"].asList() == null || claims["modes"].asList() == null || claims["iat"] !is Number || claims["exp"] !is Number || claims["lease"] !is Number
        ) {
            return invalid
        }
        val iat = claims.long("iat")!!
        val deadline = if (forSessionStart) claims.long("exp")!! else iat + claims.long("lease")!!
        if (nowSeconds > deadline + CLOCK_SKEW_SECONDS || nowSeconds < iat - CLOCK_SKEW_SECONDS) return GrantValidation.Invalid(ErrorCodes.GRANT_EXPIRED)
        return GrantValidation.Valid(Grant(claims))
    }

    /** The JCA wants ECDSA signatures in DER; JWS writes them as 64 bytes r || s. */
    private fun derSignature(raw: ByteArray): ByteArray {
        fun integer(part: ByteArray): ByteArray {
            var bytes = part.dropWhile { it == 0.toByte() }.toByteArray()
            if (bytes.isEmpty()) bytes = byteArrayOf(0)
            if (bytes[0].toInt() and 0x80 != 0) bytes = byteArrayOf(0) + bytes
            return byteArrayOf(0x02, bytes.size.toByte()) + bytes
        }
        val body = integer(raw.copyOfRange(0, 32)) + integer(raw.copyOfRange(32, 64))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
