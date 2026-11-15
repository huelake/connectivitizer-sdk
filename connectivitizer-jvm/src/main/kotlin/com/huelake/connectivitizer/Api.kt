package com.huelake.connectivitizer

import com.huelake.connectivitizer.internal.GrantValidation
import com.huelake.connectivitizer.internal.Grants
import com.huelake.connectivitizer.internal.Json
import com.huelake.connectivitizer.internal.asList
import com.huelake.connectivitizer.internal.asMap
import com.huelake.connectivitizer.internal.long
import com.huelake.connectivitizer.internal.string
import com.huelake.connectivitizer.internal.strings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.PublicKey

/** An access token of the control plane, and what it says about the endpoint. */
class TokenResponse(
    val accessToken: String,
    val endpointId: String,
    val workspaceId: String,
    /** The control plane's clock, Unix seconds. */
    val serverTime: Long?,
    /** Device logins: the name the device is addressed by. */
    val slug: String?,
) {
    override fun toString(): String = "TokenResponse(endpointId=$endpointId)" // never the token itself

    internal companion object {
        fun from(data: Map<String, Any?>) = TokenResponse(data.string("accessToken")!!, data.string("endpointId") ?: "", data.string("workspaceId") ?: "", data.long("serverTime"), data.string("slug"))
    }
}

/** A device an application may open sessions to. */
data class ReachableDevice(
    val id: String,
    /** What the device calls itself. */
    val name: String,
    /** The name sessions are opened to. */
    val slug: String,
    val alias: String?,
    val online: Boolean,
    /** What the device's software announced; `path.udp-kcp` means it offers peer to peer. */
    val capabilities: List<String>,
    /** The services of the device this application may use. */
    val services: List<String>,
)

/** The machine-facing REST calls of the control plane (protocol section 11). */
internal class PlatformApi(apiUrl: String, private val platform: Platform, private val scope: CoroutineScope) {
    val baseUrl: String = apiUrl.trimEnd('/') + "/"

    /** The signaling endpoint that belongs to this API. */
    val signalUrl: String get() = baseUrl.replaceFirst(Regex("^http"), "ws") + "v1/signal"

    suspend fun credentialToken(apiKey: String) = TokenResponse.from(post("v1/auth/credential/token", mapOf("apiKey" to apiKey)))

    suspend fun deviceKeyToken(key: String, name: String, platformName: String?, agentVersion: String?) =
        TokenResponse.from(post("v1/auth/device-key/token", mapOf("key" to key, "name" to name, "platform" to platformName, "agentVersion" to agentVersion)))

    suspend fun startLink(client: String, platformName: String?) = post("v1/auth/link", mapOf("client" to client, "platform" to platformName))

    suspend fun pollLink(deviceCode: String) = post("v1/auth/link/token", mapOf("deviceCode" to deviceCode))

    suspend fun reachableDevices(accessToken: String): List<ReachableDevice> =
        (request("GET", "v1/devices", null, accessToken).asList() ?: emptyList()).mapNotNull { it.asMap() }.map {
            ReachableDevice(it.string("id") ?: "", it.string("name") ?: "", it.string("slug") ?: "", it.string("alias"), it["online"] == true, it.strings("capabilities") ?: emptyList(), it.strings("services") ?: emptyList())
        }

    suspend fun grantKeys(): Map<String, PublicKey> = Grants.parseJwks(request("GET", ".well-known/jwks.json", null, null))

    private suspend fun post(path: String, body: Map<String, Any?>): Map<String, Any?> = request("POST", path, body, null).asMap() ?: emptyMap()

    private suspend fun request(method: String, path: String, body: Map<String, Any?>?, bearer: String?): Any? {
        val headers = LinkedHashMap<String, String>()
        headers["Accept"] = "application/json"
        if (body != null) headers["Content-Type"] = "application/json"
        if (bearer != null) headers["Authorization"] = "Bearer $bearer"
        val (status, text) = try {
            platform.fetch(baseUrl + path, method, headers, body?.let { Json.write(it) }, scope)
        } catch (e: Exception) {
            throw ConnectivitizerException(ErrorCodes.SIGNALING_UNAVAILABLE, "The Connectivitizer API at $baseUrl could not be reached.", e)
        }
        val parsed = runCatching { if (text.isEmpty()) null else Json.parse(text) }.getOrNull()
        // Only the API names its refusals. An answer without a code comes from something in between (a proxy while
        // the API restarts, a captive portal) and is a passing failure: devices keep retrying instead of giving up.
        if (status in 200..299) return parsed ?: throw ConnectivitizerException(ErrorCodes.SIGNALING_UNAVAILABLE, "The API returned an empty response.")
        val failure = parsed.asMap() ?: emptyMap()
        val code = failure.string("error") ?: if (status == 401) ErrorCodes.UNAUTHENTICATED else ErrorCodes.SIGNALING_UNAVAILABLE
        throw ConnectivitizerException(code, failure.string("message") ?: "The API refused the request ($status $code).")
    }
}

/** Verifies grants offline with the control plane's published keys, fetching them when a new key id appears. */
internal class GrantVerifier(private val api: PlatformApi, private val nowSeconds: () -> Long) {
    private var keys: Map<String, PublicKey> = emptyMap()
    private var lastRefresh = Long.MIN_VALUE / 2
    private val refreshing = Mutex()

    suspend fun validate(token: String, forSessionStart: Boolean): GrantValidation {
        val keyId = Grants.readKeyId(token) ?: return GrantValidation.Invalid(ErrorCodes.GRANT_INVALID)
        if (keyId !in keys) refresh()
        return validateKnown(token, forSessionStart)
    }

    /** Validates with the keys already known (for in-session lease renewals, which must not wait on the network). */
    fun validateKnown(token: String, forSessionStart: Boolean): GrantValidation = Grants.validate(token, keys, nowSeconds(), forSessionStart)

    private suspend fun refresh() = refreshing.withLock {
        if (System.currentTimeMillis() - lastRefresh < 30_000) return@withLock
        lastRefresh = System.currentTimeMillis()
        // Without keys the grant simply does not validate; the caller reports GRANT_INVALID.
        runCatching { keys = api.grantKeys() }
    }
}
