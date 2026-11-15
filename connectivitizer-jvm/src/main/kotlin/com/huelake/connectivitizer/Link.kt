package com.huelake.connectivitizer

import com.huelake.connectivitizer.internal.long
import com.huelake.connectivitizer.internal.string
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.util.function.Consumer

/** Where the person has to go to approve a link, and the code that page must show. */
class LinkPrompt(
    /** The page of the web app with the code already filled in. */
    val url: String,
    /** The same page without the code, for showing it next to the code. */
    val page: String,
    /** The short code the page must show, e.g. `KQTR-7MPL`. */
    val code: String,
    /** Seconds the person has to approve. */
    val expiresIn: Long,
)

/** What a linked application holds from then on. The API key exists only here: store it where only the application can read it. */
class LinkedApp(val apiKey: String, val workspaceId: String, val workspaceName: String, val client: String, val credentialId: String) {
    override fun toString(): String = "LinkedApp(workspaceName=$workspaceName, client=$client)" // never the key itself
}

/** Linking an application to somebody's account without a login inside it (protocol section 11.5). */
object Link {
    /**
     * Links this application to an account: the person signs in to the web app in a browser and approves, and
     * the application receives an API key of its own. Throws `LINK_DENIED` when the person refused, and
     * `LINK_EXPIRED` when nobody decided in time.
     */
    @JvmStatic
    @JvmOverloads
    suspend fun linkApp(apiUrl: String, client: String, onPrompt: (LinkPrompt) -> Unit, platformName: String? = null, platform: Platform = Platform()): LinkedApp {
        val runtime = SdkRuntime("connectivitizer-link")
        try {
            val api = PlatformApi(apiUrl, platform, runtime.scope)
            val link = api.startLink(client, platformName ?: platform.description)
            val expiresIn = link.long("expiresIn") ?: 600
            onPrompt(LinkPrompt(link.string("verificationUrlComplete") ?: "", link.string("verificationUrl") ?: "", link.string("userCode") ?: "", expiresIn))
            val deadline = System.currentTimeMillis() + expiresIn * 1000
            val interval = ((link.long("interval") ?: 5).coerceIn(1, 30)) * 1000
            while (System.currentTimeMillis() < deadline) {
                delay(interval)
                val answer = api.pollLink(link.string("deviceCode") ?: "")
                val apiKey = answer.string("apiKey")
                if (answer["status"] == "approved" && apiKey != null) {
                    return LinkedApp(apiKey, answer.string("workspaceId") ?: "", answer.string("workspaceName") ?: "", answer.string("client") ?: client, answer.string("credentialId") ?: "")
                }
            }
            throw ConnectivitizerException(ErrorCodes.LINK_EXPIRED, "Nobody approved the link in time.")
        } finally {
            runtime.shutdown()
        }
    }

    /** [linkApp] for Java code that does not use coroutines. */
    @JvmStatic
    fun linkAppBlocking(apiUrl: String, client: String, onPrompt: Consumer<LinkPrompt>): LinkedApp = runBlocking { linkApp(apiUrl, client, { onPrompt.accept(it) }) }
}
