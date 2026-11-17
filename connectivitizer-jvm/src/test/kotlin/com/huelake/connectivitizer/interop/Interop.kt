// The programs the interoperability tests run as separate processes, with the same environment and output as
// the Node.js (connectivitizer-js/interop) and Python ones:
//
//   InteropKt client   a calling application: connects, uses the service every way the SDK offers, prints one JSON report
//   InteropKt device   a device: logs in with a device key, exposes CZ_TARGET as CZ_SERVICE, prints READY, then its log
//   InteropKt link     links itself to an account: prints PROMPT <json>, then LINKED <json> or FAILED <code>
//
// With CZ_CALL=<device>/<service> the device, once connected, opens a session to that device and does GET /hello on
// that service. It prints one line "CALLED <mode> <body>", or "CALL_FAILED <code>", and keeps that session open
// until it stops.
package com.huelake.connectivitizer.interop

import com.huelake.connectivitizer.ConnectivitizerAgent
import com.huelake.connectivitizer.ConnectivitizerClient
import com.huelake.connectivitizer.ConnectivitizerException
import com.huelake.connectivitizer.Link
import com.huelake.connectivitizer.Platform
import com.huelake.connectivitizer.WebSocketMessage
import com.huelake.connectivitizer.internal.Bytes
import com.huelake.connectivitizer.internal.Json
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.system.exitProcess

private fun env(name: String, fallback: String? = null): String = System.getenv(name)?.takeIf { it.isNotEmpty() } ?: fallback ?: throw IllegalStateException("$name is not set.")

private fun platform() = Platform(includeLoopback = System.getenv("CZ_LOOPBACK") == "true")

fun main(args: Array<String>) {
    when (args.firstOrNull()) {
        "client" -> exitProcess(client())
        "device" -> exitProcess(device())
        "link" -> exitProcess(link())
        else -> {
            System.err.println("usage: client | device | link")
            exitProcess(64)
        }
    }
}

private fun client(): Int = runBlocking {
    val report = LinkedHashMap<String, Any?>()
    var exitCode = 0
    var client: ConnectivitizerClient? = null
    try {
        val device = env("CZ_DEVICE", "home-pc")
        val service = env("CZ_SERVICE", "api")
        client = ConnectivitizerClient.builder(env("CZ_API_URL")).apiKey(env("CZ_API_KEY")).sharedKey(env("CZ_SHARED_KEY"))
            .disableDirect(System.getenv("CZ_DIRECT") == "none").platform(platform()).build()
        if (System.getenv("CZ_LIST_DEVICES") == "true") {
            report["devices"] = client.listDevices().map { mapOf("name" to it.name, "slug" to it.slug, "alias" to it.alias, "online" to it.online, "services" to it.services) }
        }
        val session = client.connect(device, listOf(service))
        val info = session.info
        report["session"] = linkedMapOf(
            "id" to info.sessionId, "mode" to info.mode, "transport" to info.transport, "relayed" to info.relayed,
            "endToEndEncrypted" to info.endToEndEncrypted, "platformCanReadPayload" to info.platformCanReadPayload, "trust" to info.trust,
            "e2eMethod" to info.e2eMethod, "peerFingerprint" to info.peerFingerprint, "peerName" to info.peerName,
            "directFailureReason" to (info.directFailureReason ?: ""), "peerAddress" to (info.peerAddress ?: ""),
        )
        // 1. REST.
        val hello = session.fetch(service, env("CZ_HELLO_PATH", "/health"))
        report["helloStatus"] = hello.status
        report["hello"] = hello.text()
        val canary = System.getenv("CZ_CANARY") ?: "canary-" + Bytes.hex(ByteArray(12).also { SecureRandom().nextBytes(it) })
        report["echoMatches"] = session.fetch(service, env("CZ_ECHO_PATH", "/api/echo"), "POST", emptyMap(), canary.toByteArray()).text() == canary
        val large = ByteArray(300_000).also { SecureRandom().nextBytes(it) }
        report["largeEchoMatches"] = session.fetch(service, env("CZ_ECHO_PATH", "/api/echo"), "POST", mapOf("Content-Type" to "application/octet-stream"), large).bytes().contentEquals(large)
        // 2. A WebSocket.
        val socket = session.webSocket(service, env("CZ_WS_PATH", "/ws"))
        socket.send("ping over websocket")
        report["webSocketEchoMatches"] = (withTimeout(10_000) { socket.receive() } as? WebSocketMessage.Text)?.text == "ping over websocket"
        socket.close()
        // 3. Optionally a larger download, to see the throughput of the path in use.
        val blobBytes = System.getenv("CZ_BLOB_BYTES")?.toLongOrNull() ?: 0
        if (blobBytes > 0) {
            val started = System.currentTimeMillis()
            val response = session.fetch(service, env("CZ_BLOB_PATH", "/api/blob/") + blobBytes, timeoutMillis = 60_000)
            val digest = MessageDigest.getInstance("SHA-256")
            var received = 0L
            response.chunks().collect {
                digest.update(it)
                received += it.size
            }
            val millis = maxOf(System.currentTimeMillis() - started, 1)
            report["blob"] = mapOf("bytes" to received, "sha256" to Bytes.hex(digest.digest()), "milliseconds" to millis, "megabytesPerSecond" to Math.round(received / 1024.0 / 1024.0 / (millis / 1000.0) * 100) / 100.0)
        }
        report["bytesSent"] = session.bytesSent
        report["bytesReceived"] = session.bytesReceived
        report["ok"] = true
        val hold = System.getenv("CZ_HOLD_SECONDS")?.toLongOrNull() ?: 0
        if (hold > 0) report["endedWhileHolding"] = withTimeoutOrNull(hold * 1000) { session.completion.await() }
    } catch (e: Exception) {
        // Every refusal carries a stable code that says which layer said no.
        report["ok"] = false
        report["error"] = (e as? ConnectivitizerException)?.code ?: e.javaClass.simpleName
        report["message"] = e.message ?: e.toString()
        exitCode = 2
    }
    runCatching { client?.shutdown() }
    // The JSON writer leaves out null members; the reports of the other SDKs carry these two as null.
    println(Json.write(report).replace(Regex("\"(directFailureReason|peerAddress)\":\"\""), "\"$1\":null"))
    System.out.flush()
    exitCode
}

private fun device(): Int {
    val agent = try {
        ConnectivitizerAgent.builder(env("CZ_API_URL")).deviceKey(env("CZ_DEVICE_KEY")).name(env("CZ_DEVICE_NAME")).sharedKey(env("CZ_SHARED_KEY"))
            .service(env("CZ_SERVICE", "api"), env("CZ_TARGET"), "http").disableDirect(System.getenv("CZ_DIRECT") == "none")
            .agentVersion("0.0.0-interop").platform(platform()).log { println(it); System.out.flush() }.build()
    } catch (e: Exception) {
        System.err.println(e.message)
        return 64
    }
    // Any line, or the end of stdin, stops the device.
    Thread({
        runCatching { System.`in`.bufferedReader().readLine() }
        agent.stopBlocking()
    }, "stdin").apply { isDaemon = true }.start()
    return runBlocking {
        launch {
            agent.waitUntilConnected()
            println("READY")
            System.out.flush()
            val call = System.getenv("CZ_CALL")?.takeIf { it.isNotEmpty() } ?: return@launch
            val line = try {
                val device = call.substringBefore('/')
                val service = call.substringAfter('/')
                val session = agent.connect(device, listOf(service))
                "CALLED ${session.info.mode} ${session.fetch(service, "/hello").text()}"
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                "CALL_FAILED ${(e as? ConnectivitizerException)?.code ?: e.javaClass.simpleName}"
            }
            println(line)
            System.out.flush()
        }
        try {
            agent.run()
            0
        } catch (e: ConnectivitizerException) {
            println("STOPPED ${e.code}")
            System.out.flush()
            2
        }.also { coroutineContext[kotlinx.coroutines.Job]?.cancelChildren() }
    }
}

private fun kotlinx.coroutines.Job.cancelChildren() = children.forEach { it.cancel() }

private fun link(): Int = runBlocking {
    try {
        val linked = Link.linkApp(env("CZ_API_URL"), env("CZ_CLIENT", "JVM app"), { prompt ->
            println("PROMPT " + Json.write(mapOf("url" to prompt.url, "page" to prompt.page, "code" to prompt.code, "expiresIn" to prompt.expiresIn)))
            System.out.flush()
        })
        println("LINKED " + Json.write(mapOf("apiKey" to linked.apiKey, "workspaceId" to linked.workspaceId, "workspaceName" to linked.workspaceName, "client" to linked.client, "credentialId" to linked.credentialId)))
        0
    } catch (e: ConnectivitizerException) {
        println("FAILED ${e.code}")
        2
    }
}
