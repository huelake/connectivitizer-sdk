package com.huelake.connectivitizer

import com.huelake.connectivitizer.internal.ChunkQueue
import com.huelake.connectivitizer.internal.Json
import com.huelake.connectivitizer.internal.StreamReader
import com.huelake.connectivitizer.internal.asMap
import com.huelake.connectivitizer.internal.map
import com.huelake.connectivitizer.internal.string
import com.huelake.connectivitizer.internal.strings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * A device that opens sessions to other devices, against a scripted control plane: what the device sends on its
 * signaling connection and what it makes of the answers. Sessions that carry data are covered by the
 * interoperability tests, which run against the real control plane.
 */
class DeviceCallsTest {
    private class Side(private val incoming: ChunkQueue, private val outgoing: ChunkQueue) : ByteStream {
        override suspend fun read() = incoming.read()
        override suspend fun write(data: ByteArray) = outgoing.push(data.copyOf())
        override suspend fun end() = outgoing.end()
        override suspend fun close() {
            outgoing.end()
            incoming.end()
        }
    }

    /** Answers the REST calls of a device and hands the test the platform's end of every signaling connection. */
    private class ScriptedPlatform(private val testScope: CoroutineScope) : Platform() {
        val connections = Channel<StreamWebSocket>(Channel.UNLIMITED)
        val bearers = CopyOnWriteArrayList<String>()

        override suspend fun fetch(url: String, method: String, headers: Map<String, String>, body: String?, scope: CoroutineScope): Pair<Int, String> = when {
            url.endsWith("v1/auth/device-key/token") -> 200 to """{"accessToken":"device-token","endpointId":"dev-1","workspaceId":"w-1","slug":"here"}"""
            url.endsWith("v1/devices") -> {
                bearers.add(headers["Authorization"] ?: "")
                200 to """[{"id":"dev-2","name":"There","slug":"there","online":true,"capabilities":["path.relay-ws"],"services":["api"]}]"""
            }
            else -> 404 to ""
        }

        override suspend fun connectWebSocket(url: String, headers: Map<String, String>, scope: CoroutineScope): StreamWebSocket {
            bearers.add(headers["Authorization"] ?: "")
            val toPlatform = ChunkQueue()
            val toDevice = ChunkQueue()
            val device = Side(toDevice, toPlatform)
            val platform = Side(toPlatform, toDevice)
            connections.send(StreamWebSocket(platform, StreamReader(platform), ::randomBytes, 1 shl 20, testScope))
            return StreamWebSocket(device, StreamReader(device), ::randomBytes, 1 shl 20, scope)
        }
    }

    private suspend fun next(connection: StreamWebSocket): Map<String, Any?> =
        withTimeout(10_000) { Json.parse((connection.receive() as WebSocketMessage.Text).text).asMap()!! }

    /** Takes the device's next signaling connection and welcomes it. Returns the connection and the device's hello. */
    private suspend fun welcome(platform: ScriptedPlatform): Pair<StreamWebSocket, Map<String, Any?>> {
        val connection = withTimeout(10_000) { platform.connections.receive() }
        val hello = next(connection)
        assertEquals("hello", hello["t"])
        connection.send(Json.write(mapOf("t" to "welcome", "re" to hello["id"], "d" to mapOf("serverTime" to System.currentTimeMillis() / 1000))))
        return connection to hello
    }

    private fun agent(platform: Platform, log: (String) -> Unit = {}) =
        ConnectivitizerAgent.builder("https://api.example").deviceKey("czd_x").name("here").sharedKey(SharedKey.generate())
            .service("api", "127.0.0.1:8080").disableDirect().platform(platform).log { log(it) }.build()

    @Test
    fun aDeviceAsksOnItsOwnConnectionAndPassesOnWhatThePlatformAndTheOtherDeviceAnswer() = runBlocking {
        val scope = CoroutineScope(coroutineContext + SupervisorJob())
        val platform = ScriptedPlatform(scope)
        val lines = CopyOnWriteArrayList<String>()
        val agent = agent(platform) { lines.add(it) }

        // Asked before the device is connected: the request waits for the connection.
        val early = scope.async { runCatching { agent.connect("there", listOf("api")) } }
        val running = scope.launch { runCatching { agent.run() } }
        val (connection, hello) = welcome(platform)
        assertEquals("Bearer device-token", platform.bearers.single())
        assertEquals(listOf("api"), (hello.map("d")!!["services"] as List<*>).map { it.asMap()!!.string("name") })

        // The request travels on the connection the device logged in on. The platform's refusal is the caller's error.
        val refused = next(connection)
        assertEquals("connect.request", refused["t"])
        assertEquals("there", refused.map("d")!!.string("device"))
        assertEquals(listOf("api"), refused.map("d")!!.strings("services"))
        assertEquals(listOf("shared-key"), refused.map("d")!!.strings("e2e"))
        connection.send(Json.write(mapOf("t" to "error", "re" to refused["id"], "d" to mapOf("code" to ErrorCodes.FORBIDDEN, "message" to "This device key may not connect."))))
        assertEquals(ErrorCodes.FORBIDDEN, (early.await().exceptionOrNull() as ConnectivitizerException).code)

        // Granted by the platform, refused by the other device: the answer arrives on the same connection, and the
        // device reports the failed session there.
        val second = scope.async { runCatching { agent.connect("there", listOf("api")) } }
        val request = next(connection)
        assertEquals("connect.request", request["t"])
        connection.send(Json.write(mapOf("t" to "connect.grant", "re" to request["id"], "d" to mapOf("sid" to "s-1", "grant" to "not-a-grant", "peer" to mapOf("id" to "dev-2", "name" to "there", "caps" to listOf<String>())))))
        // Candidates of a session nobody on this device asked for are no reason to fail.
        connection.send(Json.write(mapOf("t" to "path.candidates", "d" to mapOf("sid" to "s-9", "blob" to "AAAA"))))
        connection.send(Json.write(mapOf("t" to "connect.answer", "d" to mapOf("sid" to "s-1", "accept" to false, "error" to ErrorCodes.DEVICE_REJECTED))))
        assertEquals(ErrorCodes.DEVICE_REJECTED, (second.await().exceptionOrNull() as ConnectivitizerException).code)
        val update = next(connection)
        assertEquals("session.update", update["t"])
        assertEquals(mapOf<String, Any?>("sid" to "s-1", "state" to "failed", "error" to ErrorCodes.DEVICE_REJECTED), update.map("d"))
        assertTrue(agent.outgoingSessions.isEmpty())
        assertTrue(agent.openSessions.isEmpty())

        // What the device may reach is asked with the device's own token.
        assertEquals(listOf("there"), agent.listDevices().map { it.slug })
        assertEquals("Bearer device-token", platform.bearers.last())

        // The device loses its connection. A request made meanwhile goes out on the next one.
        connection.close()
        withTimeout(10_000) { while (agent.isConnected) delay(10) }
        val late = scope.async { runCatching { agent.connect("there", listOf("api")) } }
        val (reconnected, _) = welcome(platform)
        val again = next(reconnected)
        assertEquals("connect.request", again["t"])
        reconnected.send(Json.write(mapOf("t" to "error", "re" to again["id"], "d" to mapOf("code" to ErrorCodes.NOT_FOUND))))
        assertEquals(ErrorCodes.NOT_FOUND, (late.await().exceptionOrNull() as ConnectivitizerException).code)

        // A stopped device opens nothing.
        agent.stop()
        withTimeout(10_000) { running.join() }
        assertEquals(ErrorCodes.SESSION_CLOSED, assertFailsWith<ConnectivitizerException> { agent.connect("there", listOf("api")) }.code)
        assertEquals(ErrorCodes.SESSION_CLOSED, assertFailsWith<ConnectivitizerException> { agent.listDevices() }.code)
        assertTrue(lines.none { it.contains("opened to") }, lines.toString())
        scope.coroutineContext[Job]!!.cancel()
    }

    @Test
    fun aRequestThatWaitsForTheConnectionEndsWhenTheDeviceStops() = runBlocking {
        val scope = CoroutineScope(coroutineContext + SupervisorJob())
        val agent = agent(ScriptedPlatform(scope))
        val waiting = scope.async { runCatching { agent.connect("there", listOf("api")) } }
        delay(100)
        agent.stop()
        assertEquals(ErrorCodes.SESSION_CLOSED, (withTimeout(10_000) { waiting.await() }.exceptionOrNull() as ConnectivitizerException).code)
        scope.coroutineContext[Job]!!.cancel()
    }
}
