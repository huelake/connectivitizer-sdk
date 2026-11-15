package com.huelake.connectivitizer

import com.huelake.connectivitizer.internal.Bytes
import com.huelake.connectivitizer.internal.ChunkQueue
import com.huelake.connectivitizer.internal.Json
import com.huelake.connectivitizer.internal.Kcp
import com.huelake.connectivitizer.internal.MuxSession
import com.huelake.connectivitizer.internal.Stun
import com.huelake.connectivitizer.internal.Yamux
import com.huelake.connectivitizer.internal.asList
import com.huelake.connectivitizer.internal.asMap
import com.huelake.connectivitizer.internal.long
import com.huelake.connectivitizer.internal.string
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.io.File
import java.security.SecureRandom
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The layers of a session on their own: the shared-key channel, multiplexing, KCP over a bad link. */
class CoreTest {
    private fun vector(name: String): Map<String, Any?> = Json.parse(File(System.getProperty("connectivitizer.vectors"), name).readText()).asMap()!!

    private val random = SecureRandom()
    private fun bytes(n: Int) = ByteArray(n).also { random.nextBytes(it) }

    private class Side(private val incoming: ChunkQueue, private val outgoing: ChunkQueue) : ByteStream {
        override suspend fun read() = incoming.read()
        override suspend fun write(data: ByteArray) = outgoing.push(data.copyOf())
        override suspend fun end() = outgoing.end()
        override suspend fun close() {
            outgoing.end()
            incoming.end()
        }
    }

    private fun memoryPair(): Pair<ByteStream, ByteStream> {
        val aToB = ChunkQueue()
        val bToA = ChunkQueue()
        return Side(bToA, aToB) to Side(aToB, bToA)
    }

    private val prologue = Noise.prologue("0123456789abcdef0123456789abcdef", "a".repeat(64))

    @Test
    fun stunVector() {
        val data = vector("stun.json")
        val id = Bytes.fromHex(data.string("transactionId")!!)
        assertEquals(data["request"], Bytes.hex(Stun.request(id)))
        for (case in data["responses"].asList()!!.map { it.asMap()!! }) assertEquals(case["mapped"], Stun.readSuccess(Bytes.fromHex(case.string("response")!!), id))
    }

    @Test
    fun kcpVector() {
        val data = vector("kcp.json")
        val packets = ArrayList<String>()
        val kcp = Kcp(data.long("conv")!!) { packets.add(Bytes.hex(it)) }
        kcp.update(1000)
        kcp.send("hello".toByteArray())
        kcp.update(1100)
        assertEquals(data["packets"], packets)
    }

    @Test
    fun yamuxVector() = runBlocking {
        val scope = CoroutineScope(coroutineContext + SupervisorJob())
        val (a, b) = memoryPair()
        val initiator = MuxSession(a, true, scope)
        initiator.start()
        val stream = initiator.open()
        stream.write("GET / HTTP/1.1\r\n\r\n".toByteArray())
        stream.end()
        val frames = List(3) { Bytes.hex(b.read()!!) }
        initiator.close()
        assertEquals(vector("yamux.json")["frames"].asList()!!.map { it.asMap()!!["hex"] }, frames)
        scope.coroutineContext[kotlinx.coroutines.Job]!!.cancel()
    }

    @Test
    fun generatedKeysAreReadableAndOrdinary() {
        val readable = Regex("^czs_[A-HJ-NP-Z2-9]{42}[AQ]$")
        repeat(200) {
            val text = SharedKey.generate()
            assertTrue(readable.matches(text), text)
            assertEquals(32, SharedKey.parse(text).bytes.size)
        }
    }

    @Test
    fun sharedKeyChannelCarriesDataBothWaysAndRefusesOtherKeys() = runBlocking {
        val text = SharedKey.generate()
        val (app, device) = memoryPair()
        val accepting = async { Noise.accept(device, listOf(SharedKey.parse(SharedKey.generate(), "other"), SharedKey.parse(text, "example app")), prologue, ::bytes) }
        val appChannel = Noise.connect(app, SharedKey.parse(text, "lamp"), prologue, ::bytes)
        val deviceChannel = accepting.await()
        assertEquals("example app", deviceChannel.keyName)
        val request = bytes(3 * Noise.MAX_PLAINTEXT + 17)
        val writing = async { appChannel.stream.write(request) }
        var received = ByteArray(0)
        while (received.size < request.size) received += deviceChannel.stream.read()!!
        writing.await()
        assertContentEquals(request, received)

        val (app2, device2) = memoryPair()
        val refusing = async { runCatching { Noise.accept(device2, listOf(SharedKey.parse(SharedKey.generate())), prologue, ::bytes) } }
        val error = assertFailsWith<ConnectivitizerException> { Noise.connect(app2, SharedKey.parse(SharedKey.generate()), prologue, ::bytes) }
        assertEquals(ErrorCodes.E2E_SHARED_KEY_MISMATCH, error.code)
        assertEquals(ErrorCodes.E2E_SHARED_KEY_MISMATCH, (refusing.await().exceptionOrNull() as ConnectivitizerException).code)
    }

    @Test
    fun muxStreamsAreIndependentAndFlowControlled() = runBlocking {
        val scope = CoroutineScope(coroutineContext + SupervisorJob())
        val (a, b) = memoryPair()
        val initiator = MuxSession(a, true, scope)
        val device = MuxSession(b, false, scope)
        initiator.start()
        device.start()
        scope.launch {
            while (true) {
                val stream = device.accept() ?: break
                scope.launch {
                    while (true) stream.write(stream.read() ?: break)
                    stream.end()
                }
            }
        }
        val payloads = List(3) { bytes(3 * Yamux.INITIAL_WINDOW + 12345) }
        val echoed = payloads.map { payload ->
            async {
                val stream = initiator.open()
                val reading = async {
                    var all = ByteArray(0)
                    while (true) all += stream.read() ?: break
                    all
                }
                stream.write(payload)
                stream.end()
                reading.await()
            }
        }.awaitAll()
        for ((got, sent) in echoed.zip(payloads)) assertContentEquals(Bytes.sha256(sent), Bytes.sha256(got))
        initiator.close()
        assertEquals(ErrorCodes.SESSION_CLOSED, initiator.completion.await())
        assertEquals(ErrorCodes.SESSION_CLOSED, device.completion.await())
        scope.coroutineContext[kotlinx.coroutines.Job]!!.cancel()
    }

    @Test
    fun kcpDeliversAMegabyteOverALossyReorderingLink() {
        val rng = Random(7)
        val link = ArrayList<Triple<Long, Int, ByteArray>>()
        var now = 0L
        val kcps = arrayOfNulls<Kcp>(2)
        fun sender(target: Int): (ByteArray) -> Unit = { packet ->
            if (rng.nextDouble() >= 0.1) repeat(if (rng.nextDouble() < 0.05) 2 else 1) { link.add(Triple(now + rng.nextLong(5, 41), target, packet)) }
        }
        val a = Kcp(0x01020304, sender(1))
        val b = Kcp(0x01020304, sender(0))
        kcps[0] = a
        kcps[1] = b
        for (kcp in kcps) {
            kcp!!.stream = true
            kcp.noDelay(1, 10, 2, 1)
            kcp.wndSize(256, 256)
        }
        val payload = bytes(1024 * 1024)
        var offset = 0
        val received = java.io.ByteArrayOutputStream()
        while (received.size() < payload.size && now < 600_000) {
            while (offset < payload.size && a.waitSnd < 512) offset += a.send(payload, offset, minOf(payload.size, offset + 64 * 1024))
            now += 10
            val due = link.filter { it.first <= now }
            link.removeAll { it.first <= now }
            for ((_, target, packet) in due) kcps[target]!!.input(packet)
            a.update(now)
            b.update(now)
            while (true) received.write(b.recv() ?: break)
        }
        assertContentEquals(Bytes.sha256(payload), Bytes.sha256(received.toByteArray()))
        val other = ArrayList<ByteArray>()
        val sender = Kcp(1) { other.add(it) }
        sender.update(0)
        sender.send(byteArrayOf(1))
        sender.update(100)
        assertTrue(Kcp(2) {}.input(other[0]) < 0)
    }

    @Test
    fun jsonRoundTrips() {
        val text = """{"a":[1,2.5,"x\n\"y",true,null],"b":{"c":"ü"}}"""
        assertEquals("""{"a":[1,2.5,"x\n\"y",true,null],"b":{"c":"ü"}}""", Json.write(Json.parse(text)))
        assertNull(Json.parse("null"))
    }

    @Test
    fun onlyARefusalTheApiNamesIsPassedOn() = runBlocking {
        class Answering(private val status: Int, private val body: String) : Platform() {
            override suspend fun fetch(url: String, method: String, headers: Map<String, String>, body: String?, scope: CoroutineScope) = status to this.body
        }
        // What a proxy says while the API restarts must not make a device give up.
        for ((status, body, code) in listOf(
            Triple(502, "<html><body>502 Bad Gateway</body></html>", ErrorCodes.SIGNALING_UNAVAILABLE),
            Triple(503, "", ErrorCodes.SIGNALING_UNAVAILABLE),
            Triple(200, "", ErrorCodes.SIGNALING_UNAVAILABLE),
            Triple(401, "", ErrorCodes.UNAUTHENTICATED),
            Triple(403, """{"error":"DEVICE_REVOKED"}""", ErrorCodes.DEVICE_REVOKED),
        )) {
            val api = PlatformApi("https://api.example", Answering(status, body), CoroutineScope(SupervisorJob()))
            val error = assertFailsWith<ConnectivitizerException> { api.deviceKeyToken("czd_x", "d", null, null) }
            assertEquals(code, error.code, "HTTP $status")
        }
    }
}
