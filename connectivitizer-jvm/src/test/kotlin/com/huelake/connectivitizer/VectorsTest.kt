package com.huelake.connectivitizer

import com.huelake.connectivitizer.internal.Addresses
import com.huelake.connectivitizer.internal.Bytes
import com.huelake.connectivitizer.internal.Grants
import com.huelake.connectivitizer.internal.Json
import com.huelake.connectivitizer.internal.X25519
import com.huelake.connectivitizer.internal.asList
import com.huelake.connectivitizer.internal.asMap
import com.huelake.connectivitizer.internal.long
import com.huelake.connectivitizer.internal.string
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

/** The shared test vectors in docs/protocol/vectors, which every implementation is checked against. */
class VectorsTest {
    private fun vector(name: String): Map<String, Any?> =
        Json.parse(File(System.getProperty("connectivitizer.vectors"), name).readText()).asMap()!!

    private fun hex(text: Any?) = Bytes.fromHex(text as String)

    @Test
    fun noiseHandshakeAndPrologue() {
        val data = vector("noise-nnpsk0.json")
        val v = data["handshake"].asMap()!!
        val initiator = Noise.Handshake.startInitiator(hex(v["prologue"]), hex(v["psk"]), hex(v["initiatorEphemeral"]))
        val first = initiator.writeFirst(hex(v["payload1"]))
        assertEquals(v["message1"], Bytes.hex(first))
        val (responder, payload) = assertNotNull(Noise.Handshake.tryStartResponder(hex(v["prologue"]), hex(v["psk"]), first))
        assertEquals(v["payload1"], Bytes.hex(payload))
        val second = responder.writeSecond(hex(v["responderEphemeral"]), hex(v["payload2"]))
        assertEquals(v["message2"], Bytes.hex(second))
        assertEquals(v["payload2"], Bytes.hex(assertNotNull(initiator.readSecond(second))))
        assertEquals(v["handshakeHash"], Bytes.hex(initiator.handshakeHash))
        val (send, receive) = initiator.split()
        assertEquals(v["initiatorToResponderKey"], Bytes.hex(send))
        assertEquals(v["responderToInitiatorKey"], Bytes.hex(receive))
        assertEquals("e632c3763d7669067383433197a3baddf146e9e70ad4b4e9e59e0f", Bytes.hex(Noise.seal(send, 0, Bytes.fromHex("462e20412e20486179656b"), null)))
        val p = data["prologue"].asMap()!!
        assertEquals(p["grantHash"], Grants.hash(p.string("grantToken")!!))
        assertEquals(p["bytes"], Bytes.hex(Noise.prologue(p.string("sessionId")!!, p.string("grantHash")!!)))
    }

    @Test
    fun x25519() {
        val data = vector("x25519.json")
        for (case in data["multiply"].asList()!!.map { it.asMap()!! }) {
            assertEquals(case["output"], Bytes.hex(X25519.scalarMult(hex(case["scalar"]), hex(case["u"]))))
        }
        val dh = data["diffieHellman"].asMap()!!
        assertEquals(dh["alicePublic"], Bytes.hex(X25519.publicKey(hex(dh["alicePrivate"]))))
        assertEquals(dh["bobPublic"], Bytes.hex(X25519.publicKey(hex(dh["bobPrivate"]))))
        assertEquals(dh["shared"], Bytes.hex(X25519.scalarMult(hex(dh["alicePrivate"]), hex(dh["bobPublic"]))))
    }

    @Test
    fun sharedKeys() {
        val data = vector("shared-keys.json")
        for (case in data["valid"].asList()!!.map { it.asMap()!! }) assertEquals(case["bytes"], Bytes.hex(SharedKey.parse(case.string("text")!!).bytes))
        for (text in data["invalid"].asList()!!) assertFailsWith<ConnectivitizerException>(text as String) { SharedKey.parse(text) }
    }

    @Test
    fun grants() {
        val data = vector("grants.json")
        val keys = Grants.parseJwks(data["jwks"])
        val now = data.long("now")!!
        for (case in data["cases"].asList()!!.map { it.asMap()!! }) {
            for ((forStart, expected) in listOf(true to case["atSessionStart"], false to case["duringLease"])) {
                val result = Grants.validate(case.string("token")!!, keys, now, forStart)
                assertEquals(expected, if (result.grantOrNull != null) "valid" else result.errorOrNull, case.string("name"))
            }
        }
    }

    @Test
    fun addresses() {
        val data = vector("addresses.json")
        for (case in data["normalize"].asList()!!.map { it.asMap()!! }) assertEquals(case["host"], Addresses.normalizeHost(case.string("text")!!), case.string("text"))
        for (case in data["candidates"].asList()!!.map { it.asMap()!! }) {
            val parsed = Addresses.parse(case.string("text")!!)
            assertEquals(case["host"], parsed?.host, case.string("text"))
            assertEquals(case.long("port"), parsed?.port?.toLong(), case.string("text"))
            assertEquals(case["formatted"], parsed?.let { Addresses.format(it) }, case.string("text"))
        }
        for (case in data["globalIpv6"].asList()!!.map { it.asMap()!! }) assertEquals(case["global"], Addresses.isGlobalIpv6(case.string("host")!!), case.string("host"))
    }
}
