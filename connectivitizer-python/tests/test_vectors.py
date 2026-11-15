"""The shared test vectors in docs/protocol/vectors, which every implementation is checked against."""

from __future__ import annotations

import asyncio
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from connectivitizer.direct.addresses import format_address, is_global_ipv6, normalize_host, parse_address
from connectivitizer.direct.attempt import read_stun_success, stun_request
from connectivitizer.direct.kcp import Kcp
from connectivitizer.errors import ConnectivitizerError
from connectivitizer.grants import hash_grant, parse_jwks, validate_grant
from connectivitizer.mux import MuxSession
from connectivitizer.noise import NoiseHandshake, nonce, parse_shared_key, prologue

from .support import memory_pair, vector


class Vectors(unittest.IsolatedAsyncioTestCase):
    def test_noise_handshake(self) -> None:
        data = vector("noise-nnpsk0.json")
        v = data["handshake"]
        h = bytes.fromhex
        initiator = NoiseHandshake.start_initiator(h(v["prologue"]), h(v["psk"]), h(v["initiatorEphemeral"]))
        first = initiator.write_first(h(v["payload1"]))
        self.assertEqual(first.hex(), v["message1"])
        started = NoiseHandshake.try_start_responder(h(v["prologue"]), h(v["psk"]), first)
        assert started is not None
        responder, payload = started
        self.assertEqual(payload.hex(), v["payload1"])
        second = responder.write_second(h(v["responderEphemeral"]), h(v["payload2"]))
        self.assertEqual(second.hex(), v["message2"])
        self.assertEqual(initiator.read_second(second).hex(), v["payload2"])  # type: ignore[union-attr]
        self.assertEqual(initiator.handshake_hash.hex(), v["handshakeHash"])
        send, receive = initiator.split()
        self.assertEqual((send.hex(), receive.hex()), (v["initiatorToResponderKey"], v["responderToInitiatorKey"]))
        self.assertEqual(responder.split(), initiator.split())
        p = data["prologue"]
        self.assertEqual(hash_grant(p["grantToken"]), p["grantHash"])
        self.assertEqual(prologue(p["sessionId"], p["grantHash"]).hex(), p["bytes"])

    def test_noise_transport_matches_the_published_vector(self) -> None:
        # The cacophony transport messages for the same handshake, as in the TypeScript tests.
        data = vector("noise-nnpsk0.json")["handshake"]
        key = bytes.fromhex(data["initiatorToResponderKey"])
        self.assertEqual(ChaCha20Poly1305(key).encrypt(nonce(0), bytes.fromhex("462e20412e20486179656b"), None).hex(), "e632c3763d7669067383433197a3baddf146e9e70ad4b4e9e59e0f")

    def test_x25519(self) -> None:
        data = vector("x25519.json")
        for case in data["multiply"]:
            private = X25519PrivateKey.from_private_bytes(bytes.fromhex(case["scalar"]))
            shared = private.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(case["u"])))
            self.assertEqual(shared.hex(), case["output"])
        dh = data["diffieHellman"]
        alice = X25519PrivateKey.from_private_bytes(bytes.fromhex(dh["alicePrivate"]))
        self.assertEqual(alice.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(), dh["alicePublic"])
        self.assertEqual(alice.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(dh["bobPublic"]))).hex(), dh["shared"])

    def test_shared_keys(self) -> None:
        data = vector("shared-keys.json")
        for case in data["valid"]:
            self.assertEqual(parse_shared_key(case["text"]).bytes.hex(), case["bytes"])
        for text in data["invalid"]:
            with self.assertRaises(ConnectivitizerError, msg=text):
                parse_shared_key(text)

    def test_grants(self) -> None:
        data = vector("grants.json")
        keys = parse_jwks(data["jwks"])
        for case in data["cases"]:
            for for_start, expected in ((True, case["atSessionStart"]), (False, case["duringLease"])):
                grant, error = validate_grant(case["token"], keys, data["now"], for_start)
                self.assertEqual("valid" if grant is not None else error, expected, case["name"])
        self.assertEqual(hash_grant(data["hash"]["token"]), data["hash"]["sha256"])

    def test_addresses(self) -> None:
        data = vector("addresses.json")
        for case in data["normalize"]:
            self.assertEqual(normalize_host(case["text"]), case["host"], case["text"])
        for case in data["candidates"]:
            parsed = parse_address(case["text"])
            self.assertEqual(parsed.host if parsed else None, case["host"], case["text"])
            self.assertEqual(parsed.port if parsed else None, case["port"], case["text"])
            self.assertEqual(format_address(parsed) if parsed else None, case["formatted"], case["text"])
        for case in data["globalIpv6"]:
            self.assertEqual(is_global_ipv6(case["host"]), case["global"], case["host"])

    def test_stun(self) -> None:
        data = vector("stun.json")
        transaction = bytes.fromhex(data["transactionId"])
        self.assertEqual(stun_request(transaction).hex(), data["request"])
        for case in data["responses"]:
            self.assertEqual(read_stun_success(bytes.fromhex(case["response"]), transaction), case["mapped"])

    async def test_yamux(self) -> None:
        a, b = memory_pair()
        initiator = MuxSession(a, True)
        initiator.start()
        stream = initiator.open()
        await stream.write(b"GET / HTTP/1.1\r\n\r\n")
        await stream.end()
        frames = [(await b.read()).hex() for _ in range(3)]  # type: ignore[union-attr]
        await initiator.close()
        self.assertEqual(frames, [frame["hex"] for frame in vector("yamux.json")["frames"]])

    def test_kcp(self) -> None:
        data = vector("kcp.json")
        packets = []
        kcp = Kcp(data["conv"], lambda packet: packets.append(packet.hex()))
        kcp.update(1000)
        kcp.send(b"hello")
        kcp.update(1100)
        self.assertEqual(packets, data["packets"])


if __name__ == "__main__":
    unittest.main()
