"""The layers of a session on their own: the shared-key channel, multiplexing, KCP over a bad link, and HTTP
and WebSocket over a stream. The same cases as the TypeScript SDK's tests."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import random
import unittest
from typing import List, Optional, Tuple

from connectivitizer.api import PlatformApi
from connectivitizer.direct.kcp import Kcp
from connectivitizer.errors import ConnectivitizerError, ErrorCodes
from connectivitizer.http import http_request
from connectivitizer.mux import INITIAL_WINDOW, MuxSession
from connectivitizer.noise import MAX_PLAINTEXT, accept_shared_key, connect_shared_key, generate_shared_key, parse_shared_key, prologue
from connectivitizer.streams import ByteStream, StreamReader
from connectivitizer.websocket import GUID, StreamWebSocket, parse_head

from .support import memory_pair

PROLOGUE = prologue("0123456789abcdef0123456789abcdef", "a" * 64)


async def read_all(stream: ByteStream) -> bytes:
    parts = []
    while True:
        chunk = await stream.read()
        if chunk is None:
            return b"".join(parts)
        parts.append(chunk)


class ReadableKeys(unittest.TestCase):
    def test_generated_keys_are_readable_and_ordinary(self) -> None:
        for _ in range(200):
            text = generate_shared_key()
            self.assertRegex(text, r"^czs_[A-HJ-NP-Z2-9]{42}[AQ]$")
            self.assertEqual(len(parse_shared_key(text).bytes), 32)


class SharedKeyChannel(unittest.IsolatedAsyncioTestCase):
    async def test_same_key_carries_data_both_ways(self) -> None:
        text = generate_shared_key()
        app_side, device_side = memory_pair()
        accepting = asyncio.ensure_future(accept_shared_key(device_side, [parse_shared_key(generate_shared_key(), "other"), parse_shared_key(text, "example app")], PROLOGUE, os.urandom))
        app = await connect_shared_key(app_side, parse_shared_key(text, "lamp"), PROLOGUE, os.urandom)
        device = await accepting
        self.assertEqual(app.key_name, "lamp")
        # The device held two keys; it reports the one the application proved to have.
        self.assertEqual(device.key_name, "example app")
        request = os.urandom(3 * MAX_PLAINTEXT + 17)
        writing = asyncio.ensure_future(app.stream.write(request))
        received = b""
        while len(received) < len(request):
            received += await device.stream.read()  # type: ignore[operator]
        await writing
        self.assertEqual(received, request)
        await device.stream.write(b"200 OK")
        self.assertEqual(await app.stream.read(), b"200 OK")

    async def test_different_keys_give_no_channel(self) -> None:
        app_side, device_side = memory_pair()
        accepting = asyncio.ensure_future(accept_shared_key(device_side, [parse_shared_key(generate_shared_key())], PROLOGUE, os.urandom))
        with self.assertRaises(ConnectivitizerError) as app_error:
            await connect_shared_key(app_side, parse_shared_key(generate_shared_key()), PROLOGUE, os.urandom)
        self.assertEqual(app_error.exception.code, ErrorCodes.E2E_SHARED_KEY_MISMATCH)
        with self.assertRaises(ConnectivitizerError) as device_error:
            await accepting
        self.assertEqual(device_error.exception.code, ErrorCodes.E2E_SHARED_KEY_MISMATCH)

    async def test_ends_that_disagree_about_the_session_get_no_channel(self) -> None:
        key = parse_shared_key(generate_shared_key())
        app_side, device_side = memory_pair()
        accepting = asyncio.ensure_future(accept_shared_key(device_side, [key], prologue("f" * 32, "a" * 64), os.urandom))
        with self.assertRaises(ConnectivitizerError):
            await connect_shared_key(app_side, key, PROLOGUE, os.urandom)
        with self.assertRaises(ConnectivitizerError):
            await accepting


class Multiplexing(unittest.IsolatedAsyncioTestCase):
    async def test_streams_are_independent_flow_controlled_and_half_closable(self) -> None:
        a, b = memory_pair()
        initiator, device = MuxSession(a, True), MuxSession(b, False)
        initiator.start()
        device.start()

        async def echo() -> None:
            while True:
                stream = await device.accept()
                if stream is None:
                    return

                async def serve(s=stream) -> None:
                    while True:
                        chunk = await s.read()
                        if chunk is None:
                            break
                        await s.write(chunk)
                    await s.end()

                asyncio.ensure_future(serve())

        asyncio.ensure_future(echo())
        payloads = [os.urandom(3 * INITIAL_WINDOW + 12345) for _ in range(3)]

        async def round_trip(payload: bytes) -> bytes:
            stream = initiator.open()
            self.assertEqual(stream.id % 2, 1)
            reading = asyncio.ensure_future(read_all(stream))
            await stream.write(payload)
            await stream.end()
            return await reading

        echoed = await asyncio.gather(*(round_trip(p) for p in payloads))
        for got, sent in zip(echoed, payloads):
            self.assertEqual(hashlib.sha256(got).digest(), hashlib.sha256(sent).digest())
        await initiator.close()
        self.assertEqual(await initiator.completion, ErrorCodes.SESSION_CLOSED)
        self.assertEqual(await device.completion, ErrorCodes.SESSION_CLOSED)

    async def test_broken_framing_and_wrong_parity_are_protocol_errors(self) -> None:
        a, b = memory_pair()
        session = MuxSession(a, True)
        session.start()
        await b.write(bytes([1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]))  # version 1 does not exist
        self.assertEqual(await session.completion, ErrorCodes.MUX_PROTOCOL_ERROR)
        a, b = memory_pair()
        session = MuxSession(a, True)
        session.start()
        await b.write(bytes([0, 1, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0]))  # the device may only open even streams
        self.assertEqual(await session.completion, ErrorCodes.MUX_PROTOCOL_ERROR)


def serve_once(response: List[bytes], close_after: bool = True):
    client, server = memory_pair()

    async def handle() -> bytes:
        reader = StreamReader(server)
        head = await reader.read_head(65536)
        _, headers = parse_head(head)  # type: ignore[arg-type]
        length = int(headers.get("content-length", "0"))
        body = await reader.read_exact(length) if length else b""
        for part in response:
            await server.write(part)
        if close_after:
            await server.end()
        return head + (body or b"")  # type: ignore[operator]

    task = asyncio.ensure_future(handle())

    async def open_stream() -> ByteStream:
        return client

    return open_stream, task


class Http(unittest.IsolatedAsyncioTestCase):
    async def test_content_length_and_what_the_service_receives(self) -> None:
        open_stream, request = serve_once([b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-A: 1\r\nX-A: 2\r\nContent-Length: 5\r\n\r\nhello"])
        response = await http_request(open_stream, "api", "/things?x=1", method="post", body="ping", headers={"X-Token": "abc"})
        self.assertEqual((response.status, response.ok, response.headers["x-a"]), (200, True, "1, 2"))
        self.assertEqual(await response.text(), "hello")
        sent = (await request).decode()
        self.assertTrue(sent.startswith("POST /things?x=1 HTTP/1.1\r\n"))
        for line in ("\r\nHost: api\r\n", "\r\nX-Token: abc\r\n", "\r\nContent-Length: 4\r\n"):
            self.assertIn(line, sent)
        self.assertTrue(sent.endswith("\r\n\r\nping"))

    async def test_chunked_interim_and_until_close(self) -> None:
        open_stream, _ = serve_once([b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n", b"5\r\npedia\r\n0\r\n\r\n"])
        self.assertEqual(await (await http_request(open_stream, "api", "/")).text(), "Wikipedia")
        open_stream, _ = serve_once([b"HTTP/1.1 200 OK\r\n\r\nuntil ", b"the end"])
        self.assertEqual(await (await http_request(open_stream, "api", "/")).text(), "until the end")

    async def test_truncated_body_is_an_error(self) -> None:
        open_stream, _ = serve_once([b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"])
        response = await http_request(open_stream, "api", "/")
        with self.assertRaises(ConnectivitizerError):
            await response.bytes()


class ApiErrors(unittest.IsolatedAsyncioTestCase):
    async def test_only_a_refusal_the_api_names_is_passed_on(self) -> None:
        class Answering:
            def __init__(self, status: int, body: str) -> None:
                self.answer = (status, body)

            async def fetch(self, url: str, method: str, headers: object, body: Optional[str]) -> Tuple[int, str]:
                return self.answer

        # What a proxy says while the API restarts must not make a device give up.
        for status, body, code in (
            (502, "<html><body>502 Bad Gateway</body></html>", ErrorCodes.SIGNALING_UNAVAILABLE),
            (503, "", ErrorCodes.SIGNALING_UNAVAILABLE),
            (200, "", ErrorCodes.SIGNALING_UNAVAILABLE),
            (401, "", ErrorCodes.UNAUTHENTICATED),
            (403, '{"error":"DEVICE_REVOKED"}', ErrorCodes.DEVICE_REVOKED),
        ):
            api = PlatformApi("https://api.example", Answering(status, body))  # type: ignore[arg-type]
            with self.assertRaises(ConnectivitizerError) as caught:
                await api.device_key_token("czd_x", "d", None, None)
            self.assertEqual(caught.exception.code, code, status)


class WebSocket(unittest.IsolatedAsyncioTestCase):
    async def test_handshake_text_binary_fragments_ping_and_close(self) -> None:
        client, server = memory_pair()
        reader = StreamReader(server)

        async def accept() -> None:
            head = await reader.read_head(16384)
            _, headers = parse_head(head)  # type: ignore[arg-type]
            accept_key = base64.b64encode(hashlib.sha1((headers["sec-websocket-key"] + GUID).encode()).digest()).decode()
            await server.write(f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept_key}\r\n\r\n".encode())
            # A fragmented text message, a ping and a binary message, unmasked as a server sends them.
            await server.write(bytes([0x01, 3]) + b"Hel" + bytes([0x80, 2]) + b"lo" + bytes([0x89, 1]) + b"p" + bytes([0x82, 3]) + b"\x01\x02\x03")

        accepted = asyncio.ensure_future(accept())
        socket = await StreamWebSocket.connect(client, "api", "/ws", os.urandom)
        await accepted
        self.assertEqual(await socket.receive(), "Hello")
        self.assertEqual(await socket.receive(), b"\x01\x02\x03")

        async def frame() -> tuple:
            header = await reader.read_exact(2)
            length = header[1] & 0x7F  # type: ignore[index]
            mask = await reader.read_exact(4)
            payload = await reader.read_exact(length) if length else b""
            return header[0] & 0x0F, bytes(b ^ mask[i % 4] for i, b in enumerate(payload))  # type: ignore[index]

        self.assertEqual(await frame(), (0xA, b"p"))  # the pong to the ping, masked by the client
        await socket.send("hi")
        self.assertEqual(await frame(), (0x1, b"hi"))
        await server.write(bytes([0x88, 2, 0x03, 0xE8]))  # the server closes with 1000
        self.assertIsNone(await socket.receive())
        self.assertEqual(socket.close_code, 1000)


class KcpOverABadLink(unittest.IsolatedAsyncioTestCase):
    async def test_a_megabyte_arrives_intact_over_a_lossy_reordering_link(self) -> None:
        rng = random.Random(7)
        link: List[tuple] = []  # (deliver at, target, packet)
        now = [0]

        def send_to(target: List[Optional[Kcp]]):
            def output(packet: bytes) -> None:
                if rng.random() < 0.1:
                    return  # lost
                copies = 2 if rng.random() < 0.05 else 1  # duplicated
                for _ in range(copies):
                    link.append((now[0] + rng.randint(5, 40), target, packet))  # reordered by the random delay

            return output

        a_ref: List[Optional[Kcp]] = [None]
        b_ref: List[Optional[Kcp]] = [None]
        a = Kcp(0x01020304, send_to(b_ref))
        b = Kcp(0x01020304, send_to(a_ref))
        a_ref[0], b_ref[0] = a, b
        for kcp in (a, b):
            kcp.stream = True
            kcp.no_delay(1, 10, 2, 1)
            kcp.wnd_size(256, 256)
        payload = os.urandom(1024 * 1024)
        offset = 0
        received = bytearray()
        while len(received) < len(payload) and now[0] < 600_000:
            while offset < len(payload) and a.wait_snd < 512:
                offset += a.send(payload[offset : offset + 64 * 1024])
            now[0] += 10
            due = [item for item in link if item[0] <= now[0]]
            link[:] = [item for item in link if item[0] > now[0]]
            for _, target, packet in due:
                target[0].input(packet)
            a.update(now[0])
            b.update(now[0])
            while (chunk := b.recv()) is not None:
                received.extend(chunk)
        self.assertEqual(hashlib.sha256(bytes(received)).digest(), hashlib.sha256(payload).digest())

    def test_a_packet_of_another_conversation_is_refused(self) -> None:
        packets: List[bytes] = []
        sender = Kcp(1, packets.append)
        sender.update(0)
        sender.send(b"x")
        sender.update(100)
        self.assertLess(Kcp(2, lambda _: None).input(packets[0]), 0)


if __name__ == "__main__":
    unittest.main()
