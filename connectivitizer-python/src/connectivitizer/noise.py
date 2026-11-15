"""The end-to-end layer for endpoints that share a key (protocol section 4a): the Noise handshake NNpsk0 with
X25519, ChaCha20-Poly1305 and SHA-256. Each session agrees on fresh keys, so recorded traffic stays
unreadable even if the shared key leaks later; the shared key is what authenticates the two ends to each
other. Nothing between them holds it."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Callable, Optional, Sequence, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .encoding import b64decode
from .errors import ConnectivitizerError, ErrorCodes
from .streams import ByteStream, StreamReader

PROTOCOL_NAME = b"Noise_NNpsk0_25519_ChaChaPoly_SHA256"
KEY_SIZE = 32
TAG_SIZE = 16
HANDSHAKE_MESSAGE_SIZE = KEY_SIZE + TAG_SIZE

MAX_PLAINTEXT = 4096
"""Largest number of plaintext bytes in one message, so an endpoint with little memory needs only small buffers."""

SHARED_KEY_PREFIX = "czs_"


@dataclass(frozen=True)
class SharedKey:
    """A key that two endpoints hold and nobody else does, written ``czs_`` followed by 43 characters. The
    platform never receives it. ``name`` is what this endpoint calls the key; it is never transmitted."""

    name: str
    bytes: bytes

    def __repr__(self) -> str:  # never print the key itself
        return f"SharedKey(name={self.name!r})"


def parse_shared_key(text: str, name: str = "default") -> SharedKey:
    trimmed = text.strip()
    data: Optional[bytes] = None
    if trimmed.startswith(SHARED_KEY_PREFIX) and len(trimmed) == len(SHARED_KEY_PREFIX) + 43:
        try:
            data = b64decode(trimmed[len(SHARED_KEY_PREFIX) :])
        except ValueError:
            data = None
    if data is None or len(data) != KEY_SIZE:
        raise ConnectivitizerError(ErrorCodes.INVALID_REQUEST, "A shared key looks like czs_ followed by 43 characters.")
    return SharedKey(name, data)


READABLE_KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
"""The characters of a generated key (protocol section 1.2): one case, no I and O, no 0 and 1."""


def generate_shared_key(random_bytes: Callable[[int], bytes] = secrets.token_bytes) -> str:
    """A new shared key in its text form, readable: 42 characters of READABLE_KEY_ALPHABET and a last A or Q."""
    data = random_bytes(43)
    if len(data) != 43:
        raise ValueError("The random source did not return 43 bytes.")
    # 32 characters: the low five bits of a random byte pick one uniformly.
    body = "".join(READABLE_KEY_ALPHABET[byte & 31] for byte in data[:42])
    return SHARED_KEY_PREFIX + body + ("A" if data[42] & 1 == 0 else "Q")


def prologue(session_id: str, grant_hash_hex: str) -> bytes:
    """What both handshakes are bound to: this protocol, this session and this grant."""
    return f"cz-e2e-shared-key/1|{session_id}|{grant_hash_hex}".encode("utf-8")


def nonce(counter: int) -> bytes:
    """Four zero bytes, then the counter as 64-bit little-endian."""
    return b"\x00\x00\x00\x00" + counter.to_bytes(8, "little")


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _hkdf(chaining_key: bytes, material: bytes, outputs: int) -> Tuple[bytes, ...]:
    temp = _hmac(chaining_key, material)
    first = _hmac(temp, b"\x01")
    second = _hmac(temp, first + b"\x02")
    if outputs == 2:
        return first, second
    return first, second, _hmac(temp, second + b"\x03")


def _public(private: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _agree(private: bytes, remote_public: bytes) -> bytes:
    try:
        shared = X25519PrivateKey.from_private_bytes(private).exchange(X25519PublicKey.from_public_bytes(remote_public))
    except ValueError as error:
        # cryptography refuses a point of small order, which would force a known result.
        raise ConnectivitizerError(ErrorCodes.E2E_HANDSHAKE_FAILED, "The peer sent an invalid key-agreement value.") from error
    if not any(shared):
        raise ConnectivitizerError(ErrorCodes.E2E_HANDSHAKE_FAILED, "The peer sent an invalid key-agreement value.")
    return shared


class NoiseHandshake:
    """``Noise_NNpsk0_25519_ChaChaPoly_SHA256`` as the Noise specification (revision 34) defines it::

        -> psk, e
        <- e, ee
    """

    def __init__(self, prologue_bytes: bytes, shared_key: bytes) -> None:
        # The protocol name is longer than a hash, so the initial hash is the hash of the name.
        self._hash = hashlib.sha256(PROTOCOL_NAME).digest()
        self._chaining_key = self._hash
        self._key: Optional[bytes] = None
        self._counter = 0
        self._ephemeral: Optional[bytes] = None
        self._remote_public: Optional[bytes] = None
        self._mix_hash(prologue_bytes)
        self._mix_key_and_hash(shared_key)

    @classmethod
    def start_initiator(cls, prologue_bytes: bytes, shared_key: bytes, ephemeral_private: bytes) -> "NoiseHandshake":
        handshake = cls(prologue_bytes, shared_key)
        handshake._ephemeral = ephemeral_private
        return handshake

    def write_first(self, payload: bytes = b"") -> bytes:
        ephemeral_public = _public(self._ephemeral)  # type: ignore[arg-type]
        self._mix_hash(ephemeral_public)
        self._mix_key(ephemeral_public)
        return ephemeral_public + self._encrypt_and_hash(payload)

    def read_second(self, message: bytes) -> Optional[bytes]:
        """Processes the responder's message. None when it was not made with the same shared key."""
        if len(message) < HANDSHAKE_MESSAGE_SIZE:
            return None
        remote_public = message[:KEY_SIZE]
        self._mix_hash(remote_public)
        self._mix_key(remote_public)
        self._mix_key(_agree(self._ephemeral, remote_public))  # type: ignore[arg-type]
        self._ephemeral = None
        return self._decrypt_and_hash(message[KEY_SIZE:])

    @classmethod
    def try_start_responder(cls, prologue_bytes: bytes, shared_key: bytes, first_message: bytes) -> Optional[Tuple["NoiseHandshake", bytes]]:
        """Processes the initiator's message with one candidate key. None when it was not made with that key."""
        if len(first_message) < HANDSHAKE_MESSAGE_SIZE:
            return None
        handshake = cls(prologue_bytes, shared_key)
        remote_public = first_message[:KEY_SIZE]
        handshake._mix_hash(remote_public)
        handshake._mix_key(remote_public)
        payload = handshake._decrypt_and_hash(first_message[KEY_SIZE:])
        if payload is None:
            return None
        handshake._remote_public = remote_public
        return handshake, payload

    def write_second(self, ephemeral_private: bytes, payload: bytes = b"") -> bytes:
        ephemeral_public = _public(ephemeral_private)
        self._mix_hash(ephemeral_public)
        self._mix_key(ephemeral_public)
        self._mix_key(_agree(ephemeral_private, self._remote_public))  # type: ignore[arg-type]
        return ephemeral_public + self._encrypt_and_hash(payload)

    @property
    def handshake_hash(self) -> bytes:
        return self._hash

    def split(self) -> Tuple[bytes, bytes]:
        """The two transport keys: what the initiator sends, and what the responder sends."""
        first, second = _hkdf(self._chaining_key, b"", 2)
        return first, second

    def _mix_hash(self, data: bytes) -> None:
        self._hash = hashlib.sha256(self._hash + data).digest()

    def _mix_key(self, material: bytes) -> None:
        self._chaining_key, self._key = _hkdf(self._chaining_key, material, 2)
        self._counter = 0

    def _mix_key_and_hash(self, material: bytes) -> None:
        self._chaining_key, second, self._key = _hkdf(self._chaining_key, material, 3)
        self._mix_hash(second)
        self._counter = 0

    def _encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = ChaCha20Poly1305(self._key).encrypt(nonce(self._counter), plaintext, self._hash)  # type: ignore[arg-type]
        self._counter += 1
        self._mix_hash(ciphertext)
        return ciphertext

    def _decrypt_and_hash(self, ciphertext: bytes) -> Optional[bytes]:
        try:
            plaintext = ChaCha20Poly1305(self._key).decrypt(nonce(self._counter), ciphertext, self._hash)  # type: ignore[arg-type]
        except InvalidTag:
            return None
        self._counter += 1
        self._mix_hash(ciphertext)
        return plaintext


def _frame(message: bytes) -> bytes:
    return len(message).to_bytes(2, "big") + message


async def _read_frame(reader: StreamReader, max_length: int) -> Optional[bytes]:
    header = await reader.read_exact(2)
    if header is None:
        return None
    length = int.from_bytes(header, "big")
    if length > max_length:
        raise ConnectivitizerError(ErrorCodes.E2E_HANDSHAKE_FAILED, "The peer sent a message that is too long for this protocol.")
    if length == 0:
        return b""
    return await reader.read_exact(length)


@dataclass
class SharedKeyChannel:
    """The outcome of a handshake: the encrypted stream and the name of the key both ends proved to hold."""

    stream: ByteStream
    key_name: str


async def connect_shared_key(path: ByteStream, key: SharedKey, prologue_bytes: bytes, random_bytes: Callable[[int], bytes]) -> SharedKeyChannel:
    """Runs the handshake as the initiating endpoint."""
    reader = StreamReader(path)
    try:
        handshake = NoiseHandshake.start_initiator(prologue_bytes, key.bytes, random_bytes(KEY_SIZE))
        await path.write(_frame(handshake.write_first()))
        second = await _read_frame(reader, HANDSHAKE_MESSAGE_SIZE)
        if second is not None and len(second) == 0:
            # The device answers with an empty message when none of its keys fits.
            raise ConnectivitizerError(ErrorCodes.E2E_SHARED_KEY_MISMATCH, "The device does not hold this shared key.")
        if second is None or len(second) != HANDSHAKE_MESSAGE_SIZE:
            raise ConnectivitizerError(ErrorCodes.E2E_HANDSHAKE_FAILED, "The peer ended the end-to-end handshake.")
        if handshake.read_second(second) is None:
            raise ConnectivitizerError(ErrorCodes.E2E_SHARED_KEY_MISMATCH, "The device answered with a different shared key.")
        send_key, receive_key = handshake.split()
        return SharedKeyChannel(NoiseStream(path, reader, send_key, receive_key), key.name)
    except BaseException as error:
        await _close_quietly(path)
        if isinstance(error, ConnectivitizerError) or isinstance(error, asyncio.CancelledError):
            raise
        raise ConnectivitizerError(ErrorCodes.E2E_HANDSHAKE_FAILED, "The path ended during the end-to-end handshake.") from error


async def accept_shared_key(path: ByteStream, keys: Sequence[SharedKey], prologue_bytes: bytes, random_bytes: Callable[[int], bytes]) -> SharedKeyChannel:
    """Runs the handshake as the accepting endpoint, which may hold several keys; the one the initiator used
    is found by trying them."""
    reader = StreamReader(path)
    try:
        first = await _read_frame(reader, HANDSHAKE_MESSAGE_SIZE)
        if first is None or len(first) != HANDSHAKE_MESSAGE_SIZE:
            raise ConnectivitizerError(ErrorCodes.E2E_HANDSHAKE_FAILED, "The peer ended the end-to-end handshake.")
        handshake: Optional[NoiseHandshake] = None
        used: Optional[SharedKey] = None
        for key in keys:
            started = NoiseHandshake.try_start_responder(prologue_bytes, key.bytes, first)
            if started is not None:
                handshake, used = started[0], key
                break
        if handshake is None or used is None:
            await path.write(_frame(b""))
            raise ConnectivitizerError(ErrorCodes.E2E_SHARED_KEY_MISMATCH, "The initiator used a shared key this endpoint does not hold.")
        await path.write(_frame(handshake.write_second(random_bytes(KEY_SIZE))))
        initiator_key, responder_key = handshake.split()
        return SharedKeyChannel(NoiseStream(path, reader, responder_key, initiator_key), used.name)
    except BaseException as error:
        await _close_quietly(path)
        if isinstance(error, ConnectivitizerError) or isinstance(error, asyncio.CancelledError):
            raise
        raise ConnectivitizerError(ErrorCodes.E2E_HANDSHAKE_FAILED, "The path ended during the end-to-end handshake.") from error


async def _close_quietly(stream: ByteStream) -> None:
    try:
        await stream.close()
    except Exception:
        pass


class NoiseStream(ByteStream):
    """The encrypted byte stream after the handshake: length-prefixed messages of at most MAX_PLAINTEXT bytes."""

    def __init__(self, path: ByteStream, reader: StreamReader, send_key: bytes, receive_key: bytes) -> None:
        self._path = path
        self._reader = reader
        self._send = ChaCha20Poly1305(send_key)
        self._receive = ChaCha20Poly1305(receive_key)
        self._send_counter = 0
        self._receive_counter = 0
        self._writing = asyncio.Lock()

    async def read(self) -> Optional[bytes]:
        while True:
            header = await self._reader.read_exact(2)
            if header is None:
                return None
            length = int.from_bytes(header, "big")
            if length < TAG_SIZE or length > MAX_PLAINTEXT + TAG_SIZE:
                raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, "The peer sent a malformed encrypted message.")
            ciphertext = await self._reader.read_exact(length)
            if ciphertext is None:
                # Cut off inside a message: the path broke, this is not an orderly end.
                raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, "The path ended inside an encrypted message.")
            try:
                plaintext = self._receive.decrypt(nonce(self._receive_counter), ciphertext, None)
            except InvalidTag as error:
                raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, "An encrypted message was altered on the way.") from error
            self._receive_counter += 1
            if plaintext:
                return plaintext

    async def write(self, data: bytes) -> None:
        # One writer at a time: the message counter and the order on the path must agree.
        async with self._writing:
            for offset in range(0, len(data), MAX_PLAINTEXT):
                chunk = data[offset : offset + MAX_PLAINTEXT]
                ciphertext = self._send.encrypt(nonce(self._send_counter), chunk, None)
                self._send_counter += 1
                await self._path.write(_frame(ciphertext))

    async def end(self) -> None:
        await self.close()

    async def close(self) -> None:
        await self._path.close()
