#!/usr/bin/env python3
"""Aion 2 world-handshake and C2S RC4 primitives.

The module contains no socket or account logic.  A caller owns one
``C2SStreamCipher`` per world TCP connection and must feed every post-handshake
C2S body to it exactly once and in wire order.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass


CLIENT_HANDSHAKE_OPCODE = b"\x10\x36"
SERVER_HANDSHAKE_OPCODE = b"\x11\x36"
EXPECTED_SECRET_LENGTH = 214


def encode_uvarint(value: int) -> bytes:
    if value < 0:
        raise ValueError("uvarint value must be non-negative")
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def decode_uvarint(data: bytes, offset: int = 0) -> tuple[int, int]:
    value = 0
    for index in range(5):
        at = offset + index
        if at >= len(data):
            raise ValueError("incomplete uvarint")
        byte = data[at]
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            width = index + 1
            if encode_uvarint(value) != data[offset : offset + width]:
                raise ValueError("non-minimal uvarint")
            return value, width
    raise ValueError("uvarint exceeds five bytes")


def frame_clear_body(body: bytes) -> bytes:
    if len(body) < 2:
        raise ValueError("Aion frame body must include a two-byte opcode")
    return encode_uvarint(len(body) + 4) + body


class RC4:
    """Standard stateful RC4 with an arbitrary non-empty key."""

    def __init__(self, key: bytes):
        if not key:
            raise ValueError("RC4 key must not be empty")
        self.state = list(range(256))
        swap = 0
        for index in range(256):
            swap = (swap + self.state[index] + key[index % len(key)]) & 0xFF
            self.state[index], self.state[swap] = self.state[swap], self.state[index]
        self.index = 0
        self.swap = 0
        self.consumed = 0

    def crypt(self, data: bytes) -> bytes:
        output = bytearray(len(data))
        for offset, value in enumerate(data):
            self.index = (self.index + 1) & 0xFF
            self.swap = (self.swap + self.state[self.index]) & 0xFF
            self.state[self.index], self.state[self.swap] = (
                self.state[self.swap],
                self.state[self.index],
            )
            key_byte = self.state[(self.state[self.index] + self.state[self.swap]) & 0xFF]
            output[offset] = value ^ key_byte
        self.consumed += len(data)
        return bytes(output)


class C2SStreamCipher:
    """Continuous body-only RC4 state for one world connection."""

    def __init__(self, oaep_secret: bytes):
        if len(oaep_secret) != EXPECTED_SECRET_LENGTH:
            raise ValueError(
                f"expected {EXPECTED_SECRET_LENGTH} OAEP bytes, got {len(oaep_secret)}"
            )
        self.rc4 = RC4(oaep_secret)

    @property
    def consumed_body_bytes(self) -> int:
        return self.rc4.consumed

    def crypt_body(self, body: bytes) -> bytes:
        return self.rc4.crypt(body)

    def encode_frame(self, plaintext_body: bytes) -> bytes:
        ciphertext = self.crypt_body(plaintext_body)
        return encode_uvarint(len(ciphertext) + 4) + ciphertext


@dataclass(frozen=True)
class ServerHandshake:
    status: int
    timeout_ms: int
    rsa_ciphertext: bytes
    reserved: int
    result: int


def generate_client_key_and_handshake(
    revision: int,
    region: str = "DE",
):
    """Return ``(private_key, framed_10_36_bytes)`` for a new world session."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError as error:
        raise RuntimeError("install dependency: python -m pip install cryptography") from error

    region_bytes = region.encode("ascii")
    if len(region_bytes) != 2:
        raise ValueError("region must contain exactly two ASCII characters")
    if not 0 <= revision <= 0xFFFFFFFF:
        raise ValueError("revision must fit u32")

    private_key = rsa.generate_private_key(public_exponent=3, key_size=2048)
    public_der = private_key.public_key().public_bytes(Encoding.DER, PublicFormat.PKCS1)
    body = b"".join(
        (
            CLIENT_HANDSHAKE_OPCODE,
            encode_uvarint(len(public_der)),
            public_der,
            revision.to_bytes(4, "little"),
            b"\x04\x06\x05\x02",
            region_bytes,
            b"\x02",
        )
    )
    return private_key, frame_clear_body(body)


def parse_server_handshake(body: bytes) -> ServerHandshake:
    """Parse the clear body of an Aion 2 ``11 36`` world handshake."""
    if not body.startswith(SERVER_HANDSHAKE_OPCODE):
        raise ValueError("server handshake opcode is not 11 36")
    if len(body) < 2 + 2 + 4 + 1 + 8 + 4:
        raise ValueError("server handshake is truncated")
    status = int.from_bytes(body[2:4], "little")
    timeout_ms = int.from_bytes(body[4:8], "little")
    cipher_length, width = decode_uvarint(body, 8)
    cipher_at = 8 + width
    trailer_at = cipher_at + cipher_length
    if cipher_length != 256:
        raise ValueError(f"expected 256 RSA ciphertext bytes, got {cipher_length}")
    if trailer_at + 12 != len(body):
        raise ValueError("unexpected server handshake trailer length")
    return ServerHandshake(
        status=status,
        timeout_ms=timeout_ms,
        rsa_ciphertext=body[cipher_at:trailer_at],
        reserved=int.from_bytes(body[trailer_at : trailer_at + 8], "little"),
        result=int.from_bytes(body[trailer_at + 8 : trailer_at + 12], "little", signed=True),
    )


def decrypt_server_secret(private_key, handshake: ServerHandshake) -> bytes:
    """Decrypt and validate the 214-byte RC4 key from an ``11 36`` body."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as error:
        raise RuntimeError("install dependency: python -m pip install cryptography") from error

    secret = private_key.decrypt(
        handshake.rsa_ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    if len(secret) != EXPECTED_SECRET_LENGTH:
        raise ValueError(
            f"expected {EXPECTED_SECRET_LENGTH} decrypted bytes, got {len(secret)}"
        )
    return secret


def self_test() -> None:
    # Published RC4 test vector: Key / Plaintext -> BBF316E8D940AF0AD3.
    assert RC4(b"Key").crypt(b"Plaintext").hex() == "bbf316e8d940af0ad3"

    private_key, client_frame = generate_client_key_and_handshake(3527, "DE")
    encoded_length, width = decode_uvarint(client_frame)
    assert encoded_length - 4 == len(client_frame) - width
    assert client_frame[width : width + 2] == CLIENT_HANDSHAKE_OPCODE

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    secret = bytes(range(EXPECTED_SECRET_LENGTH))
    ciphertext = private_key.public_key().encrypt(
        secret,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    server_body = b"".join(
        (
            SERVER_HANDSHAKE_OPCODE,
            (0).to_bytes(2, "little"),
            (60_000).to_bytes(4, "little"),
            encode_uvarint(len(ciphertext)),
            ciphertext,
            (0).to_bytes(8, "little"),
            (-7).to_bytes(4, "little", signed=True),
        )
    )
    parsed = parse_server_handshake(server_body)
    assert parsed.status == 0 and parsed.timeout_ms == 60_000 and parsed.result == -7
    assert decrypt_server_secret(private_key, parsed) == secret

    sender = C2SStreamCipher(secret)
    receiver = C2SStreamCipher(secret)
    bodies = [b"\x13\x36setup", b"\x01\x36" + (123456789).to_bytes(8, "little"), b"\x10\x56"]
    for body in bodies:
        framed = sender.encode_frame(body)
        length, prefix_width = decode_uvarint(framed)
        encrypted = framed[prefix_width:]
        assert length - 4 == len(encrypted)
        assert receiver.crypt_body(encrypted) == body
    assert sender.consumed_body_bytes == receiver.consumed_body_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("Aion 2 client crypto self-test: OK")
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
