#!/usr/bin/env python3
"""Aion 2 world-handshake, session-setup, and C2S RC4 primitives.

The module contains no socket or account logic.  A caller owns one
``C2SStreamCipher`` per world TCP connection and must feed every post-handshake
C2S body to it exactly once and in wire order.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass


CLIENT_HANDSHAKE_OPCODE = b"\x10\x36"
SERVER_HANDSHAKE_OPCODE = b"\x11\x36"
CLIENT_SESSION_SETUP_OPCODE = b"\x13\x36"
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


@dataclass(frozen=True)
class ClientSessionSetup:
    """Decoded fields of the first encrypted ``13 36`` C2S body.

    Identifier names describe their observed lifetime, not a confirmed account,
    character, or device meaning.
    """

    primary_identifier: str
    stable_identifier: str
    connection_identifier: str
    setup_flags: int
    optional_value: int

    @property
    def flag0(self) -> bool:
        """Return the still-unknown first flag used by the client builder."""
        return bool(self.setup_flags & 0x01)

    @property
    def has_optional_value(self) -> bool:
        """Return the builder's ``optional_value > 0`` flag."""
        return bool(self.setup_flags & 0x02)


def _ascii_bytes(value: str, field: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field} must contain only ASCII characters") from error
    if b"\x00" in encoded:
        raise ValueError(f"{field} must not contain a NUL byte")
    return encoded


def build_client_session_setup(
    primary_identifier: str,
    stable_identifier: str,
    connection_identifier: str,
    flag0: bool = False,
    optional_value: int = 0,
) -> bytes:
    """Build a ``13 36`` body and derive its two-bit flags like the client."""
    primary = _ascii_bytes(primary_identifier, "primary_identifier")
    stable = _ascii_bytes(stable_identifier, "stable_identifier")
    connection = _ascii_bytes(connection_identifier, "connection_identifier")
    if b":" in stable or b":" in connection:
        raise ValueError("stable and connection identifiers must not contain ':'")
    if not isinstance(flag0, bool):
        raise ValueError("flag0 must be a bool")
    if not 0 <= optional_value <= 0x7FFFFFFFFFFFFFFF:
        raise ValueError("optional_value must be a non-negative i64")

    token = base64.b64encode(stable + b":" + connection + b"\x00")
    setup_flags = int(flag0) | (int(optional_value > 0) << 1)
    return b"".join(
        (
            CLIENT_SESSION_SETUP_OPCODE,
            encode_uvarint(len(primary)),
            primary,
            b"\x00",
            encode_uvarint(len(token)),
            token,
            b"\x00",
            bytes((setup_flags,)),
            optional_value.to_bytes(8, "little"),
        )
    )


def _parse_terminated_ascii(
    body: bytes,
    offset: int,
    field: str,
) -> tuple[str, int]:
    length, width = decode_uvarint(body, offset)
    value_at = offset + width
    terminator_at = value_at + length
    if terminator_at >= len(body):
        raise ValueError(f"{field} exceeds session setup body")
    if body[terminator_at] != 0:
        raise ValueError(f"{field} is not NUL-terminated")
    try:
        value = body[value_at:terminator_at].decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(f"{field} is not ASCII") from error
    return value, terminator_at + 1


def parse_client_session_setup(body: bytes) -> ClientSessionSetup:
    """Parse and strictly validate a plaintext ``13 36`` C2S body."""
    if not body.startswith(CLIENT_SESSION_SETUP_OPCODE):
        raise ValueError("client session setup opcode is not 13 36")

    primary, offset = _parse_terminated_ascii(body, 2, "primary_identifier")
    encoded_token, offset = _parse_terminated_ascii(body, offset, "encoded_token")
    if len(body) - offset != 9:
        raise ValueError("unexpected client session setup trailer length")

    try:
        encoded_bytes = encoded_token.encode("ascii")
        decoded_token = base64.b64decode(encoded_bytes, validate=True)
    except (UnicodeEncodeError, binascii.Error) as error:
        raise ValueError("encoded_token is not valid Base64") from error
    if base64.b64encode(decoded_token) != encoded_bytes:
        raise ValueError("encoded_token does not use canonical Base64")
    if not decoded_token.endswith(b"\x00"):
        raise ValueError("decoded session token is not NUL-terminated")
    identifiers = decoded_token[:-1].split(b":")
    if len(identifiers) != 2:
        raise ValueError("decoded session token does not contain two identifiers")
    try:
        stable, connection = (value.decode("ascii") for value in identifiers)
    except UnicodeDecodeError as error:
        raise ValueError("decoded session identifiers are not ASCII") from error

    setup_flags = body[offset]
    if setup_flags & ~0x03:
        raise ValueError("client session setup contains unknown flag bits")
    optional_value = int.from_bytes(body[offset + 1 : offset + 9], "little")
    if bool(setup_flags & 0x02) != (optional_value > 0):
        raise ValueError("optional-value flag does not match the trailer value")

    return ClientSessionSetup(
        primary_identifier=primary,
        stable_identifier=stable,
        connection_identifier=connection,
        setup_flags=setup_flags,
        optional_value=optional_value,
    )


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

    setup = ClientSessionSetup(
        primary_identifier="123456:11111111-1111-1111-1111-111111111111",
        stable_identifier="22222222-2222-2222-2222-222222222222",
        connection_identifier="33333333-3333-3333-3333-333333333333",
        setup_flags=2,
        optional_value=0x1122334455667788,
    )
    setup_body = build_client_session_setup(
        setup.primary_identifier,
        setup.stable_identifier,
        setup.connection_identifier,
        setup.flag0,
        setup.optional_value,
    )
    assert len(setup_body) == 158
    assert parse_client_session_setup(setup_body) == setup
    assert not setup.flag0 and setup.has_optional_value

    flag0_body = build_client_session_setup(
        setup.primary_identifier,
        setup.stable_identifier,
        setup.connection_identifier,
        flag0=True,
    )
    flag0_setup = parse_client_session_setup(flag0_body)
    assert flag0_setup.setup_flags == 1
    assert flag0_setup.flag0 and not flag0_setup.has_optional_value

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
    bodies = [
        setup_body,
        b"\x01\x36" + (123456789).to_bytes(8, "little"),
        b"\x10\x56",
    ]
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
