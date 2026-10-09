#!/usr/bin/env python3
"""Decrypt an Aion 2 11 36 server block with a recovered RSA private key."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

try:
    from .analyze_pcaps import (
        CLIENT_SIGNATURE,
        SERVER_SIGNATURE,
        iter_file_matches,
        parse_client_window,
        parse_server_window,
    )
except ImportError:  # Direct execution: python tools/decrypt_handshake.py
    from analyze_pcaps import (
        CLIENT_SIGNATURE,
        SERVER_SIGNATURE,
        iter_file_matches,
        parse_client_window,
        parse_server_window,
    )


def load_private_key(path: Path):
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError as error:
        raise SystemExit("install dependency: python -m pip install cryptography") from error
    data = path.read_bytes()
    loaders = (serialization.load_pem_private_key, serialization.load_der_private_key)
    for loader in loaders:
        try:
            return loader(data, password=None)
        except (TypeError, ValueError):
            pass
    raise SystemExit("private key is neither an unencrypted PEM nor DER RSA key")


def latest_pair(path: Path):
    clients = []
    servers = []
    for offset, window in iter_file_matches(path, CLIENT_SIGNATURE):
        item = parse_client_window(path.name, offset, window)
        if item:
            clients.append(item)
    for offset, window in iter_file_matches(path, SERVER_SIGNATURE):
        item = parse_server_window(path.name, offset, window)
        if item:
            servers.append(item)
    if not clients or not servers:
        raise SystemExit("capture does not contain a validated 10 36 / 11 36 pair")
    client = max(clients, key=lambda item: item.file_offset)
    following = [item for item in servers if item.file_offset > client.file_offset]
    if not following:
        raise SystemExit("latest client handshake has no following server response")
    return client, min(following, key=lambda item: item.file_offset)


def printable_ascii(data: bytes) -> str:
    return "".join(chr(value) if 32 <= value < 127 else "." for value in data)


def candidate_record(mode: str, endian: str, plaintext: bytes) -> dict:
    return {
        "mode": mode,
        "ciphertext_endian": endian,
        "length": len(plaintext),
        "sha256": hashlib.sha256(plaintext).hexdigest(),
        "hex": plaintext.hex(),
        "ascii": printable_ascii(plaintext),
    }


def mgf1(seed: bytes, length: int, digest_name: str) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        digest = hashlib.new(digest_name)
        digest.update(seed)
        digest.update(counter.to_bytes(4, "big"))
        output.extend(digest.digest())
        counter += 1
    return bytes(output[:length])


def decode_oaep(encoded_message: bytes, digest_name: str) -> bytes | None:
    digest_size = hashlib.new(digest_name).digest_size
    if len(encoded_message) < 2 * digest_size + 2 or encoded_message[0] != 0:
        return None
    masked_seed = encoded_message[1 : 1 + digest_size]
    masked_db = encoded_message[1 + digest_size :]
    seed_mask = mgf1(masked_db, digest_size, digest_name)
    seed = bytes(left ^ right for left, right in zip(masked_seed, seed_mask))
    db_mask = mgf1(seed, len(masked_db), digest_name)
    db = bytes(left ^ right for left, right in zip(masked_db, db_mask))
    expected_hash = hashlib.new(digest_name, b"").digest()
    if db[:digest_size] != expected_hash:
        return None
    separator = digest_size
    while separator < len(db) and db[separator] == 0:
        separator += 1
    if separator >= len(db) or db[separator] != 1:
        return None
    return db[separator + 1 :]


def decode_pkcs1_v15(encoded_message: bytes) -> tuple[str, bytes] | None:
    if len(encoded_message) < 11 or encoded_message[0] != 0 or encoded_message[1] not in (1, 2):
        return None
    separator = encoded_message.find(b"\x00", 2)
    if separator < 10:
        return None
    padding = encoded_message[2:separator]
    if encoded_message[1] == 1 and any(value != 0xFF for value in padding):
        return None
    if encoded_message[1] == 2 and any(value == 0 for value in padding):
        return None
    return f"PKCS1-v1.5-type-{encoded_message[1]}", encoded_message[separator + 1 :]


def decrypt_candidates(private_key, ciphertext: bytes, show_raw: bool) -> list[dict]:
    results = []
    numbers = private_key.private_numbers()
    key_bytes = (numbers.public_numbers.n.bit_length() + 7) // 8
    for endian, encoded in (("big", ciphertext), ("little", ciphertext[::-1])):
        value = int.from_bytes(encoded, "big")
        if value >= numbers.public_numbers.n:
            continue
        encoded_message = pow(value, numbers.d, numbers.public_numbers.n).to_bytes(key_bytes, "big")
        pkcs1 = decode_pkcs1_v15(encoded_message)
        if pkcs1:
            results.append(candidate_record(pkcs1[0], endian, pkcs1[1]))
        for name, digest_name in (("OAEP-SHA1", "sha1"), ("OAEP-SHA256", "sha256")):
            plaintext = decode_oaep(encoded_message, digest_name)
            if plaintext is not None:
                results.append(candidate_record(name, endian, plaintext))
        if show_raw:
            results.append(candidate_record("raw-private-operation", endian, encoded_message))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path, help="PEM or DER RSA private key")
    parser.add_argument("--json", dest="json_path", type=Path)
    parser.add_argument("--show-raw", action="store_true", help="include raw 256-byte private operation")
    args = parser.parse_args()

    client, server = latest_pair(args.capture.resolve())
    key = load_private_key(args.private_key.resolve())
    numbers = key.private_numbers().public_numbers
    key_modulus_hash = hashlib.sha256(numbers.n.to_bytes(256, "big")).hexdigest()
    if numbers.n != client.modulus:
        raise SystemExit(
            "private key modulus does not match latest capture handshake "
            f"({key_modulus_hash} != {client.modulus_sha256})"
        )

    report = {
        "schema": "aion2-handshake-decrypt/v1",
        "capture": args.capture.name,
        "revision": client.revision,
        "region": client.region,
        "public_exponent": numbers.e,
        "modulus_sha256": key_modulus_hash,
        "ciphertext_sha256": server.ciphertext_sha256,
        "candidates": decrypt_candidates(key, server.ciphertext, args.show_raw),
    }
    rendered = json.dumps(report, indent=2)
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["candidates"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
