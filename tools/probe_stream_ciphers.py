#!/usr/bin/env python3
"""Test broad raw-slice AES-CTR, ChaCha20 and RC4 combinations on one known ping."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Candidate:
    label: str
    value: bytes


def load_secret(path: Path) -> bytes:
    report = json.loads(path.read_text(encoding="utf-8"))
    items = [
        item
        for item in report.get("candidates", [])
        if item.get("mode") == "OAEP-SHA1" and item.get("ciphertext_endian") == "big"
    ]
    if len(items) != 1:
        raise SystemExit("handshake report needs exactly one big-endian OAEP-SHA1 candidate")
    return bytes.fromhex(items[0]["hex"])


def load_sample(path: Path, modulus_hash: str) -> dict:
    report = json.loads(path.read_text(encoding="utf-8"))
    for flow in report.get("flows", []):
        if flow.get("modulus_sha256") == modulus_hash and flow.get("samples"):
            return flow["samples"][0]
    raise SystemExit("sample report has no retained sample for the selected modulus")


def sized_candidates(secret: bytes, sizes: tuple[int, ...]) -> list[Candidate]:
    found: dict[bytes, str] = {}

    def add(label: str, value: bytes) -> None:
        if len(value) in sizes and value not in found:
            found[value] = label

    for size in sizes:
        for offset in range(len(secret) - size + 1):
            add(f"oaep.slice[{offset}:{offset + size}]", secret[offset : offset + size])
    for digest_name in ("md5", "sha1", "sha256", "sha384", "sha512"):
        digest = hashlib.new(digest_name, secret).digest()
        add(f"{digest_name}(oaep)", digest)
        for size in sizes:
            if len(digest) >= size:
                add(f"{digest_name}(oaep)[:{size}]", digest[:size])
                add(f"{digest_name}(oaep)[-{size}:]", digest[-size:])
    return [Candidate(label, value) for value, label in found.items()]


def increment_counter(initial: bytes, blocks: int, style: str) -> bytes:
    value = bytearray(initial)
    if style == "full-be":
        return ((int.from_bytes(value, "big") + blocks) & ((1 << 128) - 1)).to_bytes(16, "big")
    if style == "full-le":
        return ((int.from_bytes(value, "little") + blocks) & ((1 << 128) - 1)).to_bytes(16, "little")
    if style == "last8-be":
        tail = (int.from_bytes(value[8:], "big") + blocks) & ((1 << 64) - 1)
        value[8:] = tail.to_bytes(8, "big")
        return bytes(value)
    if style == "last8-le":
        tail = (int.from_bytes(value[8:], "little") + blocks) & ((1 << 64) - 1)
        value[8:] = tail.to_bytes(8, "little")
        return bytes(value)
    raise AssertionError(style)


def aes_ctr_probe(
    expected: bytes,
    keys: list[Candidate],
    ivs: list[Candidate],
    offsets: list[int],
) -> tuple[int, list[dict]]:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as error:
        raise SystemExit("install dependency: python -m pip install cryptography") from error
    styles = ("full-be", "full-le", "last8-be", "last8-le")
    matches = []
    tested = 0
    for key in keys:
        encryptor = Cipher(algorithms.AES(key.value), modes.ECB()).encryptor()
        for iv in ivs:
            for style in styles:
                for offset in offsets:
                    block_index, intra = divmod(offset, 16)
                    needed = (intra + len(expected) + 15) // 16
                    counters = b"".join(
                        increment_counter(iv.value, block_index + index, style)
                        for index in range(needed)
                    )
                    stream = encryptor.update(counters)[intra : intra + len(expected)]
                    tested += 1
                    if stream == expected:
                        matches.append(
                            {
                                "cipher": "AES-CTR",
                                "key": key.label,
                                "iv": iv.label,
                                "counter_style": style,
                                "stream_offset": offset,
                            }
                        )
        encryptor.finalize()
    return tested, matches


def chacha_probe(
    expected: bytes,
    keys: list[Candidate],
    nonces: list[Candidate],
    offsets: list[int],
) -> tuple[int, list[dict]]:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    except ImportError as error:
        raise SystemExit("install dependency: python -m pip install cryptography") from error
    matches = []
    tested = 0
    maximum = max(offsets) + len(expected)
    zeros = b"\x00" * maximum
    for key in keys:
        for nonce in nonces:
            encryptor = Cipher(algorithms.ChaCha20(key.value, nonce.value), mode=None).encryptor()
            stream = encryptor.update(zeros)
            for offset in offsets:
                tested += 1
                if stream[offset : offset + len(expected)] == expected:
                    matches.append(
                        {
                            "cipher": "ChaCha20",
                            "key": key.label,
                            "nonce": nonce.label,
                            "stream_offset": offset,
                        }
                    )
    return tested, matches


def rc4_stream(key: bytes, length: int) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    output = bytearray(length)
    i = j = 0
    for index in range(length):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output[index] = state[(state[i] + state[j]) & 0xFF]
    return bytes(output)


def rc4_probe(expected: bytes, keys: list[Candidate], offsets: list[int]) -> tuple[int, list[dict]]:
    matches = []
    tested = 0
    maximum = max(offsets) + len(expected)
    for key in keys:
        stream = rc4_stream(key.value, maximum)
        for offset in offsets:
            tested += 1
            if stream[offset : offset + len(expected)] == expected:
                matches.append({"cipher": "RC4", "key": key.label, "stream_offset": offset})
    return tested, matches


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handshake-json", required=True, type=Path)
    parser.add_argument("--samples-json", required=True, type=Path)
    parser.add_argument("--modulus-sha256", required=True)
    parser.add_argument("--offsets", default="0,158,160,214,256,768,1024,1536,3072")
    parser.add_argument("--json", dest="json_path", type=Path)
    args = parser.parse_args()

    secret = load_secret(args.handshake_json.resolve())
    sample = load_sample(args.samples_json.resolve(), args.modulus_sha256.lower())
    expected = bytes.fromhex(sample["keystream_hex"])
    offsets = sorted({int(value, 0) for value in args.offsets.split(",")})

    aes_keys = sized_candidates(secret, (16, 24, 32))
    ivs = sized_candidates(secret, (16,))
    chacha_keys = sized_candidates(secret, (32,))
    # Aion 2 feeds the complete 214-byte OAEP plaintext into its RC4 KSA.
    # Keep the shorter legacy hypotheses as regression cases as well.
    rc4_keys = sized_candidates(secret, (16, 20, 24, 32, 48, 64, len(secret)))
    aes_tested, aes_matches = aes_ctr_probe(expected, aes_keys, ivs, offsets)
    chacha_tested, chacha_matches = chacha_probe(expected, chacha_keys, ivs, offsets)
    rc4_tested, rc4_matches = rc4_probe(expected, rc4_keys, offsets)
    matches = aes_matches + chacha_matches + rc4_matches
    report = {
        "schema": "aion2-stream-cipher-probe/v1",
        "modulus_sha256": args.modulus_sha256.lower(),
        "known_keystream_bytes": len(expected),
        "stream_offsets": offsets,
        "candidate_counts": {
            "aes_keys": len(aes_keys),
            "ivs_or_nonces": len(ivs),
            "chacha_keys": len(chacha_keys),
            "rc4_keys": len(rc4_keys),
        },
        "constructions_tested": {
            "aes_ctr": aes_tested,
            "chacha20": chacha_tested,
            "rc4": rc4_tested,
        },
        "exact_matches": len(matches),
        "matches": matches,
    }
    rendered = json.dumps(report, indent=2)
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
