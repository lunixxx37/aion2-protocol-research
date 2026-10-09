#!/usr/bin/env python3
"""Probe common per-packet PRF constructions against known Aion 2 pings."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class KeyCandidate:
    label: str
    value: bytes


def load_secret(path: Path) -> bytes:
    report = json.loads(path.read_text(encoding="utf-8"))
    candidates = [
        item
        for item in report.get("candidates", [])
        if item.get("mode") == "OAEP-SHA1" and item.get("ciphertext_endian") == "big"
    ]
    if len(candidates) != 1:
        raise SystemExit("handshake report needs exactly one big-endian OAEP-SHA1 candidate")
    return bytes.fromhex(candidates[0]["hex"])


def load_samples(path: Path, modulus_hash: str) -> list[dict]:
    report = json.loads(path.read_text(encoding="utf-8"))
    for flow in report.get("flows", []):
        if flow.get("modulus_sha256") == modulus_hash:
            samples = flow.get("samples", [])
            if samples:
                return samples
    raise SystemExit("sample report has no retained samples for the selected modulus")


def key_candidates(secret: bytes) -> list[KeyCandidate]:
    found: dict[bytes, str] = {}

    def add(label: str, value: bytes) -> None:
        if value and value not in found:
            found[value] = label

    add("oaep.full", secret)
    for size in (16, 20, 24, 32, 48, 64):
        if size > len(secret):
            continue
        for offset in range(len(secret) - size + 1):
            add(f"oaep.slice[{offset}:{offset + size}]", secret[offset : offset + size])
    for digest_name in ("md5", "sha1", "sha256", "sha384", "sha512"):
        add(f"{digest_name}(oaep)", hashlib.new(digest_name, secret).digest())
    return [KeyCandidate(label, value) for value, label in found.items()]


def message_candidates(sample: dict, index: int, first_sequence: int) -> list[tuple[str, bytes]]:
    tick = int(sample["tick"])
    sequence = int(sample["tcp_sequence"])
    relative = sequence - first_sequence
    plain = bytes.fromhex(sample["plaintext_hex"])
    values = {
        "tick.le8": tick.to_bytes(8, "little"),
        "tick.be8": tick.to_bytes(8, "big"),
        "plain": plain,
        "tcp-seq.le4": (sequence & 0xFFFFFFFF).to_bytes(4, "little"),
        "tcp-seq.be4": (sequence & 0xFFFFFFFF).to_bytes(4, "big"),
        "tcp-seq.le8": sequence.to_bytes(8, "little"),
        "tcp-seq.be8": sequence.to_bytes(8, "big"),
        "relative.le4": (relative & 0xFFFFFFFF).to_bytes(4, "little"),
        "relative.be4": (relative & 0xFFFFFFFF).to_bytes(4, "big"),
        "sample-index.le4": index.to_bytes(4, "little"),
        "sample-index.be4": index.to_bytes(4, "big"),
        "sample-index1.le4": (index + 1).to_bytes(4, "little"),
        "sample-index1.be4": (index + 1).to_bytes(4, "big"),
    }
    combinations = {
        "tick.le8||relative.le4": values["tick.le8"] + values["relative.le4"],
        "relative.le4||tick.le8": values["relative.le4"] + values["tick.le8"],
        "tick.le8||tcp-seq.le4": values["tick.le8"] + values["tcp-seq.le4"],
        "tcp-seq.le4||tick.le8": values["tcp-seq.le4"] + values["tick.le8"],
        "tick.le8||sample-index.le4": values["tick.le8"] + values["sample-index.le4"],
        "sample-index.le4||tick.le8": values["sample-index.le4"] + values["tick.le8"],
    }
    values.update(combinations)
    return list(values.items())


def hash_outputs(key: bytes, message: bytes):
    for digest_name in ("md5", "sha1", "sha256", "sha384", "sha512"):
        digest = hmac.new(key, message, digest_name).digest()
        yield f"HMAC-{digest_name}", digest
        digest = hashlib.new(digest_name, key + message).digest()
        yield f"{digest_name}(key||message)", digest
        digest = hashlib.new(digest_name, message + key).digest()
        yield f"{digest_name}(message||key)", digest
    if len(key) <= 32:
        yield "BLAKE2s-keyed", hashlib.blake2s(message, key=key).digest()
    if len(key) <= 64:
        yield "BLAKE2b-keyed", hashlib.blake2b(message, key=key).digest()


def aes_blocks(key: bytes, message: bytes):
    if len(key) not in (16, 24, 32):
        return
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as error:
        raise SystemExit("install dependency: python -m pip install cryptography") from error
    blocks = {
        "message-left-zero-pad": message[:16].ljust(16, b"\x00"),
        "message-right-zero-pad": message[-16:].rjust(16, b"\x00"),
    }
    for block_label, block in blocks.items():
        encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        yield f"AES-ECB({block_label})", encryptor.update(block) + encryptor.finalize()


def verify_match(
    samples: list[dict],
    key: bytes,
    message_label: str,
    construction: str,
    side: str,
    limit: int,
) -> int:
    first_sequence = int(samples[0]["tcp_sequence"])
    hits = 0
    for index, sample in enumerate(samples[:limit]):
        messages = dict(message_candidates(sample, index, first_sequence))
        message = messages[message_label]
        outputs = dict(hash_outputs(key, message))
        outputs.update(dict(aes_blocks(key, message) or []))
        output = outputs[construction]
        expected = bytes.fromhex(sample["keystream_hex"])
        actual = output[:10] if side == "prefix" else output[-10:]
        if actual != expected:
            break
        hits += 1
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handshake-json", required=True, type=Path)
    parser.add_argument("--samples-json", required=True, type=Path)
    parser.add_argument("--modulus-sha256", required=True)
    parser.add_argument("--verify-samples", type=int, default=32)
    parser.add_argument("--json", dest="json_path", type=Path)
    args = parser.parse_args()

    secret = load_secret(args.handshake_json.resolve())
    samples = load_samples(args.samples_json.resolve(), args.modulus_sha256.lower())
    keys = key_candidates(secret)
    first = samples[0]
    expected = bytes.fromhex(first["keystream_hex"])
    messages = message_candidates(first, 0, int(first["tcp_sequence"]))
    matches = []
    constructions_tested = 0
    for candidate in keys:
        for message_label, message in messages:
            outputs = list(hash_outputs(candidate.value, message))
            outputs.extend(list(aes_blocks(candidate.value, message) or []))
            for construction, output in outputs:
                constructions_tested += 2
                for side, actual in (("prefix", output[:10]), ("suffix", output[-10:])):
                    if actual != expected:
                        continue
                    hits = verify_match(
                        samples,
                        candidate.value,
                        message_label,
                        construction,
                        side,
                        args.verify_samples,
                    )
                    matches.append(
                        {
                            "key_candidate": candidate.label,
                            "message": message_label,
                            "construction": construction,
                            "output_side": side,
                            "consecutive_hits": hits,
                        }
                    )
    matches.sort(key=lambda item: item["consecutive_hits"], reverse=True)
    report = {
        "schema": "aion2-keystream-prf-probe/v1",
        "modulus_sha256": args.modulus_sha256.lower(),
        "known_plaintext_samples": len(samples),
        "key_candidates": len(keys),
        "message_candidates": len(messages),
        "first_sample_constructions_tested": constructions_tested,
        "exact_first_sample_matches": len(matches),
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
