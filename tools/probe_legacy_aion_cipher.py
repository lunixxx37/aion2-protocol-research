#!/usr/bin/env python3
"""Test the legacy Aion packet cipher against an Aion 2 C2S capture.

This is an offline probe.  It selects the TCP flow whose client RSA modulus
matches a decrypted handshake report, then tests candidate 8-byte packet keys
derived from the 214-byte OAEP message.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

try:
    from .analyze_pcaps import (
        CLIENT_SIGNATURE,
        find_client_handshake_frame,
        iter_frames,
        reassemble_prefix,
    )
except ImportError:
    from analyze_pcaps import (
        CLIENT_SIGNATURE,
        find_client_handshake_frame,
        iter_frames,
        reassemble_prefix,
    )


STATIC_KEY = b"nKO/WctQ0AVLbpzfBkS6NevDYT8ourG5CRlmdjyJ72aswx4EPq1UgZhFMXH?3iI9"
LEGACY_KEY_TAIL = bytes.fromhex("a16c5487")
MASK64 = (1 << 64) - 1


@dataclass(frozen=True)
class Candidate:
    label: str
    key: bytes


def load_handshake_report(path: Path) -> tuple[str, bytes]:
    report = json.loads(path.read_text(encoding="utf-8"))
    modulus_hash = report["modulus_sha256"]
    candidates = [
        item
        for item in report.get("candidates", [])
        if item.get("mode") == "OAEP-SHA1" and item.get("ciphertext_endian") == "big"
    ]
    if len(candidates) != 1:
        raise SystemExit("handshake report needs exactly one big-endian OAEP-SHA1 candidate")
    secret = bytes.fromhex(candidates[0]["hex"])
    if len(secret) != 214:
        raise SystemExit(f"expected a 214-byte OAEP message, got {len(secret)}")
    return modulus_hash, secret


def collect_c2s_streams(path: Path, port: int, stream_limit: int) -> tuple[list[bytes], str | None]:
    try:
        from scapy.all import IP, IPv6, TCP, PcapReader
    except ImportError as error:
        raise SystemExit("install dependency: python -m pip install scapy") from error

    flows: dict[tuple, list[tuple[int, bytes]]] = collections.defaultdict(list)
    stored: collections.Counter[tuple] = collections.Counter()
    read_error = None
    try:
        with PcapReader(str(path.resolve())) as reader:
            for packet in reader:
                if TCP not in packet:
                    continue
                tcp = packet[TCP]
                if int(tcp.dport) != port:
                    continue
                payload = bytes(tcp.payload)
                if not payload:
                    continue
                if IP in packet:
                    source, destination = packet[IP].src, packet[IP].dst
                elif IPv6 in packet:
                    source, destination = packet[IPv6].src, packet[IPv6].dst
                else:
                    continue
                key = (source, int(tcp.sport), destination, int(tcp.dport))
                if stored[key] >= stream_limit:
                    continue
                room = stream_limit - stored[key]
                flows[key].append((int(tcp.seq), payload[:room]))
                stored[key] += min(len(payload), room)
    except Exception as error:  # Active captures can end with a partial pcapng block.
        read_error = str(error)

    streams = []
    for segments in flows.values():
        streams.extend(reassemble_prefix(segments, stream_limit))
    return streams, read_error


def stream_modulus_hash(stream: bytes, handshake: tuple[int, int]) -> str | None:
    frame_at, _ = handshake
    body_at = stream.find(CLIENT_SIGNATURE, frame_at)
    if body_at < 0 or body_at + 269 > len(stream):
        return None
    modulus = stream[body_at + 13 : body_at + 269]
    return hashlib.sha256(modulus).hexdigest()


def matching_frames(streams: list[bytes], modulus_hash: str) -> tuple[list[tuple[int, bytes]], int]:
    matches = []
    matched_streams = 0
    for stream in streams:
        handshake = find_client_handshake_frame(stream)
        if not handshake or stream_modulus_hash(stream, handshake) != modulus_hash:
            continue
        matched_streams += 1
        matches.extend(iter_frames(stream, handshake[1]))
    if not matches:
        raise SystemExit("no post-handshake C2S frames match the report's RSA modulus")
    return matches, matched_streams


def candidate_keys(secret: bytes) -> list[Candidate]:
    found: dict[bytes, str] = {}

    def add(label: str, key: bytes) -> None:
        if len(key) == 8 and key not in found:
            found[key] = label

    for offset in range(len(secret) - 7):
        add(f"oaep.raw8[{offset}]", secret[offset : offset + 8])
    for offset in range(len(secret) - 3):
        word = secret[offset : offset + 4]
        add(f"oaep.u32le+legacy-tail[{offset}]", word + LEGACY_KEY_TAIL)
        for endian in ("little", "big"):
            encoded = int.from_bytes(word, endian)
            base = ((encoded - 0x3FF2CCCF) & 0xFFFFFFFF) ^ 0xCD92E4DF
            add(
                f"oaep.deobfuscated-{endian}[{offset}]",
                base.to_bytes(4, "little") + LEGACY_KEY_TAIL,
            )
    return [Candidate(label, key) for key, label in found.items()]


def decrypt_frame(ciphertext: bytes, key_value: int) -> bytes:
    if not ciphertext:
        return b""
    key = key_value.to_bytes(8, "little")
    plaintext = bytearray(len(ciphertext))
    previous = ciphertext[0]
    plaintext[0] = ciphertext[0] ^ key[0]
    for index in range(1, len(ciphertext)):
        current = ciphertext[index]
        plaintext[index] = current ^ STATIC_KEY[index & 63] ^ key[index & 7] ^ previous
        previous = current
    return bytes(plaintext)


def update_amount(model: str, total: int, body: bytes) -> int:
    if model == "body":
        return len(body)
    if model == "physical":
        return total
    if model == "encoded":
        return len(body) + 4
    if model == "body+2":
        return len(body) + 2
    raise AssertionError(model)


def score_candidate(
    candidate: Candidate,
    model: str,
    frames: list[tuple[int, bytes]],
    max_frames: int,
) -> dict:
    initial = int.from_bytes(candidate.key, "little")
    cumulative = 0
    ten_byte_frames = 0
    header_hits = 0
    timestamp_hits = 0
    first_plaintext = None
    for index, (total, body) in enumerate(frames):
        if index >= max_frames:
            break
        if len(body) == 10:
            ten_byte_frames += 1
            current_key = (initial + cumulative) & MASK64
            key0 = current_key & 0xFF
            key1 = (current_key >> 8) & 0xFF
            plain0 = body[0] ^ key0
            plain1 = body[1] ^ STATIC_KEY[1] ^ key1 ^ body[0]
            if plain0 == 0x03 and plain1 == 0x36:
                header_hits += 1
                plaintext = decrypt_frame(body, current_key)
                timestamp = int.from_bytes(plaintext[2:], "little")
                if 1_500_000_000_000 <= timestamp <= 2_500_000_000_000:
                    timestamp_hits += 1
                    if first_plaintext is None:
                        first_plaintext = plaintext.hex()
        cumulative = (cumulative + update_amount(model, total, body)) & MASK64
    return {
        "candidate": candidate.label,
        "initial_key_hex": candidate.key.hex(),
        "update_model": model,
        "frames_tested": min(len(frames), max_frames),
        "ten_byte_frames": ten_byte_frames,
        "opcode_header_hits": header_hits,
        "timestamp_hits": timestamp_hits,
        "first_tick_plaintext_hex": first_plaintext,
    }


def static_key_tail_probe(frames: list[tuple[int, bytes]], max_frames: int) -> dict:
    """Test bytes 8/9 using only the assumed 03 36 header and key periodicity.

    For a 10-byte body, bytes 8 and 9 reuse packet-key bytes 0 and 1.  Those
    two key bytes are recoverable from the assumed plaintext opcode, so this
    check is independent of the initial key and its per-packet update.
    """
    tested = 0
    high_timestamp_hits = 0
    inferred_pairs: collections.Counter[str] = collections.Counter()
    for index, (_, body) in enumerate(frames):
        if index >= max_frames:
            break
        if len(body) != 10:
            continue
        tested += 1
        key0 = body[0] ^ 0x03
        key1 = body[1] ^ STATIC_KEY[1] ^ body[0] ^ 0x36
        plain8 = body[8] ^ STATIC_KEY[8] ^ body[7] ^ key0
        plain9 = body[9] ^ STATIC_KEY[9] ^ body[8] ^ key1
        pair = bytes((plain8, plain9))
        inferred_pairs[pair.hex()] += 1
        high_timestamp_hits += pair == b"\x01\x00"
    return {
        "ten_byte_frames_tested": tested,
        "expected_unix_ms_high_bytes": "0100",
        "expected_high_byte_hits": high_timestamp_hits,
        "top_inferred_high_byte_pairs": [
            {"hex": pair, "count": count} for pair, count in inferred_pairs.most_common(10)
        ],
    }


def additive_state_probe(frames: list[tuple[int, bytes]], max_frames: int) -> list[dict]:
    """Test key += packet_size using only plaintext byte zero (03).

    In the legacy transform, cipher[0] = plain[0] XOR key[0].  Therefore each
    ping directly reveals the low state byte.  Subtracting the cumulative
    packet-size advancement must produce one invariant initial byte even if
    the 64-byte static XOR table was changed in a newer protocol.
    """
    reports = []
    for model in ("body", "physical", "encoded", "body+2"):
        cumulative = 0
        inferred: collections.Counter[int] = collections.Counter()
        tested = 0
        for index, (total, body) in enumerate(frames):
            if index >= max_frames:
                break
            if len(body) == 10:
                current_low = body[0] ^ 0x03
                inferred[(current_low - cumulative) & 0xFF] += 1
                tested += 1
            cumulative = (cumulative + update_amount(model, total, body)) & MASK64
        top = inferred.most_common(5)
        reports.append(
            {
                "update_model": model,
                "ten_byte_frames_tested": tested,
                "top_inferred_initial_low_bytes": [
                    {"hex": f"{value:02x}", "count": count} for value, count in top
                ],
                "top_fraction": round(top[0][1] / tested, 6) if tested and top else None,
            }
        )
    return reports


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--handshake-json", required=True, type=Path)
    parser.add_argument("--port", type=int, default=13328)
    parser.add_argument("--stream-limit", type=int, default=512 << 20)
    parser.add_argument("--max-frames", type=int, default=2_000)
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--json", dest="json_path", type=Path)
    args = parser.parse_args()

    modulus_hash, secret = load_handshake_report(args.handshake_json.resolve())
    streams, read_error = collect_c2s_streams(args.capture, args.port, args.stream_limit)
    frames, matched_streams = matching_frames(streams, modulus_hash)
    candidates = candidate_keys(secret)
    scored = []
    for candidate in candidates:
        for model in ("body", "physical", "encoded", "body+2"):
            scored.append(score_candidate(candidate, model, frames, args.max_frames))
    scored.sort(
        key=lambda item: (item["timestamp_hits"], item["opcode_header_hits"]),
        reverse=True,
    )

    report = {
        "schema": "aion2-legacy-cipher-probe/v1",
        "capture": args.capture.name,
        "modulus_sha256": modulus_hash,
        "matched_streams": matched_streams,
        "post_handshake_frames": len(frames),
        "candidate_keys": len(candidates),
        "update_models": ["body", "physical", "encoded", "body+2"],
        "legacy_static_key_sha256": hashlib.sha256(STATIC_KEY).hexdigest(),
        "static_key_tail_probe": static_key_tail_probe(frames, args.max_frames),
        "additive_state_probe": additive_state_probe(frames, args.max_frames),
        "top_candidates": scored[: args.top],
        "read_error": read_error,
    }
    rendered = json.dumps(report, indent=2)
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
