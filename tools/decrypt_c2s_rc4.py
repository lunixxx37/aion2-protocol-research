#!/usr/bin/env python3
"""Decrypt post-handshake Aion 2 C2S frames with the recovered RC4 key."""

from __future__ import annotations

import argparse
import bisect
import collections
import hashlib
import json
from pathlib import Path

try:
    from .aion2_client_crypto import RC4
    from .analyze_pcaps import CLIENT_SIGNATURE, decode_uvarint, find_client_handshake_frame
except ImportError:
    from aion2_client_crypto import RC4
    from analyze_pcaps import CLIENT_SIGNATURE, decode_uvarint, find_client_handshake_frame


def load_secret(path: Path) -> bytes:
    report = json.loads(path.read_text(encoding="utf-8"))
    candidates = [
        candidate
        for candidate in report.get("candidates", [])
        if candidate.get("mode") == "OAEP-SHA1"
        and candidate.get("ciphertext_endian") == "big"
    ]
    if len(candidates) != 1:
        raise SystemExit("handshake report needs exactly one big-endian OAEP-SHA1 candidate")
    secret = bytes.fromhex(candidates[0]["hex"])
    if len(secret) != 214:
        raise SystemExit(f"expected the complete 214-byte OAEP plaintext, got {len(secret)} bytes")
    return secret


def load_raw_secret(path: Path) -> bytes:
    secret = path.read_bytes()
    if len(secret) != 214:
        raise SystemExit(
            f"expected a 214-byte raw session key, got {len(secret)} bytes"
        )
    return secret


def reassemble(segments: list[tuple[int, bytes, float]]) -> list[tuple[int, bytes]]:
    """Reassemble non-wrapping TCP segments and split only at real gaps."""
    chunks: list[tuple[int, bytearray]] = []
    for sequence, payload, _timestamp in sorted(segments, key=lambda item: item[0]):
        if not payload:
            continue
        if not chunks:
            chunks.append((sequence, bytearray(payload)))
            continue
        start, data = chunks[-1]
        end = start + len(data)
        if sequence > end:
            chunks.append((sequence, bytearray(payload)))
            continue
        if sequence + len(payload) <= end:
            continue
        overlap = max(0, end - sequence)
        data.extend(payload[overlap:])
    return [(start, bytes(data)) for start, data in chunks]


def timestamp_for_sequence(
    segments: list[tuple[int, bytes, float]],
    starts: list[int],
    sequence: int,
) -> float | None:
    """Return a capture timestamp for sequence in O(log n) typical time."""
    index = bisect.bisect_right(starts, sequence) - 1
    while index > 0 and starts[index] == starts[index - 1]:
        index -= 1
    for candidate in range(index, min(len(segments), index + 8)):
        start, payload, timestamp = segments[candidate]
        if start > sequence:
            break
        if sequence < start + len(payload):
            return timestamp
    return None


def iter_frames_with_offsets(data: bytes, offset: int):
    while offset < len(data):
        if data[offset] == 0:
            offset += 1
            continue
        decoded = decode_uvarint(data, offset)
        if not decoded:
            return
        encoded_length, width = decoded
        if encoded_length < 6:
            return
        body_length = encoded_length - 4
        total = width + body_length
        if total > 1 << 20 or offset + total > len(data):
            return
        body_start = offset + width
        yield offset, width, data[body_start : body_start + body_length]
        offset += total


def classify_plaintext(body: bytes) -> dict:
    result = {
        "opcode_hex": body[:2].hex() if len(body) >= 2 else body.hex(),
        "compressed_lz4": body.startswith(b"\xff\xff") and len(body) >= 6,
    }
    if len(body) == 10 and body[:2] == b"\x01\x36":
        result["kind"] = "client-time-ping"
        result["unix_ms"] = int.from_bytes(body[2:], "little")
    elif len(body) == 2:
        result["kind"] = "opcode-only"
    else:
        result["kind"] = "packet"
    if result["compressed_lz4"]:
        result["uncompressed_size"] = int.from_bytes(body[2:6], "little")
    return result


def render_sequence_counts(
    counts: collections.Counter[tuple[str, ...]],
    limit: int,
) -> list[dict]:
    """Render opcode-only sequence aggregates in stable frequency order."""
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    if limit:
        ordered = ordered[:limit]
    return [
        {"opcodes": list(opcodes), "frames": frames}
        for opcodes, frames in ordered
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    key_source = parser.add_mutually_exclusive_group(required=True)
    key_source.add_argument("--handshake-json", type=Path)
    key_source.add_argument(
        "--session-key",
        type=Path,
        help="raw 214-byte key exported by locate_session_key.py",
    )
    parser.add_argument("--modulus-sha256", required=True)
    parser.add_argument("--port", type=int, default=13328)
    parser.add_argument("--frame-limit", type=int, default=200)
    parser.add_argument(
        "--samples-per-opcode",
        type=int,
        default=0,
        help="retain up to N plaintext examples for every opcode",
    )
    parser.add_argument(
        "--sample-opcode",
        action="append",
        default=[],
        metavar="HEX",
        help="retain samples only for this two-byte wire opcode; repeat as needed",
    )
    parser.add_argument(
        "--sequence-limit",
        type=int,
        default=250,
        help="retain the N most frequent opcode pairs/triples/quadruples; 0 keeps all",
    )
    parser.add_argument("--json", dest="json_path", type=Path)
    parser.add_argument("--quiet", action="store_true", help="write JSON without printing it")
    args = parser.parse_args()
    sample_filter = {value.replace(" ", "").lower() for value in args.sample_opcode}
    invalid_filters = sorted(
        value
        for value in sample_filter
        if len(value) != 4 or any(character not in "0123456789abcdef" for character in value)
    )
    if invalid_filters:
        raise SystemExit(f"invalid --sample-opcode value: {invalid_filters[0]}")
    if args.sequence_limit < 0:
        raise SystemExit("--sequence-limit must be zero or greater")

    try:
        from scapy.all import IP, IPv6, TCP, PcapReader
    except ImportError as error:
        raise SystemExit("install dependency: python -m pip install scapy") from error

    if args.session_key is not None:
        secret = load_raw_secret(args.session_key.resolve())
        secret_source = "raw 214-byte runtime session key"
    else:
        secret = load_secret(args.handshake_json.resolve())
        secret_source = "complete 214-byte big-endian OAEP-SHA1 plaintext"
    modulus_hash = args.modulus_sha256.lower()
    flows: dict[tuple, list[tuple[int, bytes, float]]] = collections.defaultdict(list)
    seen_segments: set[tuple] = set()
    read_error = None
    try:
        with PcapReader(str(args.capture.resolve())) as reader:
            for packet in reader:
                if TCP not in packet:
                    continue
                tcp = packet[TCP]
                if int(tcp.dport) != args.port:
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
                identity = (
                    source,
                    int(tcp.sport),
                    destination,
                    int(tcp.dport),
                    int(tcp.seq),
                    len(payload),
                    hashlib.blake2s(payload, digest_size=8).digest(),
                )
                if identity in seen_segments:
                    continue
                seen_segments.add(identity)
                key = (source, int(tcp.sport), destination, int(tcp.dport))
                flows[key].append((int(tcp.seq), payload, float(packet.time)))
    except Exception as error:  # Active pcapng files can end in a partial block.
        read_error = str(error)

    selected = []
    for flow_id, segments in flows.items():
        for base_sequence, stream in reassemble(segments):
            handshake = find_client_handshake_frame(stream)
            if not handshake:
                continue
            frame_at, encrypted_at = handshake
            body_at = stream.find(CLIENT_SIGNATURE, frame_at, encrypted_at)
            if body_at < 0 or body_at + 269 > len(stream):
                continue
            modulus = stream[body_at + 13 : body_at + 269]
            actual_hash = hashlib.sha256(modulus).hexdigest()
            if actual_hash != modulus_hash:
                continue

            cipher = RC4(secret)
            timestamp_segments = sorted(segments, key=lambda item: (item[0], item[2]))
            timestamp_starts = [item[0] for item in timestamp_segments]
            frames = []
            opcode_samples: dict[str, list[dict]] = collections.defaultdict(list)
            opcode_counts: collections.Counter[str] = collections.Counter()
            body_length_counts: collections.Counter[int] = collections.Counter()
            immediate_pairs: collections.Counter[tuple[str, ...]] = collections.Counter()
            non_time_sequences = {
                size: collections.Counter() for size in range(2, 5)
            }
            previous_opcode: str | None = None
            recent_non_time_opcodes: collections.deque[str] = collections.deque(
                maxlen=3
            )
            ping_count = 0
            for index, (offset, width, ciphertext) in enumerate(
                iter_frames_with_offsets(stream, encrypted_at)
            ):
                stream_offset = cipher.consumed
                plaintext = cipher.crypt(ciphertext)
                classification = classify_plaintext(plaintext)
                opcode_counts[classification["opcode_hex"]] += 1
                body_length_counts[len(plaintext)] += 1
                ping_count += classification["kind"] == "client-time-ping"
                opcode = classification["opcode_hex"]
                if previous_opcode is not None:
                    immediate_pairs[(previous_opcode, opcode)] += 1
                previous_opcode = opcode
                if classification["kind"] != "client-time-ping":
                    sequence = (*recent_non_time_opcodes, opcode)
                    for size in range(2, min(4, len(sequence)) + 1):
                        non_time_sequences[size][sequence[-size:]] += 1
                    recent_non_time_opcodes.append(opcode)
                absolute_sequence = base_sequence + offset
                capture_epoch = timestamp_for_sequence(
                    timestamp_segments, timestamp_starts, absolute_sequence
                )
                retain_opcode = not sample_filter or opcode in sample_filter
                if retain_opcode and len(opcode_samples[opcode]) < args.samples_per_opcode:
                    opcode_samples[opcode].append(
                        {
                            "index": index,
                            "tcp_sequence": absolute_sequence,
                            "capture_epoch": capture_epoch,
                            "body_length": len(plaintext),
                            "rc4_stream_offset": stream_offset,
                            "plaintext_hex": plaintext.hex(),
                        }
                    )
                if len(frames) < args.frame_limit:
                    frames.append(
                        {
                            "index": index,
                            "tcp_sequence": absolute_sequence,
                            "capture_epoch": capture_epoch,
                            "prefix_width": width,
                            "body_length": len(ciphertext),
                            "rc4_stream_offset": stream_offset,
                            "ciphertext_hex": ciphertext.hex(),
                            "plaintext_hex": plaintext.hex(),
                            **classification,
                        }
                    )
            selected.append(
                {
                    "flow": {
                        "client": f"{flow_id[0]}:{flow_id[1]}",
                        "server": f"{flow_id[2]}:{flow_id[3]}",
                        "base_tcp_sequence": base_sequence,
                    },
                    "modulus_sha256": actual_hash,
                    "rsa_handshake_tcp_sequence": base_sequence + frame_at,
                    "encrypted_stream_tcp_sequence": base_sequence + encrypted_at,
                    "frames_decrypted": sum(opcode_counts.values()),
                    "rc4_body_bytes_consumed": cipher.consumed,
                    "client_time_pings": ping_count,
                    "opcode_counts": dict(opcode_counts.most_common()),
                    "body_length_counts": {
                        str(length): count for length, count in body_length_counts.most_common()
                    },
                    "opcode_sequences": {
                        "immediate_pairs": render_sequence_counts(
                            immediate_pairs, args.sequence_limit
                        ),
                        "without_client_time_pings": {
                            "pairs": render_sequence_counts(
                                non_time_sequences[2], args.sequence_limit
                            ),
                            "triples": render_sequence_counts(
                                non_time_sequences[3], args.sequence_limit
                            ),
                            "quadruples": render_sequence_counts(
                                non_time_sequences[4], args.sequence_limit
                            ),
                        },
                    },
                    "opcode_samples": dict(opcode_samples),
                    "frames": frames,
                }
            )

    report = {
        "schema": "aion2-c2s-rc4-decrypt/v1",
        "capture": args.capture.name,
        "modulus_sha256": modulus_hash,
        "key_source": secret_source,
        "cipher": "RC4; one continuous state; clear outer uvarint; encrypted body only",
        "sample_opcodes": sorted(sample_filter),
        "matching_flows": len(selected),
        "flows": selected,
        "read_error": read_error,
    }
    rendered = json.dumps(report, indent=2)
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(rendered + "\n", encoding="utf-8")
    if not args.quiet:
        print(rendered)
    return 0 if selected else 1


if __name__ == "__main__":
    raise SystemExit(main())
