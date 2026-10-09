#!/usr/bin/env python3
"""Correlate 10-byte encrypted C2S bodies with clear S2C 00 36 ticks.

This is a historical timing probe.  Its 03 36/echoed-tick plaintext model was
disproved after the RC4 stream was recovered; use decrypt_c2s_rc4.py for real
plaintext and keystream bytes.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import statistics
from pathlib import Path

try:
    from .analyze_pcaps import CLIENT_SIGNATURE, iter_frames
except ImportError:
    from analyze_pcaps import CLIENT_SIGNATURE, iter_frames


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * fraction)))
    return ordered[index]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--port", type=int, default=13328)
    parser.add_argument("--max-delay-ms", type=float, default=100.0)
    parser.add_argument("--modulus-sha256", help="only retain samples from this client RSA modulus")
    parser.add_argument("--sample-limit", type=int, default=0, help="retain up to N local ciphertext/plaintext samples")
    parser.add_argument(
        "--allow-midstream",
        action="store_true",
        help="analyze a short capture that starts after the handshake",
    )
    parser.add_argument("--json", dest="json_path", type=Path)
    parser.add_argument("--quiet", action="store_true", help="write JSON without printing the full report")
    args = parser.parse_args()

    try:
        from scapy.all import IP, IPv6, TCP, PcapReader
    except ImportError as error:
        raise SystemExit("install dependency: python -m pip install scapy") from error

    # Flow key is client endpoint + server endpoint. Each value stores whether
    # the clear client handshake was seen and the latest clear server tick.
    state: dict[tuple, dict] = collections.defaultdict(
        lambda: {
            "handshake": args.allow_midstream,
            "modulus_sha256": args.modulus_sha256.lower() if args.allow_midstream and args.modulus_sha256 else None,
            "last_tick": None,
            "c2s_10": 0,
            "matches": [],
            "seen_c2s_frame_sequences": set(),
            "seen_s2c_tick_sequences": set(),
            "samples": [],
        }
    )
    seen_segments: set[tuple] = set()
    read_error = None
    try:
        with PcapReader(str(args.capture.resolve())) as reader:
            for packet in reader:
                if TCP not in packet:
                    continue
                tcp = packet[TCP]
                payload = bytes(tcp.payload)
                if not payload or (int(tcp.sport) != args.port and int(tcp.dport) != args.port):
                    continue
                if IP in packet:
                    source, destination = packet[IP].src, packet[IP].dst
                elif IPv6 in packet:
                    source, destination = packet[IPv6].src, packet[IPv6].dst
                else:
                    continue
                timestamp = float(packet.time)
                segment_id = (
                    source,
                    int(tcp.sport),
                    destination,
                    int(tcp.dport),
                    int(tcp.seq),
                    len(payload),
                    hashlib.blake2s(payload, digest_size=8).digest(),
                )
                if segment_id in seen_segments:
                    continue
                seen_segments.add(segment_id)
                if int(tcp.dport) == args.port:
                    key = (source, int(tcp.sport), destination, int(tcp.dport))
                    flow = state[key]
                    if CLIENT_SIGNATURE in payload:
                        flow["handshake"] = True
                        body_at = payload.find(CLIENT_SIGNATURE)
                        if body_at >= 0 and body_at + 269 <= len(payload):
                            modulus = payload[body_at + 13 : body_at + 269]
                            flow["modulus_sha256"] = hashlib.sha256(modulus).hexdigest()
                        continue
                    if not flow["handshake"]:
                        continue
                    consumed = 0
                    parsed = []
                    for total, body in iter_frames(payload, 0):
                        parsed.append((total, body))
                        consumed += total
                    if consumed != len(payload):
                        continue
                    frame_offset = 0
                    for total, body in parsed:
                        frame_sequence = int(tcp.seq) + frame_offset
                        frame_offset += total
                        if frame_sequence in flow["seen_c2s_frame_sequences"]:
                            continue
                        flow["seen_c2s_frame_sequences"].add(frame_sequence)
                        if total != 11 or len(body) != 10:
                            continue
                        flow["c2s_10"] += 1
                        tick = flow["last_tick"]
                        if not tick:
                            continue
                        delay_ms = (timestamp - tick[0]) * 1000.0
                        if not 0.0 <= delay_ms <= args.max_delay_ms:
                            continue
                        plain = bytes.fromhex("0336") + tick[1].to_bytes(8, "little")
                        keystream = bytes(left ^ right for left, right in zip(body, plain))
                        flow["matches"].append(
                            {
                                "delay_ms": delay_ms,
                                "tick": tick[1],
                                "keystream_sha256": hashlib.sha256(keystream).hexdigest(),
                            }
                        )
                        modulus_selected = (
                            not args.modulus_sha256
                            or flow["modulus_sha256"] == args.modulus_sha256.lower()
                        )
                        if modulus_selected and len(flow["samples"]) < args.sample_limit:
                            flow["samples"].append(
                                {
                                    "tcp_sequence": frame_sequence,
                                    "delay_ms": round(delay_ms, 3),
                                    "tick": tick[1],
                                    "ciphertext_hex": body.hex(),
                                    "plaintext_hex": plain.hex(),
                                    "keystream_hex": keystream.hex(),
                                }
                            )
                else:
                    key = (destination, int(tcp.dport), source, int(tcp.sport))
                    flow = state[key]
                    # Tick frame is exactly: 0E | 00 36 | unix_ms:u64le.
                    start = 0
                    while True:
                        index = payload.find(b"\x0e\x00\x36", start)
                        if index < 0:
                            break
                        if index + 11 <= len(payload):
                            tick_sequence = int(tcp.seq) + index
                            if tick_sequence in flow["seen_s2c_tick_sequences"]:
                                start = index + 1
                                continue
                            flow["seen_s2c_tick_sequences"].add(tick_sequence)
                            tick_value = int.from_bytes(payload[index + 3 : index + 11], "little")
                            if 1_500_000_000_000 <= tick_value <= 2_500_000_000_000:
                                flow["last_tick"] = (timestamp, tick_value)
                        start = index + 1
    except Exception as error:
        read_error = str(error)

    per_flow = []
    all_delays = []
    all_hashes = []
    for flow_id, flow in state.items():
        if not flow["handshake"]:
            continue
        delays = [item["delay_ms"] for item in flow["matches"]]
        hashes = [item["keystream_sha256"] for item in flow["matches"]]
        all_delays.extend(delays)
        all_hashes.extend(hashes)
        per_flow.append(
            {
                "flow_sha256": hashlib.sha256(repr(flow_id).encode()).hexdigest(),
                "modulus_sha256": flow["modulus_sha256"],
                "c2s_10_byte_bodies": flow["c2s_10"],
                "matched_preceding_ticks": len(delays),
                "median_delay_ms": round(statistics.median(delays), 3) if delays else None,
                "p95_delay_ms": round(percentile(delays, 0.95), 3) if delays else None,
                "unique_candidate_keystreams": len(set(hashes)),
                "samples": flow["samples"],
            }
        )

    report = {
        "schema": "aion2-tick-plaintext-probe/v1",
        "capture": args.capture.name,
        "status": "legacy timing correlation; plaintext hypothesis disproved",
        "warning": (
            "plaintext_hex and keystream_hex samples are hypothetical only; "
            "confirmed plaintext is 01 36 || current client unix_ms, not an echoed server tick"
        ),
        "plaintext_hypothesis": "03 36 || preceding S2C 00 36 unix_ms:u64le",
        "max_delay_ms": args.max_delay_ms,
        "sample_limit_per_flow": args.sample_limit,
        "sample_modulus_sha256": args.modulus_sha256,
        "flows": per_flow,
        "total_c2s_10_byte_bodies": sum(item["c2s_10_byte_bodies"] for item in per_flow),
        "matched_preceding_ticks": len(all_delays),
        "median_delay_ms": round(statistics.median(all_delays), 3) if all_delays else None,
        "p95_delay_ms": round(percentile(all_delays, 0.95), 3) if all_delays else None,
        "unique_candidate_keystreams": len(set(all_hashes)),
        "read_error": read_error,
    }
    rendered = json.dumps(report, indent=2)
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(rendered + "\n", encoding="utf-8")
    if not args.quiet:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
