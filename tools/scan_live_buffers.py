#!/usr/bin/env python3
"""Find recent Aion 2 ping plaintext/ciphertext bytes in process memory read-only."""

from __future__ import annotations

import argparse
import collections
import ctypes
import hashlib
import json
import os
from ctypes import wintypes
from pathlib import Path

try:
    from .analyze_pcaps import iter_frames
    from .scan_process_rsa import PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, scan
except ImportError:
    from analyze_pcaps import iter_frames
    from scan_process_rsa import PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, scan


def capture_pairs(path: Path, port: int, max_delay_ms: float) -> list[dict]:
    try:
        from scapy.all import IP, IPv6, TCP, PcapReader
    except ImportError as error:
        raise SystemExit("install dependency: python -m pip install scapy") from error

    states: dict[tuple, dict] = collections.defaultdict(lambda: {"tick": None, "pairs": []})
    with PcapReader(str(path.resolve())) as reader:
        for packet in reader:
            if TCP not in packet:
                continue
            tcp = packet[TCP]
            payload = bytes(tcp.payload)
            if not payload or (int(tcp.sport) != port and int(tcp.dport) != port):
                continue
            if IP in packet:
                source, destination = packet[IP].src, packet[IP].dst
            elif IPv6 in packet:
                source, destination = packet[IPv6].src, packet[IPv6].dst
            else:
                continue
            timestamp = float(packet.time)
            if int(tcp.sport) == port:
                key = (destination, int(tcp.dport), source, int(tcp.sport))
                start = 0
                while True:
                    index = payload.find(b"\x0e\x00\x36", start)
                    if index < 0:
                        break
                    if index + 11 <= len(payload):
                        tick = int.from_bytes(payload[index + 3 : index + 11], "little")
                        if 1_500_000_000_000 <= tick <= 2_500_000_000_000:
                            states[key]["tick"] = (timestamp, tick)
                    start = index + 1
                continue

            key = (source, int(tcp.sport), destination, int(tcp.dport))
            state = states[key]
            parsed = list(iter_frames(payload, 0))
            if sum(total for total, _ in parsed) != len(payload):
                continue
            for total, body in parsed:
                if total != 11 or len(body) != 10 or not state["tick"]:
                    continue
                tick_time, tick = state["tick"]
                delay_ms = (timestamp - tick_time) * 1000.0
                if not 0 <= delay_ms <= max_delay_ms:
                    continue
                plaintext = b"\x03\x36" + tick.to_bytes(8, "little")
                state["pairs"].append(
                    {
                        "delay_ms": round(delay_ms, 3),
                        "ciphertext": body,
                        "plaintext": plaintext,
                    }
                )
    return max((state["pairs"] for state in states.values()), key=len, default=[])


def read_contexts(pid: int, hits: list[dict], before: int, after: int) -> None:
    if os.name != "nt" or not hits:
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return
    try:
        for hit in hits:
            address = int(hit["address"], 16)
            start = max(0, address - before)
            size = before + after
            buffer = ctypes.create_string_buffer(size)
            received = ctypes.c_size_t()
            if kernel32.ReadProcessMemory(
                handle,
                ctypes.c_void_p(start),
                buffer,
                size,
                ctypes.byref(received),
            ):
                data = buffer.raw[: received.value]
                hit["context_address"] = f"0x{start:016X}"
                hit["match_offset_in_context"] = address - start
                hit["context_hex"] = data.hex()
    finally:
        kernel32.CloseHandle(handle)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--port", type=int, default=13328)
    parser.add_argument("--pairs", type=int, default=16)
    parser.add_argument("--max-delay-ms", type=float, default=100.0)
    parser.add_argument("--context-before", type=int, default=48)
    parser.add_argument("--context-after", type=int, default=80)
    parser.add_argument("--json", dest="json_path", type=Path)
    args = parser.parse_args()

    pairs = capture_pairs(args.capture, args.port, args.max_delay_ms)
    selected = pairs[-args.pairs :]
    if not selected:
        raise SystemExit("capture contains no correlated C2S ping pairs")
    patterns = {}
    metadata = {}
    for index, pair in enumerate(selected):
        for kind in ("ciphertext", "plaintext"):
            value = pair[kind]
            name = f"pair-{index:02d}-{kind}"
            patterns[name] = value
            metadata[name] = {
                "kind": kind,
                "length": len(value),
                "sha256": hashlib.sha256(value).hexdigest(),
                "delay_ms": pair["delay_ms"],
            }

    hits, stats = scan(args.pid, patterns, 4 << 20, 512 << 20)
    read_contexts(args.pid, hits, args.context_before, args.context_after)
    for hit in hits:
        hit.update(metadata[hit["pattern"]])
    report = {
        "schema": "aion2-live-buffer-scan/v1",
        "pid": args.pid,
        "capture": args.capture.name,
        "correlated_pairs_in_capture": len(pairs),
        "recent_pairs_scanned": len(selected),
        "stats": stats,
        "hits": hits,
    }
    rendered = json.dumps(report, indent=2)
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
