#!/usr/bin/env python3
"""Scan a bounded Windows process address range for exact byte patterns read-only."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path

try:
    from .scan_process_rsa import (
        MEMORY_BASIC_INFORMATION,
        MEM_COMMIT,
        PROCESS_QUERY_INFORMATION,
        PROCESS_VM_READ,
        readable,
    )
except ImportError:
    from scan_process_rsa import (
        MEMORY_BASIC_INFORMATION,
        MEM_COMMIT,
        PROCESS_QUERY_INFORMATION,
        PROCESS_VM_READ,
        readable,
    )


def named_hex(value: str) -> tuple[str, bytes]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("pattern must be NAME=HEX")
    name, encoded = value.split("=", 1)
    try:
        pattern = bytes.fromhex(encoded)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    if not name or not pattern:
        raise argparse.ArgumentTypeError("pattern name and bytes must be non-empty")
    return name, pattern


def scan_range(pid: int, start: int, end: int, patterns: dict[str, bytes], chunk_size: int):
    if os.name != "nt":
        raise SystemExit("this scanner is Windows-only")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
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
        error = ctypes.get_last_error()
        raise SystemExit(f"OpenProcess({pid}) failed with Win32 error {error}; run elevated")

    hits = []
    stats = {"regions_read": 0, "bytes_read": 0, "read_failures": 0}
    overlap = max(len(value) for value in patterns.values()) - 1
    address = start
    try:
        while address < end:
            mbi = MEMORY_BASIC_INFORMATION()
            if not kernel32.VirtualQueryEx(
                handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
            ):
                break
            base = int(mbi.BaseAddress or 0)
            region_end = base + int(mbi.RegionSize)
            if region_end <= address:
                break
            address = region_end
            read_start = max(start, base)
            read_end = min(end, region_end)
            if mbi.State != MEM_COMMIT or not readable(mbi.Protect) or read_start >= read_end:
                continue
            tail = b""
            offset = read_start
            region_read = False
            while offset < read_end:
                request = min(chunk_size, read_end - offset)
                buffer = ctypes.create_string_buffer(request)
                received = ctypes.c_size_t()
                if not kernel32.ReadProcessMemory(
                    handle,
                    ctypes.c_void_p(offset),
                    buffer,
                    request,
                    ctypes.byref(received),
                ) or not received.value:
                    stats["read_failures"] += 1
                    break
                region_read = True
                block = tail + buffer.raw[: received.value]
                block_base = offset - len(tail)
                for name, pattern in patterns.items():
                    cursor = 0
                    while True:
                        index = block.find(pattern, cursor)
                        if index < 0:
                            break
                        hits.append(
                            {
                                "pattern": name,
                                "address": f"0x{block_base + index:016X}",
                                "region_base": f"0x{base:016X}",
                                "region_size": int(mbi.RegionSize),
                                "protection": f"0x{mbi.Protect:X}",
                                "type": f"0x{mbi.Type:X}",
                            }
                        )
                        cursor = index + 1
                stats["bytes_read"] += received.value
                tail = block[-overlap:] if overlap else b""
                offset += received.value
            stats["regions_read"] += region_read
    finally:
        kernel32.CloseHandle(handle)
    return hits, stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--start", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--end", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--hex-pattern", required=True, action="append", type=named_hex)
    parser.add_argument("--chunk-size", type=int, default=8 << 20)
    parser.add_argument("--json", dest="json_path", type=Path)
    args = parser.parse_args()
    if args.end <= args.start:
        raise SystemExit("--end must be greater than --start")
    patterns = dict(args.hex_pattern)
    hits, stats = scan_range(args.pid, args.start, args.end, patterns, args.chunk_size)
    report = {
        "schema": "aion2-process-range-scan/v1",
        "pid": args.pid,
        "range": {"start": f"0x{args.start:X}", "end": f"0x{args.end:X}"},
        "patterns": {name: len(value) for name, value in patterns.items()},
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
