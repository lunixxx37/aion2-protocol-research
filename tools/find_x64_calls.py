#!/usr/bin/env python3
"""Find direct and RIP-indirect x64 calls to selected process addresses.

This is a read-only Windows process-memory scanner.  It recognizes `E8 rel32`
and `FF 15 disp32` call sites in committed executable regions.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path

from locate_openssl_rsa import (
    MEMORY_BASIC_INFORMATION,
    MEM_COMMIT,
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
    is_executable,
)


def parse_address(value: str) -> int:
    return int(value, 0)


def read_qword(kernel32, handle, address: int) -> int | None:
    buffer = ctypes.create_string_buffer(8)
    received = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buffer,
        8,
        ctypes.byref(received),
    ) or received.value != 8:
        return None
    return int.from_bytes(buffer.raw, "little")


def scan(
    pid: int,
    targets: set[int],
    chunk_size: int,
    max_region: int,
    start: int = 0,
    end: int = 1 << 47,
) -> tuple[list[dict], dict]:
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
        raise SystemExit(f"OpenProcess({pid}) failed with Win32 error {error}; run this shell elevated")

    hits: list[dict] = []
    stats = {
        "regions_considered": 0,
        "regions_read": 0,
        "bytes_read": 0,
        "read_failures": 0,
    }
    address = start
    overlap = 16
    try:
        while address < end:
            mbi = MEMORY_BASIC_INFORMATION()
            queried = kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if not queried or not mbi.RegionSize:
                break
            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize)
            next_address = base + size
            if next_address <= address:
                break
            address = next_address
            if (
                mbi.State != MEM_COMMIT
                or not is_executable(mbi.Protect)
                or size > max_region
            ):
                continue

            read_start = max(base, start)
            read_end = min(next_address, end)
            read_size = read_end - read_start
            if read_size <= 0:
                continue

            stats["regions_considered"] += 1
            offset = 0
            tail = b""
            region_read = False
            seen: set[tuple[str, int]] = set()
            while offset < read_size:
                request = min(chunk_size, read_size - offset)
                buffer = ctypes.create_string_buffer(request)
                received = ctypes.c_size_t()
                ok = kernel32.ReadProcessMemory(
                    handle,
                    ctypes.c_void_p(read_start + offset),
                    buffer,
                    request,
                    ctypes.byref(received),
                )
                if not ok or received.value == 0:
                    stats["read_failures"] += 1
                    break
                region_read = True
                block = tail + buffer.raw[: received.value]
                block_base = read_start + offset - len(tail)

                cursor = 0
                while True:
                    index = block.find(b"\xE8", cursor)
                    if index < 0:
                        break
                    cursor = index + 1
                    if index + 5 > len(block):
                        continue
                    displacement = int.from_bytes(block[index + 1 : index + 5], "little", signed=True)
                    callsite = block_base + index
                    target = callsite + 5 + displacement
                    identity = ("direct_rel32", callsite)
                    if target in targets and identity not in seen:
                        seen.add(identity)
                        hits.append(
                            {
                                "kind": "direct_rel32",
                                "callsite": f"0x{callsite:016X}",
                                "target": f"0x{target:016X}",
                                "region_base": f"0x{base:016X}",
                            }
                        )

                cursor = 0
                while True:
                    index = block.find(b"\xFF\x15", cursor)
                    if index < 0:
                        break
                    cursor = index + 1
                    if index + 6 > len(block):
                        continue
                    displacement = int.from_bytes(block[index + 2 : index + 6], "little", signed=True)
                    callsite = block_base + index
                    pointer_slot = callsite + 6 + displacement
                    target = read_qword(kernel32, handle, pointer_slot)
                    identity = ("rip_indirect", callsite)
                    if target in targets and identity not in seen:
                        seen.add(identity)
                        hits.append(
                            {
                                "kind": "rip_indirect",
                                "callsite": f"0x{callsite:016X}",
                                "pointer_slot": f"0x{pointer_slot:016X}",
                                "target": f"0x{target:016X}",
                                "region_base": f"0x{base:016X}",
                            }
                        )

                stats["bytes_read"] += received.value
                tail = block[-overlap:]
                offset += received.value
            if region_read:
                stats["regions_read"] += 1
    finally:
        kernel32.CloseHandle(handle)
    return hits, stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--target", required=True, action="append", type=parse_address)
    parser.add_argument("--json", dest="json_path", type=Path)
    parser.add_argument("--chunk-size", type=int, default=4 << 20)
    parser.add_argument("--max-region", type=int, default=512 << 20)
    parser.add_argument(
        "--start",
        type=parse_address,
        default=0,
        help="inclusive virtual-address lower bound (default: 0)",
    )
    parser.add_argument(
        "--end",
        type=parse_address,
        default=1 << 47,
        help="exclusive virtual-address upper bound (default: 0x800000000000)",
    )
    args = parser.parse_args()
    if args.start < 0 or args.end <= args.start:
        parser.error("--end must be greater than a non-negative --start")

    targets = set(args.target)
    hits, stats = scan(
        args.pid,
        targets,
        args.chunk_size,
        args.max_region,
        args.start,
        args.end,
    )
    report = {
        "schema": "aion2-x64-call-reference-scan/v1",
        "pid": args.pid,
        "targets": [f"0x{value:016X}" for value in sorted(targets)],
        "range": {
            "start": f"0x{args.start:016X}",
            "end": f"0x{args.end:016X}",
        },
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
