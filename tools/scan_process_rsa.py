#!/usr/bin/env python3
"""Read-only Windows process scan for the current Aion 2 ephemeral RSA key.

The modulus is taken from the latest validated 10 36 handshake in a pcapng.
No target memory is allocated, protected, or written.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import struct
import sys
from ctypes import wintypes
from pathlib import Path

try:
    from .analyze_pcaps import CLIENT_SIGNATURE, iter_file_matches, parse_client_window
except ImportError:  # Direct execution: python tools/scan_process_rsa.py
    from analyze_pcaps import CLIENT_SIGNATURE, iter_file_matches, parse_client_window


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def latest_modulus(path: Path) -> tuple[bytes, dict]:
    matches = []
    for offset, window in iter_file_matches(path, CLIENT_SIGNATURE):
        item = parse_client_window(path.name, offset, window)
        if item:
            matches.append((offset, window[13 : 13 + 256], item))
    if not matches:
        raise SystemExit("no validated 10 36 RSA handshake found in capture")
    offset, modulus, item = max(matches, key=lambda value: value[0])
    return modulus, {
        "capture": path.name,
        "file_offset": offset,
        "revision": item.revision,
        "region": item.region,
        "modulus_sha256": item.modulus_sha256,
    }


def readable(protection: int) -> bool:
    return not (protection & PAGE_GUARD) and not (protection & PAGE_NOACCESS)


def scan(pid: int, patterns: dict[str, bytes], chunk_size: int, max_region: int) -> tuple[list[dict], dict]:
    if os.name != "nt":
        raise SystemExit("this scanner is Windows-only")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL

    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        raise SystemExit(f"OpenProcess({pid}) failed with Win32 error {error}; run this shell elevated")

    hits: list[dict] = []
    stats = {"regions_considered": 0, "regions_read": 0, "bytes_read": 0, "read_failures": 0}
    overlap = max(len(value) for value in patterns.values()) - 1
    address = 0
    maximum_address = (1 << 47) - 1
    try:
        while address < maximum_address:
            mbi = MEMORY_BASIC_INFORMATION()
            queried = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not queried or not mbi.RegionSize:
                break
            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize)
            next_address = base + size
            if next_address <= address:
                break
            address = next_address
            if mbi.State != MEM_COMMIT or not readable(mbi.Protect) or size > max_region:
                continue
            stats["regions_considered"] += 1
            region_read = False
            tail = b""
            offset = 0
            while offset < size:
                request = min(chunk_size, size - offset)
                buffer = ctypes.create_string_buffer(request)
                received = ctypes.c_size_t()
                ok = kernel32.ReadProcessMemory(
                    handle,
                    ctypes.c_void_p(base + offset),
                    buffer,
                    request,
                    ctypes.byref(received),
                )
                if not ok or received.value == 0:
                    stats["read_failures"] += 1
                    break
                region_read = True
                block = tail + buffer.raw[: received.value]
                block_base = base + offset - len(tail)
                for name, pattern in patterns.items():
                    start = 0
                    while True:
                        index = block.find(pattern, start)
                        if index < 0:
                            break
                        hits.append(
                            {
                                "pattern": name,
                                "address": f"0x{block_base + index:016X}",
                                "region_base": f"0x{base:016X}",
                                "region_size": size,
                                "protection": f"0x{mbi.Protect:X}",
                                "type": f"0x{mbi.Type:X}",
                            }
                        )
                        start = index + 1
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
    parser.add_argument("--pid", required=True, type=int, help="Aion2 process ID owning the world socket")
    parser.add_argument("--capture", required=True, type=Path, help="pcapng containing the current connection handshake")
    parser.add_argument("--json", dest="json_path", type=Path, help="optional JSON output")
    parser.add_argument("--chunk-size", type=int, default=4 << 20)
    parser.add_argument("--max-region", type=int, default=512 << 20)
    args = parser.parse_args()

    modulus, handshake = latest_modulus(args.capture.resolve())
    der_prefix = bytes.fromhex("308201080282010100") + modulus + bytes.fromhex("020103")
    bcrypt_rsa2 = struct.pack("<6I", 0x32415352, 2048, 1, 256, 128, 128) + b"\x03" + modulus
    bcrypt_rsa3 = struct.pack("<6I", 0x33415352, 2048, 1, 256, 128, 128) + b"\x03" + modulus
    cryptoapi_private = bytes.fromhex("0702000000a40000525341320008000003000000") + modulus[::-1]
    pkcs1_private_prefix = bytes.fromhex("0201000282010100") + modulus
    patterns = {
        "rsa_modulus_be": modulus,
        "rsa_modulus_le": modulus[::-1],
        "pkcs1_public_der": der_prefix,
        "pkcs1_private_der_prefix": pkcs1_private_prefix,
        "bcrypt_rsa2_private_blob": bcrypt_rsa2,
        "bcrypt_rsa3_full_private_blob": bcrypt_rsa3,
        "cryptoapi_privatekeyblob": cryptoapi_private,
        "bcrypt_private_magic_rsa2": b"RSA2",
        "bcrypt_full_private_magic_rsa3": b"RSA3",
    }
    hits, stats = scan(args.pid, patterns, args.chunk_size, args.max_region)
    report = {
        "schema": "aion2-process-rsa-scan/v1",
        "pid": args.pid,
        "handshake": handshake,
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
