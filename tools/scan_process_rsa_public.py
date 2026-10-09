#!/usr/bin/env python3
"""Find serialized 2048-bit, e=3 PKCS#1 RSA public keys in a process read-only."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from ctypes import wintypes
from pathlib import Path

try:
    from .scan_process_rsa import PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, scan
except ImportError:
    from scan_process_rsa import PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, scan


DER_PREFIX = bytes.fromhex("308201080282010100")
DER_SUFFIX = bytes.fromhex("020103")
DER_SIZE = 268


def read_at(pid: int, addresses: list[int], size: int) -> dict[int, bytes]:
    if os.name != "nt":
        raise SystemExit("this scanner is Windows-only")
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
        error = ctypes.get_last_error()
        raise SystemExit(f"OpenProcess({pid}) failed with Win32 error {error}; run elevated")
    output = {}
    try:
        for address in addresses:
            buffer = ctypes.create_string_buffer(size)
            received = ctypes.c_size_t()
            if kernel32.ReadProcessMemory(
                handle,
                ctypes.c_void_p(address),
                buffer,
                size,
                ctypes.byref(received),
            ) and received.value == size:
                output[address] = buffer.raw
    finally:
        kernel32.CloseHandle(handle)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--json", dest="json_path", type=Path)
    args = parser.parse_args()

    prefix_hits, stats = scan(args.pid, {"pkcs1-rsa-public-prefix": DER_PREFIX}, 8 << 20, 512 << 20)
    addresses = sorted({int(hit["address"], 16) for hit in prefix_hits})
    blobs = read_at(args.pid, addresses, DER_SIZE)
    keys = []
    for address, der in blobs.items():
        if not der.startswith(DER_PREFIX) or der[-3:] != DER_SUFFIX:
            continue
        modulus = der[9:265]
        if len(modulus) != 256 or modulus[0] == 0 or not modulus[-1] & 1:
            continue
        keys.append(
            {
                "address": f"0x{address:016X}",
                "der_sha256": hashlib.sha256(der).hexdigest(),
                "modulus_sha256": hashlib.sha256(modulus).hexdigest(),
                "modulus_bits": int.from_bytes(modulus, "big").bit_length(),
                "public_exponent": 3,
            }
        )
    report = {
        "schema": "aion2-process-rsa-public-scan/v1",
        "pid": args.pid,
        "stats": stats,
        "prefix_hits": len(prefix_hits),
        "validated_public_keys": keys,
    }
    rendered = json.dumps(report, indent=2)
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
