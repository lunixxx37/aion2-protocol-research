#!/usr/bin/env python3
"""Locate OpenSSL RSA wrapper functions in a running Windows process.

The scanner is read-only.  It recognizes the compact x64 legacy-API wrapper
sequence used by the mapped OpenSSL build for RSA_private_decrypt/encrypt and
RSA_public_decrypt/encrypt.
Addresses are discovered from executable memory and are therefore not tied to
a fixed image base or a particular process restart.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
EXECUTE_PROTECTIONS = {0x10, 0x20, 0x40, 0x80}


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


def is_executable(protection: int) -> bool:
    base = protection & 0xFF
    return (
        base in EXECUTE_PROTECTIONS
        and not protection & PAGE_GUARD
        and base != PAGE_NOACCESS
    )


def relative_call_target(block: bytes, offset: int, virtual_base: int) -> int:
    displacement = int.from_bytes(block[offset + 6 : offset + 10], "little", signed=True)
    return virtual_base + offset + 10 + displacement


def wrapper_matches(block: bytes, offset: int, field: int, slot: int) -> bool:
    if offset < 0 or offset + 25 > len(block):
        return False
    expected = {
        0: 0xB8,
        1: 0x38,
        2: 0x00,
        3: 0x00,
        4: 0x00,
        5: 0xE8,
        10: 0x48,
        11: 0x2B,
        12: 0xE0,
        13: 0x4D,
        14: 0x8B,
        15: 0x51,
        16: field,
        17: 0x48,
        18: 0x83,
        19: 0xC4,
        20: 0x38,
        21: 0x49,
        22: 0xFF,
        23: 0x62,
        24: slot,
    }
    return all(block[offset + index] == value for index, value in expected.items())


def find_wrapper_groups(block: bytes, virtual_base: int) -> list[dict]:
    hits: list[dict] = []
    cursor = 0
    prefix = b"\xB8\x38\x00\x00\x00\xE8"
    names_and_slots = [
        ("RSA_private_decrypt", 0x20),
        ("RSA_private_encrypt", 0x18),
        ("RSA_public_decrypt", 0x10),
        ("RSA_public_encrypt", 0x08),
    ]
    while True:
        first = block.find(prefix, cursor)
        if first < 0:
            break
        cursor = first + 1
        if first + 0x60 + 25 > len(block):
            continue
        field = block[first + 16]
        wrappers = []
        valid = True
        call_targets = set()
        for index, (name, slot) in enumerate(names_and_slots):
            offset = first + index * 0x20
            if not wrapper_matches(block, offset, field, slot):
                valid = False
                break
            call_targets.add(relative_call_target(block, offset, virtual_base))
            wrappers.append(
                {
                    "name": name,
                    "address": f"0x{virtual_base + offset:016X}",
                    "method_dispatch_slot": f"0x{slot:X}",
                }
            )
        if valid and len(call_targets) == 1:
            hits.append(
                {
                    "rsa_method_pointer_field": f"0x{field:X}",
                    "stack_probe_target": f"0x{call_targets.pop():016X}",
                    "wrappers": wrappers,
                }
            )
    return hits


def scan(pid: int, chunk_size: int, max_region: int) -> tuple[list[dict], dict]:
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
    address = 0
    maximum_address = (1 << 47) - 1
    overlap = 0x80
    try:
        while address < maximum_address:
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

            stats["regions_considered"] += 1
            offset = 0
            tail = b""
            region_read = False
            seen_addresses: set[str] = set()
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
                for group in find_wrapper_groups(block, block_base):
                    identity = group["wrappers"][0]["address"]
                    if identity in seen_addresses:
                        continue
                    seen_addresses.add(identity)
                    group.update(
                        {
                            "region_base": f"0x{base:016X}",
                            "region_size": size,
                            "protection": f"0x{mbi.Protect:X}",
                            "type": f"0x{mbi.Type:X}",
                        }
                    )
                    hits.append(group)
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
    parser.add_argument("--pid", required=True, type=int, help="target process ID")
    parser.add_argument("--json", dest="json_path", type=Path, help="optional JSON output")
    parser.add_argument("--chunk-size", type=int, default=4 << 20)
    parser.add_argument("--max-region", type=int, default=512 << 20)
    args = parser.parse_args()

    hits, stats = scan(args.pid, args.chunk_size, args.max_region)
    report = {
        "schema": "aion2-openssl-rsa-locator/v1",
        "pid": args.pid,
        "stats": stats,
        "hits": hits,
        "breakpoint_recipe": {
            "function": "RSA_private_decrypt",
            "entry_registers_win64": {
                "RCX": "flen; expected 256 for the server handshake block",
                "RDX": "input ciphertext pointer",
                "R8": "plaintext output pointer; preserve this value until return",
                "R9": "RSA object pointer",
                "[RSP+0x28]": "padding argument",
            },
            "return": "RAX is the plaintext length; read that many bytes from the saved R8 pointer",
        },
    }
    rendered = json.dumps(report, indent=2)
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
