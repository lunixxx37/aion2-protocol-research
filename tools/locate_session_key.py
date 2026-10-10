#!/usr/bin/env python3
"""Locate the active Aion 2 C2S RC4 session key through runtime state.

The locator is read-only. It derives the RC4 object vtable from a constructor
signature in the main image, searches writable private memory for live objects,
and validates the complete 256-byte RC4 permutation before accepting a hit.
It avoids the multi-pass RSA/BIGNUM recovery path used during initial research.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import struct
import time
from ctypes import wintypes
from pathlib import Path

try:
    from .scan_process_rsa import (
        MEMORY_BASIC_INFORMATION,
        MEM_COMMIT,
        PAGE_GUARD,
        PAGE_NOACCESS,
        PROCESS_QUERY_INFORMATION,
        PROCESS_VM_READ,
    )
except ImportError:  # Direct execution: python tools/locate_session_key.py
    from scan_process_rsa import (
        MEMORY_BASIC_INFORMATION,
        MEM_COMMIT,
        PAGE_GUARD,
        PAGE_NOACCESS,
        PROCESS_QUERY_INFORMATION,
        PROCESS_VM_READ,
    )


MEM_PRIVATE = 0x20000
EXECUTE_PROTECTIONS = {0x10, 0x20, 0x40, 0x80}
WRITABLE_PROTECTIONS = {0x04, 0x08, 0x40, 0x80}
LIST_MODULES_ALL = 0x03
RC4_KEY_LENGTH = 214
RC4_STATE_SIZE = 0x124
AF_INET = 2
MIB_TCP_STATE_ESTABLISHED = 5
TCP_TABLE_OWNER_PID_ALL = 5
ERROR_INSUFFICIENT_BUFFER = 122
OWNER_ARENA_START = 0x2_0000_0000
OWNER_ARENA_END = 0x3_0000_0000
OWNER_REGION_SIZE = 0x10000
NETWORK_OWNER_VTABLE_DELTA = 0x148
OWNER_RSA_SLOT = 0xE10
OWNER_STATE_A_SLOT = 0xE20
OWNER_STATE_B_SLOT = 0xE30


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class ProcessReader:
    def __init__(self, pid: int):
        if os.name != "nt":
            raise SystemExit("this locator is Windows-only")

        self.pid = pid
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.psapi = ctypes.WinDLL("psapi", use_last_error=True)
        self._configure_functions()
        self.handle = self.kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
        )
        if not self.handle:
            error = ctypes.get_last_error()
            raise SystemExit(
                f"OpenProcess({pid}) failed with Win32 error {error}; "
                "run this shell elevated"
            )

    def _configure_functions(self) -> None:
        self.kernel32.OpenProcess.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.VirtualQueryEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(MEMORY_BASIC_INFORMATION),
            ctypes.c_size_t,
        ]
        self.kernel32.VirtualQueryEx.restype = ctypes.c_size_t
        self.kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.kernel32.ReadProcessMemory.restype = wintypes.BOOL
        self.psapi.EnumProcessModulesEx.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ctypes.c_void_p),
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.DWORD,
        ]
        self.psapi.EnumProcessModulesEx.restype = wintypes.BOOL
        self.psapi.GetModuleInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(MODULEINFO),
            wintypes.DWORD,
        ]
        self.psapi.GetModuleInformation.restype = wintypes.BOOL
        self.psapi.GetModuleBaseNameW.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.LPWSTR,
            wintypes.DWORD,
        ]
        self.psapi.GetModuleBaseNameW.restype = wintypes.DWORD

    def close(self) -> None:
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self) -> ProcessReader:
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def read(self, address: int, size: int) -> bytes | None:
        if size <= 0:
            return b""
        buffer = ctypes.create_string_buffer(size)
        received = ctypes.c_size_t()
        ok = self.kernel32.ReadProcessMemory(
            self.handle,
            ctypes.c_void_p(address),
            buffer,
            size,
            ctypes.byref(received),
        )
        if not ok or received.value != size:
            return None
        return buffer.raw

    def regions(self, start: int = 0, end: int = (1 << 47) - 1) -> list[dict]:
        regions: list[dict] = []
        address = start
        while address < end:
            mbi = MEMORY_BASIC_INFORMATION()
            queried = self.kernel32.VirtualQueryEx(
                self.handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if not queried or not mbi.RegionSize:
                break
            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize)
            region_end = base + size
            if region_end <= address:
                break
            address = region_end
            if region_end <= start or base >= end:
                continue
            regions.append(
                {
                    "base": max(base, start),
                    "size": min(region_end, end) - max(base, start),
                    "state": int(mbi.State),
                    "protect": int(mbi.Protect),
                    "type": int(mbi.Type),
                }
            )
        return regions

    def main_module(self) -> dict:
        capacity = 256
        while True:
            modules = (ctypes.c_void_p * capacity)()
            needed = wintypes.DWORD()
            ok = self.psapi.EnumProcessModulesEx(
                self.handle,
                modules,
                ctypes.sizeof(modules),
                ctypes.byref(needed),
                LIST_MODULES_ALL,
            )
            if not ok:
                error = ctypes.get_last_error()
                raise SystemExit(f"EnumProcessModulesEx failed with Win32 error {error}")
            count = needed.value // ctypes.sizeof(ctypes.c_void_p)
            if count <= capacity:
                break
            capacity = count + 32

        module = modules[0]
        info = MODULEINFO()
        if not self.psapi.GetModuleInformation(
            self.handle, module, ctypes.byref(info), ctypes.sizeof(info)
        ):
            error = ctypes.get_last_error()
            raise SystemExit(f"GetModuleInformation failed with Win32 error {error}")
        name_buffer = ctypes.create_unicode_buffer(1024)
        self.psapi.GetModuleBaseNameW(
            self.handle, module, name_buffer, len(name_buffer)
        )
        return {
            "name": name_buffer.value,
            "base": int(info.lpBaseOfDll or 0),
            "size": int(info.SizeOfImage),
        }


def established_tcp_pids(remote_port: int) -> list[int]:
    """Return PIDs owning established IPv4 connections to remote_port."""
    if os.name != "nt":
        raise SystemExit("automatic PID discovery is Windows-only")
    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    iphlpapi.GetExtendedTcpTable.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
        wintypes.ULONG,
        wintypes.DWORD,
        wintypes.ULONG,
    ]
    iphlpapi.GetExtendedTcpTable.restype = wintypes.DWORD

    size = wintypes.DWORD()
    result = iphlpapi.GetExtendedTcpTable(
        None,
        ctypes.byref(size),
        True,
        AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0,
    )
    if result not in (0, ERROR_INSUFFICIENT_BUFFER):
        raise SystemExit(f"GetExtendedTcpTable sizing failed with error {result}")
    buffer = ctypes.create_string_buffer(size.value)
    result = iphlpapi.GetExtendedTcpTable(
        buffer,
        ctypes.byref(size),
        True,
        AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0,
    )
    if result != 0:
        raise SystemExit(f"GetExtendedTcpTable failed with error {result}")

    count = struct.unpack_from("<I", buffer.raw, 0)[0]
    row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
    pids: set[int] = set()
    for index in range(count):
        offset = 4 + index * row_size
        row = MIB_TCPROW_OWNER_PID.from_buffer_copy(buffer.raw, offset)
        port = int.from_bytes(
            struct.pack("<I", row.dwRemotePort)[:2], "big"
        )
        if row.dwState == MIB_TCP_STATE_ESTABLISHED and port == remote_port:
            pids.add(int(row.dwOwningPid))
    return sorted(pids)


def discover_world_pid(remote_port: int, process_name: str) -> tuple[int, dict]:
    candidates = established_tcp_pids(remote_port)
    matches: list[int] = []
    inspected: list[dict] = []
    for pid in candidates:
        try:
            with ProcessReader(pid) as reader:
                module = reader.main_module()
        except SystemExit as error:
            inspected.append({"pid": pid, "error": str(error)})
            continue
        inspected.append({"pid": pid, "process": module["name"]})
        if module["name"].lower() == process_name.lower():
            matches.append(pid)
    if len(matches) != 1:
        failures = [
            f"PID {item['pid']}: {item['error']}"
            for item in inspected
            if "error" in item
        ]
        detail = f"; inspection failed for {'; '.join(failures)}" if failures else ""
        raise SystemExit(
            f"expected one established {process_name} connection to remote port "
            f"{remote_port}, found {len(matches)}{detail}"
        )
    return matches[0], {
        "method": "GetExtendedTcpTable",
        "remote_port": remote_port,
        "process_name": process_name,
        "tcp_candidate_pids": candidates,
        "inspected": inspected,
    }


def usable_region(region: dict) -> bool:
    protection = region["protect"]
    return (
        region["state"] == MEM_COMMIT
        and not protection & PAGE_GUARD
        and not protection & PAGE_NOACCESS
    )


def executable_region(region: dict) -> bool:
    return usable_region(region) and (region["protect"] & 0xFF) in EXECUTE_PROTECTIONS


def writable_private_region(region: dict) -> bool:
    return (
        usable_region(region)
        and region["type"] == MEM_PRIVATE
        and (region["protect"] & 0xFF) in WRITABLE_PROTECTIONS
    )


def iter_region_chunks(
    reader: ProcessReader,
    regions: list[dict],
    chunk_size: int,
    overlap: int,
    stats: dict,
):
    for region in regions:
        base = region["base"]
        end = base + region["size"]
        offset = base
        tail = b""
        region_read = False
        while offset < end:
            request = min(chunk_size, end - offset)
            block = reader.read(offset, request)
            if block is None:
                stats["read_failures"] += 1
                break
            region_read = True
            stats["bytes_read"] += len(block)
            yield offset - len(tail), tail + block
            tail = block[-overlap:] if overlap else b""
            offset += len(block)
        if region_read:
            stats["regions_read"] += 1


def coalesce_regions(regions: list[dict]) -> list[dict]:
    """Merge adjacent readable scan regions to reduce ReadProcessMemory calls."""
    merged: list[dict] = []
    for region in sorted(regions, key=lambda item: item["base"]):
        if merged and merged[-1]["base"] + merged[-1]["size"] == region["base"]:
            merged[-1]["size"] += region["size"]
        else:
            merged.append({"base": region["base"], "size": region["size"]})
    return merged


RC4_CONSTRUCTOR_PATTERN = re.compile(
    b"\xB9\x38\x01\x00\x00\xE8...."
    b"\x48\x8B\xD8\x48\x85\xC0\x0F\x84...."
    b"\x48\x89\x6C\\$\x30\x48\x8D\x0D(....)"
    b"\x48\x89\x74\\$\x38\x33\xD2\xBE\x01\x00\x00\x00"
    b"\x41\xB8\x00\x01\x00\x00\x89\x70\x08\x89\x70\x0C"
    b"\x48\x8D\x05....\x48\x89\x03",
    re.DOTALL,
)


def locate_rc4_vtable(
    reader: ProcessReader, module: dict, chunk_size: int
) -> tuple[int, dict]:
    start = module["base"]
    end = start + module["size"]
    regions = [
        region
        for region in reader.regions(start, end)
        if executable_region(region)
    ]
    stats = {
        "regions_considered": len(regions),
        "regions_read": 0,
        "bytes_read": 0,
        "read_failures": 0,
    }
    hits: list[tuple[int, int]] = []
    overlap = 96
    for block_base, block in iter_region_chunks(
        reader, regions, chunk_size, overlap, stats
    ):
        for match in RC4_CONSTRUCTOR_PATTERN.finditer(block):
            match_address = block_base + match.start()
            lea_address = match_address + 27
            displacement = struct.unpack("<i", match.group(1))[0]
            vtable = lea_address + 7 + displacement
            first_method = reader.read(vtable, 8)
            if first_method is None:
                continue
            method_address = struct.unpack("<Q", first_method)[0]
            if start <= method_address < end:
                hits.append((match_address, vtable))
    unique = sorted(set(hits))
    if len(unique) != 1:
        rendered = ", ".join(
            f"constructor=0x{address:X}/vtable=0x{vtable:X}"
            for address, vtable in unique
        )
        raise SystemExit(
            f"expected one RC4 constructor signature, found {len(unique)}: {rendered}"
        )
    constructor, vtable = unique[0]
    stats.update(
        {
            "constructor_address": f"0x{constructor:016X}",
            "vtable_address": f"0x{vtable:016X}",
        }
    )
    return vtable, stats


def validate_rc4_state(
    reader: ProcessReader,
    address: int,
    vtable: int,
    expected_key_sha256: str | None,
) -> tuple[dict, bytes] | None:
    raw = reader.read(address, RC4_STATE_SIZE)
    if raw is None:
        return None
    object_vtable = struct.unpack_from("<Q", raw, 0)[0]
    key_pointer = struct.unpack_from("<Q", raw, 0x10)[0]
    key_length, index_i, index_j = struct.unpack_from("<III", raw, 0x18)
    if (
        object_vtable != vtable
        or key_length != RC4_KEY_LENGTH
        or index_i > 0xFF
        or index_j > 0xFF
    ):
        return None
    permutation = raw[0x24 : 0x24 + 256]
    if len(permutation) != 256 or sorted(permutation) != list(range(256)):
        return None
    key = reader.read(key_pointer, key_length)
    if key is None:
        return None
    key_sha256 = hashlib.sha256(key).hexdigest()
    return (
        {
            "address": f"0x{address:016X}",
            "key_pointer": f"0x{key_pointer:016X}",
            "key_length": key_length,
            "key_sha256": key_sha256,
            "matches_expected_key": (
                key_sha256 == expected_key_sha256
                if expected_key_sha256 is not None
                else None
            ),
            "rc4_i": index_i,
            "rc4_j": index_j,
            "permutation_valid": True,
        },
        key,
    )


def locate_states_via_owner_arena(
    reader: ProcessReader,
    vtable: int,
    expected_key_sha256: str | None,
    owner_hint: int | None,
) -> tuple[list[dict], dict[str, bytes], dict, int | None]:
    stats = {
        "method": "owner_hint" if owner_hint is not None else "owner_arena_pattern",
        "regions_considered": 0,
        "regions_read": 0,
        "owner_candidates_read": 0,
        "bytes_read": 0,
        "read_failures": 0,
    }

    def validate_owner(
        owner: int, slots: tuple[int, int, int, int, int, int]
    ) -> tuple[list[dict], dict[str, bytes], dict, int] | None:
        stats["owner_candidates_read"] += 1
        (
            rsa_object,
            rsa_control,
            state_a,
            control_a,
            state_b,
            control_b,
        ) = slots
        if not rsa_object or not rsa_control:
            return None
        if control_a != state_a - 0x10 or control_b != state_b - 0x10:
            return None
        validated_a = validate_rc4_state(
            reader, state_a, vtable, expected_key_sha256
        )
        validated_b = validate_rc4_state(
            reader, state_b, vtable, expected_key_sha256
        )
        if validated_a is None or validated_b is None:
            return None
        item_a, key_a = validated_a
        item_b, key_b = validated_b
        if key_a != key_b:
            return None
        key_hash = item_a["key_sha256"]
        if expected_key_sha256 is not None and key_hash != expected_key_sha256:
            return None
        item_a["role"] = "state_a"
        item_b["role"] = "state_b"
        stats["rsa_handler_present"] = True
        return [item_a, item_b], {key_hash: key_a}, stats, owner

    if owner_hint is not None:
        raw = reader.read(owner_hint + OWNER_RSA_SLOT, 0x30)
        if raw is None:
            stats["read_failures"] += 1
            return [], {}, stats, None
        stats["bytes_read"] += len(raw)
        validated = validate_owner(owner_hint, struct.unpack("<6Q", raw))
        return validated if validated is not None else ([], {}, stats, None)

    regions = [
        region
        for region in reader.regions(OWNER_ARENA_START, OWNER_ARENA_END)
        if writable_private_region(region)
        and region["size"] == OWNER_REGION_SIZE
    ]
    regions.sort(key=lambda region: region["base"], reverse=True)
    stats["regions_considered"] = len(regions)
    owner_vtable = struct.pack("<Q", vtable + NETWORK_OWNER_VTABLE_DELTA)
    for region in regions:
        block = reader.read(region["base"], region["size"])
        if block is None:
            stats["read_failures"] += 1
            continue
        stats["regions_read"] += 1
        stats["bytes_read"] += len(block)
        cursor = 0
        while True:
            offset = block.find(owner_vtable, cursor)
            if offset < 0:
                break
            cursor = offset + 1
            slots_offset = offset + OWNER_RSA_SLOT
            if slots_offset + 0x30 > len(block):
                continue
            owner = region["base"] + offset
            slots = struct.unpack_from("<6Q", block, slots_offset)
            validated = validate_owner(owner, slots)
            if validated is not None:
                stats["method"] = "owner_vtable"
                stats["owner_vtable"] = (
                    f"0x{vtable + NETWORK_OWNER_VTABLE_DELTA:016X}"
                )
                return validated

    stats["method"] = "owner_arena_pattern"
    for region in regions:
        block = reader.read(region["base"], region["size"])
        if block is None:
            stats["read_failures"] += 1
            continue
        stats["regions_read"] += 1
        stats["bytes_read"] += len(block)
        for offset in range(0, len(block) - 0x30 + 1, 0x10):
            slots = struct.unpack_from("<6Q", block, offset)
            (
                rsa_object,
                rsa_control,
                state_a,
                control_a,
                state_b,
                control_b,
            ) = slots
            if (
                rsa_object
                and rsa_control
                and state_a
                and state_b
                and control_a == state_a - 0x10
                and control_b == state_b - 0x10
            ):
                owner = region["base"] + offset - OWNER_RSA_SLOT
                validated = validate_owner(owner, slots)
                if validated is not None:
                    return validated
    return [], {}, stats, None


def locate_states(
    reader: ProcessReader,
    vtable: int,
    chunk_size: int,
    max_region: int,
    expected_key_sha256: str | None,
) -> tuple[list[dict], dict[str, bytes], dict]:
    regions = [
        region
        for region in reader.regions()
        if writable_private_region(region) and region["size"] <= max_region
    ]
    allocator_regions = [
        region for region in regions if region["size"] == OWNER_REGION_SIZE
    ]
    other_regions = [
        region for region in regions if region["size"] != OWNER_REGION_SIZE
    ]
    scan_regions = coalesce_regions(allocator_regions) + coalesce_regions(
        other_regions
    )
    stats = {
        "regions_considered": len(regions),
        "allocator_regions_prioritized": len(allocator_regions),
        "scan_spans": len(scan_regions),
        "regions_read": 0,
        "bytes_read": 0,
        "read_failures": 0,
        "stopped_after_matching_pair": False,
    }
    pointer = struct.pack("<Q", vtable)
    hits: list[dict] = []
    keys: dict[str, bytes] = {}
    seen_addresses: set[int] = set()
    grouped_addresses: dict[str, list[int]] = {}
    for block_base, block in iter_region_chunks(
        reader, scan_regions, chunk_size, len(pointer) - 1, stats
    ):
        cursor = 0
        while True:
            index = block.find(pointer, cursor)
            if index < 0:
                break
            cursor = index + 1
            address = block_base + index
            if address in seen_addresses:
                continue
            seen_addresses.add(address)
            validated = validate_rc4_state(
                reader, address, vtable, expected_key_sha256
            )
            if validated is None:
                continue
            item, key = validated
            hits.append(item)
            key_hash = item["key_sha256"]
            keys[key_hash] = key
            grouped_addresses.setdefault(key_hash, []).append(address)
            if len(grouped_addresses[key_hash]) >= 2:
                stats["stopped_after_matching_pair"] = True
                return hits, keys, stats
    return hits, keys, stats


def select_key(hits: list[dict], keys: dict[str, bytes]) -> tuple[str, bytes] | None:
    counts: dict[str, int] = {}
    for hit in hits:
        key_hash = hit["key_sha256"]
        counts[key_hash] = counts.get(key_hash, 0) + 1
    pairs = [key_hash for key_hash, count in counts.items() if count >= 2]
    if len(pairs) != 1:
        return None
    key_hash = pairs[0]
    return key_hash, keys[key_hash]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pid",
        type=int,
        help="Aion2 process ID; omit to discover it from the world connection",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=13328,
        help="world server remote port used for automatic PID discovery",
    )
    parser.add_argument(
        "--process-name",
        default="AION2.exe",
        help="main executable name used to validate an automatically found PID",
    )
    parser.add_argument(
        "--owner",
        type=lambda value: int(value, 0),
        help="optional cached network_owner address for the current process run",
    )
    parser.add_argument(
        "--expected-key-sha256",
        help="optional expected SHA-256 for capture-to-runtime validation",
    )
    parser.add_argument(
        "--key-out",
        type=Path,
        help="optional local output for the selected 214-byte session key",
    )
    parser.add_argument("--json", dest="json_path", type=Path)
    parser.add_argument("--chunk-size", type=int, default=8 << 20)
    parser.add_argument("--max-region", type=int, default=512 << 20)
    parser.add_argument(
        "--full-scan-fallback",
        action="store_true",
        help="opt into the slow private-memory scan when the owner-arena profile misses",
    )
    args = parser.parse_args()

    if args.expected_key_sha256 is not None:
        expected = args.expected_key_sha256.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise SystemExit("--expected-key-sha256 must contain 64 hex characters")
    else:
        expected = None

    started = time.perf_counter()
    discovery_started = time.perf_counter()
    if args.pid is None:
        target_pid, discovery = discover_world_pid(args.port, args.process_name)
    else:
        target_pid = args.pid
        discovery = {"method": "explicit_pid"}
    discovery_elapsed = time.perf_counter() - discovery_started

    with ProcessReader(target_pid) as reader:
        module_started = time.perf_counter()
        module = reader.main_module()
        module_elapsed = time.perf_counter() - module_started

        signature_started = time.perf_counter()
        vtable, signature_stats = locate_rc4_vtable(
            reader, module, args.chunk_size
        )
        signature_elapsed = time.perf_counter() - signature_started

        state_started = time.perf_counter()
        hits, keys, state_stats, owner = locate_states_via_owner_arena(
            reader,
            vtable,
            expected,
            args.owner,
        )
        if not hits and args.owner is None and args.full_scan_fallback:
            hits, keys, fallback_stats = locate_states(
                reader,
                vtable,
                args.chunk_size,
                args.max_region,
                expected,
            )
            state_stats = {
                "method": "full_private_memory_fallback",
                "owner_arena": state_stats,
                "fallback": fallback_stats,
            }
        state_elapsed = time.perf_counter() - state_started

    selected = select_key(hits, keys)
    if selected is None:
        raise SystemExit(
            "no unique matching RC4 state pair found through the fast path; "
            f"validated objects: {len(hits)}"
        )
    selected_hash, selected_key = selected
    if expected is not None and selected_hash != expected:
        raise SystemExit(
            "the located state pair does not match the expected session key hash"
        )

    if args.key_out is not None:
        args.key_out.parent.mkdir(parents=True, exist_ok=True)
        args.key_out.write_bytes(selected_key)

    total_elapsed = time.perf_counter() - started
    report = {
        "schema": "aion2-session-key-locator/v1",
        "pid": target_pid,
        "pid_discovery": discovery,
        "module": {
            "name": module["name"],
            "base": f"0x{module['base']:016X}",
            "size": module["size"],
        },
        "rc4_vtable": f"0x{vtable:016X}",
        "network_owner": f"0x{owner:016X}" if owner is not None else None,
        "session_key": {
            "length": len(selected_key),
            "sha256": selected_hash,
            "matches_expected": selected_hash == expected if expected else None,
            "output_path": str(args.key_out.resolve()) if args.key_out else None,
        },
        "state_objects": hits,
        "timings_ms": {
            "pid_discovery": round(discovery_elapsed * 1000, 3),
            "module": round(module_elapsed * 1000, 3),
            "signature": round(signature_elapsed * 1000, 3),
            "state_scan": round(state_elapsed * 1000, 3),
            "total": round(total_elapsed * 1000, 3),
        },
        "signature_scan": signature_stats,
        "state_scan": state_stats,
    }
    rendered = json.dumps(report, indent=2)
    if args.json_path is not None:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
