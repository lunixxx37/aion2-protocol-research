#!/usr/bin/env python3
"""Read and disassemble small x64 windows around live process addresses."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path

try:
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
except ImportError as error:
    raise SystemExit("install dependency: python -m pip install capstone") from error


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


def parse_address(value: str) -> int:
    return int(value, 0)


def read_memory(pid: int, address: int, size: int) -> bytes:
    if os.name != "nt":
        raise SystemExit("this tool is Windows-only")
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
        raise SystemExit(f"OpenProcess({pid}) failed with Win32 error {ctypes.get_last_error()}")
    try:
        buffer = ctypes.create_string_buffer(size)
        received = ctypes.c_size_t()
        if not kernel32.ReadProcessMemory(
            handle,
            ctypes.c_void_p(address),
            buffer,
            size,
            ctypes.byref(received),
        ):
            raise SystemExit(
                f"ReadProcessMemory(0x{address:X}, {size}) failed with Win32 error "
                f"{ctypes.get_last_error()}"
            )
        return buffer.raw[: received.value]
    finally:
        kernel32.CloseHandle(handle)


def decode_window(data: bytes, base: int, focus: int) -> list[dict]:
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    best = []
    best_score = (-1, -1)
    focus_offset = focus - base
    # Try nearby starts and prefer a valid stream that lands exactly on focus.
    for start in range(max(0, focus_offset - 96), focus_offset + 1):
        decoded = list(decoder.disasm(data[start:], base + start))
        addresses = {instruction.address for instruction in decoded}
        if focus not in addresses:
            continue
        before_count = sum(instruction.address < focus for instruction in decoded)
        byte_count = sum(instruction.size for instruction in decoded)
        score = (before_count, byte_count)
        if score > best_score:
            best_score = score
            best = decoded
    if not best:
        best = list(decoder.disasm(data, base))
    return [
        {
            "address": f"0x{instruction.address:016X}",
            "bytes": instruction.bytes.hex(),
            "mnemonic": instruction.mnemonic,
            "operands": instruction.op_str,
            "focus": instruction.address == focus,
        }
        for instruction in best
        if focus - 96 <= instruction.address <= focus + 128
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--address", required=True, action="append", type=parse_address)
    parser.add_argument("--before", type=int, default=160)
    parser.add_argument("--after", type=int, default=192)
    parser.add_argument("--json", dest="json_path", type=Path)
    args = parser.parse_args()

    windows = []
    for focus in args.address:
        base = focus - args.before
        data = read_memory(args.pid, base, args.before + args.after)
        windows.append(
            {
                "focus": f"0x{focus:016X}",
                "read_base": f"0x{base:016X}",
                "bytes_read": len(data),
                "instructions": decode_window(data, base, focus),
            }
        )
    report = {"schema": "aion2-process-disassembly/v1", "pid": args.pid, "windows": windows}
    rendered = json.dumps(report, indent=2)
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
