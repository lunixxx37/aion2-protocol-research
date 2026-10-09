#!/usr/bin/env python3
"""Export and validate an OpenSSL RSA private key from a live process.

--fields-address points at eight consecutive BIGNUM pointers in this order:
n, e, d, p, q, dmp1, dmq1, iqmp.  The public modulus is checked against the
latest validated 10 36 handshake in --capture before any key is written.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import struct
from ctypes import wintypes
from pathlib import Path

try:
    from .scan_process_rsa import latest_modulus
except ImportError:
    from scan_process_rsa import latest_modulus


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


def parse_address(value: str) -> int:
    return int(value, 0)


class ProcessReader:
    def __init__(self, pid: int):
        if os.name != "nt":
            raise SystemExit("this exporter is Windows-only")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.kernel32.ReadProcessMemory.restype = wintypes.BOOL
        self.handle = self.kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
        )
        if not self.handle:
            error = ctypes.get_last_error()
            raise SystemExit(f"OpenProcess({pid}) failed with Win32 error {error}; run this shell elevated")

    def close(self) -> None:
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            self.handle = None

    def read(self, address: int, size: int) -> bytes:
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
            error = ctypes.get_last_error()
            raise SystemExit(
                f"ReadProcessMemory(0x{address:X}, {size}) failed: "
                f"Win32 error {error}, read {received.value} bytes"
            )
        return buffer.raw

    def bignum(self, address: int) -> tuple[int, dict]:
        data_pointer, top, dmax, negative, flags = struct.unpack(
            "<Qiiii", self.read(address, 24)
        )
        if not data_pointer or not (0 <= top <= dmax <= 256) or negative not in (0, 1):
            raise SystemExit(f"invalid OpenSSL BIGNUM at 0x{address:X}")
        magnitude = int.from_bytes(self.read(data_pointer, top * 8), "little")
        value = -magnitude if negative else magnitude
        return value, {
            "address": f"0x{address:016X}",
            "data_address": f"0x{data_pointer:016X}",
            "top": top,
            "dmax": dmax,
            "negative": negative,
            "flags": flags,
            "bits": magnitude.bit_length(),
        }

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--fields-address", required=True, type=parse_address)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--json", dest="json_path", type=Path)
    args = parser.parse_args()

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError as error:
        raise SystemExit("install dependency: python -m pip install cryptography") from error

    modulus_bytes, handshake = latest_modulus(args.capture.resolve())
    names = ("n", "e", "d", "p", "q", "dmp1", "dmq1", "iqmp")
    with ProcessReader(args.pid) as process:
        pointers = struct.unpack("<8Q", process.read(args.fields_address, 8 * len(names)))
        values = {}
        metadata = {}
        for name, pointer in zip(names, pointers):
            values[name], metadata[name] = process.bignum(pointer)

    n = values["n"]
    e = values["e"]
    d = values["d"]
    p = values["p"]
    q = values["q"]
    dmp1 = values["dmp1"]
    dmq1 = values["dmq1"]
    iqmp = values["iqmp"]
    validations = {
        "modulus_matches_capture": n.to_bytes(256, "big") == modulus_bytes,
        "public_exponent_is_3": e == 3,
        "p_times_q_equals_n": p * q == n,
        "ed_mod_lcm_equals_1": (e * d) % math.lcm(p - 1, q - 1) == 1,
        "dmp1_matches": dmp1 == d % (p - 1),
        "dmq1_matches": dmq1 == d % (q - 1),
        "iqmp_matches": iqmp == pow(q, -1, p),
    }
    if not all(validations.values()):
        raise SystemExit(f"RSA validation failed: {validations}")

    private_numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
    )
    key = private_numbers.private_key()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    args.private_key.parent.mkdir(parents=True, exist_ok=True)
    args.private_key.write_bytes(pem)

    report = {
        "schema": "aion2-openssl-rsa-export/v1",
        "pid": args.pid,
        "capture": handshake,
        "fields_address": f"0x{args.fields_address:016X}",
        "modulus_sha256": hashlib.sha256(modulus_bytes).hexdigest(),
        "private_key_pem_sha256": hashlib.sha256(pem).hexdigest(),
        "private_key_path": str(args.private_key.resolve()),
        "bignums": metadata,
        "validations": validations,
    }
    rendered = json.dumps(report, indent=2)
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
