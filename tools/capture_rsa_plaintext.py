#!/usr/bin/env python3
"""Capture RSA_private_decrypt input/output from a running Aion 2 process.

The target address can be supplied directly, loaded from the JSON emitted by
locate_openssl_rsa.py, or located automatically.  With --capture, only calls
whose 256-byte input matches the latest validated 11 36 block are persisted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

try:
    from .decrypt_handshake import latest_pair
    from .locate_openssl_rsa import scan as locate_rsa
except ImportError:  # Direct execution: python tools/capture_rsa_plaintext.py
    from decrypt_handshake import latest_pair
    from locate_openssl_rsa import scan as locate_rsa


def parse_address(value: str) -> int:
    return int(value, 0)


def address_from_report(path: Path) -> int:
    report = json.loads(path.read_text(encoding="utf-8"))
    for group in report.get("hits", []):
        for wrapper in group.get("wrappers", []):
            if wrapper.get("name") == "RSA_private_decrypt":
                return int(wrapper["address"], 0)
    raise SystemExit(f"no RSA_private_decrypt address in {path}")


def locate_address(pid: int) -> int:
    hits, _stats = locate_rsa(pid, 4 << 20, 512 << 20)
    for group in hits:
        for wrapper in group["wrappers"]:
            if wrapper["name"] == "RSA_private_decrypt":
                return int(wrapper["address"], 0)
    raise SystemExit("RSA_private_decrypt wrapper group not found")


def expected_server_block(path: Path | None) -> tuple[str | None, dict | None]:
    if path is None:
        return None, None
    client, server = latest_pair(path.resolve())
    return server.ciphertext_sha256, {
        "capture": path.name,
        "revision": client.revision,
        "region": client.region,
        "modulus_sha256": client.modulus_sha256,
        "ciphertext_sha256": server.ciphertext_sha256,
    }


def javascript(address: int) -> str:
    return f"""
'use strict';

const target = ptr('0x{address:X}');
let sequence = 0;

Interceptor.attach(target, {{
  onEnter(args) {{
    this.callId = ++sequence;
    this.flen = args[0].toInt32();
    this.input = args[1];
    this.output = args[2];
    this.rsa = args[3];
    try {{
      this.padding = this.context.rsp.add(0x28).readS32();
    }} catch (error) {{
      this.padding = -2147483648;
    }}

    if (this.flen > 0 && this.flen <= 4096) {{
      try {{
        send({{
          phase: 'entry',
          call_id: this.callId,
          flen: this.flen,
          input: this.input.toString(),
          output: this.output.toString(),
          rsa: this.rsa.toString(),
          padding: this.padding
        }}, this.input.readByteArray(this.flen));
      }} catch (error) {{
        send({{ phase: 'error', call_id: this.callId, where: 'entry', error: error.toString() }});
      }}
    }}
  }},

  onLeave(retval) {{
    const length = retval.toInt32();
    if (length >= 0 && length <= 4096) {{
      try {{
        send({{
          phase: 'return',
          call_id: this.callId,
          result_length: length
        }}, this.output.readByteArray(length));
      }} catch (error) {{
        send({{ phase: 'error', call_id: this.callId, where: 'return', error: error.toString() }});
      }}
    }} else {{
      send({{ phase: 'return', call_id: this.callId, result_length: length }});
    }}
  }}
}});

send({{ phase: 'ready', address: target.toString() }});
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--address", type=parse_address, help="runtime RSA_private_decrypt address")
    source.add_argument("--locator-json", type=Path, help="output from locate_openssl_rsa.py")
    parser.add_argument("--capture", type=Path, help="pcapng used to filter the exact server RSA block")
    parser.add_argument("--output", type=Path, default=Path("artifacts/rsa-runtime-capture.jsonl"))
    args = parser.parse_args()

    try:
        import frida
    except ImportError as error:
        raise SystemExit("install dependency: python -m pip install frida") from error

    if args.address is not None:
        address = args.address
    elif args.locator_json is not None:
        address = address_from_report(args.locator_json.resolve())
    else:
        address = locate_address(args.pid)

    expected_hash, handshake = expected_server_block(args.capture)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    entries: dict[int, dict] = {}
    lock = threading.Lock()

    def on_message(message, data) -> None:
        if message.get("type") == "error":
            print(json.dumps(message, indent=2), file=sys.stderr, flush=True)
            return
        payload = message.get("payload", {})
        phase = payload.get("phase")
        if phase == "ready":
            print(
                json.dumps(
                    {
                        "status": "hook-ready",
                        "pid": args.pid,
                        "address": payload.get("address"),
                        "expected_ciphertext_sha256": expected_hash,
                    }
                ),
                flush=True,
            )
            return
        if phase == "error":
            print(json.dumps(payload), file=sys.stderr, flush=True)
            return

        call_id = int(payload["call_id"])
        if phase == "entry":
            input_bytes = bytes(data or b"")
            input_hash = hashlib.sha256(input_bytes).hexdigest()
            entry = dict(payload)
            entry["input_hex"] = input_bytes.hex()
            entry["input_sha256"] = input_hash
            entry["matches_capture"] = expected_hash is None or input_hash == expected_hash
            with lock:
                entries[call_id] = entry
            if payload.get("flen") == 256:
                print(
                    json.dumps(
                        {
                            "phase": "entry",
                            "call_id": call_id,
                            "flen": payload.get("flen"),
                            "padding": payload.get("padding"),
                            "input_sha256": input_hash,
                            "matches_capture": entry["matches_capture"],
                        }
                    ),
                    flush=True,
                )
            return

        if phase == "return":
            with lock:
                entry = entries.pop(call_id, None)
            if entry is None:
                return
            output_bytes = bytes(data or b"")
            record = {
                "schema": "aion2-rsa-runtime-capture/v1",
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "pid": args.pid,
                "function_address": f"0x{address:016X}",
                "handshake": handshake,
                "call": entry,
                "result_length": payload.get("result_length"),
                "plaintext_sha256": hashlib.sha256(output_bytes).hexdigest(),
                "plaintext_hex": output_bytes.hex(),
            }
            if entry["matches_capture"] and entry.get("flen") == 256:
                with args.output.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(record, separators=(",", ":")) + "\n")
                print(
                    json.dumps(
                        {
                            "status": "captured",
                            "output": str(args.output),
                            "padding": entry.get("padding"),
                            "result_length": payload.get("result_length"),
                            "plaintext_sha256": record["plaintext_sha256"],
                            "plaintext_hex": record["plaintext_hex"],
                        }
                    ),
                    flush=True,
                )

    session = frida.attach(args.pid)
    script = session.create_script(javascript(address))
    script.on("message", on_message)
    script.load()
    print("waiting for RSA handshake calls; press Ctrl+C to stop", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        script.unload()
        session.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
