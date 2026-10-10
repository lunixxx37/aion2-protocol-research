#!/usr/bin/env python3
"""Watch the Aion 2 world connection and refresh its runtime session key.

The monitor discovers the process through the established world TCP socket.
After the first signature/owner lookup it reuses process-local addresses and
reads only the two small RC4 state objects. A reconnect or process restart
causes automatic rediscovery. Key bytes are written only to the requested
local file; console and JSON reports contain the SHA-256 fingerprint.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from .locate_session_key import (
        ProcessReader,
        discover_world_pid,
        established_tcp_pids,
        locate_rc4_vtable,
        locate_states,
        locate_states_via_owner_arena,
        select_key,
        validate_rc4_state,
    )
except ImportError:  # Direct execution: python tools/watch_session_key.py
    from locate_session_key import (
        ProcessReader,
        discover_world_pid,
        established_tcp_pids,
        locate_rc4_vtable,
        locate_states,
        locate_states_via_owner_arena,
        select_key,
        validate_rc4_state,
    )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def append_json_line(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, separators=(",", ":")) + "\n")


def close_context(context: dict | None) -> None:
    if context is not None:
        context["reader"].close()


def initialize_context(
    pid: int,
    chunk_size: int,
    max_region: int,
    full_scan_fallback: bool,
    fallback_after_misses: int,
) -> dict:
    reader = ProcessReader(pid)
    try:
        module = reader.main_module()
        vtable, signature_stats = locate_rc4_vtable(reader, module, chunk_size)
    except BaseException:
        reader.close()
        raise
    return {
        "pid": pid,
        "reader": reader,
        "module": module,
        "vtable": vtable,
        "signature_stats": signature_stats,
        "owner": None,
        "state_addresses": [],
        "chunk_size": chunk_size,
        "max_region": max_region,
        "full_scan_fallback": full_scan_fallback,
        "fallback_after_misses": fallback_after_misses,
        "fast_misses": 0,
        "fallback_attempted": False,
    }


def read_session(context: dict) -> tuple[dict, bytes] | None:
    reader = context["reader"]

    if context["state_addresses"]:
        cached_hits = []
        cached_keys = {}
        for address in context["state_addresses"]:
            validated = validate_rc4_state(reader, address, context["vtable"], None)
            if validated is None:
                continue
            item, key = validated
            cached_hits.append(item)
            cached_keys[item["key_sha256"]] = key
        cached_selected = select_key(cached_hits, cached_keys)
        if cached_selected is not None:
            key_hash, key = cached_selected
            return (
                {
                    "network_owner": None,
                    "session_key_sha256": key_hash,
                    "state_objects": cached_hits,
                    "state_lookup": {
                        "method": "cached_state_addresses",
                        "objects_read": len(context["state_addresses"]),
                    },
                },
                key,
            )
        context["state_addresses"] = []
        context["fast_misses"] = 0
        context["fallback_attempted"] = False

    hits, keys, stats, owner = locate_states_via_owner_arena(
        reader,
        context["vtable"],
        None,
        context["owner"],
    )
    if not hits and context["owner"] is not None:
        hits, keys, stats, owner = locate_states_via_owner_arena(
            reader,
            context["vtable"],
            None,
            None,
        )
    selected = select_key(hits, keys)
    if selected is not None:
        key_hash, key = selected
        context["owner"] = owner
        context["fast_misses"] = 0
        return (
            {
                "network_owner": f"0x{owner:016X}" if owner is not None else None,
                "session_key_sha256": key_hash,
                "state_objects": hits,
                "state_lookup": stats,
            },
            key,
        )

    context["fast_misses"] += 1
    if (
        not context["full_scan_fallback"]
        or context["fallback_attempted"]
        or context["fast_misses"] < context["fallback_after_misses"]
    ):
        return None

    context["fallback_attempted"] = True
    fallback_hits, fallback_keys, fallback_stats = locate_states(
        reader,
        context["vtable"],
        context["chunk_size"],
        context["max_region"],
        None,
    )
    fallback_selected = select_key(fallback_hits, fallback_keys)
    if fallback_selected is None:
        return None
    key_hash, key = fallback_selected
    context["state_addresses"] = [
        int(item["address"], 16)
        for item in fallback_hits
        if item["key_sha256"] == key_hash
    ]
    return (
        {
            "network_owner": None,
            "session_key_sha256": key_hash,
            "state_objects": fallback_hits,
            "state_lookup": {
                "method": "full_private_memory_fallback",
                "owner_arena": stats,
                "fallback": fallback_stats,
            },
        },
        key,
    )


def render_event(
    context: dict,
    session: dict,
    key_out: Path,
    lookup_ms: float,
) -> dict:
    return {
        "schema": "aion2-session-key-event/v1",
        "observed_at": utc_now(),
        "pid": context["pid"],
        "module": {
            "name": context["module"]["name"],
            "base": f"0x{context['module']['base']:016X}",
            "size": context["module"]["size"],
        },
        "rc4_vtable": f"0x{context['vtable']:016X}",
        "network_owner": session["network_owner"],
        "session_key": {
            "length": 214,
            "sha256": session["session_key_sha256"],
            "output_path": str(key_out.resolve()),
        },
        "state_objects": session["state_objects"],
        "lookup_ms": round(lookup_ms, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=13328)
    parser.add_argument("--process-name", default="AION2.exe")
    parser.add_argument(
        "--key-out",
        type=Path,
        default=Path("artifacts/current-session-key.bin"),
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        type=Path,
        help="atomic JSON snapshot of the latest detected session",
    )
    parser.add_argument(
        "--events-jsonl",
        type=Path,
        help="optional append-only metadata log for session changes",
    )
    parser.add_argument("--poll-interval", type=float, default=0.25)
    parser.add_argument("--chunk-size", type=int, default=8 << 20)
    parser.add_argument("--max-region", type=int, default=512 << 20)
    parser.add_argument(
        "--full-scan-fallback",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "perform one validated full-memory lookup when the fast owner-arena "
            "profile misses (default: enabled)"
        ),
    )
    parser.add_argument(
        "--fallback-after-misses",
        type=int,
        default=4,
        help="number of fast misses before the one-time fallback (default: 4)",
    )
    parser.add_argument(
        "--max-polls",
        type=int,
        default=0,
        help="stop after N polls; zero keeps watching",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=0,
        help="stop after N new session keys; zero keeps watching",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    if args.poll_interval < 0:
        raise SystemExit("--poll-interval must be zero or greater")
    if args.fallback_after_misses < 1:
        raise SystemExit("--fallback-after-misses must be at least one")
    if args.max_polls < 0 or args.max_events < 0:
        raise SystemExit("--max-polls and --max-events must be zero or greater")

    context: dict | None = None
    last_key_hash: str | None = None
    last_discovery_error: str | None = None
    polls = 0
    events = 0
    poll_timings: list[float] = []
    cached_poll_timings: list[float] = []
    try:
        while not args.max_polls or polls < args.max_polls:
            poll_started = time.perf_counter()
            polls += 1
            connected_pids = established_tcp_pids(args.port)
            active_pid = context["pid"] if context is not None else None
            cached_poll = context is not None and active_pid in connected_pids
            if active_pid not in connected_pids:
                close_context(context)
                context = None
                last_key_hash = None
                try:
                    pid, _discovery = discover_world_pid(
                        args.port, args.process_name
                    )
                    context = initialize_context(
                        pid,
                        args.chunk_size,
                        args.max_region,
                        args.full_scan_fallback,
                        args.fallback_after_misses,
                    )
                    last_discovery_error = None
                except SystemExit as error:
                    context = None
                    message = str(error)
                    if connected_pids and message != last_discovery_error:
                        print(
                            f"session-key watcher: {message}",
                            file=sys.stderr,
                            flush=True,
                        )
                    last_discovery_error = message

            if context is not None:
                session_started = time.perf_counter()
                session = read_session(context)
                lookup_ms = (time.perf_counter() - session_started) * 1000
                if session is not None:
                    session_data, key = session
                    key_hash = session_data["session_key_sha256"]
                    if key_hash != last_key_hash:
                        atomic_write(args.key_out.resolve(), key)
                        event = render_event(
                            context,
                            session_data,
                            args.key_out,
                            lookup_ms,
                        )
                        if args.json_path is not None:
                            atomic_write(
                                args.json_path.resolve(),
                                (json.dumps(event, indent=2) + "\n").encode("utf-8"),
                            )
                        if args.events_jsonl is not None:
                            append_json_line(args.events_jsonl.resolve(), event)
                        if not args.quiet:
                            print(json.dumps(event, indent=2), flush=True)
                        last_key_hash = key_hash
                        events += 1
                        if args.max_events and events >= args.max_events:
                            elapsed_ms = (time.perf_counter() - poll_started) * 1000
                            poll_timings.append(elapsed_ms)
                            if cached_poll:
                                cached_poll_timings.append(elapsed_ms)
                            break

            elapsed_ms = (time.perf_counter() - poll_started) * 1000
            poll_timings.append(elapsed_ms)
            if cached_poll:
                cached_poll_timings.append(elapsed_ms)
            if args.poll_interval:
                time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        pass
    finally:
        close_context(context)

    if args.max_polls or args.max_events:
        summary = {
            "schema": "aion2-session-key-monitor-summary/v1",
            "polls": polls,
            "events": events,
            "cached_polls": len(cached_poll_timings),
            "poll_ms": {
                "minimum": round(min(poll_timings), 3) if poll_timings else None,
                "average": (
                    round(sum(poll_timings) / len(poll_timings), 3)
                    if poll_timings
                    else None
                ),
                "maximum": round(max(poll_timings), 3) if poll_timings else None,
            },
            "cached_poll_ms": {
                "minimum": (
                    round(min(cached_poll_timings), 3)
                    if cached_poll_timings
                    else None
                ),
                "average": (
                    round(sum(cached_poll_timings) / len(cached_poll_timings), 3)
                    if cached_poll_timings
                    else None
                ),
                "maximum": (
                    round(max(cached_poll_timings), 3)
                    if cached_poll_timings
                    else None
                ),
            },
        }
        print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
