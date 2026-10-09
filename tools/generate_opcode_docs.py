#!/usr/bin/env python3
"""Validate protocol/opcodes.json and generate docs/OPCODES.md."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "protocol" / "opcodes.json"
DEFAULT_OUTPUT = ROOT / "docs" / "OPCODES.md"
WIRE_PATTERN = re.compile(r"^[0-9A-F]{4}$")
ALLOWED_DIRECTIONS = {"C2S", "S2C"}
ALLOWED_PHASES = {"login", "lobby", "world"}
ALLOWED_ENCRYPTION = {"clear", "rc4", "unknown"}
ALLOWED_CONFIDENCE = {
    "locally-confirmed",
    "publicly-confirmed",
    "parser-based",
    "inferred",
    "observed",
    "hypothesis",
}


def load_registry(path: Path) -> dict:
    try:
        registry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"failed to load opcode registry: {error}") from error
    validate_registry(registry)
    return registry


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_lengths(lengths, context: str) -> None:
    require(isinstance(lengths, list), f"{context}: body_lengths must be a list")
    require(
        all(isinstance(value, int) and value >= 2 for value in lengths),
        f"{context}: body lengths must be integers >= 2",
    )
    require(lengths == sorted(set(lengths)), f"{context}: body lengths must be sorted and unique")


def validate_registry(registry: dict) -> None:
    require(registry.get("schema_version") == 1, "schema_version must equal 1")
    require(isinstance(registry.get("confidence_levels"), dict), "missing confidence_levels")
    require(isinstance(registry.get("opcodes"), list), "opcodes must be a list")

    seen: set[tuple[str, str, str]] = set()
    semantic_keys: set[tuple[str, str]] = set()
    for index, entry in enumerate(registry["opcodes"]):
        context = f"opcodes[{index}]"
        wire = entry.get("wire")
        require(isinstance(wire, str) and WIRE_PATTERN.fullmatch(wire), f"{context}: invalid wire opcode")
        require(entry.get("phase") in ALLOWED_PHASES, f"{context}: invalid phase")
        directions = entry.get("directions")
        require(
            isinstance(directions, list)
            and directions
            and set(directions) <= ALLOWED_DIRECTIONS,
            f"{context}: invalid directions",
        )
        require(entry.get("encryption") in ALLOWED_ENCRYPTION, f"{context}: invalid encryption")
        require(entry.get("confidence") in ALLOWED_CONFIDENCE, f"{context}: invalid confidence")
        require(isinstance(entry.get("name"), str) and entry["name"], f"{context}: missing name")
        validate_lengths(entry.get("body_lengths", []), context)
        for direction in directions:
            identity = (entry["phase"], direction, wire)
            require(identity not in seen, f"{context}: duplicate {identity}")
            seen.add(identity)
            semantic_keys.add((direction, wire))
        fields = entry.get("fields", [])
        require(isinstance(fields, list), f"{context}: fields must be a list")
        for field_index, field in enumerate(fields):
            require(isinstance(field.get("name"), str), f"{context}.fields[{field_index}]: missing name")
            require(isinstance(field.get("type"), str), f"{context}.fields[{field_index}]: missing type")
            require(
                isinstance(field.get("offset"), (int, str)),
                f"{context}.fields[{field_index}]: invalid offset",
            )

    observations = registry.get("observations", {}).get("world_c2s", {})
    require(isinstance(observations, dict), "observations.world_c2s must be an object")
    total_frames = 0
    for wire, observation in observations.items():
        context = f"observations.world_c2s.{wire}"
        require(WIRE_PATTERN.fullmatch(wire) is not None, f"{context}: invalid wire opcode")
        require(
            isinstance(observation.get("frames"), int) and observation["frames"] > 0,
            f"{context}: frames must be positive",
        )
        validate_lengths(observation.get("body_lengths", []), context)
        total_frames += observation["frames"]

    snapshot = registry.get("capture_snapshot", {})
    require(snapshot.get("total_frames") == total_frames, "capture total_frames does not equal opcode counts")
    require(snapshot.get("sessions") >= 1, "capture sessions must be positive")
    require(snapshot.get("rc4_body_bytes") >= total_frames * 2, "invalid RC4 body-byte total")


def little_endian_value(wire: str) -> str:
    return f"0x{int.from_bytes(bytes.fromhex(wire), 'little'):04X}"


def escape_cell(value) -> str:
    if value is None:
        return "—"
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value) if value else "—"
    return str(value).replace("|", "\\|").replace("\n", " ")


def merged_entries(registry: dict) -> list[dict]:
    entries = [dict(entry) for entry in registry["opcodes"]]
    by_c2s_wire = {
        entry["wire"]: entry
        for entry in entries
        if entry["phase"] == "world" and "C2S" in entry["directions"]
    }
    for wire, observation in registry["observations"]["world_c2s"].items():
        entry = by_c2s_wire.get(wire)
        if entry is None:
            entry = {
                "wire": wire,
                "phase": "world",
                "directions": ["C2S"],
                "name": f"UNKNOWN_C2S_{wire}",
                "encryption": "rc4",
                "confidence": "observed",
                "body_lengths": [],
                "notes": "Observed after successful RC4 decryption; semantics not assigned.",
                "fields": [],
            }
            entries.append(entry)
            by_c2s_wire[wire] = entry
        entry["observed_frames"] = observation["frames"]
        if observation.get("notes") and entry["name"].startswith("UNKNOWN_C2S_"):
            entry["notes"] = observation["notes"]
        if observation["body_lengths"]:
            entry["body_lengths"] = sorted(
                set(entry.get("body_lengths", [])) | set(observation["body_lengths"])
            )
    return entries


def table(lines: list[str], headers: list[str], rows: list[list[object]]) -> None:
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + "|".join("---" for _ in headers) + "|")
    for row in rows:
        lines.append("| " + " | ".join(escape_cell(value) for value in row) + " |")
    lines.append("")


def render(registry: dict) -> str:
    entries = merged_entries(registry)
    snapshot = registry["capture_snapshot"]
    lines = [
        "# Opcode Catalog",
        "",
        "<!-- Generated by tools/generate_opcode_docs.py from protocol/opcodes.json. -->",
        "",
        "Opcodes are written in wire order. The little-endian value is how a `uint16`",
        "reader represents the same two bytes. Treat observed frequency as structural",
        "evidence, not as proof of packet meaning.",
        "",
        "## Capture snapshot",
        "",
        f"The local C2S snapshot combines **{snapshot['sessions']:,}** independently keyed",
        f"world sessions, **{snapshot['total_frames']:,}** decrypted frames, and",
        f"**{snapshot['rc4_body_bytes']:,}** RC4 body bytes. It contains",
        f"**{snapshot['client_time_frames']:,}** confirmed `01 36` time packets.",
        f"Snapshot date: `{snapshot['date']}`; client revisions:",
        ", ".join(f"`{revision}`" for revision in snapshot["client_revisions"]) + ".",
        "",
        "## Mapped opcodes",
        "",
    ]

    mapped = [entry for entry in entries if not entry["name"].startswith("UNKNOWN_")]
    mapped.sort(key=lambda entry: (entry["phase"], entry["wire"], ",".join(entry["directions"])))
    table(
        lines,
        ["Wire", "LE value", "Phase", "Direction", "Name", "Frames", "Body lengths", "Confidence"],
        [
            [
                f"`{entry['wire'][:2]} {entry['wire'][2:]}`",
                f"`{little_endian_value(entry['wire'])}`",
                entry["phase"],
                "/".join(entry["directions"]),
                f"`{entry['name']}`",
                f"{entry['observed_frames']:,}" if entry.get("observed_frames") else "—",
                entry.get("body_lengths", []),
                entry["confidence"],
            ]
            for entry in mapped
        ],
    )

    lines.extend(["## Observed C2S opcodes with open semantics", ""])
    unknown = [entry for entry in entries if entry["name"].startswith("UNKNOWN_C2S_")]
    unknown.sort(key=lambda entry: (-entry.get("observed_frames", 0), entry["wire"]))
    table(
        lines,
        ["Wire", "LE value", "Frames", "Sampled body lengths", "Notes"],
        [
            [
                f"`{entry['wire'][:2]} {entry['wire'][2:]}`",
                f"`{little_endian_value(entry['wire'])}`",
                f"{entry.get('observed_frames', 0):,}",
                entry.get("body_lengths", []),
                entry.get("notes", ""),
            ]
            for entry in unknown
        ],
    )

    lines.extend(["## Confirmed and partial field layouts", ""])
    for entry in mapped:
        fields = entry.get("fields", [])
        if not fields:
            continue
        lines.extend(
            [
                f"### `{entry['wire'][:2]} {entry['wire'][2:]}` — `{entry['name']}`",
                "",
            ]
        )
        if entry.get("notes"):
            lines.extend([entry["notes"], ""])
        table(
            lines,
            ["Offset", "Type", "Field", "Status"],
            [
                [field["offset"], f"`{field['type']}`", f"`{field['name']}`", field.get("status", "confirmed")]
                for field in fields
            ],
        )

    lines.extend(["## Confidence levels", ""])
    table(
        lines,
        ["Level", "Meaning"],
        [[f"`{name}`", meaning] for name, meaning in registry["confidence_levels"].items()],
    )
    lines.extend(
        [
            "## Updating the registry",
            "",
            "Edit `protocol/opcodes.json`, then regenerate and validate:",
            "",
            "```powershell",
            "python tools/generate_opcode_docs.py --write",
            "python tools/generate_opcode_docs.py --check",
            "```",
            "",
            "Raw payloads, session identifiers, and capture-specific secrets must remain",
            "in ignored local artifacts.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write", action="store_true", help="write the generated Markdown")
    group.add_argument("--check", action="store_true", help="fail if the Markdown is stale")
    args = parser.parse_args()

    try:
        registry = load_registry(args.registry)
    except ValueError as error:
        raise SystemExit(f"invalid opcode registry: {error}") from error
    rendered = render(registry)
    if args.write:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
        print(f"wrote {args.output}")
        return 0
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.exists() else ""
        if current != rendered:
            raise SystemExit(f"generated documentation is stale: run {Path(__file__).name} --write")
        print("opcode registry and generated documentation: OK")
        return 0
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
