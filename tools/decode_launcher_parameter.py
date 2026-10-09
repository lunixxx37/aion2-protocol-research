#!/usr/bin/env python3
"""Decode an Aion 2 ``-lp`` value and report its structure.

Input is read from standard input unless ``--encoded`` or ``--encoded-file``
is supplied. Field values are redacted by default.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.aion2_client_crypto import (  # noqa: E402
    LAUNCH_PARAMETER_AES_KEY,
    decrypt_launcher_parameter,
)


def split_plaintext(plaintext: str) -> tuple[str, list[tuple[str, str, str]]]:
    """Return the marker and ``(name, separator, value)`` field tuples."""
    segments = plaintext.split("&")
    marker = segments[0]
    fields: list[tuple[str, str, str]] = []
    for index, segment in enumerate(segments[1:], start=1):
        candidates = [
            (offset, separator)
            for offset, separator in (
                (segment.find("="), "="),
                (segment.find(":"), ":"),
            )
            if offset >= 0
        ]
        if not candidates:
            raise ValueError(f"launcher field {index} has no recognized separator")
        offset, separator = min(candidates)
        name = segment[:offset]
        value = segment[offset + 1 :]
        if not name:
            raise ValueError(f"launcher field {index} has an empty name")
        fields.append((name, separator, value))
    return marker, fields


def load_encoded(args: argparse.Namespace) -> str:
    if args.encoded is not None:
        value = args.encoded
    elif args.encoded_file is not None:
        value = args.encoded_file.read_text(encoding="ascii")
    else:
        value = sys.stdin.read()
    value = value.strip()
    if not value:
        raise ValueError("launcher parameter input is empty")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--encoded", help="Base64 -lp value")
    source.add_argument(
        "--encoded-file",
        type=Path,
        help="text file containing the Base64 value",
    )
    parser.add_argument(
        "--show-values",
        action="store_true",
        help="include decoded field values instead of redacting them",
    )
    parser.add_argument("--json", dest="json_path", type=Path)
    args = parser.parse_args()

    try:
        encoded = load_encoded(args)
        ciphertext_length = len(base64.b64decode(encoded, validate=True))
        plaintext = decrypt_launcher_parameter(encoded)
        marker, fields = split_plaintext(plaintext)
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(str(error))

    report = {
        "schema": "aion2-launch-parameter/v1",
        "encoded_length": len(encoded),
        "ciphertext_length": ciphertext_length,
        "plaintext_length": len(plaintext.encode("utf-8")),
        "marker_matches_key": marker.encode("utf-8") == LAUNCH_PARAMETER_AES_KEY,
        "fields": [
            {
                "name": name,
                "separator": separator,
                "value_length": len(value),
                **({"value": value} if args.show_values else {}),
            }
            for name, separator, value in fields
        ],
    }
    rendered = json.dumps(report, indent=2)
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
