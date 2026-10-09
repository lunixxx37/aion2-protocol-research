#!/usr/bin/env python3
"""Probe contiguous Aion 2 ping keystream runs for simple PRNG structure."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path


FRAME_WIRE_SIZE = 11  # one-byte outer length plus ten encrypted body bytes


def load_samples(path: Path, modulus_hash: str) -> list[dict]:
    report = json.loads(path.read_text(encoding="utf-8"))
    for flow in report.get("flows", []):
        if flow.get("modulus_sha256", "").lower() == modulus_hash.lower():
            samples = flow.get("samples", [])
            if samples:
                return samples
    raise SystemExit("sample report has no retained samples for the selected modulus")


def contiguous_runs(samples: list[dict]) -> list[list[dict]]:
    runs: list[list[dict]] = []
    current: list[dict] = []
    previous_sequence: int | None = None
    for sample in samples:
        sequence = int(sample["tcp_sequence"])
        if previous_sequence is None or sequence == previous_sequence + FRAME_WIRE_SIZE:
            current.append(sample)
        else:
            runs.append(current)
            current = [sample]
        previous_sequence = sequence
    if current:
        runs.append(current)
    return runs


def run_bytes(run: list[dict]) -> bytes:
    return b"".join(bytes.fromhex(sample["keystream_hex"]) for sample in run)


def words(data: bytes, width: int, offset: int, endian: str) -> list[int]:
    return [
        int.from_bytes(data[index : index + width], endian)
        for index in range(offset, len(data) - width + 1, width)
    ]


def xorshift(value: int, bits: int, left_a: int, right_b: int, left_c: int) -> int:
    mask = (1 << bits) - 1
    value ^= (value << left_a) & mask
    value ^= value >> right_b
    value ^= (value << left_c) & mask
    return value & mask


def lcg_candidates(values: list[int], bits: int, candidate_cap: int = 256):
    """Yield affine recurrence candidates derived from consecutive triples."""
    modulus = 1 << bits
    seen: set[tuple[int, int]] = set()
    for index in range(len(values) - 2):
        delta_1 = (values[index + 1] - values[index]) % modulus
        delta_2 = (values[index + 2] - values[index + 1]) % modulus
        divisor = math.gcd(delta_1, modulus)
        if delta_2 % divisor:
            continue
        reduced_modulus = modulus // divisor
        if divisor > candidate_cap or reduced_modulus == 1:
            continue
        base = (
            (delta_2 // divisor)
            * pow(delta_1 // divisor, -1, reduced_modulus)
        ) % reduced_modulus
        for multiple in range(divisor):
            multiplier = base + multiple * reduced_modulus
            increment = (values[index + 1] - multiplier * values[index]) % modulus
            pair = (multiplier, increment)
            if pair not in seen:
                seen.add(pair)
                yield pair


def follows_lcg(values: list[int], bits: int, multiplier: int, increment: int) -> bool:
    mask = (1 << bits) - 1
    return all(
        ((multiplier * current + increment) & mask) == following
        for current, following in zip(values, values[1:])
    )


def probe_word_recurrences(runs: list[list[dict]]) -> tuple[list[dict], dict]:
    matches: list[dict] = []
    stats = {
        "word_views_tested": 0,
        "lcg_parameter_pairs_tested": 0,
        "xorshift_parameter_sets_tested": 0,
        "xorshift64star_parameter_sets_tested": 0,
    }
    shifts = {
        32: [(13, 17, 5), (5, 17, 13), (13, 7, 17), (15, 4, 21), (3, 1, 14), (10, 5, 26), (16, 5, 1)],
        64: [(13, 7, 17), (12, 25, 27), (7, 9, 13), (21, 35, 4)],
    }
    multiplier_64star = 2685821657736338717
    inverse_64star = pow(multiplier_64star, -1, 1 << 64)

    for run_index, run in enumerate(runs):
        data = run_bytes(run)
        for width in (4, 8):
            bits = width * 8
            for offset in range(width):
                for endian in ("little", "big"):
                    values = words(data, width, offset, endian)
                    if len(values) < 8:
                        continue
                    stats["word_views_tested"] += 1

                    for multiplier, increment in lcg_candidates(values, bits):
                        stats["lcg_parameter_pairs_tested"] += 1
                        if follows_lcg(values, bits, multiplier, increment):
                            matches.append(
                                {
                                    "family": f"LCG{bits}",
                                    "run_index": run_index,
                                    "run_frames": len(run),
                                    "offset": offset,
                                    "endian": endian,
                                    "words": len(values),
                                    "multiplier": multiplier,
                                    "increment": increment,
                                }
                            )

                    for parameters in shifts[bits]:
                        stats["xorshift_parameter_sets_tested"] += 1
                        if all(
                            xorshift(current, bits, *parameters) == following
                            for current, following in zip(values, values[1:])
                        ):
                            matches.append(
                                {
                                    "family": f"XorShift{bits}",
                                    "run_index": run_index,
                                    "run_frames": len(run),
                                    "offset": offset,
                                    "endian": endian,
                                    "words": len(values),
                                    "parameters": parameters,
                                }
                            )

                    if bits == 64:
                        for parameters in shifts[64]:
                            stats["xorshift64star_parameter_sets_tested"] += 1
                            states = [(value * inverse_64star) & ((1 << 64) - 1) for value in values]
                            if all(
                                xorshift(current, 64, *parameters) == following
                                for current, following in zip(states, states[1:])
                            ):
                                matches.append(
                                    {
                                        "family": "XorShift64Star",
                                        "run_index": run_index,
                                        "run_frames": len(run),
                                        "offset": offset,
                                        "endian": endian,
                                        "words": len(values),
                                        "parameters": parameters,
                                        "output_multiplier": multiplier_64star,
                                    }
                                )
    return matches, stats


def probe_chunk_chains(runs: list[list[dict]]) -> tuple[list[dict], dict]:
    matches: list[dict] = []
    stats = {
        "runs_with_at_least_8_frames": 0,
        "hash_chain_constructions_tested": 0,
        "constant_chunk_delta_constructions_tested": 0,
        "exact_byte_periods_tested": 0,
    }
    digest_names = ("md5", "sha1", "sha256", "sha384", "sha512", "blake2s", "blake2b")

    for run_index, run in enumerate(runs):
        if len(run) < 8:
            continue
        stats["runs_with_at_least_8_frames"] += 1
        chunks = [bytes.fromhex(sample["keystream_hex"]) for sample in run]

        for digest_name in digest_names:
            for side in ("prefix", "suffix"):
                stats["hash_chain_constructions_tested"] += 1
                outputs = [hashlib.new(digest_name, chunk).digest() for chunk in chunks[:-1]]
                predicted = [output[:10] if side == "prefix" else output[-10:] for output in outputs]
                if predicted == chunks[1:]:
                    matches.append(
                        {
                            "family": "HashChain",
                            "run_index": run_index,
                            "run_frames": len(run),
                            "digest": digest_name,
                            "output_side": side,
                        }
                    )

        xor_deltas = [bytes(a ^ b for a, b in zip(left, right)) for left, right in zip(chunks, chunks[1:])]
        add_deltas = [bytes((b - a) & 0xFF for a, b in zip(left, right)) for left, right in zip(chunks, chunks[1:])]
        for operation, deltas in (("xor", xor_deltas), ("add-mod-256", add_deltas)):
            stats["constant_chunk_delta_constructions_tested"] += 1
            if len(set(deltas)) == 1:
                matches.append(
                    {
                        "family": "ConstantChunkDelta",
                        "run_index": run_index,
                        "run_frames": len(run),
                        "operation": operation,
                        "delta_hex": deltas[0].hex(),
                    }
                )

        data = run_bytes(run)
        for period in range(1, min(512, len(data) // 2) + 1):
            stats["exact_byte_periods_tested"] += 1
            if all(data[index] == data[index - period] for index in range(period, len(data))):
                matches.append(
                    {
                        "family": "ExactBytePeriod",
                        "run_index": run_index,
                        "run_frames": len(run),
                        "period_bytes": period,
                    }
                )
                break
    return matches, stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples-json", required=True, type=Path)
    parser.add_argument("--modulus-sha256", required=True)
    parser.add_argument("--json", dest="json_path", type=Path)
    args = parser.parse_args()

    samples = load_samples(args.samples_json.resolve(), args.modulus_sha256)
    runs = contiguous_runs(samples)
    ordered = sorted(enumerate(runs), key=lambda item: len(item[1]), reverse=True)
    recurrence_matches, recurrence_stats = probe_word_recurrences(runs)
    chain_matches, chain_stats = probe_chunk_chains(runs)
    matches = recurrence_matches + chain_matches
    longest_bytes = len(ordered[0][1]) * 10
    report = {
        "schema": "aion2-keystream-prng-probe/v1",
        "modulus_sha256": args.modulus_sha256.lower(),
        "known_plaintext_samples": len(samples),
        "continuity_rule": "next tcp_sequence == previous tcp_sequence + 11",
        "contiguous_runs": len(runs),
        "longest_runs_frames": [len(run) for _, run in ordered[:20]],
        "longest_run_keystream_bytes": longest_bytes,
        "mt19937_direct_state_test": {
            "required_aligned_output_bytes": 624 * 4,
            "available_longest_run_bytes": longest_bytes,
            "status": "ready" if longest_bytes >= 624 * 4 else "insufficient-contiguous-output",
        },
        "tests": {**recurrence_stats, **chain_stats},
        "exact_matches": len(matches),
        "matches": matches,
        "interpretation": (
            "A null result rejects only the explicitly listed direct-output recurrences and chains; "
            "it does not reject a cryptographic stream cipher, a KDF, or a PRNG behind another output transform."
        ),
    }
    rendered = json.dumps(report, indent=2)
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
