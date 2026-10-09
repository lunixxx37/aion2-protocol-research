#!/usr/bin/env python3
"""Extract privacy-preserving Aion 2 handshake and C2S statistics.

The fast pass scans pcap/pcapng bytes for the validated, uncompressed handshake
signatures.  --deep additionally reassembles a bounded prefix of TCP flows with
Scapy and parses post-handshake C2S frame lengths.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import glob
import hashlib
import json
import math
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence


CLIENT_SIGNATURE = bytes.fromhex("10368c02308201080282010100")
SERVER_SIGNATURE = bytes.fromhex("1136000060ea00008002")
SERVER_TRAILER = bytes.fromhex("0000000000000000f9ffffff")
HANDSHAKE_MARKER = bytes.fromhex("04060502")


@dataclass(frozen=True)
class ClientHandshake:
    capture: str
    file_offset: int
    revision: int
    region: str
    variant: int
    modulus_sha256: str
    der_sha256: str
    modulus: int


@dataclass(frozen=True)
class ServerHandshake:
    capture: str
    file_offset: int
    ciphertext_sha256: str
    ciphertext: bytes


def expand_inputs(patterns: Sequence[str]) -> list[Path]:
    found: dict[str, Path] = {}
    for pattern in patterns:
        matches = glob.glob(pattern, recursive=True)
        if not matches and Path(pattern).is_file():
            matches = [pattern]
        for value in matches:
            path = Path(value).resolve()
            if path.is_file() and path.suffix.lower() in {".pcap", ".pcapng"}:
                found[str(path).lower()] = path
    return sorted(found.values(), key=lambda p: str(p).lower())


def iter_file_matches(path: Path, needle: bytes, chunk_size: int = 8 << 20) -> Iterator[tuple[int, bytes]]:
    """Yield absolute offsets and a window beginning at each signature."""
    overlap = max(len(needle) - 1, 1024)
    tail = b""
    absolute = 0
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            data = tail + chunk
            base = absolute - len(tail)
            start = 0
            while True:
                index = data.find(needle, start)
                if index < 0:
                    break
                yield base + index, data[index : index + 2048]
                start = index + 1
            absolute += len(chunk)
            tail = data[-overlap:]


def parse_client_window(capture: str, offset: int, window: bytes) -> ClientHandshake | None:
    # Signature begins at the opcode. DER begins after opcode + uvarint(268).
    if not window.startswith(CLIENT_SIGNATURE):
        return None
    der = window[4 : 4 + 268]
    if len(der) != 268:
        return None
    if der[:9] != bytes.fromhex("308201080282010100"):
        return None
    if der[265:] != bytes.fromhex("020103"):
        return None
    modulus_bytes = der[9:265]
    if len(modulus_bytes) != 256 or modulus_bytes[0] == 0:
        return None
    tail = window[272 : 272 + 11]
    if len(tail) != 11 or tail[4:8] != HANDSHAKE_MARKER:
        return None
    try:
        region = tail[8:10].decode("ascii")
    except UnicodeDecodeError:
        return None
    if not region.isprintable():
        return None
    return ClientHandshake(
        capture=capture,
        file_offset=offset,
        revision=int.from_bytes(tail[:4], "little"),
        region=region,
        variant=tail[10],
        modulus_sha256=hashlib.sha256(modulus_bytes).hexdigest(),
        der_sha256=hashlib.sha256(der).hexdigest(),
        modulus=int.from_bytes(modulus_bytes, "big"),
    )


def parse_server_window(capture: str, offset: int, window: bytes) -> ServerHandshake | None:
    if not window.startswith(SERVER_SIGNATURE):
        return None
    ciphertext = window[len(SERVER_SIGNATURE) : len(SERVER_SIGNATURE) + 256]
    trailer_start = len(SERVER_SIGNATURE) + 256
    trailer = window[trailer_start : trailer_start + len(SERVER_TRAILER)]
    if len(ciphertext) != 256 or trailer != SERVER_TRAILER:
        return None
    return ServerHandshake(
        capture=capture,
        file_offset=offset,
        ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest(),
        ciphertext=ciphertext,
    )


def scan_handshakes(paths: Sequence[Path]) -> tuple[list[ClientHandshake], list[ServerHandshake]]:
    clients: list[ClientHandshake] = []
    servers: list[ServerHandshake] = []
    for path in paths:
        name = path.name
        seen_client_offsets: set[int] = set()
        seen_server_offsets: set[int] = set()
        for offset, window in iter_file_matches(path, CLIENT_SIGNATURE):
            item = parse_client_window(name, offset, window)
            if item and offset not in seen_client_offsets:
                clients.append(item)
                seen_client_offsets.add(offset)
        for offset, window in iter_file_matches(path, SERVER_SIGNATURE):
            item = parse_server_window(name, offset, window)
            if item and offset not in seen_server_offsets:
                servers.append(item)
                seen_server_offsets.add(offset)
    return clients, servers


def integer_cube_root(value: int) -> int:
    if value < 2:
        return value
    estimate = 1 << ((value.bit_length() + 2) // 3)
    while True:
        next_estimate = (2 * estimate + value // (estimate * estimate)) // 3
        if next_estimate >= estimate:
            while (estimate + 1) ** 3 <= value:
                estimate += 1
            while estimate**3 > value:
                estimate -= 1
            return estimate
        estimate = next_estimate


def small_primes(limit: int) -> list[int]:
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[:2] = b"\x00\x00"
    for value in range(2, math.isqrt(limit) + 1):
        if sieve[value]:
            start = value * value
            sieve[start : limit + 1 : value] = b"\x00" * (((limit - start) // value) + 1)
    return [value for value in range(2, limit + 1) if sieve[value]]


def weak_modulus_statistics(moduli: Sequence[int], prime_limit: int = 100_000, fermat_steps: int = 4096) -> dict:
    primes = small_primes(prime_limit)
    small_factor_hits = 0
    fermat_hits = 0
    for modulus in moduli:
        if any(modulus % prime == 0 for prime in primes):
            small_factor_hits += 1
        root = math.isqrt(modulus)
        if root * root < modulus:
            root += 1
        for _ in range(fermat_steps):
            difference = root * root - modulus
            square_root = math.isqrt(difference)
            if square_root * square_root == difference:
                fermat_hits += 1
                break
            root += 1
    return {
        "small_prime_limit": prime_limit,
        "small_prime_factor_hits": small_factor_hits,
        "fermat_steps_per_modulus": fermat_steps,
        "fermat_close_prime_hits": fermat_hits,
    }


def rsa_statistics(clients: Sequence[ClientHandshake], servers: Sequence[ServerHandshake]) -> dict:
    unique_moduli = {item.modulus for item in clients}
    shared_prime_pairs: list[tuple[int, int]] = []
    moduli = list(unique_moduli)
    for left in range(len(moduli)):
        for right in range(left + 1, len(moduli)):
            divisor = math.gcd(moduli[left], moduli[right])
            if divisor != 1:
                shared_prime_pairs.append((left, right))

    # Pair handshakes by validated occurrence order within each capture.
    clients_by_capture: dict[str, list[ClientHandshake]] = collections.defaultdict(list)
    servers_by_capture: dict[str, list[ServerHandshake]] = collections.defaultdict(list)
    for item in clients:
        clients_by_capture[item.capture].append(item)
    for item in servers:
        servers_by_capture[item.capture].append(item)

    perfect_cubes_be = 0
    perfect_cubes_le = 0
    paired = 0
    ciphertext_ge_modulus = 0
    rsa_pairs: list[tuple[ClientHandshake, int]] = []
    for capture, capture_clients in clients_by_capture.items():
        capture_clients.sort(key=lambda item: item.file_offset)
        capture_servers = sorted(servers_by_capture.get(capture, []), key=lambda item: item.file_offset)
        for client, server in zip(capture_clients, capture_servers):
            paired += 1
            be = int.from_bytes(server.ciphertext, "big")
            le = int.from_bytes(server.ciphertext, "little")
            perfect_cubes_be += integer_cube_root(be) ** 3 == be
            perfect_cubes_le += integer_cube_root(le) ** 3 == le
            ciphertext_ge_modulus += be >= client.modulus
            if be < client.modulus:
                rsa_pairs.append((client, be))

    # Håstad broadcast test: if the same unpadded plaintext was sent to three
    # independent e=3 moduli, CRT reconstructs m**3 as an exact integer cube.
    # Sliding triples are enough to falsify a session-invariant plaintext in
    # the ordered corpus without storing any recovered message in the report.
    hastad_tested = 0
    hastad_hits = 0
    for revision in sorted({client.revision for client, _ in rsa_pairs}):
        revision_pairs = [(client.modulus, ciphertext) for client, ciphertext in rsa_pairs if client.revision == revision]
        for index in range(max(0, len(revision_pairs) - 2)):
            triple = revision_pairs[index : index + 3]
            product = triple[0][0] * triple[1][0] * triple[2][0]
            combined = 0
            for modulus, ciphertext in triple:
                partial = product // modulus
                combined += ciphertext * partial * pow(partial, -1, modulus)
            combined %= product
            root = integer_cube_root(combined)
            hastad_tested += 1
            hastad_hits += root**3 == combined

    result = {
        "public_exponent": 3,
        "modulus_bits": 2048,
        "unique_moduli": len(unique_moduli),
        "shared_prime_pairs": len(shared_prime_pairs),
        "paired_client_server_handshakes": paired,
        "raw_perfect_cubes_big_endian": perfect_cubes_be,
        "raw_perfect_cubes_little_endian": perfect_cubes_le,
        "ciphertexts_not_below_paired_modulus": ciphertext_ge_modulus,
        "raw_hastad_broadcast_triplets_tested": hastad_tested,
        "raw_hastad_broadcast_hits": hastad_hits,
    }
    result.update(weak_modulus_statistics(moduli))
    return result


def decode_uvarint(data: bytes, offset: int = 0) -> tuple[int, int] | None:
    value = 0
    for width in range(1, 6):
        index = offset + width - 1
        if index >= len(data):
            return None
        byte = data[index]
        value |= (byte & 0x7F) << (7 * (width - 1))
        if byte < 0x80:
            if width > 1 and value < (1 << (7 * (width - 1))):
                return None
            return value, width
    return None


def body_length_from_physical(total: int) -> int | None:
    for width in range(1, 6):
        body_length = total - width
        if body_length < 0:
            continue
        encoded_length = body_length + 4
        expected_width = max(1, (encoded_length.bit_length() + 6) // 7)
        if expected_width == width:
            return body_length
    return None


def reassemble_prefix(segments: Sequence[tuple[int, bytes]], limit: int) -> list[bytes]:
    """Return contiguous chunks, trimming retransmitted overlaps."""
    if not segments:
        return []
    ordered = sorted(segments, key=lambda item: item[0])
    chunks: list[bytearray] = []
    start_seq = 0
    end_seq = 0
    for seq, payload in ordered:
        if not payload:
            continue
        if not chunks or seq > end_seq:
            if sum(len(chunk) for chunk in chunks) >= limit:
                break
            chunks.append(bytearray(payload[:limit]))
            start_seq = seq
            end_seq = seq + len(chunks[-1])
            continue
        if seq + len(payload) <= end_seq:
            continue
        tail_offset = max(0, end_seq - seq)
        room = limit - sum(len(chunk) for chunk in chunks)
        if room <= 0:
            break
        tail = payload[tail_offset : tail_offset + room]
        chunks[-1].extend(tail)
        end_seq += len(tail)
    return [bytes(chunk) for chunk in chunks]


def find_client_handshake_frame(data: bytes) -> tuple[int, int] | None:
    start = 0
    while True:
        body_at = data.find(CLIENT_SIGNATURE, start)
        if body_at < 0:
            return None
        for prefix_width in (1, 2, 3, 4, 5):
            frame_at = body_at - prefix_width
            if frame_at < 0:
                continue
            decoded = decode_uvarint(data, frame_at)
            if not decoded:
                continue
            encoded_length, width = decoded
            total = encoded_length + width - 4
            if width == prefix_width and frame_at + width == body_at and total >= 0:
                end = frame_at + total
                if end <= len(data) and data[body_at : body_at + len(CLIENT_SIGNATURE)] == CLIENT_SIGNATURE:
                    return frame_at, end
        start = body_at + 1


def iter_frames(data: bytes, offset: int) -> Iterator[tuple[int, bytes]]:
    while offset < len(data):
        if data[offset] == 0:
            offset += 1
            continue
        decoded = decode_uvarint(data, offset)
        if not decoded:
            return
        encoded_length, width = decoded
        if encoded_length < 6:
            return
        total = encoded_length + width - 4
        body_length = encoded_length - 4
        if total > 1 << 20 or offset + total > len(data):
            return
        body_start = offset + width
        body = data[body_start : body_start + body_length]
        yield total, body
        offset += total


def shannon_entropy(counts: collections.Counter[int]) -> float:
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def deep_c2s_statistics(paths: Sequence[Path], port: int, stream_limit: int) -> dict:
    try:
        from scapy.all import IP, IPv6, TCP, PcapReader
    except ImportError as error:
        raise SystemExit("--deep requires Scapy: python -m pip install scapy") from error

    length_counts: collections.Counter[int] = collections.Counter()
    body_byte_counts: collections.Counter[int] = collections.Counter()
    exact_bodies: dict[int, collections.Counter[bytes]] = collections.defaultdict(collections.Counter)
    parsed_flows = 0
    parsed_frames = 0
    tls_flows = 0
    gaps = 0
    read_errors: list[dict[str, str]] = []

    for path in paths:
        flows: dict[tuple, list[tuple[int, bytes]]] = collections.defaultdict(list)
        stored: collections.Counter[tuple] = collections.Counter()
        try:
            with PcapReader(str(path)) as reader:
                for packet in reader:
                    if TCP not in packet:
                        continue
                    tcp = packet[TCP]
                    if int(tcp.dport) != port:
                        continue
                    if IP in packet:
                        source, destination = packet[IP].src, packet[IP].dst
                    elif IPv6 in packet:
                        source, destination = packet[IPv6].src, packet[IPv6].dst
                    else:
                        continue
                    payload = bytes(tcp.payload)
                    if not payload:
                        continue
                    key = (source, int(tcp.sport), destination, int(tcp.dport))
                    if stored[key] >= stream_limit:
                        continue
                    flows[key].append((int(tcp.seq), payload))
                    stored[key] += len(payload)
        except Exception as error:  # Preserve usable packets from truncated active captures.
            read_errors.append({"capture": path.name, "error": str(error)})

        for segments in flows.values():
            chunks = reassemble_prefix(segments, stream_limit)
            for chunk in chunks:
                if chunk[:3] in {b"\x16\x03\x01", b"\x16\x03\x02", b"\x16\x03\x03"}:
                    tls_flows += 1
                    continue
                handshake = find_client_handshake_frame(chunk)
                if not handshake:
                    continue
                parsed_flows += 1
                _, offset = handshake
                for total, body in iter_frames(chunk, offset):
                    parsed_frames += 1
                    length_counts[total] += 1
                    body_byte_counts.update(body)
                    if total <= 64:
                        exact_bodies[total][body] += 1
            gaps += max(0, len(chunks) - 1)

    total_bodies = sum(body_byte_counts.values())
    collision_summary = {}
    for length, bodies in sorted(exact_bodies.items()):
        count = sum(bodies.values())
        duplicates = sum(value - 1 for value in bodies.values() if value > 1)
        body_length = body_length_from_physical(length) or 0
        random_pair_collisions = (count * (count - 1) / 2) / (256**body_length) if body_length else 0.0
        collision_summary[str(length)] = {
            "frames": count,
            "unique_bodies": len(bodies),
            "duplicate_instances": duplicates,
            "maximum_multiplicity": max(bodies.values(), default=0),
            "expected_random_pair_collisions": random_pair_collisions,
        }
    return {
        "parsed_world_flows": parsed_flows,
        "post_handshake_frames": parsed_frames,
        "post_handshake_body_bytes": total_bodies,
        "body_byte_entropy_bits": round(shannon_entropy(body_byte_counts), 6),
        "physical_frame_lengths": {str(k): v for k, v in length_counts.most_common()},
        "exact_body_collisions_by_physical_length": collision_summary,
        "frame_lengths_mod_16": {
            str(remainder): sum(count for length, count in length_counts.items() if length % 16 == remainder)
            for remainder in range(16)
        },
        "body_lengths_mod_16": {
            str(remainder): sum(
                count
                for length, count in length_counts.items()
                if body_length_from_physical(length) is not None
                and body_length_from_physical(length) % 16 == remainder
            )
            for remainder in range(16)
        },
        "tls_c2s_flows_skipped": tls_flows,
        "reassembly_gaps": gaps,
        "stream_prefix_limit_bytes": stream_limit,
        "read_errors": read_errors,
    }


def public_client_record(item: ClientHandshake) -> dict:
    value = asdict(item)
    value.pop("modulus")
    return value


def build_report(paths: Sequence[Path], deep: bool, port: int, stream_limit: int, details: bool) -> dict:
    clients, servers = scan_handshakes(paths)
    revisions = collections.Counter(item.revision for item in clients)
    regions = collections.Counter(item.region for item in clients)
    report = {
        "schema": "aion2-c2s-analysis/v1",
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "captures": len(paths),
        "capture_names": [path.name for path in paths],
        "client_handshakes": len(clients),
        "server_handshakes": len(servers),
        "revisions": {str(key): value for key, value in sorted(revisions.items())},
        "regions": dict(sorted(regions.items())),
        "rsa": rsa_statistics(clients, servers),
    }
    if details:
        report["client_handshake_details"] = [public_client_record(item) for item in clients]
        report["server_handshake_details"] = [
            {
                "capture": item.capture,
                "file_offset": item.file_offset,
                "ciphertext_sha256": item.ciphertext_sha256,
            }
            for item in servers
        ]
    if deep:
        report["c2s"] = deep_c2s_statistics(paths, port, stream_limit)
    return report


def parse_size(value: str) -> int:
    suffixes = {"k": 1 << 10, "m": 1 << 20, "g": 1 << 30}
    text = value.strip().lower()
    if text[-1:] in suffixes:
        return int(text[:-1]) * suffixes[text[-1]]
    return int(text)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", help="pcap/pcapng files or glob patterns")
    parser.add_argument("--json", dest="json_path", help="write the report as JSON")
    parser.add_argument("--details", action="store_true", help="include privacy-safe per-handshake hashes")
    parser.add_argument("--deep", action="store_true", help="reassemble bounded C2S TCP prefixes with Scapy")
    parser.add_argument("--port", type=int, default=13328, help="game server TCP port (default: 13328)")
    parser.add_argument("--stream-limit", type=parse_size, default=8 << 20, help="bytes kept per C2S flow (default: 8M)")
    args = parser.parse_args(argv)

    paths = expand_inputs(args.inputs)
    if not paths:
        parser.error("no pcap/pcapng input files matched")

    report = build_report(paths, args.deep, args.port, args.stream_limit, args.details)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.json_path:
        output = Path(args.json_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")

    print(f"captures:          {report['captures']}")
    print(f"client handshakes: {report['client_handshakes']}")
    print(f"server handshakes: {report['server_handshakes']}")
    print(f"revisions:         {report['revisions']}")
    print(f"regions:           {report['regions']}")
    print(f"unique moduli:     {report['rsa']['unique_moduli']}")
    print(f"shared primes:     {report['rsa']['shared_prime_pairs']}")
    print(f"raw RSA cubes BE:  {report['rsa']['raw_perfect_cubes_big_endian']}")
    if args.deep:
        print(f"C2S frames:        {report['c2s']['post_handshake_frames']}")
        print(f"C2S entropy:       {report['c2s']['body_byte_entropy_bits']:.6f} bits/byte")
    if args.json_path:
        print(f"report:            {Path(args.json_path).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
