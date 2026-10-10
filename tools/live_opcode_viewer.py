#!/usr/bin/env python3
"""Display decrypted Aion 2 C2S opcodes from a live world connection.

The viewer starts dumpcap, follows new world TCP connections, recovers the
matching 214-byte RC4 key through the read-only runtime locator, and displays
decrypted client packets.  Session keys remain in memory.  Captures and the
JSONL event log are written below the ignored ``artifacts`` directory.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Callable

try:
    from .aion2_client_crypto import RC4, frame_clear_body
    from .analyze_pcaps import (
        CLIENT_SIGNATURE,
        decode_uvarint,
        find_client_handshake_frame,
    )
    from .decrypt_c2s_rc4 import classify_plaintext
    from .locate_session_key import established_tcp_pids
    from .watch_session_key import (
        close_context,
        discover_world_pid,
        initialize_context,
        read_session,
    )
except ImportError:  # Direct execution: python tools/live_opcode_viewer.py
    from aion2_client_crypto import RC4, frame_clear_body
    from analyze_pcaps import (
        CLIENT_SIGNATURE,
        decode_uvarint,
        find_client_handshake_frame,
    )
    from decrypt_c2s_rc4 import classify_plaintext
    from locate_session_key import established_tcp_pids
    from watch_session_key import (
        close_context,
        discover_world_pid,
        initialize_context,
        read_session,
    )


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "protocol" / "opcodes.json"
DEFAULT_ARTIFACTS = ROOT / "artifacts"
MAX_UNSYNCED_BYTES = 1 << 20
MAX_FRAME_SIZE = 1 << 20
SESSION_SETUP_OPCODE = b"\x13\x36"
SESSION_SETUP_LENGTH = 158


def local_timestamp(epoch: float | None = None) -> str:
    moment = datetime.fromtimestamp(epoch) if epoch is not None else datetime.now()
    return moment.astimezone().isoformat(timespec="milliseconds")


def wire_opcode(body: bytes) -> str:
    return body[:2].hex().upper()


def display_opcode(body: bytes) -> str:
    return " ".join(f"{value:02X}" for value in body[:2])


def payload_preview(body: bytes, limit: int = 32) -> str:
    rendered = body[:limit].hex(" ").upper()
    return rendered + (" …" if len(body) > limit else "")


def load_opcode_names(path: Path) -> dict[str, str]:
    registry = json.loads(path.read_text(encoding="utf-8"))
    names: dict[str, str] = {}
    for item in registry["opcodes"]:
        if "C2S" in item["directions"]:
            names[item["wire"].upper()] = item["name"]
    for wire in registry["observations"]["world_c2s"]:
        names.setdefault(wire.upper(), "OBSERVED_C2S")
    return names


class EventLog:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._stream = path.open("a", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()

    def append(self, event: dict) -> None:
        with self._lock:
            if self._stream.closed:
                return
            self._stream.write(json.dumps(event, separators=(",", ":")) + "\n")

    def close(self) -> None:
        with self._lock:
            if not self._stream.closed:
                self._stream.close()


class TcpByteStream:
    """Incrementally trim overlap and hold out-of-order TCP payloads."""

    def __init__(self):
        self.next_sequence: int | None = None
        self.pending: dict[int, bytes] = {}

    def feed(self, sequence: int, payload: bytes) -> bytes:
        if not payload:
            return b""
        if self.next_sequence is None:
            self.next_sequence = sequence
        end = sequence + len(payload)
        if end <= self.next_sequence:
            return b""
        if sequence < self.next_sequence:
            payload = payload[self.next_sequence - sequence :]
            sequence = self.next_sequence
        previous = self.pending.get(sequence)
        if previous is None or len(payload) > len(previous):
            self.pending[sequence] = payload

        output = bytearray()
        while True:
            candidates = [
                start
                for start, block in self.pending.items()
                if start <= self.next_sequence < start + len(block)
            ]
            if not candidates:
                break
            start = min(candidates)
            block = self.pending.pop(start)
            offset = self.next_sequence - start
            tail = block[offset:]
            output.extend(tail)
            self.next_sequence += len(tail)
        return bytes(output)


class C2SFlow:
    def __init__(
        self,
        flow_id: tuple[str, int, str, int],
        publish: Callable[[dict], None],
        session_number: Callable[[], int],
    ):
        self.flow_id = flow_id
        self.publish = publish
        self.session_number = session_number
        self.tcp = TcpByteStream()
        self.buffer = bytearray()
        self.handshake_seen = False
        self.session_id: int | None = None
        self.modulus_sha256: str | None = None
        self.pending_frames: list[tuple[float, bytes]] = []
        self.cipher: RC4 | None = None
        self.parse_offset = 0

    def feed(self, sequence: int, payload: bytes, capture_epoch: float) -> None:
        contiguous = self.tcp.feed(sequence, payload)
        if not contiguous:
            return
        self.buffer.extend(contiguous)
        if not self.handshake_seen:
            self._find_handshake(capture_epoch)
            if not self.handshake_seen:
                self._trim_unsynchronized()
                return
        self._collect_frames(capture_epoch)

    def _find_handshake(self, capture_epoch: float) -> None:
        found = find_client_handshake_frame(bytes(self.buffer))
        if found is None:
            return
        frame_at, encrypted_at = found
        decoded = decode_uvarint(self.buffer, frame_at)
        if decoded is None:
            return
        encoded_length, width = decoded
        body_length = encoded_length - 4
        body_at = frame_at + width
        if body_length != 283 or encrypted_at != body_at + body_length:
            return
        body = bytes(self.buffer[body_at:encrypted_at])
        if not body.startswith(CLIENT_SIGNATURE):
            return
        modulus = body[13:269]
        if len(modulus) != 256:
            return
        self.handshake_seen = True
        self.session_id = self.session_number()
        self.modulus_sha256 = hashlib.sha256(modulus).hexdigest()
        del self.buffer[:encrypted_at]
        self.parse_offset = 0
        self.publish(
            {
                "kind": "session",
                "session": self.session_id,
                "timestamp": capture_epoch,
                "observed_at": local_timestamp(capture_epoch),
                "message": (
                    f"World handshake #{self.session_id} captured; "
                    "waiting for the matching runtime key"
                ),
            }
        )

    def _trim_unsynchronized(self) -> None:
        if len(self.buffer) <= MAX_UNSYNCED_BYTES:
            return
        keep = max(len(CLIENT_SIGNATURE) + 5, MAX_UNSYNCED_BYTES // 2)
        del self.buffer[:-keep]

    def _collect_frames(self, capture_epoch: float) -> None:
        while self.parse_offset < len(self.buffer):
            if self.buffer[self.parse_offset] == 0:
                self.parse_offset += 1
                continue
            decoded = decode_uvarint(self.buffer, self.parse_offset)
            if decoded is None:
                break
            encoded_length, width = decoded
            if encoded_length < 6:
                self.publish(
                    {
                        "kind": "error",
                        "message": "invalid live C2S frame length after handshake",
                    }
                )
                return
            body_length = encoded_length - 4
            total = width + body_length
            if total > MAX_FRAME_SIZE:
                self.publish(
                    {
                        "kind": "error",
                        "message": "live C2S frame exceeds the configured size limit",
                    }
                )
                return
            if self.parse_offset + total > len(self.buffer):
                break
            body_at = self.parse_offset + width
            ciphertext = bytes(self.buffer[body_at : body_at + body_length])
            self.pending_frames.append((capture_epoch, ciphertext))
            self.parse_offset += total

        if self.parse_offset:
            del self.buffer[: self.parse_offset]
            self.parse_offset = 0
        if self.cipher is not None:
            self._decrypt_pending()

    def offer_key(self, key: bytes) -> bool:
        if self.cipher is not None or not self.handshake_seen:
            return False
        if len(key) != 214 or not self.pending_frames:
            return False
        probe = RC4(key)
        first_plaintext = probe.crypt(self.pending_frames[0][1])
        if (
            len(first_plaintext) != SESSION_SETUP_LENGTH
            or not first_plaintext.startswith(SESSION_SETUP_OPCODE)
        ):
            return False
        self.cipher = probe
        first_epoch, _first_ciphertext = self.pending_frames.pop(0)
        self._publish_plaintext(first_epoch, first_plaintext)
        self._decrypt_pending()
        self.publish(
            {
                "kind": "ready",
                "session": self.session_id,
                "message": f"Session #{self.session_id} is decrypting live",
            }
        )
        return True

    def _decrypt_pending(self) -> None:
        if self.cipher is None:
            return
        pending, self.pending_frames = self.pending_frames, []
        for capture_epoch, ciphertext in pending:
            self._publish_plaintext(capture_epoch, self.cipher.crypt(ciphertext))

    def _publish_plaintext(self, capture_epoch: float, plaintext: bytes) -> None:
        classification = classify_plaintext(plaintext)
        self.publish(
            {
                "kind": "packet",
                "session": self.session_id,
                "timestamp": capture_epoch,
                "observed_at": local_timestamp(capture_epoch),
                "opcode": wire_opcode(plaintext),
                "opcode_display": display_opcode(plaintext),
                "body_length": len(plaintext),
                "payload_hex": plaintext.hex(),
                "preview": payload_preview(plaintext),
                "packet_kind": classification["kind"],
                "rc4_stream_offset": self.cipher.consumed - len(plaintext),
            }
        )


class CaptureWorker(threading.Thread):
    def __init__(
        self,
        *,
        dumpcap: Path,
        interface: str,
        port: int,
        capture_path: Path,
        publish: Callable[[dict], None],
        stop_event: threading.Event,
    ):
        super().__init__(name="aion2-live-capture", daemon=True)
        self.dumpcap = dumpcap
        self.interface = interface
        self.port = port
        self.capture_path = capture_path
        self.publish = publish
        self.stop_event = stop_event
        self.process: subprocess.Popen | None = None
        self.flows: dict[tuple[str, int, str, int], C2SFlow] = {}
        self.keys: list[bytes] = []
        self.lock = threading.RLock()
        self._session_count = 0

    def next_session(self) -> int:
        self._session_count += 1
        return self._session_count

    def offer_key(self, key: bytes) -> None:
        digest = hashlib.sha256(key).digest()
        with self.lock:
            if not any(hashlib.sha256(item).digest() == digest for item in self.keys):
                self.keys.append(key)
                self.keys = self.keys[-4:]
            for flow in self.flows.values():
                flow.offer_key(key)

    def _publish_from_flow(self, event: dict) -> None:
        self.publish(event)
        if event["kind"] == "session":
            with self.lock:
                flow = next(
                    (
                        item
                        for item in self.flows.values()
                        if item.session_id == event["session"]
                    ),
                    None,
                )
                if flow is not None:
                    for key in reversed(self.keys):
                        if flow.offer_key(key):
                            break

    def run(self) -> None:
        try:
            self._capture()
        except BaseException as error:
            if not self.stop_event.is_set():
                self.publish(
                    {"kind": "error", "message": f"live capture stopped: {error}"}
                )
        finally:
            self._terminate_process()

    def _capture(self) -> None:
        try:
            from scapy.all import IP, IPv6, TCP, PcapReader, PcapWriter
        except ImportError as error:
            raise RuntimeError("install dependencies with requirements.txt") from error

        command = [
            str(self.dumpcap),
            "-i",
            self.interface,
            "-f",
            f"tcp port {self.port}",
            "-P",
            "-s",
            "0",
            "-w",
            "-",
            "-q",
        ]
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creation_flags,
        )
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        stderr_thread = threading.Thread(
            target=self._drain_stderr,
            name="dumpcap-stderr",
            daemon=True,
        )
        stderr_thread.start()
        self.capture_path.parent.mkdir(parents=True, exist_ok=True)
        self.publish(
            {
                "kind": "status",
                "message": (
                    f"Capturing on {self.interface}; waiting for a new world handshake"
                ),
            }
        )
        with PcapReader(self.process.stdout) as reader, PcapWriter(
            str(self.capture_path), append=False, sync=True
        ) as writer:
            for packet in reader:
                if self.stop_event.is_set():
                    break
                writer.write(packet)
                if TCP not in packet:
                    continue
                tcp = packet[TCP]
                if int(tcp.dport) != self.port:
                    continue
                if IP in packet:
                    source, destination = packet[IP].src, packet[IP].dst
                elif IPv6 in packet:
                    source, destination = packet[IPv6].src, packet[IPv6].dst
                else:
                    continue
                flow_id = (
                    source,
                    int(tcp.sport),
                    destination,
                    int(tcp.dport),
                )
                with self.lock:
                    flow = self.flows.get(flow_id)
                    if flow is None:
                        flow = C2SFlow(
                            flow_id,
                            self._publish_from_flow,
                            self.next_session,
                        )
                        self.flows[flow_id] = flow
                    has_syn = bool(int(tcp.flags) & 0x02)
                    if has_syn and flow.tcp.next_sequence is None:
                        flow.tcp.next_sequence = int(tcp.seq) + 1
                    payload = bytes(tcp.payload)
                    if not payload:
                        continue
                    payload_sequence = int(tcp.seq) + (1 if has_syn else 0)
                    flow.feed(payload_sequence, payload, float(packet.time))

        return_code = self.process.poll()
        if return_code not in (None, 0) and not self.stop_event.is_set():
            raise RuntimeError(f"dumpcap exited with status {return_code}")

    def _drain_stderr(self) -> None:
        assert self.process is not None and self.process.stderr is not None
        for raw_line in iter(self.process.stderr.readline, b""):
            line = raw_line.decode(errors="replace").strip()
            if line and ("error" in line.lower() or "denied" in line.lower()):
                self.publish({"kind": "error", "message": f"dumpcap: {line}"})

    def _terminate_process(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()


class KeyMonitor(threading.Thread):
    def __init__(
        self,
        *,
        port: int,
        process_name: str,
        publish: Callable[[dict], None],
        offer_key: Callable[[bytes], None],
        stop_event: threading.Event,
    ):
        super().__init__(name="aion2-key-monitor", daemon=True)
        self.port = port
        self.process_name = process_name
        self.publish = publish
        self.offer_key = offer_key
        self.stop_event = stop_event
        self.context: dict | None = None
        self.last_status: str | None = None
        self.last_key_hash: str | None = None

    def status(self, message: str) -> None:
        if message != self.last_status:
            self.last_status = message
            self.publish({"kind": "status", "message": message})

    def run(self) -> None:
        try:
            self._monitor()
        finally:
            close_context(self.context)
            self.context = None

    def _monitor(self) -> None:
        while not self.stop_event.is_set():
            try:
                connected_pids = established_tcp_pids(self.port)
                active_pid = self.context["pid"] if self.context else None
                if active_pid not in connected_pids:
                    close_context(self.context)
                    self.context = None
                    self.last_key_hash = None
                if self.context is None:
                    if not connected_pids:
                        self.status("Key monitor: waiting for the world connection")
                        self.stop_event.wait(0.25)
                        continue
                    pid, _discovery = discover_world_pid(
                        self.port, self.process_name
                    )
                    self.status("Key monitor: locating the runtime RC4 objects")
                    self.context = initialize_context(
                        pid,
                        8 << 20,
                        512 << 20,
                        True,
                        4,
                    )

                assert self.context is not None
                if self.context["fast_misses"] == 3:
                    self.status(
                        "Key monitor: optimized full fallback in progress "
                        "(typically several seconds)"
                    )
                session = read_session(self.context)
                if session is not None:
                    session_data, key = session
                    key_hash = session_data["session_key_sha256"]
                    if key_hash != self.last_key_hash:
                        self.last_key_hash = key_hash
                        self.offer_key(key)
                    method = session_data["state_lookup"]["method"]
                    self.status(f"Key monitor ready ({method})")
            except SystemExit as error:
                self.status(f"Key monitor: {error}")
            except OSError as error:
                self.status(f"Key monitor: {error}")
            self.stop_event.wait(0.25)


def find_dumpcap(explicit: Path | None) -> Path:
    candidates = []
    if explicit is not None:
        candidates.append(explicit)
    discovered = shutil.which("dumpcap")
    if discovered:
        candidates.append(Path(discovered))
    candidates.extend(
        [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            / "Wireshark"
            / "dumpcap.exe",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
            / "Wireshark"
            / "dumpcap.exe",
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise SystemExit("dumpcap.exe was not found; install Wireshark or pass --dumpcap")


def is_elevated() -> bool:
    if os.name != "nt":
        return True
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def relaunch_elevated() -> bool:
    if os.name != "nt" or is_elevated():
        return False
    arguments = [str(Path(__file__).resolve()), *sys.argv[1:], "--elevated"]
    parameters = subprocess.list2cmdline(arguments)
    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        parameters,
        str(ROOT),
        1,
    )
    if result <= 32:
        raise SystemExit(f"elevation request failed with ShellExecute status {result}")
    return True


class OpcodeViewer:
    def __init__(self, args: argparse.Namespace):
        import tkinter as tk
        from tkinter import messagebox, ttk

        self.tk = tk
        self.ttk = ttk
        self.messagebox = messagebox
        self.args = args
        self.names = load_opcode_names(args.registry)
        self.events: queue.Queue[dict] = queue.Queue()
        self.stop_event = threading.Event()
        self.last_packet_epoch: float | None = None
        self.packet_events: dict[str, dict] = {}
        self.counts: Counter[str] = Counter()
        self.lengths: dict[str, set[int]] = defaultdict(set)
        self.paused = False

        stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
        args.artifacts.mkdir(parents=True, exist_ok=True)
        self.capture_path = args.artifacts / f"live-opcodes-{stamp}.pcap"
        self.log = EventLog(args.artifacts / f"live-opcodes-{stamp}.jsonl")

        self.root = tk.Tk()
        self.root.title("Aion 2 Live C2S Opcode Viewer")
        self.root.geometry("1420x820")
        self.root.minsize(1050, 620)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self.show_time = tk.BooleanVar(value=False)
        self.marker_text = tk.StringVar()
        self.status_text = tk.StringVar(value="Starting …")
        self._build_ui()

        dumpcap = find_dumpcap(args.dumpcap)
        self.capture = CaptureWorker(
            dumpcap=dumpcap,
            interface=args.interface,
            port=args.port,
            capture_path=self.capture_path,
            publish=self.publish,
            stop_event=self.stop_event,
        )
        self.keys = KeyMonitor(
            port=args.port,
            process_name=args.process_name,
            publish=self.publish,
            offer_key=self.capture.offer_key,
            stop_event=self.stop_event,
        )
        self.capture.start()
        self.keys.start()
        self.root.after(50, self._drain_events)

    def _build_ui(self) -> None:
        tk, ttk = self.tk, self.ttk
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)

        controls = ttk.Frame(outer)
        controls.pack(fill="x", pady=(0, 8))
        ttk.Label(controls, text="Action label:").pack(side="left")
        marker = ttk.Entry(controls, textvariable=self.marker_text, width=34)
        marker.pack(side="left", padx=(6, 6))
        marker.bind("<Return>", lambda _event: self.add_marker())
        ttk.Button(controls, text="Add marker", command=self.add_marker).pack(
            side="left"
        )
        ttk.Button(
            controls,
            text="Reset before action",
            command=self.reset_view,
        ).pack(side="left", padx=(12, 4))
        self.pause_button = ttk.Button(
            controls, text="Pause display", command=self.toggle_pause
        )
        self.pause_button.pack(side="left", padx=4)
        ttk.Button(controls, text="Copy selected", command=self.copy_selected).pack(
            side="left", padx=4
        )
        ttk.Checkbutton(
            controls,
            text="Show 01 36 time packets",
            variable=self.show_time,
        ).pack(side="right")

        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)
        live_frame = ttk.Frame(notebook)
        count_frame = ttk.Frame(notebook)
        notebook.add(live_frame, text="Live events")
        notebook.add(count_frame, text="Opcode counts")

        columns = ("time", "delta", "session", "opcode", "name", "length", "preview")
        self.tree = ttk.Treeview(
            live_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        headings = {
            "time": "Local time",
            "delta": "Δ ms",
            "session": "Session",
            "opcode": "Opcode",
            "name": "Registry name",
            "length": "Length",
            "preview": "Plaintext preview",
        }
        widths = {
            "time": 105,
            "delta": 75,
            "session": 65,
            "opcode": 75,
            "name": 300,
            "length": 65,
            "preview": 580,
        }
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], stretch=column in {"name", "preview"})
        scrollbar = ttk.Scrollbar(live_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.tag_configure("marker", background="#ffe6a6")
        self.tree.tag_configure("observed", background="#fff3c4")
        self.tree.tag_configure("unknown", background="#ffd6d6")
        self.tree.tag_configure("session", background="#d9ecff")
        self.tree.bind("<<TreeviewSelect>>", self._show_details)

        count_columns = ("opcode", "name", "count", "lengths")
        self.count_tree = ttk.Treeview(
            count_frame, columns=count_columns, show="headings"
        )
        for column, title, width in (
            ("opcode", "Opcode", 100),
            ("name", "Registry name", 520),
            ("count", "Count", 100),
            ("lengths", "Body lengths", 260),
        ):
            self.count_tree.heading(column, text=title)
            self.count_tree.column(column, width=width, stretch=column == "name")
        self.count_tree.pack(fill="both", expand=True)

        details_box = ttk.LabelFrame(outer, text="Selected plaintext", padding=6)
        details_box.pack(fill="x", pady=(8, 6))
        self.details = tk.Text(details_box, height=4, wrap="word")
        self.details.pack(fill="x")
        self.details.configure(state="disabled")

        ttk.Label(outer, textvariable=self.status_text, anchor="w").pack(fill="x")
        ttk.Label(
            outer,
            text=f"Capture: {self.capture_path}    Event log: {self.log.path}",
            anchor="w",
        ).pack(fill="x", pady=(3, 0))
        marker.focus_set()

    def publish(self, event: dict) -> None:
        if event["kind"] in {"packet", "session", "ready", "marker", "error"}:
            self.log.append(event)
        self.events.put(event)

    def _drain_events(self) -> None:
        handled = 0
        while handled < 500:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            handled += 1
            kind = event["kind"]
            if kind == "packet":
                self._add_packet(event)
            elif kind in {"status", "ready"}:
                self.status_text.set(event["message"])
            elif kind == "session":
                self.status_text.set(event["message"])
                self._add_message_row(event, "session")
            elif kind == "marker":
                self._add_message_row(event, "marker")
            elif kind == "error":
                self.status_text.set(event["message"])
                self._add_message_row(event, "unknown")
        if not self.stop_event.is_set():
            self.root.after(50, self._drain_events)

    def _add_packet(self, event: dict) -> None:
        opcode = event["opcode"]
        if opcode == "0136" and not self.show_time.get():
            return
        self.counts[opcode] += 1
        self.lengths[opcode].add(event["body_length"])
        self._refresh_count(opcode)
        if self.paused:
            return
        epoch = event["timestamp"]
        delta = (
            "—"
            if self.last_packet_epoch is None
            else f"{(epoch - self.last_packet_epoch) * 1000:.1f}"
        )
        self.last_packet_epoch = epoch
        time_text = datetime.fromtimestamp(epoch).astimezone().strftime("%H:%M:%S.%f")[:-3]
        name = self.names.get(opcode, "UNKNOWN_C2S")
        tag = (
            "unknown"
            if name == "UNKNOWN_C2S"
            else "observed" if name == "OBSERVED_C2S" else ""
        )
        item = self.tree.insert(
            "",
            "end",
            values=(
                time_text,
                delta,
                event["session"],
                event["opcode_display"],
                name,
                event["body_length"],
                event["preview"],
            ),
            tags=(tag,) if tag else (),
        )
        self.packet_events[item] = event
        self._limit_rows()
        self.tree.see(item)

    def _add_message_row(self, event: dict, tag: str) -> None:
        epoch = event.get("timestamp", time.time())
        message = event.get("message", event.get("label", ""))
        item = self.tree.insert(
            "",
            "end",
            values=(
                datetime.fromtimestamp(epoch).astimezone().strftime("%H:%M:%S.%f")[:-3],
                "",
                event.get("session", ""),
                "MARK" if tag == "marker" else "",
                message,
                "",
                "",
            ),
            tags=(tag,),
        )
        self.tree.see(item)

    def _refresh_count(self, opcode: str) -> None:
        name = self.names.get(opcode, "UNKNOWN_C2S")
        values = (
            f"{opcode[:2]} {opcode[2:]}",
            name,
            self.counts[opcode],
            ", ".join(str(value) for value in sorted(self.lengths[opcode])),
        )
        if self.count_tree.exists(opcode):
            self.count_tree.item(opcode, values=values)
        else:
            self.count_tree.insert("", "end", iid=opcode, values=values)

    def _limit_rows(self) -> None:
        children = self.tree.get_children()
        while len(children) > 5000:
            item = children[0]
            self.packet_events.pop(item, None)
            self.tree.delete(item)
            children = children[1:]

    def _show_details(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        event = self.packet_events.get(selection[0])
        text = "" if event is None else event["payload_hex"].upper()
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def add_marker(self) -> None:
        label = self.marker_text.get().strip()
        if not label:
            self.messagebox.showinfo(
                "Action label required",
                "Enter a short action label before adding the marker.",
            )
            return
        event = {
            "kind": "marker",
            "timestamp": time.time(),
            "observed_at": local_timestamp(),
            "label": label,
            "message": f"ACTION: {label}",
        }
        self.publish(event)
        self.marker_text.set("")

    def reset_view(self) -> None:
        if not self.marker_text.get().strip():
            self.messagebox.showinfo(
                "Action label required",
                "Enter the next action label, then click Reset before action.",
            )
            return
        for item in self.tree.get_children():
            self.tree.delete(item)
        for item in self.count_tree.get_children():
            self.count_tree.delete(item)
        self.packet_events.clear()
        self.counts.clear()
        self.lengths.clear()
        self.last_packet_epoch = None
        self.add_marker()

    def toggle_pause(self) -> None:
        self.paused = not self.paused
        self.pause_button.configure(
            text="Resume display" if self.paused else "Pause display"
        )

    def copy_selected(self) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        event = self.packet_events.get(selection[0])
        if event is None:
            values = self.tree.item(selection[0], "values")
            text = "\t".join(str(value) for value in values)
        else:
            text = json.dumps(event, indent=2)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def close(self) -> None:
        self.stop_event.set()
        self.capture._terminate_process()
        self.log.close()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def self_test() -> None:
    published: list[dict] = []
    sessions = iter(range(1, 10))
    flow = C2SFlow(
        ("127.0.0.1", 50000, "127.0.0.2", 13328),
        published.append,
        lambda: next(sessions),
    )
    handshake_body = CLIENT_SIGNATURE + bytes(283 - len(CLIENT_SIGNATURE))
    key = bytes(range(214))
    cipher = RC4(key)
    setup = SESSION_SETUP_OPCODE + bytes(SESSION_SETUP_LENGTH - 2)
    movement = bytes.fromhex("0A37") + bytes(38)
    stream = (
        frame_clear_body(handshake_body)
        + frame_clear_body(cipher.crypt(setup))
        + frame_clear_body(cipher.crypt(movement))
    )
    split = len(stream) // 3
    epoch = time.time()
    flow.feed(1000, stream[:split], epoch)
    flow.feed(1000 + split - 10, stream[split - 10 :], epoch + 0.01)
    assert flow.handshake_seen
    assert flow.offer_key(bytes(reversed(range(214)))) is False
    assert flow.offer_key(key) is True
    packets = [event for event in published if event["kind"] == "packet"]
    assert [event["opcode"] for event in packets] == ["1336", "0A37"]
    assert packets[1]["body_length"] == 40
    names = load_opcode_names(DEFAULT_REGISTRY)
    assert names["0A37"].startswith("CLIENT_SPECIAL_MOVEMENT")
    assert names["5136"] == "CLIENT_STARTUP_FLOAT_51"
    assert names["2236"] == "OBSERVED_C2S"
    print("Aion 2 live opcode viewer self-test: OK")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default="Ethernet")
    parser.add_argument("--port", type=int, default=13328)
    parser.add_argument("--process-name", default="AION2.exe")
    parser.add_argument("--dumpcap", type=Path)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--artifacts", type=Path, default=DEFAULT_ARTIFACTS)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--no-elevate", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.registry = args.registry.resolve()
    args.artifacts = args.artifacts.resolve()
    if not 1 <= args.port <= 65535:
        raise SystemExit("--port must be between 1 and 65535")
    return args


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.no_elevate and relaunch_elevated():
        return 0
    if os.name == "nt" and not is_elevated():
        raise SystemExit("run the live viewer from an elevated process")
    viewer = OpcodeViewer(args)
    viewer.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
