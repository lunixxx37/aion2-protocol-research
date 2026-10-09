# Repository Guidelines

## Project Structure & Module Organization

`tools/` contains standalone Python utilities. `aion2_client_crypto.py` is the reusable world-handshake and continuous C2S RC4 implementation; `analyze_pcaps.py`, `decrypt_handshake.py`, and `decrypt_c2s_rc4.py` form the offline decoding path. The Windows-only scanners and disassemblers read process memory to recover or inspect runtime state. `docs/PROTOCOL.md` is the protocol specification, `docs/OPCODES.md` records opcode evidence, and `docs/C2S_RESEARCH.md` preserves the reverse-engineering trail. `artifacts/README.md` documents local reports; all generated artifacts are ignored because they may contain keys or session data.

## Build, Test, and Development Commands

Create an environment and install the supported analysis dependencies:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run the deterministic crypto/handshake test with `python tools/aion2_client_crypto.py --self-test`. Compile every utility with `python -m compileall -q tools`. Use `python tools/<name>.py --help` to inspect a tool without touching captures or processes.

## Coding Style & Naming Conventions

The codebase targets Python 3.10 or newer, uses four-space indentation, postponed annotations, `pathlib.Path`, snake_case functions, and PascalCase classes. Keep protocol byte order explicit through `int.from_bytes`/`to_bytes`; write opcodes in wire order. Utilities should remain importable while also providing an `argparse` CLI under a `main()` guard.

## Testing Guidelines

The current test surface is the built-in self-test plus compilation of all scripts. When changing framing, OAEP, or RC4 state handling, extend `self_test()` with deterministic vectors and verify continuous multi-frame state rather than only a single packet.

## Data and Artifact Hygiene

Never commit PCAPs, PEM files, handshake JSON, decrypted packet bodies, crash logs, account values, API keys, or fixed local process addresses presented as portable facts. Keep generated reports under `artifacts/`; only its redacted README is versioned.

## Commit & Pull Request Guidelines

No prior Git history exists, so there is no established commit-message convention. Keep changes focused and state which capture-independent checks passed. Protocol claims should identify whether they are locally confirmed, inferred, or sourced publicly, and update the relevant document alongside code changes.
