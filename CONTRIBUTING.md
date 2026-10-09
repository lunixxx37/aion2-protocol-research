# Contributing

## Development setup

Python 3.10 or newer is required. On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python tools/aion2_client_crypto.py --self-test
python -m compileall -q tools
```

The PCAP analyzers are cross-platform. Runtime process-memory tools use Windows
APIs and must be run from a process with sufficient access to the target.

## Protocol evidence

Document byte fields in wire order and specify endianness for every integer.
Mark findings as locally confirmed, inferred, or sourced publicly. A new packet
layout should be checked against more than one occurrence; session crypto
changes should also be validated on a fresh connection.

## Sensitive local data

Do not commit captures, private keys, OAEP plaintexts, decrypted session
payloads, account identifiers, launcher values, crash logs, or API tokens. The
root `.gitignore` excludes the usual forms, but review `git status` before every
commit. Generated JSON belongs in `artifacts/`, where only `README.md` is
versioned.

## Pull requests

Describe the observed client revision, the evidence behind the change, and the
commands used to verify it. Update `docs/PROTOCOL.md`, `docs/OPCODES.md`, or
`docs/C2S_RESEARCH.md` when a code change establishes a new protocol fact.
