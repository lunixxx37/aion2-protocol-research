# Protocol Registry

`opcodes.json` is the canonical machine-readable opcode registry. It combines
semantic mappings with a capture-derived C2S observation snapshot. Unknown
observed values stay in the registry instead of being discarded or assigned a
meaning prematurely.

`opcodes.schema.json` describes the public file format. The repository also
performs stricter semantic checks, including duplicate direction detection,
minimal body lengths, uppercase wire values, and equality between aggregate
frame totals and per-opcode counts.

Generate and validate the human-readable catalog with:

```powershell
python tools/generate_opcode_docs.py --write
python tools/generate_opcode_docs.py --check
```

## Adding an opcode mapping

1. Keep the opcode in two-byte wire order, such as `0136`, not host-endian
   `0x3601` notation.
2. Add or update its semantic entry under `opcodes`.
3. Preserve an `observed` or `hypothesis` confidence until a controlled action
   or independent parser confirms the meaning.
4. Record body lengths without copying raw session payloads.
5. Add fields only where offsets and types have evidence.
6. Regenerate `docs/OPCODES.md` and run the self-tests.

Capture-specific identifiers, plaintext bodies, private keys, and session
values belong in ignored local artifacts, never in this registry.
