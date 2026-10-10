# Aion 2 Network Protocol Research

[![Python checks](https://github.com/lunixxx37/aion2-protocol-research/actions/workflows/python.yml/badge.svg)](https://github.com/lunixxx37/aion2-protocol-research/actions/workflows/python.yml)

Reproducible research into the Aion 2 network protocol, with a focus on
client-to-server (C2S), server-to-client (S2C), TCP framing, compressed bundles,
the RSA world handshake, and the post-handshake C2S cipher.

Research snapshot: **October 10, 2026**, Global client revision `3527`.

This is an independent, unofficial project. It is not affiliated with NCSOFT
or the operators of Aion 2.

## Project status

| Area | Status |
|---|---|
| TCP reassembly | understood |
| outer unsigned-varint framing | understood |
| LZ4 bundles | understood |
| lobby-to-world redirect | understood |
| S2C opcodes and payloads | partially understood |
| C2S RSA handshake | fully reconstructed |
| RSA private-key reconstruction | reproducible through read-only memory access |
| RSA padding and handshake plaintext | OAEP-SHA1, exactly 214 bytes |
| symmetric C2S encryption | **standard RC4, fully reconstructed** |
| offline C2S PCAP decryption | reproduced across independent sessions |
| first encrypted `13 36` packet | byte layout and codec reconstructed; `authn_token` handoff traced |
| C2S opcode semantics | visible; most payload meanings still being mapped |

The client generates an ephemeral 2048-bit RSA key with public exponent `3`
and sends the public key in opcode `10 36`. The server replies with a 256-byte
RSA block in `11 36`. Big-endian RSA-OAEP-SHA1 with an empty label produces
exactly 214 bytes. Those complete 214 bytes, without a KDF or slicing, are the
RC4 key.

RC4 is continuous across every post-handshake C2S frame body. The outer
unsigned-varint length remains clear and consumes no keystream. This model was
validated over more than 172,000 frames and 1.9 million encrypted body bytes
across six independently keyed world sessions.

## Documentation

- [Getting started](docs/GETTING_STARTED.md)
- [Protocol specification](docs/PROTOCOL.md)
- [C2S reverse-engineering report](docs/C2S_RESEARCH.md)
- [Opcode catalog](docs/OPCODES.md)
- [Machine-readable opcode registry](protocol/opcodes.json)
- [Sources and confidence levels](docs/SOURCES.md)
- [Contributing](CONTRIBUTING.md)

## Quick start

Python 3.10 or newer is required:

```powershell
git clone https://github.com/lunixxx37/aion2-protocol-research.git
cd aion2-protocol-research
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python tools/aion2_client_crypto.py --self-test
```

The self-test covers a published RC4 vector, RSA-2048/e=3, PKCS#1 public-key
DER, OAEP-SHA1, the `10 36`/`11 36` layouts, the `13 36` session-setup codec,
the AES-256-ECB launcher-parameter decoder, and continuous multi-frame RC4.

## Live opcode viewer

Start the Windows viewer before the next world connection:

```powershell
python tools/live_opcode_viewer.py
```

The tool requests elevation, starts a filtered `dumpcap` stream, warms the
runtime key locator, and opens a GUI showing decrypted C2S opcode, registry
name, body length, inter-packet delay, and a plaintext preview. Regular
`01 36` time packets are hidden by default. The counts tab makes action bursts
easy to compare. Mapped packets use the normal background, catalogued packets
whose semantics remain open are yellow, and genuinely new opcodes are red.

If the game was already connected when the viewer started, keep it open while
the key monitor warms up, then create one new world connection. The viewer
needs that connection's clear `10 36` handshake so RC4 starts at byte zero.
Wait for `Session #N is decrypting live`, enter an action label, click
`Reset before action`, perform exactly one action, and wait briefly before the
next marker. This records the label and packets in the same timeline.

The raw PCAP and JSONL event log are stored as timestamped
`artifacts/live-opcodes-*` files and remain ignored by Git. The session key is
kept in memory. On systems whose capture adapter has another name, pass it with
`--interface`.

## Standalone-client primitives

[`tools/aion2_client_crypto.py`](tools/aion2_client_crypto.py) provides the
connection-specific cryptographic layer:

- ephemeral RSA-2048/e=3 generation;
- `10 36` public-key handshake serialization;
- `11 36` server-handshake parsing;
- OAEP-SHA1 recovery of the 214-byte session secret;
- `13 36` session-setup parsing and serialization;
- Base64/AES-256-ECB decoding of the separate `-lp` launcher configuration;
- continuous body-only RC4 framing for outgoing C2S packets;
- strict unsigned-varint framing helpers.

`protocol/opcodes.json` is the canonical opcode source for code generators and
packet codecs. `docs/OPCODES.md` is generated from it, so the human and
machine-readable catalogs remain synchronized.

A standalone client owns its generated private key, so it does not need the
process-memory recovery tools. Those tools exist to analyze captures produced
by the original client.

The `13 36` encoded token is supplied by the NC Platform SDK field
`authn_token`, with an additional `-authnToken:` command-line input supported
by the client. The remaining major layers for a complete client are performing
that authenticated login exchange, reproducing lobby state and redirects,
locating the remaining structured `13 36` values, and completing semantic
codecs for gameplay packets.

To inspect a captured `-lp` value without printing its field values:

```powershell
Get-Content artifacts\launcher-parameter.txt |
  python tools/decode_launcher_parameter.py
```

The input file remains local under the ignored `artifacts/` directory. Add
`--show-values` only when plaintext values are needed for a local comparison.

## Offline capture workflow

Analyze one or more captures:

```powershell
python tools/analyze_pcaps.py `
  "C:\path\to\captures\*.pcapng" `
  --json artifacts\pcap-analysis.json
```

The analyzer does not modify captures. It extracts handshakes, revisions,
regions, RSA modulus fingerprints, frame sizes, and C2S traffic statistics.

When the capture's ephemeral RSA private key is available, decrypt its server
handshake:

```powershell
python tools/decrypt_handshake.py `
  --capture "C:\path\to\session.pcapng" `
  --private-key "C:\local-secrets\session-key.pem" `
  --json artifacts\handshake-plaintext.json
```

Then decrypt the complete C2S stream. The modulus fingerprint selects the exact
world flow associated with the OAEP secret:

```powershell
python tools/decrypt_c2s_rc4.py `
  "C:\path\to\session.pcapng" `
  --handshake-json artifacts\handshake-plaintext.json `
  --modulus-sha256 MODULUS_SHA256 `
  --frame-limit 0 --samples-per-opcode 3 --quiet `
  --json artifacts\c2s-rc4-decrypt.json
```

The decryptor reassembles TCP, deduplicates retransmissions, locates the matching
clear client handshake, and advances one RC4 instance over all subsequent body
bytes.

## Fast original-client session-key recovery

For a live revision-3527 client, recover the active 214-byte RC4 key directly
from the two validated runtime state objects. The locator finds `AION2.exe`
from its established world connection, so a PID is normally unnecessary:

```powershell
python tools/locate_session_key.py `
  --key-out artifacts\session-key.bin `
  --json artifacts\session-key-locator.json
```

Use the monitor for normal companion-tool startup. It waits for the world
connection, performs the full lookup once, and then reuses the process-local
addresses until a reconnect or process restart requires rediscovery:

```powershell
python tools/watch_session_key.py `
  --key-out artifacts\current-session-key.bin `
  --json artifacts\session-key-monitor.json `
  --events-jsonl artifacts\session-key-events.jsonl
```

Stop it with `Ctrl+C`. The default 250 ms poll interval can be changed with
`--poll-interval`. The event report contains only the key fingerprint and
runtime metadata; the raw 214-byte key is written only to `--key-out`.
Run the monitor from an elevated shell when the game process requires it. If a
world socket exists but process access fails, the monitor now emits the Win32
access error even in quiet mode instead of waiting silently.

The JSON report contains key hashes and structural validation, not the key
bytes. `--key-out` is optional and writes the raw key only to the specified
ignored local path. Feed that file directly to the C2S decryptor:

```powershell
python tools/decrypt_c2s_rc4.py `
  "C:\path\to\session.pcapng" `
  --session-key artifacts\session-key.bin `
  --modulus-sha256 MODULUS_SHA256 `
  --frame-limit 0 --samples-per-opcode 0 --quiet `
  --json artifacts\c2s-rc4-decrypt.json
```

The locator derives the RC4 and adjacent network-owner vtables from runtime
code, locates the current owner allocation without a fixed heap offset, and
accepts only two states with valid 256-byte RC4 permutations and the same key.
Ten repeated local tests after an independent restart completed the internal
lookup in 269-297 ms (280 ms average), or 348-385 ms including Python process
startup. Subsequent monitor polls took 0.40-0.76 ms (0.55 ms average). The
standalone locator keeps its broader search opt-in through
`--full-scan-fallback`. The monitor automatically performs that validated
fallback once if the allocator-specific fast profile misses, then caches the
two discovered state addresses; use `--no-full-scan-fallback` to disable it.
Fallback latency depends on the client's current allocation size. Prioritizing
64-KiB allocator regions and coalescing adjacent reads reduced the largest
measured revision-3527 case from 84.87 seconds and 12.99 GB read to 6.83
seconds and 2.44 GB read. Cached checks remain sub-millisecond; the fallback is
not a millisecond path.

## Original-client RSA recovery fallback

The Windows runtime tools use `VirtualQueryEx` and `ReadProcessMemory`; the
active workflow does not modify or pause the target process. Depending on the
target process permissions, the analysis shell may need elevated rights.

Locate the runtime OpenSSL RSA wrapper group:

```powershell
python tools/locate_openssl_rsa.py `
  --pid PROCESS_ID `
  --json artifacts\openssl-rsa-locator.json
```

Search for the capture's current RSA object when the fast live-state path is
not applicable:

```powershell
python tools/scan_process_rsa.py `
  --pid PROCESS_ID `
  --capture "C:\path\to\session.pcapng" `
  --json artifacts\process-rsa-scan.json
```

After locating the eight-pointer OpenSSL RSA field block, export and validate
the private key:

```powershell
python tools/export_openssl_rsa.py `
  --pid PROCESS_ID `
  --capture "C:\path\to\session.pcapng" `
  --fields-address 0xFIELDS_ADDRESS `
  --private-key "C:\local-secrets\session-key.pem" `
  --json artifacts\openssl-rsa-export.json
```

The exporter verifies `p*q=n`, the private exponent relation, every CRT
parameter, and the capture modulus before writing a PEM file. Runtime addresses
are process-specific and must never be treated as portable constants.

## Repository data policy

Raw captures and generated reports may contain account identifiers, character
data, chat, login values, session tokens, private keys, or decrypted payloads.
They are excluded by `.gitignore`. Generated analysis belongs under
`artifacts/`; only its redacted README is versioned.

Before publishing changes, inspect `git status` and keep all PCAP, PEM,
handshake JSON, decrypted-body samples, crash logs, credentials, and API tokens
out of commits.

## License

The original source code and documentation in this repository are available
under the [MIT License](LICENSE). External projects referenced by the research
retain their own licenses.
