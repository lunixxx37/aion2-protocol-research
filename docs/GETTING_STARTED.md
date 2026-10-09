# Getting Started

This guide explains which components are implemented and how to use them as the
foundation for an Aion 2 protocol client or offline capture decoder. The
documented snapshot is the Global Windows client revision `3527`, observed on
October 9, 2026.

## 1. Installation

Python 3.10 or newer is required:

```powershell
git clone https://github.com/lunixxx37/aion2-protocol-research.git
cd aion2-protocol-research
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python tools/aion2_client_crypto.py --self-test
```

The self-test verifies a published RC4 vector, RSA-2048/e=3, PKCS#1 public-key
DER, OAEP-SHA1, the `10 36`/`11 36` layouts, and continuous RC4 state across
multiple bodies.

## 2. Available building blocks

`tools/aion2_client_crypto.py` exports:

- `generate_client_key_and_handshake(revision, region)`: generates an ephemeral
  RSA key and a completely framed `10 36` handshake.
- `parse_server_handshake(body)`: parses a clear `11 36` body.
- `decrypt_server_secret(private_key, handshake)`: recovers the exact 214-byte
  RC4 key through OAEP-SHA1.
- `C2SStreamCipher(secret)`: continuously encrypts C2S bodies and adds the outer
  unsigned-varint prefix.
- `encode_uvarint`, `decode_uvarint`, and `frame_clear_body`: basic Aion framing
  primitives.

Minimal cryptographic flow:

```python
from tools.aion2_client_crypto import (
    C2SStreamCipher,
    decrypt_server_secret,
    generate_client_key_and_handshake,
    parse_server_handshake,
)

private_key, client_10_36 = generate_client_key_and_handshake(3527, "DE")

# Send client_10_36 in full over the world TCP socket. Then read one complete,
# clear 11-36 frame and remove its unsigned-varint prefix. The variable below
# contains only the frame body.
server_handshake = parse_server_handshake(server_11_36_body)
secret = decrypt_server_secret(private_key, server_handshake)
c2s = C2SStreamCipher(secret)

wire_packet = c2s.encode_frame(b"\x01\x36" + unix_ms.to_bytes(8, "little"))
# Send wire_packet in full. Reuse this exact c2s instance for every later body
# on the same TCP connection.
```

`server_11_36_body` and `unix_ms` are intentionally input values in this
snippet. A network project must add a buffered TCP reader, authentication,
lobby/world redirect handling, and connection state management.

## 3. Confirmed wire rules

```text
frame = uvarint(len(body) + 4) || body

before the world handshake:
    C2S body is clear

after 11 36:
    C2S = clear_uvarint || RC4(plaintext_body)
    S2C = clear_uvarint || plaintext_body
```

The RC4 key is the complete 214-byte OAEP plaintext. There is no KDF, IV,
RC4-drop, or frame-boundary reset. Only C2S body bytes consume keystream;
unsigned-varint bytes do not.

## 4. Decode an existing capture

First obtain the ephemeral RSA key belonging to the captured connection. The
original client retains that key only for the corresponding world session. A
standalone client already owns its generated key and skips this analysis step.

```powershell
python tools/decrypt_handshake.py `
  --capture "C:\captures\session.pcapng" `
  --private-key "C:\local-secrets\session-key.pem" `
  --json artifacts\handshake-plaintext.json

python tools/decrypt_c2s_rc4.py `
  "C:\captures\session.pcapng" `
  --handshake-json artifacts\handshake-plaintext.json `
  --modulus-sha256 MODULUS_SHA256 `
  --frame-limit 0 --samples-per-opcode 3 --quiet `
  --json artifacts\c2s-report.json
```

Every file below `artifacts/`, except its README, is ignored by Git. Handshake
reports and plaintext samples may contain session values.

## 5. Next implementation layers

A complete client still needs:

1. Launcher/login session handling and transfer of required values to lobby.
2. Lobby parsing, including the `0F 39` world redirect.
3. Required fields of the first encrypted `13 36` session packet.
4. Semantic codecs for movement, target selection, skills, and inventory.
5. Buffered S2C processing, including nested LZ4 bundles.

Record new opcode mappings with a confidence level in
`protocol/opcodes.json`. Move confirmed wire rules into `PROTOCOL.md` and
preserve the supporting analysis in `C2S_RESEARCH.md`. Regenerate the Markdown
catalog after editing the registry:

```powershell
python tools/generate_opcode_docs.py --write
python tools/generate_opcode_docs.py --check
```
