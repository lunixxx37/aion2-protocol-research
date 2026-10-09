# Aion 2 Network Protocol

Research snapshot: October 9, 2026. Observed with Global Windows client
revisions `3526` and `3527`.

## 1. Transport and session phases

Aion 2 uses TCP for lobby and world traffic. The observed game-server port is
`13328`; the concrete address is dynamic and must be taken from the lobby
redirect.

```text
Launcher / web authentication
            |
            v
Lobby TCP --- 01/06/09/0B/0D/0F 39
            |
            | 0F 39: server id, host, port
            v
World TCP --- 10 36 / 11 36 handshake
            |
            +--> C2S: clear length, RC4-encrypted body
            +<-- S2C: clear frames and compressed bundles
```

TLS connections may appear alongside the proprietary game stream. Detect them
through their record headers and do not feed them into the game framer.

## 2. Outer frame format

Every logical frame begins with an unsigned LEB128 length:

```text
uvarint(encoded_length) || frame_body
```

The length relationship is:

```text
body_length         = encoded_length - 4
physical_frame_size = varint_width + encoded_length - 4
```

The logical offset of four is not a physical four-byte TCP header. The varint
must use its minimal encoding. Existing decoders also skip zero-byte padding
between frames.

One-byte example:

```text
06 03 36
^^ ^^^^^
|  frame body: opcode 03 36
encoded length = 6
physical size  = 1 + 6 - 4 = 3
```

Two-byte example:

```text
9F 02 ...
encoded length = 287
physical size  = 2 + 287 - 4 = 285
body length    = 283
```

TCP segment boundaries are unrelated to frame boundaries. A decoder must
handle retransmissions, overlaps, fragmentation, multiple frames per segment,
and capture gaps.

## 3. Opcodes

A clear frame body normally starts with two opcode bytes:

```text
opcode_low || opcode_family || payload
```

This project writes opcodes in wire order, for example `04 38`. A little-endian
`uint16` reader sees that value as `0x3804`.

After the world handshake, S2C bodies remain directly readable. C2S opcodes
become readable after applying the continuous session RC4 state.

## 4. Compression

### 4.1 Outer LZ4 bundles

Compressed bodies use this layout:

```text
FF FF || plain_size:u32le || raw_lz4_block
```

The decompressed stream contains complete Aion frames and may therefore be
processed recursively. Implementations should cap decompressed size,
compression ratio, and recursion depth.

An additional marked form has been observed:

```text
flag:F0..FE || FF FF || plain_size:u32le || raw_lz4_block
```

### 4.2 C2S `40 8D` zlib payload

Decrypted C2S opcode `40 8D` contains an independent zlib-compressed payload:

```text
40 8D
compressed_blob_length:uvarint
plain_size:u32le
zlib_stream                 # starts with 78 9C in observed samples
```

The varint equals all bytes following the varint. Three local samples had body
lengths `1362`, `1361`, and `1361`; they decompressed to `7050`, `7048`, and
`7048` bytes, matching `plain_size` exactly. The decompressed data begins with
UTF-16LE JSON-like configuration content. Its application-level meaning is
still under investigation.

## 5. World handshake

### 5.1 Client to server: `10 36`

```text
outer_length:uvarint
10 36
rsa_der_length:uvarint
rsa_public_key:PKCS1_RSAPublicKey_DER
client_revision:u32le
04 06 05 02
region_ascii[2]
02
```

Observed revision-3527 structure:

```text
9F 02                       outer encoded length = 287
10 36                       C2S handshake opcode
8C 02                       DER length = 268
30 82 01 08                 DER SEQUENCE
02 82 01 01 00 ...          257-byte positive RSA modulus integer
02 01 03                    public exponent = 3
C7 0D 00 00                 client revision = 3527
04 06 05 02
44 45                       region = "DE"
02
```

The key is RSA-2048 and is generated for each world connection. Every modulus
in the analyzed corpus was different.

### 5.2 Server to client: `11 36`

```text
outer_length:uvarint
11 36
status:u16le                 # observed: 0
timeout_ms:u32le             # observed: 60000
80 02                        # uvarint(256)
rsa_ciphertext[256]
reserved:u64le               # observed: 0
sentinel_or_result:i32le     # observed: -7
```

The prefix and trailer were stable across complete handshakes. Independently
recovered private keys establish the RSA parameters unambiguously:

```text
ciphertext integer byte order = big endian
padding                       = OAEP with SHA-1 / MGF1-SHA1
OAEP label                    = empty
decoded message length        = 214 bytes
```

For RSA-2048 with OAEP-SHA1, 214 bytes is the maximum payload:
`256 - 2*20 - 2`. Manual decoding verified the leading zero, `SHA1("")`, MGF1
unmasking, zero padding, and `01` separator. All 214 decoded bytes form the RC4
key directly and in their original order.

### 5.3 Post-handshake C2S cipher

```text
C2S: clear_uvarint || RC4(body)
S2C: clear_uvarint || opcode || payload
```

The cipher is standard RC4. There is no KDF, IV, RC4-drop, per-frame reset, or
authentication tag. Only body bytes advance the state.

```text
key = OAEP_SHA1_RSA_DECRYPT(server_block)  # exactly 214 bytes
S = [0, 1, ..., 255]
j = 0
for i in 0..255:
    j = (j + S[i] + key[i mod 214]) mod 256
    swap(S[i], S[j])

i = 0
j = 0
for every C2S body byte b, continuously across frames:
    i = (i + 1) mod 256
    j = (j + S[i]) mod 256
    swap(S[i], S[j])
    output = b XOR S[(S[i] + S[j]) mod 256]
```

The runtime object contains a key pointer, key length `214`, the two indices,
and the 256-byte permutation. The original client constructs two identical
state objects from the same OAEP buffer. In the observed handler pipeline one
state transforms the buffer before dispatch, while the other advances in sync
to restore the buffer afterward.

Two independently keyed world sessions remained synchronized for tens of
thousands of frames. The static KSA/PRGA disassembly and complete offline PCAP
decryption agree byte for byte.

### 5.4 Time packet

A regular S2C tick is:

```text
0E || 00 36 || server_unix_ms:u64le
```

The outer byte `0E` is the encoded length. A nearby C2S frame has the same
physical size:

```text
0E || RC4(01 36 || client_unix_ms:u64le)
```

The client timestamp is newly sampled rather than an exact echo of the server
timestamp. In one correlated example it was eight milliseconds later. The
earlier `03 36 || echoed_server_tick` hypothesis was therefore close in timing
but byte-wise incorrect.

### 5.5 Standalone-client sequence

A standalone client owns its private key and does not need runtime-memory
recovery:

1. Generate a new RSA-2048 key pair with public exponent `3`.
2. Send the public key as PKCS#1 `RSAPublicKey` DER inside clear `10 36`.
3. Read clear `11 36` and extract its 256-byte RSA block.
4. Decrypt with RSA-OAEP-SHA1, MGF1-SHA1, and an empty label.
5. Require exactly 214 output bytes and initialize RC4 with all of them.
6. For every later C2S packet, RC4-transform only the body, then prefix
   `uvarint(len(body) + 4)`.
7. Continue to parse S2C as clear frames or compressed bundles.

Every C2S body on a TCP connection must advance the same RC4 state exactly
once and in order. A reconnect creates a fresh RSA pair and fresh RC4 state.

### 5.6 First encrypted client packet

The first RC4-encrypted C2S body in all four decoded world sessions is `13 36`.
Its confirmed byte grammar is:

```text
13 36
primary_length:uvarint
primary_identifier:ascii[primary_length]
00
token_length:uvarint
encoded_token:base64-ascii[token_length]
00
setup_flags:u8
optional_value:u64le
```

Observed bodies are 158 bytes: `primary_length` is 43 and `token_length` is
100. Decoding `encoded_token` yields:

```text
stable_identifier ':' connection_identifier 00
```

Both components were 36-character UUID strings. `stable_identifier` remained
constant across the four samples, and `connection_identifier` changed in every
session. These are descriptive names based on variation, not confirmed
application semantics. The captured values are not part of this repository.

Runtime disassembly confirms that `setup_flags` is a packed two-boolean field.
Bit 0 comes directly from an as-yet unnamed caller argument. Bit 1 is set when
the builder's 64-bit `optional_value` argument is positive. The four observed
packets contained either flags `2` with a nonzero value or flags `0` with zero.

The codec is implemented as `build_client_session_setup` and
`parse_client_session_setup` in `tools/aion2_client_crypto.py`. A standalone
client still needs the authenticated upstream source for accepted values.

In two complete startup captures, S2C `15 36` later echoed
`primary_identifier` byte-for-byte near the end of its 4,610-byte body. The
complete response arrived about 1.7 seconds after the client had sent `13 36`,
so it confirms the value but cannot supply it for the first client packet.

## 6. Lobby

Public decoders identify at least:

```text
01 39 Lobby handshake
03 39 Lobby ping
06 39 Account
09 39 Server list
0B 39 Character list
0D 39 Join
0F 39 Redirect
```

The redirect contains at least server ID, host, and port. A client must use the
delivered endpoint rather than hard-coding either address or server ID.

## 7. Data types

Decoded messages primarily use:

- little-endian integers (`u16`, `u32`, `u64`);
- unsigned LEB128/varints for lengths and entity identifiers;
- UTF-8 strings with packet-specific length encoding;
- raw two-byte opcodes;
- nested frame streams inside LZ4 bundles;
- selected opcode-specific zlib content.

Field meaning remains packet-specific and should be validated through multiple
captures and controlled state changes.

## 8. Decoder requirements

A robust decoder should:

1. Reassemble TCP independently per four-tuple and direction.
2. Deduplicate retransmitted bytes.
3. Mark gaps explicitly and resynchronize only with evidence.
4. Enforce minimal unsigned-varint encoding.
5. Cap frame and decompressed sizes.
6. Separate TLS side connections.
7. Track lobby and world connections independently.
8. Preserve unknown opcodes and raw payloads locally.
9. Redact account and session values from exported reports.
10. Advance C2S RC4 only for complete body bytes in wire order.

## 9. Open protocol work

- Semantic layouts for most now-visible C2S opcodes.
- Mapping controlled player actions to exact C2S messages.
- Authenticated source and application meaning of the structured `13 36` values.
- Meaning and schema of decompressed `40 8D` content.
- Launcher/login token format and lobby handoff.
- Minimum packets for keepalive, character selection, and world join.
- Client behavior for unknown or omitted S2C messages.
