# Client-to-Server Reverse Engineering

This report separates confirmed facts, statistical evidence, historical dead
ends, and remaining hypotheses. That distinction is important: several early
assumptions were plausible and strongly correlated in time, but byte-wise
incorrect.

Research snapshot: October 9, 2026, Global client revision `3527`.

## 1. Confirmed facts

- The outer unsigned-LEB128 length remains clear after the world handshake.
- The complete post-handshake C2S body, including the two-byte opcode, is
  transformed.
- The client creates a new 2048-bit RSA key for every world connection.
- The public exponent is `3`.
- The client sends the public key as a 268-byte PKCS#1 `RSAPublicKey` DER value.
- The server returns a 256-byte RSA block.
- The matching private key can be reconstructed read-only from OpenSSL
  `BIGNUM` structures in the network process.
- The server block uses big-endian RSA with OAEP-SHA1, MGF1-SHA1, and an empty
  label.
- The OAEP plaintext is exactly 214 bytes.
- All 214 bytes are used directly as the RC4 key; there is no KDF.
- Standard RC4 runs continuously across all C2S bodies and does not reset at
  frame boundaries.
- The clear outer length does not consume RC4 keystream.
- `01 36 || client_unix_ms:u64le` is the regular C2S time packet.
- S2C remains clear in the observed world stream.
- The packed client image uses `.ncg*` sections; useful code and cryptographic
  constants become visible only in runtime mappings.

## 2. Capture corpus

The local corpus contains 31 PCAPNG files recorded from October 3 through
October 9, 2026. The initial aggregate analysis found 171 complete client
public-key handshakes:

- 70 connections using revision `3526`;
- 101 connections using revision `3527`;
- 171 distinct RSA moduli;
- no shared prime factor between any two moduli.

This rules out key reuse and shared-prime factorization for the corpus.

## 3. RSA investigation

### 3.1 Offline shortcuts that did not apply

The public exponent `e = 3` does not make the server response directly
readable. The 256-byte block is not a perfect cube under either byte order, so
an integer cube-root attack does not produce a plaintext.

The corpus analyzer also checked the Håstad broadcast condition. If three
different `e=3` moduli encrypted the same unpadded message, the Chinese
Remainder Theorem could combine them into an exact cube. Results:

- 167 revision-separated three-ciphertext windows: no broadcast hit;
- pairwise `gcd(n_i, n_j) = 1` across the modulus set;
- no small factor through `100000`;
- no Fermat factor within 4096 steps per modulus.

These tests exclude common ephemeral-RSA implementation mistakes, not general
factorization of a correctly generated 2048-bit modulus.

### 3.2 Read-only private-key reconstruction

The current capture modulus was first located in little-endian form at several
heap addresses. Pointer references led from the limb buffer to its `BIGNUM` and
then to a contiguous OpenSSL RSA field block containing eight pointers:

```text
n, e, d, p, q, dmp1, dmq1, iqmp
```

`tools/export_openssl_rsa.py` reads these values through `ReadProcessMemory`,
normalizes the `BIGNUM` limbs, and verifies:

```text
p * q == n
e == 3
e * d mod lcm(p-1, q-1) == 1
dmp1 == d mod (p-1)
dmq1 == d mod (q-1)
iqmp == q^-1 mod p
SHA256(captured modulus) == expected fingerprint
```

All relations passed for independently recovered session keys. The resulting
traditional OpenSSL PEM files decrypted only the matching `11 36` server
blocks, preventing confusion with unrelated RSA objects in the process.

Heap addresses and mapped-code bases change across process launches. They are
useful as evidence for one run, never as client constants.

### 3.3 OAEP result

`tools/decrypt_handshake.py` performs the private RSA operation and validates
PKCS#1 v1.5 and OAEP candidates manually. Exactly one form succeeds:

```text
ciphertext byte order = big endian
padding               = OAEP-SHA1 / MGF1-SHA1
label                 = empty
message length        = 214 bytes
```

Manual decoding confirms the leading zero, the `SHA1("")` label hash, MGF1
unmasking, the zero padding, and the `01` separator. A 214-byte payload is also
the exact OAEP-SHA1 maximum for RSA-2048.

Two independently decrypted messages had no equal byte at the same position
and a bit Hamming distance of `846/1712 = 49.416%`, consistent with independent
high-entropy session material.

### 3.4 Locating OpenSSL at runtime

The unpacked runtime image contains a related group of four small dispatch
wrappers corresponding to:

```text
RSA_private_decrypt
RSA_private_encrypt
RSA_public_decrypt
RSA_public_encrypt
```

`tools/locate_openssl_rsa.py` searches for the wrapper structure rather than a
fixed address, making it resilient to ASLR and process restarts. The surrounding
runtime image also contains matching OpenSSL AES, ChaCha20, Poly1305,
Montgomery, and provider-path evidence.

`RSA_private_decrypt` uses the Win64 calling convention relevant to this
handshake:

```text
RCX         flen, expected 256
RDX         pointer to the encrypted server block
R8          output buffer
R9          RSA object
[RSP+0x28]  padding selector
RAX return  plaintext length
```

A runtime match is trustworthy only when the 256 bytes at `RDX` equal the
captured server ciphertext. That condition separates the world handshake from
other internal RSA operations.

Five direct internal references were found in legacy EVP, provider RSA
decrypt, and RSASVE recovery paths. No stable application call site called the
wrapper directly, which is consistent with EVP/provider dispatch.

## 4. Symmetric encryption: standard RC4

### 4.1 Runtime ownership chain

A reference to the runtime string `g.network.HandlerRecvBuffer` led to the RSA
handler and then to its owning network object. The relevant shared-pointer slots
in the investigated revision were:

```text
network_owner + 0xE10 -> RSA handler
network_owner + 0xE20 -> RC4 state A
network_owner + 0xE30 -> RC4 state B
```

The object addresses change, while the disassembled relative layout was:

```text
+0x00  vtable
+0x08  status/flags
+0x10  key_buffer pointer
+0x18  key_length = 214
+0x1C  RC4 index i
+0x20  RC4 index j
+0x24  S[256]
```

Both key buffers matched the complete OAEP plaintext byte for byte. Each
`S[256]` area was a permutation of `0..255`. The constructor creates both
objects from the same `(key_pointer, 214)` pair immediately after successful RSA
decryption.

In the observed receive-handler path, state A transforms a body in place before
dispatch and state B, advanced identically, restores it afterward. This also
explains why two synchronized objects remain visible in memory.

### 4.2 Exact algorithm

The virtual methods implement the ordinary RC4 KSA and PRGA:

```text
key = complete_214_byte_oaep_plaintext
S = [0, 1, ..., 255]
j = 0
for i in 0..255:
    j = (j + S[i] + key[i mod 214]) & 0xff
    swap(S[i], S[j])

i = 0
j = 0
for byte in concatenated_c2s_bodies:
    i = (i + 1) & 0xff
    j = (j + S[i]) & 0xff
    swap(S[i], S[j])
    byte ^= S[(S[i] + S[j]) & 0xff]
```

State rules:

- KSA uses all 214 key bytes, with no hash or slice.
- There is no IV and no RC4-drop.
- State begins at the first C2S frame after the clear `10 36` handshake.
- State continues across frame boundaries.
- Only body bytes consume keystream; clear unsigned-varint bytes do not.
- Encryption and decryption are the same XOR operation.

### 4.3 Full-stream PCAP validation

`tools/decrypt_c2s_rc4.py` reassembles TCP, deduplicates retransmitted segments,
selects a flow through its captured RSA modulus fingerprint, skips the clear
client handshake, and advances one RC4 instance through every subsequent body.

The latest reproducible snapshot is:

| Session | Frames | RC4 body bytes | confirmed `01 36` time packets |
|---|---:|---:|---:|
| revision 3527, flow A | 22,112 | 345,763 | 15,033 |
| revision 3527, flow B after restart | 133,281 | 1,397,381 | 129,274 |
| **total** | **155,393** | **1,743,144** | **144,307** |

Both streams remained aligned to the last complete captured frame without
manual resynchronization. The sessions used different RSA moduli and OAEP
secrets, establishing that no first-session constant leaked into the method.

### 4.4 Why early cipher probes reported zero matches

The initial timing correlation assumed:

```text
03 36 || preceding_server_tick_u64le
```

The decrypted packet is actually:

```text
01 36 || current_client_unix_ms:u64le
```

The client time is only a few milliseconds after the correlated server tick,
which made the temporal relationship look compelling, but the bytes are not an
echo. In addition, the original RC4 candidate matrix tested many OAEP slices,
hash-derived keys, and drop lengths, but omitted the unsliced 214-byte key.

The zero results were therefore correct for the tested combinations but did not
cover the real construction. Historical `probe_tick_plaintext.py` artifacts are
timing-correlation data only; their fields named `plaintext` and `keystream`
come from the disproved hypothesis.

### 4.5 Other tested cipher families

Before the runtime ownership chain exposed RC4, the following families were
tested:

| Candidate | Historical result |
|---|---|
| AES-CTR/CFB/OFB | no match across direct and hash-derived key/IV candidates |
| ChaCha20 | no match across direct and derived key/nonce candidates |
| HMAC/hash/BLAKE2/AES-ECB PRFs | no exact candidate keystream match |
| older Aion packet cipher | contradicted by key-independent packet relations |
| ECB/CBC with padding | incompatible with observed arbitrary body lengths |
| per-frame AEAD | no visible fixed nonce/tag overhead |

The older Aion cipher used a 64-byte static XOR table, an eight-byte advancing
session key, and ciphertext feedback inside each packet. A dedicated probe
tested raw OAEP windows, historical `u32` deobfuscation, four packet-length
update models, and a relation independent of the initial key. Results over
1,782 time-correlated packets matched random behavior rather than the historical
construction.

## 5. Decrypted C2S stream

### 5.1 Startup sequence

Both investigated world sessions begin with the same packet pattern:

```text
13 36 || session/setup payload    # first RC4 body, observed length 158
01 36 || client_unix_ms:u64le     # time/keepalive
10 56                             # opcode-only startup packet
01 36 || client_unix_ms:u64le
...
```

The first `13 36` payload includes printable identification fields and encoded
session material. Raw values are deliberately excluded from the repository.

### 5.2 Opcode observations

High-volume decrypted families include `36`, `37`, and `38`. Frequency tables
and confidence labels are maintained in `OPCODES.md`. A packet's family and
shape are evidence, not a semantic assignment; controlled one-action captures
are still needed for movement, target, and skill labels.

Several useful structural observations are already reproducible:

- `01 36` is always a 10-byte client time body in the validated stream.
- Sampled `3A 38` and `3C 38` packets are opcode-only.
- `17 90` repeatedly carries the same short structured body in sampled traffic.
- `40 8D` contains a length-delimited zlib stream. Its declared decompressed
  lengths exactly match zlib output, which begins with UTF-16LE JSON-like text.

### 5.3 Timestamped movement and skill-request layouts

The decryptor can associate retained plaintext frames with the capture time of
their containing TCP segment. A focused replay retained every relevant family
`37`/`38` sample from flow B. Across 2,035 timestamp-bearing samples, every
trailing `u64le` was a plausible Unix-millisecond value with a stable local
clock offset from the packet-capture timestamp.

The high-volume movement forms share this layout:

```text
00 37 or 01 37
flags:u8                    # 02 in retained samples
position:f32le[3]
packed_movement_state[7]   # bit-level layout still open
client_unix_ms:u64le
```

`01 37` is the high-frequency form, commonly emitted at approximately 10 Hz
while the character moves. `00 37` has the same shape but appears less often
and commonly follows a movement-skill sequence. The precise distinction still
needs a controlled start/stop/rotate capture.

`18 37` is an action-position snapshot:

```text
18 37 || flags:u16le || position:f32le[3] || heading:f32le
      || client_unix_ms:u64le
```

It frequently appears immediately before `00 38`. The `00 38` body contains a
`u32le` at offset 4. All 16 distinct values across 323 retained packets match
published skill IDs, including Dodge, Flame Arrow, Firestorm, Blaze, and
Pyroclasm. This establishes the following partial request header:

```text
00 38
request_flags:u8
request_stage:u8            # 01 in retained samples
skill_id:u32le
entity_id_tag:u8            # 02 in retained samples
target_entity_id:uvarint
aim_heading:f32le
target_or_aim_position:f32le[3]
action_mode:u8
[optional marker:u8]
[optional_parameter_id:uvarint || optional_parameters:f32le[1 or 2]]
client_unix_ms:u64le
```

The six observed flag values are `01`, `05`, `A1`, `A5`, `E1`, and `E5`.
Bit `04` adds a marker byte, always `01` in this sample. The `A*` forms add a
varint and one float; the `E*` forms add a varint and two floats. Together with
the two- or three-byte target varint, these optional fields explain every
observed body length from 36 through 49 bytes without padding or unexplained
trailing bytes. The parameter meanings remain open.

Dodge provides a second independently structured sequence. All retained
`0E 37` packets use skill `15000100` or variant `15000101`; the public skill
catalog names `15000100` as Dodge. A request is normally followed by two
`0F 37` movement samples:

```text
0E 37 -> 0F 37 -> 0F 37 -> 00 37
```

Both packets expose finite position, normalized direction, heading, and client
timestamp fields. `0E 37` additionally carries the skill ID and target entity.
The exact layouts and confidence labels are maintained in `opcodes.json`.

Raw character positions, entity identifiers, and timestamps remain in ignored
local artifacts.

### 5.4 Offline command

```powershell
python tools/decrypt_c2s_rc4.py `
  "C:\path\to\session.pcapng" `
  --handshake-json artifacts\handshake-plaintext.json `
  --modulus-sha256 MODULUS_SHA256 `
  --frame-limit 0 --samples-per-opcode 3 --quiet `
  --json artifacts\c2s-rc4-decrypt.json
```

For focused timestamped samples, repeat `--sample-opcode` and raise the sample
limit without retaining every decrypted frame:

```powershell
python tools/decrypt_c2s_rc4.py `
  "C:\path\to\session.pcapng" `
  --handshake-json artifacts\handshake-plaintext.json `
  --modulus-sha256 MODULUS_SHA256 `
  --frame-limit 0 --samples-per-opcode 5000 `
  --sample-opcode 0037 --sample-opcode 0137 --sample-opcode 1837 `
  --sample-opcode 0038 --sample-opcode 0e37 --sample-opcode 0f37 `
  --quiet --json artifacts\c2s-focused-samples.json
```

The handshake report must contain exactly one big-endian OAEP-SHA1 candidate
for the selected session. The C2S report does not repeat the private RSA key or
OAEP secret, but retained plaintext bodies may still expose session data.

## 6. Dynamic-analysis methods

### 6.1 Instrumentation outcome

An installed meter demonstrated a Winsock `recv()` ring-buffer hook, useful for
capturing incoming ciphertext but not pre-encryption C2S plaintext. A Frida
attach attempt was rejected by the process. A native debugger attach triggered
a controlled NCGuard termination with exit value `0xE0000011`.

The productive workflow therefore uses passive PCAP capture plus read-only
process-memory inspection. It neither injects code nor pauses the process.

### 6.2 Read-only tools

- `scan_process_rsa.py` finds a captured modulus and candidate RSA layouts.
- `scan_process_rsa_public.py` locates runtime public-key objects.
- `scan_process_range.py` performs bounded pattern searches.
- `export_openssl_rsa.py` validates and exports all private/CRT components.
- `locate_openssl_rsa.py` identifies the related OpenSSL wrapper group.
- `find_x64_calls.py` and `find_x64_rip_refs.py` locate direct and RIP-relative
  references.
- `disassemble_process.py` reads and decodes bounded runtime code windows.
- `scan_live_buffers.py` correlates captured bytes with memory candidates.

The target network process was not a Windows Protected Process or PPL in the
investigated build. Access still depended on the analysis process token; an
elevated shell was required in the local setup.

### 6.3 Reproducible analysis workflow

1. Identify a world capture and its clear `10 36` client handshake.
2. Extract the RSA modulus fingerprint from that handshake.
3. Find the modulus in the corresponding live network process.
4. Follow its references to a `BIGNUM` and the eight-pointer RSA field block.
5. Export and mathematically validate the ephemeral private key.
6. Decrypt the matching `11 36` server block as OAEP-SHA1.
7. Use all 214 plaintext bytes to initialize standard RC4.
8. Reassemble the matching C2S TCP stream and advance RC4 over body bytes only.
9. Collect opcode-specific samples and correlate them with controlled actions.

A standalone client starts at step 6 with its own generated private key and
does not need process-memory recovery.

## 7. Controlled experiment matrix

Each new capture should vary one visible action:

| Experiment | Expected result |
|---|---|
| login and remain idle | baseline and keepalive set |
| one forward movement | movement opcode and coordinate fields |
| rotate camera without moving | orientation versus movement separation |
| select one target | target-selection opcode |
| trigger one known skill | skill/cast request and identifiers |
| send a distinctive chat string | string encoding and payload anchor |
| reconnect cleanly | RSA/RC4 state reset and startup sequence |

Record the UTC timestamp, client revision, action, and capture name locally.
Do not copy account values or session tokens into research documents.

## 8. Reconstruction criteria

The C2S cipher satisfies every criterion defined before the breakthrough:

1. The server block decrypts reproducibly: satisfied.
2. Key and initial state derive from the handshake: satisfied.
3. At least three different packets decrypt: satisfied.
4. State stays synchronized through a long capture: satisfied beyond 70,000
   frames in one session.
5. `encrypt(decrypt(frame)) == frame`: satisfied through RC4 symmetry and
   byte-wise comparison.
6. A fresh session works without manual cipher constants: satisfied.

## 9. Research log

### October 9, 2026

- Inspected the packed PE layout: seven `.ncg*` sections and near-uniform main
  section entropy. Useful imports and standard crypto constants were absent
  from the file image.
- Surveyed public Aion 2 repositories. They established framing, LZ4, lobby,
  and S2C layouts but contained no encrypted-C2S decoder.
- Added corpus and deep-PCAP analysis with TCP sequence deduplication.
- Correlated tens of thousands of 10-byte C2S bodies with nearby S2C ticks.
  This established packet timing but initially produced the wrong plaintext
  model.
- Ruled out shared-prime, low-exponent cube-root, Håstad broadcast, small-factor,
  and short Fermat attacks across 171 unique RSA moduli.
- Located the runtime OpenSSL wrapper group structurally rather than through a
  fixed address.
- Recovered complete private keys from OpenSSL `BIGNUM` references and
  validated every RSA/CRT relation against captured public moduli.
- Decrypted independent server blocks as big-endian OAEP-SHA1 with empty labels
  and exact 214-byte payloads.
- Tested the historical Aion packet cipher, broad AES/ChaCha/RC4 candidate
  matrices, and PRF constructions. The early tests reported zero matches.
- Removed active debugger/injection methods after guard termination and
  continued through passive captures and read-only memory access.
- Followed `g.network.HandlerRecvBuffer` ownership to two matching
  byte-permutation state objects.
- Disassembled their virtual methods and identified standard RC4 KSA using
  `key[i % 214]` and standard RC4 PRGA without a drop or frame reset.
- Matched both runtime key buffers to the full OAEP plaintext.
- Corrected the time packet to `01 36 || client_unix_ms:u64le`; the old model
  used both the wrong opcode and the nearby server timestamp.
- Implemented `decrypt_c2s_rc4.py` with TCP reassembly, modulus-based flow
  selection, continuous body-only RC4, opcode statistics, and per-opcode
  samples.
- Fully decoded two independently keyed sessions, totaling 155,393 frames and
  1,743,144 encrypted body bytes in the latest snapshot.
- Added capture timestamps and opcode filters to focused C2S sampling, then
  mapped movement coordinates, client timestamps, skill IDs, and the repeated
  Dodge request/movement sequence in families `37` and `38`.
- Implemented `aion2_client_crypto.py` with standalone RSA handshake generation,
  OAEP recovery, continuous C2S framing, and deterministic self-tests.
- Identified and verified the inner zlib container carried by C2S `40 8D`.
