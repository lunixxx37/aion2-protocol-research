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
| revision 3527, controlled actions | 2,242 | 28,520 | 1,950 |
| revision 3527, isolated jump | 735 | 9,011 | 694 |
| revision 3527, controlled actions II | 3,309 | 38,100 | 3,076 |
| revision 3527, special movement | 10,499 | 131,302 | 9,649 |
| **total** | **172,178** | **1,950,077** | **159,676** |

All six streams remained aligned to the last complete captured frame without
manual resynchronization. The sessions used different RSA moduli and OAEP
secrets, establishing that no earlier-session constant leaked into the method.

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

All six decoded world sessions begin with the same packet pattern:

```text
13 36 || session/setup payload    # first RC4 body, observed length 158
01 36 || client_unix_ms:u64le     # time/keepalive
10 56                             # opcode-only startup packet
01 36 || client_unix_ms:u64le
...
```

The live viewer's first validation connection independently reproduced the
startup and exposed its complete non-time ordering before any labeled gameplay
action:

```text
13 36
A0 FF -> 1F 36 -> 10 56 -> 59 E2 -> 59 E2
22 36
4C 8D -> 48 36 -> 02 8A -> 04 8A -> 44 8A -> 00 43
-> 0E 57 -> 14 E2 -> 48 E3 -> A7 56 -> 56 8D -> 14 E2
51 36 -> 4D E3 -> 51 36 -> 51 36 -> 51 36 -> 51 36
```

Regular `01 36` and ten-second `02 36` packets were interleaved. The five
`51 36` bodies each contain one `f32le` at offset 2. They arrived roughly one
second apart with values `2000`, `2500`, `3000`, `3500`, and `3800`; the
application meaning of this startup value remains open. `A1 FF` began about
20 seconds later and then repeated every 30.002-30.087 seconds, distinguishing
it as periodic traffic rather than a one-time login action. This live session
remains outside the fixed six-session corpus snapshot until its capture is
closed and ingested.

All six decoded `13 36` bodies have the same 158-byte layout:

```text
13 36
primary_length:uvarint                    # observed 43
primary_identifier:ascii[primary_length]  # decimal text ':' 36-character UUID
00
token_length:uvarint                      # observed 100
encoded_token:base64-ascii[token_length]
00
setup_flags:u8                            # observed 0 or 2
optional_value:u64le                      # zero in both flags-0 samples
```

The 100 Base64 characters decode canonically to 74 bytes:

```text
stable_identifier ':' connection_identifier 00
```

Both decoded identifiers are 36-character UUID strings. The first remained
constant across all six samples, while the second changed in every world
session. The UUID within `primary_identifier` had an intermediate lifetime: it
was shared by the first two samples and changed in the later captures. These
variation-based names are intentionally neutral; none establishes whether a
field identifies an account, installation, process, character, or login token.

The stable component also has an exact historical match as the `guid_` field
of a Purple NCCR sidecar under
`%LOCALAPPDATA%\NCSOFT\NccrData\com.ncsoft.nccr.purpleonp.live\` and in
Purple's blob cache. This ties the value to launcher-managed state, although it
does not yet prove which live handoff supplies it to Aion 2. Neither the
primary UUID nor the per-connection UUID was present in the examined client
files or process command line.

Revision-3527 runtime disassembly locates the client builder at module offset
`AION2.exe+0x9001BA0`. It copies the already formatted primary string from a
global client-state object and the 100-character Base64 string from a session
object at field offset `0x15C0`; it does not create either identifier while
sending.

The source chain for the `+0x15C0` string is now confirmed. A response handler
at `AION2.exe+0x9509C50` asks an incoming NC Platform SDK result for an extended
response view. Its virtual populate method at `AION2.exe+0x7AE8970` looks up
the structured field named `authn_token`, verifies that it is a string, and
stores it at response offset `+0x58`. The handler then copies that string to
session offset `+0x15C0`. Nearby SDK strings associate the path with
`GetTicketLoginResult` and third-party authentication polling; the exact C++
response class and transport endpoint remain unnamed.

There is also an initialization fallback at `AION2.exe+0x94F7A50`. It parses
the internal Unreal command line for `-authnToken:` and assigns a supplied
value to the same session field. The same routine separately recognizes
`-pushToken:`. The inspected Steam launch contained neither switch after
startup, while the live session field still contained the expected
100-character Base64 value. The response handler is therefore the confirmed
non-command-line population path, while the command-line parser remains an
alternate supported input. A launch-time trace would be needed to distinguish
which path supplied any particular session.

The encrypted `-lp` launcher switch is a separate configuration container, not
the authentication-token payload. Revision 3527 implements:

```text
Base64 decode
-> require a non-zero multiple of 16 bytes
-> AES-256-ECB decrypt with ASCII key "LaunchParameterMakingKeyforAion2"
-> strict PKCS#7 unpadding
-> UTF-8 text
```

The AES implementation has no IV argument or cross-block feedback and writes
each decrypted block directly in place. The inspected 192-character `-lp`
sample decoded to 144 ciphertext bytes and 140 plaintext bytes. Its plaintext
began with the same key text as a marker, followed by four configuration
fields: `GamePlatformType`, `NcUpdaterConfigType`, `NCCRAppIDKey`, and
`ServerListType`. It contained no `authn_token` value. Raw field values are
excluded from this report. `tools/decode_launcher_parameter.py` reproduces the
decode and reports names and lengths with values redacted by default.

The builder stores one caller-provided boolean and one `optional_value > 0`
boolean; the packet serializer packs them into bits 0 and 1 of `setup_flags`.
It then writes the 64-bit value. This explains the two captured forms: flags
`2` plus a nonzero value in two samples, and flags `0` plus zero in two samples.
Eight direct builder call sites were found; they supply combinations including
zero, a state-owned 64-bit value, and the independent bit-0 flag. The value's
application meaning remains open.

S2C `15 36` contains a byte-exact copy of `primary_identifier` near the end of
its 4,610-byte inner body in two startup captures. That complete response was
available roughly 1.7 seconds after the corresponding C2S `13 36`, so it is a
confirmation or echo rather than the source used to construct the first
client packet.

Raw captured identifiers and values are deliberately excluded from the
repository.

`tools/aion2_client_crypto.py` now parses and serializes this exact grammar.
That completes the packet's byte codec and identifies the `authn_token` handoff,
but a standalone client must still perform the preceding authenticated NC
Platform login and lobby flow to obtain fresh, accepted values. The live
sources and meanings of `primary_identifier`, `optional_value`, and the two
UUID components remain open.

### 5.2 Opcode observations

High-volume decrypted families include `36`, `37`, and `38`. Frequency tables
and confidence labels are maintained in `OPCODES.md`. A packet's family and
shape are evidence, not a semantic assignment; controlled one-action captures
are still needed for movement, target, and skill labels.

Several useful structural observations are already reproducible:

- `01 36` is always a 10-byte client time body in the validated stream.
- `02 36` is an 11-byte periodic body. Its `u64le` value at offset 2 rises by
  exactly 10,000 between consecutive retained samples, followed by one variable
  byte. This is consistent with ten-second monotonic telemetry, but the clock
  source and final-byte meaning remain open.
- `04 37` and `05 37` are timestamp-only markers with the exact layout
  `opcode:bytes[2] || client_unix_ms:u64le`. All 35 and 33 bodies respectively
  in the six-session snapshot are exactly 10 bytes long, and every retained
  plaintext value matches the packet timeline. Both occur near movement and
  skill transitions; their exact semantic distinction remains open.
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
flags:u8                    # 02 while moving; 00 in the 01 37 stop form
position:f32le[3]
movement_heading:u16le     # degrees = value * 360 / 65536
facing_heading:f32le       # signed degrees
movement_mode:u8           # 01; omitted from the 29-byte flags-00 form
client_unix_ms:u64le
```

`01 37` is the high-frequency form, commonly emitted at approximately 10 Hz
while the character moves. `00 37` has the same shape but appears less often
and commonly follows a movement-skill sequence. The precise distinction still
needs a controlled start/stop/rotate capture.

The controlled capture added two 29-byte `01 37` packets with flags `00`.
Unlike the 205 captured 30-byte packets with flags `02`, these omit the
movement-mode byte, so the timestamp is best addressed as `body_end-8`. Their
timing and positions are consistent with stop/idle updates.

The 16-bit heading uses the full unsigned range as one revolution. Values
above 180 degrees can be normalized by subtracting 360. In straight movement,
it closely tracks the following float heading. The two values diverge during
some samples, which is consistent with movement direction and character facing
being represented separately, for example while strafing or moving backwards.

An independently keyed fourth session isolated one stationary Space-key jump.
It produced this complete 877 ms non-time sequence:

```text
02 37 -> 03 37 -> 03 37 -> 03 37 -> 02 37
      -> 03 37 -> 03 37 -> 03 37 -> 18 37
```

`02 37` is an airborne-transition form used by jumping. The 40-byte takeoff
packet carried vertical velocity `+1000`, while the 41-byte form appeared 444
ms later near the apex with vertical velocity `-32.096` and one additional
marker byte:

```text
02 37
transition_flags:u8
[optional_marker:u8]
position:f32le[3]
heading_degrees:f32le
velocity:f32le[3]
movement_mode:u8
client_unix_ms:u64le
```

`03 37` supplied six 40-byte airborne-movement samples at approximately 10 Hz:

```text
03 37
movement_flags:u8           # 02 in the controlled jump
position:f32le[3]
heading_degrees:f32le
velocity:f32le[3]
movement_mode:u8            # 01
client_unix_ms:u64le
```

X/Y and heading stayed fixed. Position Z rose from the original ground value
through the apex and fell again, while velocity Z progressed from `+739.115`
through positive, near-zero, and negative values to `-797.065`. The final
`18 37` restored the exact original ground position.

A later live-viewer session isolated four additional user-labelled actions:

```text
Dodge:          00 38 -> 0E 37 -> 0F 37 x3 -> 18 37       (394 ms)
deploy wings:   0A 37 -> 0B 37 x3 -> 0A 37 -> 18 37       (402 ms)
fly up/down:    0A 37 -> 0B 37 x38 -> 18 37             (3,898 ms)
fold wings:     02 37 -> 03 37 x4 -> 18 37                (465 ms)
```

The deliberate vertical-flight run establishes `0A 37` as the flight
transition and `0B 37` as continuous flight movement. The manual wing-exit
action reuses `02 37` / `03 37`, so those two opcodes describe a broader
airborne or falling state rather than jumping exclusively. Its 41-byte `02 37`
transition used flags `11` and marker `04`; the jump-apex form used the same
flags with marker `02`.

An `A1 FF` packet occurred inside the wing-deployment window, but it was not
part of that action. The complete timeline places `A1 FF` at an approximately
30-second cadence before, during, and after the test. Its 20- and 21-byte forms
are periodic state or telemetry packets whose field semantics remain open.

The same live session also captured a controlled map open-close-reopen test.
The open intervals produced two independent periodic C2S streams:

```text
00 91 || periodic_value:u32le       # value 1110, approximately 1.05-1.10 s
0B 91                               # opcode-only, approximately 1.204 s
```

After the close marker, each stream emitted one already-scheduled packet and
then stopped. `00 91` had a 17.251-second silent gap and resumed 1.024 seconds
after the reopen marker; `0B 91` had a 17.064-second gap and resumed after
1.056 seconds. Both payloads remained invariant. This confirms their map-open
association, while the differing periods rule out a strict request/reply pair.
The exact UI or map subsystem meaning of the `00 91` value remains open.

A four-marker flight test then separated ascent, stationary hover, descent,
and forward flight:

- controlled ascent emitted two `0A 37` / `0B 37` motion bursts. Across 20
  updates, the Z velocity was a stable approximately `+1187.68`;
- stationary hover emitted no `0A 37` or `0B 37` traffic, establishing that
  `0B 37` reports active flight motion rather than periodic flight state;
- controlled descent used `02 37` followed by thirteen `03 37` updates instead
  of the flight family. Position Z fell by approximately 2,456 units while
  velocity Z progressed from approximately `-305` to `-2744`;
- controlled forward flight emitted one `0A 37`, 41 `0B 37` updates, and an
  `18 37` snapshot. Integrating the average velocity over 4.235 seconds
  reproduces the observed position delta, confirming the velocity field.

The `0A 37` transition and simultaneous first `0B 37` update carried
byte-identical velocity and heading values in both the ascent and forward
tests. The former `movement_vector_xyz` field is therefore now named
`velocity_xyz` in both layouts.

The controlled descent ended with this sequence:

```text
02 37 -> 03 37 x13 -> 10 37 + 11 37 -> 11 37 x3 -> 18 37
```

A second descent later in the same session reproduced the `10 37` / `11 37`
tail exactly. In both cases, `10 37` and the simultaneous first `11 37` had
identical post-opcode payloads, followed by three more position updates. These
forms are provisionally named the landing boundary and landing movement; one
explicitly marked landing-only test remains desirable.

`18 37` is an action-position snapshot:

```text
18 37 || flags:u16le || position:f32le[3] || heading:f32le
      || client_unix_ms:u64le
```

It frequently appears immediately before `00 38`, but the isolated jump also
used it as the final ground-position snapshot. It is therefore an action
position packet rather than a skill-specific prefix. The `00 38` body contains
a `u32le` at offset 4. All 16 distinct values across 323 retained packets match
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

`1A 38` is a separate location-targeted skill form. Every retained sample body
has 27 bytes and the inspected samples carry skill ID `15060150`, independently
catalogued as Hellfire:

```text
1A 38
skill_id:u32le              # 15060150 (Hellfire) in retained samples
entity_id_tag:u8            # 02
target_entity_id:uvarint
reserved_or_flags:u32le     # zero in retained samples
target_position:f32le[3]
action_mode:u8              # zero in retained samples
```

A fixed 13-byte `1D 38` packet repeatedly follows this request. It contains
skill variant `15060153` at offset 7. Aion2Flow's public skill-icon catalog also
enumerates this variant, and it is numerically adjacent to the Hellfire skill
ID. Its exact follow-up stage remains a hypothesis until a controlled
Hellfire-only capture separates button press, cast completion, impact, and
cancellation.

Two opcode-only packets form another repeatable skill-request boundary. The
six-session snapshot contains exactly 870 instances each of `3A 38` and
`3C 38`. Four controlled pairs bracketed Flame Arrow, Blaze, Bittercold Wind,
and Firestorm requests:

```text
3A 38 -> [30 38 target reference] -> 00 38 skill request -> 3C 38
```

The controlled gaps from `3A 38` to `3C 38` were 67-107 ms; no captured pair
remained open for a long key hold. This supports skill-request begin/end rather
than raw key-down/key-up semantics, although a dedicated hold-only capture
should confirm it. Dodge and the observed self-targeted Wish of Concentration
request used their own paths and were not enclosed by the pair.

A later labelled single-cast test isolated a fifth targeted request:

```text
33 38 target selection
3A 38 + 30 38 target context + 00 38 skill request
94 ms
3C 38
2,662 ms
30 38 zero target context
```

The request carried skill ID `15210450`, flags `01`, stage `01`, and action
mode `02`. Its target varint was byte-equal to the immediately preceding
`33 38` selection and `30 38` context. The zero `30 38` form arrived 2.756
seconds after the request, while no `33 38` target clear occurred. This
confirms that `30 38` is temporary cast context and that `3A 38` / `3C 38`
bound request construction rather than the full cast duration.

`30 38` and `33 38` both have a compact target-reference shape:

```text
30 38 or 33 38
reference_flags:u8          # zero in retained samples
target_entity_id:uvarint    # zero encodes no target
```

The varint accounts exactly for the observed four- and six-byte body lengths.
Controlled target changes produced `33 38` with the newly selected entity;
clearing the target produced its zero form. `30 38` instead carried the active
target immediately before targeted skill requests, while zero was used for an
untargeted or self-targeted request. The registry therefore distinguishes
target selection from per-skill target context.

A labelled TAB-targeting test emitted 16 six-byte `33 38` packets selecting six
distinct mob entity IDs. Repeated IDs showed the client cycling among nearby
targets, while no other non-time opcode appeared in the 60-second action
window. TAB therefore has no separate network command in this capture: the
client resolves the next mob locally and sends the resulting selected entity
through the normal `33 38` form.

A later labelled test collected the same resource three times at one location.
All `30 8D` and `3D 36` traffic in that live session was confined to this
window. Each attempt had the same core sequence:

```text
33 38 || 00 || resource_entity_id:uvarint
30 8D || resource_entity_id:uvarint
... collection interval ...
[3D 36 || resource_entity_id:uvarint]
33 38 || 00 || 00
```

`30 8D` appeared exactly three times, once at the start of every attempt, and
always carried the resource ID selected by `33 38`. This confirms it as the
client gather request. `3D 36` carried the same ID at the end of the first and
third attempts but was absent from the second, so it is recorded as a
conditional gather follow-up rather than a mandatory completion packet. The
specific resource ID remains only in the ignored local event log.

Four labelled successful loot-collection tests each emitted exactly one
`20 56` packet, 0.742-1.606 seconds after the corresponding marker. At the
separate `loot 4` marker no loot action occurred and no `20 56` was emitted,
providing a clean negative control:

```text
20 56
request_flags:u8
loot_reference_a:u32le
loot_reference_b:u32le
trailing_flags:u8
```

Two additional retained samples reproduce the same 12-byte shape: one occurred
earlier in the live world session during combat, and one came from an
independent session. Across the six inspected packets, the flags are always
`01` and the trailing byte is always zero. The first `u32le` reference repeated
in two samples and otherwise varied; the second was distinct in all six. The
repeated labelled actions confirm `20 56` as the client loot request, while the
two reference roles remain open pending correlation with the matching S2C
object or inventory records.

Dodge provides a second independently structured sequence. All retained
`0E 37` packets use skill `15000100` or variant `15000101`; the public skill
catalog names `15000100` as Dodge. Separate controlled captures produced two
and three `0F 37` movement samples after one request:

```text
0E 37 -> 0F 37 -> 0F 37 [-> 0F 37] -> action-position/movement continuation
```

Both packets expose finite position, normalized direction, heading, and client
timestamp fields. `0E 37` additionally carries the skill ID and target entity.
The exact layouts and confidence labels are maintained in `opcodes.json`.

Raw character positions, entity identifiers, and timestamps remain in ignored
local artifacts.

### 5.4 Controlled-action captures

The third independently keyed session was captured from before connection
setup through the action test. It added 2,242 decrypted C2S frames and 28,520
RC4 body bytes. The useful non-time events included:

- three explicit target changes and one target clear;
- four targeted skill requests enclosed by `3A 38` / `3C 38`;
- a self-targeted or untargeted skill request without that enclosure;
- one Dodge sequence using `0E 37` / `0F 37`;
- separated movement, stop, and rotation periods.

The decoded skill IDs independently resolve to Dodge, Flame Arrow, Blaze,
Bittercold Wind, Firestorm, and Wish of Concentration. Capture-specific entity
IDs, coordinates, clock values, the OAEP secret, and the private key remain in
ignored local artifacts.

The fourth session isolated one stationary jump after a full client restart.
It added 735 frames and 9,011 RC4 body bytes, confirmed the `02 37` / `03 37`
jump layouts above, and demonstrated that returning to character selection does
not necessarily create a new world handshake.

The fifth session added 3,309 frames and 38,100 RC4 body bytes. Its ordered
action sequence included ordinary movement, one jump, target selection and
clear, one location-targeted skill, and one Dodge. It independently reproduced
the mapped jump, target, skill, and Dodge layouts. Neither `04 37` nor `05 37`
appeared anywhere in the session, so neither timestamp marker is required for
those standard actions. The previously observed marker payload layouts remain
valid, while their state-specific trigger remains open. The still-unmapped
`07 37`, `0B 37`, and `13 37` packets were also absent, indicating that this
routine movement/combat matrix does not trigger their underlying states.

The sixth session added 10,499 frames and 131,302 RC4 body bytes. Its capture
contained three world handshakes; selecting the handshake that matched the
recovered live key produced 9,649 valid `01 36` time packets and a continuous
decrypt with no read error. The earlier activity included an event, so the
controlled eight-jump sequence was used as the reliable boundary. Those eight
jumps produced exactly 16 `02 37` transitions and 54 `03 37` updates in a
9.5-second cluster.

After that marker, the capture exposed two previously unmapped movement
families. Two `0C 37` transitions enclosed ten `0D 37` position updates, while
two `0A 37` transitions began a 126-sample `0B 37` movement run. An earlier
event-period run contributed another two `0A 37` transitions and 20 `0B 37`
updates. The capture also contained one `10 37` boundary paired with four
`11 37` updates and one timestamp-free `19 37` packet immediately before the
first `0A 37` / `0B 37` run. Their position, vector, heading, mode, and client
timestamp fields are now recorded in `opcodes.json`. The original capture mixed
auto-navigation, riding, ordinary movement, and Dodge, so the application
meanings were initially left neutral. The later isolated live-viewer actions
identify `0A 37` / `0B 37` as flight; the other families remain unnamed.

A later labelled quest auto-navigation run isolated a short ground-only
segment. At movement onset the client emitted `00 37`, a timestamp-only
`04 37`, and then 20 ordinary `01 37` updates at approximately 10 Hz. The run
ended with another `00 37`, two `18 37` action-position snapshots, and the
timestamp-only `05 37`. The position samples covered approximately 2,159 units
of path over 2.2 seconds, with about 1,904 units of net displacement. No
`0C 37` / `0D 37`, `19 37`, flight, or airborne packet appeared. In this test,
quest auto-navigation was therefore server-visible as the normal ground
movement stream; no separate C2S route-start request preceded that stream.

One `01 90` packet overlapped the movement interval, but two timestamped
samples from an earlier session were 29.143 seconds apart and all three bodies
were identical. It is a periodic value rather than an auto-navigation signal.
A single `42 8D` packet appeared 1.450 seconds after the final `05 37`. It is
recorded as a quest/auto-navigation candidate, not as a confirmed navigation
opcode: separate arrival, manual-cancel, and quest-selection markers are still
needed. Skill traffic began only after a further 26-second quiet interval and
was excluded from the navigation sequence.

### 5.5 Offline command

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

Every report records immediate opcode pairs and the most frequent two-, three-,
and four-opcode sequences after removing `01 36` client-time packets. These
payload-free aggregates make recurring action boundaries visible even when
`--frame-limit 0` and `--samples-per-opcode 0` avoid retaining plaintext. The
default keeps 250 entries per sequence size; `--sequence-limit 0` keeps all.

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
- `locate_session_key.py` finds the network owner through its runtime vtable,
  follows it to the two live RC4 states, and exports their shared 214-byte key.
- `watch_session_key.py` discovers the live world process and refreshes the
  ignored local key file across session changes.
- `live_opcode_viewer.py` combines a filtered live capture, the runtime key
  monitor, continuous C2S decryption, registry names, counters, and labeled
  action markers in a Windows GUI.
- `scan_process_rsa_public.py` locates runtime public-key objects.
- `scan_process_range.py` performs bounded pattern searches.
- `export_openssl_rsa.py` validates and exports all private/CRT components.
- `locate_openssl_rsa.py` identifies the related OpenSSL wrapper group.
- `find_x64_calls.py` and `find_x64_rip_refs.py` locate direct and RIP-relative
  references.
- `disassemble_process.py` reads and decodes bounded runtime code windows.
- `scan_live_buffers.py` correlates captured bytes with memory candidates.
- `decode_launcher_parameter.py` decodes the AES-256-ECB `-lp` configuration
  container and redacts values unless explicitly requested.

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

### 6.4 Per-session startup cost

The original game creates a fresh ephemeral RSA key for every world
connection. A passive companion therefore has to recover the matching key (or
the resulting 214-byte OAEP plaintext) after each reconnect; a key exported
from an earlier process run does not apply to the next session.

The generic RSA/BIGNUM recovery path is a research fallback. In the controlled
session it made several passes over roughly 17-22 GB of readable virtual
memory, so it took minutes. `locate_session_key.py` now implements the intended
fast path instead. It derives the RC4 vtable from a constructor signature and
uses the adjacent network-owner vtable to locate the current owner allocation
without relying on a fixed heap offset. The owner then exposes the two live
states through its `+0xE20` / `+0xE30` area. A result is accepted only when
both objects contain valid 256-byte permutations and the same 214-byte key.

Across ten repeated revision-3527 tests after the independent restart, the
heap-layout-independent lookup took 269-297 ms internally (280 ms average).
End-to-end wall time including Python startup was 348-385 ms (365 ms average).
All ten keys matched the independently recovered session key. Exporting it to
`decrypt_c2s_rc4.py` reproduced all 735 frames and 9,011 encrypted body bytes
of the isolated-jump capture. The standalone locator keeps the full-memory
fallback opt-in through `--full-scan-fallback`.

The connection-aware monitor removes the need to enter or rediscover a PID.
It can start before the world connection exists and reinitializes its cached
process-local addresses after a disconnect, reconnect, or process restart. In
a 30-poll live test, automatic discovery and the initial key event completed in
285 ms inside the running monitor. The following 29 cached polls took
0.40-0.76 ms each (0.55 ms average). With the default 250 ms interval, normal
readiness is therefore bounded mainly by one poll interval plus the initial
profile lookup rather than a whole-memory scan.

Later revision-3527 allocations placed the validated RC4 states outside the
profiled owner arena. A small fallback case located the pair in 2.08 seconds.
A much larger allocation originally required 84.87 seconds and 12.99 GB of
reads. Prioritizing 64-KiB allocator regions and coalescing adjacent readable
ranges reduced the same live-session fallback to 6.83 seconds and 2.44 GB.
The monitor invokes this validated fallback once after four fast misses and
caches the two state addresses; subsequent direct-state checks return to
sub-millisecond reads. The fallback itself is therefore a seconds-scale path,
not a millisecond path. `--no-full-scan-fallback` disables this behavior.

The monitor must have sufficient rights to open the process. In the large
fallback case it had originally been started without elevation, so it could
observe the world socket but could not read the owning process. It now reports
that Win32 access error even under `--quiet`, rather than looking like a slow
key search.

A standalone protocol client has a different lifecycle: it generates and owns
its private key before sending `10 36`, so key availability is immediate and
there is no process scan at connection startup.

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

### October 10, 2026

- Fully decoded a sixth independently keyed session, bringing the retained
  snapshot to 172,178 frames and 1,950,077 encrypted body bytes.
- Used an eight-jump marker to separate controlled movement from preceding
  event traffic, then documented the `0A 37` / `0B 37`, `0C 37` / `0D 37`,
  `10 37` / `11 37`, and `19 37` layouts without assigning premature action
  names.
- Prioritized 64-KiB allocator regions and coalesced adjacent reads in the
  full-memory state fallback, reducing the largest measured live case from
  84.87 seconds and 12.99 GB to 6.83 seconds and 2.44 GB.
- Made connection and process-access failures visible even in quiet monitor
  mode, including the elevation mismatch that invalidated the initial timing.
- Added a live C2S opcode viewer that keeps keys in memory, hides regular time
  packets by default, and records user-labeled action markers beside decrypted
  packets in an ignored local JSONL timeline.
- Isolated Dodge, wing deployment, deliberate vertical flight, and manual wing
  exit in the live viewer. This confirmed `0A 37` / `0B 37` as the flight
  transition/update pair, broadened `02 37` / `03 37` to the airborne/falling
  family, and showed that the interleaved `A1 FF` packet was periodic rather
  than wing-triggered.
- Confirmed `00 91` and opcode-only `0B 91` with a controlled map
  open-close-reopen test. Both streams stopped throughout the closed interval
  and resumed after reopening; their independent approximately 1.05- and
  1.20-second cadences exclude a one-for-one packet pair.
- Separated ascent, hover, descent, and forward flight with labelled markers.
  This confirmed the `0A 37` / `0B 37` vector triplet as velocity, established
  that stationary hover emits no flight updates, and linked `10 37` / `11 37`
  to the landing tail after airborne descent.
- Repeated gathering three times at one resource. This confirmed `30 8D` as
  the gather request, independently reproduced the `33 38` target select/clear
  lifecycle, and identified `3D 36` as a conditional same-resource follow-up.
- Repeatedly selected nearby mobs with TAB. Sixteen `33 38` packets cycled
  among six entity IDs without any companion action opcode, establishing that
  TAB selection is client-side logic followed by the normal target update.
- Isolated one labelled targeted cast. The target ID matched across `33 38`,
  `30 38`, and `00 38`; the 94-ms `3A 38` / `3C 38` envelope ended well before
  the cast-specific target context cleared, confirming the request lifecycle.
- Isolated one labelled quest auto-navigation run. It used the ordinary
  `00 37` / `01 37` ground-movement stream with `04 37` / `05 37` timestamp
  boundaries and emitted no dedicated route-start request. A coincident
  `01 90` packet was excluded as periodic, while the post-arrival `42 8D`
  sample remains a candidate pending arrival/cancel controls.
- Repeated labelled loot collection four times. Every successful action
  emitted exactly one `20 56`; the separate `loot 4` marker with no loot action
  emitted none. Two older samples reproduce its fixed 12-byte layout, promoting
  the opcode meaning to locally confirmed while leaving its two references
  open.

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
- Fully decoded the first five independently keyed sessions.
- Added capture timestamps and opcode filters to focused C2S sampling, then
  mapped movement coordinates, client timestamps, jump transitions, skill IDs,
  and the repeated Dodge request/movement sequence in families `37` and `38`.
- Implemented `aion2_client_crypto.py` with standalone RSA handshake generation,
  OAEP recovery, continuous C2S framing, and deterministic self-tests.
- Implemented and benchmarked direct live-session recovery through the owner
  arena and paired RC4 states, reducing lookup from minutes to about 0.2 seconds
  internally on the investigated revision.
- Identified and verified the inner zlib container carried by C2S `40 8D`.
- Reconstructed the complete `13 36` byte layout and traced its encoded token
  from the NC Platform SDK `authn_token` response field through the session
  object into the packet builder.
- Reconstructed the independent `-lp` launcher container as Base64-wrapped
  AES-256-ECB with strict PKCS#7 padding and added a redacting decoder.
- Promoted `04 37` and `05 37` from anonymous observations to timestamp-marker
  layouts while deliberately leaving their action-level distinction unnamed.
- Reproduced jump, target, location-skill, and Dodge sequences in a fifth
  independently keyed session; the absence of `04 37` and `05 37` narrowed
  those markers to a more specific state or action.
- Added a one-time validated full-memory fallback to the session-key monitor
  for allocator layouts that miss the fast owner-arena profile.
