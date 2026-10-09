# Sources and Confidence Levels

## Primary local evidence

Reproducible observations from local PCAPNG captures and the installed client
have the highest priority:

- 31 captures recorded from October 3 through October 9, 2026;
- Global client revisions `3526` and `3527`;
- client binary SHA-256
  `3842FC511A09121D3B3F2567002994D5C2CFDBA0CF762D035C8AE21872ABA953`;
- observed world port `13328`;
- RSA handshakes `10 36` and `11 36`;
- manually mapped OpenSSL cryptographic code containing AES, ChaCha20,
  Poly1305, Montgomery, and RSA implementations;
- internal references to `RSA_private_decrypt` and OpenSSL provider paths;
- fully validated ephemeral RSA private keys for independent sessions;
- matching server blocks decoded as OAEP-SHA1 with 214-byte messages;
- runtime RC4 KSA/PRGA disassembly and exact 214-byte key-buffer matches;
- continuous offline C2S decryption across more than 155,000 frames in two
  independently keyed sessions.

Raw captures are excluded because they contain identity and session data.

## Public implementations

### a2kit

- Repository: <https://github.com/nuriland/a2kit>
- License: MIT
- Use: current framing, TCP reassembly, LZ4, lobby, S2C parsing, and
  privacy-aware export
- Relevant files:
  - <https://github.com/nuriland/a2kit/blob/main/wire/framer.go>
  - <https://github.com/nuriland/a2kit/blob/main/wire/decoder.go>
  - <https://github.com/nuriland/a2kit/blob/main/game/opcode.go>
  - <https://github.com/nuriland/a2kit/blob/main/game/parse.go>

`wire/decoder.go` can retain client frames but identifies their bodies as
encrypted. `game.Parse` does not decode them.

### A2Tools DPS Meter

- Repository: <https://github.com/taengu/A2Tools-DPS-Meter>
- License: GPL-3.0
- Use: independent confirmation of the frame-length formula, LZ4, and TLS
  separation
- Relevant files:
  - <https://github.com/taengu/A2Tools-DPS-Meter/blob/main/src-tauri/src/capture/framing.rs>
  - <https://github.com/taengu/A2Tools-DPS-Meter/blob/main/src-tauri/src/combat/capture_dispatcher.rs>

Its dispatcher intentionally handles server-to-client traffic only.

### Aether Aion2 DPS Meter

- Repository: <https://github.com/Helveticxa/Aether-Aion2-DPS-meter-Global>
- License: GPL
- Protocol report:
  <https://github.com/Helveticxa/Aether-Aion2-DPS-meter-Global/blob/main/docs/AION2_PACKET_PROTOCOL_ANALYSIS.zh-CN.md>
- English skill-ID catalog:
  <https://github.com/Helveticxa/Aether-Aion2-DPS-meter-Global/blob/main/src/i18n/locales/aion2skills/en.json>
- Use: additional layouts for spawn, damage, HP, and owner fields
- Limitation: older than the currently investigated Global client revision

### Aion2Meter

- Repository: <https://github.com/a2meter/Aion2Meter>
- Use: historical PCAP and opcode research
- Limitation: some older documentation interprets the length byte as a packet
  delimiter; current evidence supports unsigned-varint framing instead

### Aion2Flow

- Repository: <https://github.com/cloris-chan/Aion2Flow>
- License: GPL-3.0
- Skill-icon catalog:
  <https://github.com/cloris-chan/Aion2Flow/blob/main/src/Aion2Flow.Resources/Generated/SkillIconCatalog.g.cs>
- Use: independent confirmation that observed derived skill identifiers such
  as `15060153` are valid catalogued variants
- Limitation: its live protocol parsers focus on inbound combat traffic and do
  not provide a C2S plaintext decoder

### AionFlex

The locally installed .NET application was inspected read-only. Its
`RecvHookCaptureService` locates a function pointer to Winsock `recv()`, replaces
it with a ring-buffer hook, and records incoming bytes. It contains no C2S
decryptor.

## Related file encryption

FModel/CUE4Parse contains Aion-2-specific AES decryption for data files:

<https://github.com/MeyouVA/FModelMats/blob/main/CUE4Parse/CUE4Parse/GameTypes/Aion2/Encryption/Aes/Aion2DatFileAes.cs>

One variant encrypts a 16-byte counter through AES-ECB and XORs the result with
the data, effectively implementing a CTR-like mode manually. This was useful
for prioritizing network-cipher candidates, but it is not evidence that the
network protocol uses the same construction.

## Historical Aion network cipher

The maintained `beyond-aion/aion-server` branch contains the older stateful
Aion packet cipher and key exchange:

- Repository: <https://github.com/beyond-aion/aion-server>
- [`EncryptionKeyPair.java`](https://github.com/beyond-aion/aion-server/blob/4.8/game-server/src/com/aionemu/gameserver/network/EncryptionKeyPair.java)
- [`Crypt.java`](https://github.com/beyond-aion/aion-server/blob/4.8/game-server/src/com/aionemu/gameserver/network/Crypt.java)
- [`SM_KEY.java`](https://github.com/beyond-aion/aion-server/blob/4.8/game-server/src/com/aionemu/gameserver/network/aion/serverpackets/SM_KEY.java)

These sources establish the historical 64-byte XOR key, eight-byte advancing
packet key, and obfuscation of the `u32` base key. Local testing ruled this
construction out for the investigated Aion 2 C2S stream.

OpenSSL's primary OAEP implementation was used to cross-check the manually
decoded structure:

- [`rsa_oaep.c`](https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_oaep.c)

## Unreal cryptographic interfaces

The official Unreal Engine API documents RSA private-key operations and maximum
plaintext sizes under padding:

- <https://dev.epicgames.com/documentation/unreal-engine/API/Runtime/RSA/FRSA>
- <https://dev.epicgames.com/documentation/unreal-engine/API/Runtime/Core/IEngineCrypto>
- <https://dev.epicgames.com/documentation/unreal-engine/API/Plugins/PlatformCryptoContext/FEncryptionContextOpenSSL>

`IEngineCrypto` describes RSA components as little-endian. The OpenSSL context
offers RSA and AES-256 CBC/ECB/GCM. These references justified additional
runtime signatures but do not prove which interface Aion 2 uses for its world
cipher.

## Sources not suitable as Aion 2 network evidence

- Older Aion and Aion Classic protocols from different generations.
- Repositories named `AION2` that are unrelated to the NCSOFT game.
- Visual bots based on screen capture and input simulation.
- DPS-meter output without source code or packet evidence.

## Confidence model

| Level | Meaning |
|---|---|
| locally confirmed | reproduced across multiple local sessions |
| publicly confirmed | implemented by at least two independent public parsers |
| parser-based | present in one parser but not yet validated field by field locally |
| hypothesis | explains observations but still needs another test |
