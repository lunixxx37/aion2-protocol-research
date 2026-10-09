# Opcode Catalog

Opcodes are written in wire order. The catalog combines local capture evidence
with public parser implementations. Meanings may change with client revisions
and should be validated through field invariants and controlled actions.

Confidence terms are defined in [SOURCES.md](SOURCES.md).

## Family `36`: session and world

| Opcode | Direction | Meaning | Confidence |
|---|---|---|---|
| `00 36` | S2C | server tick | locally confirmed |
| `01 36` | C2S | client time/keepalive followed by `unix_ms:u64le` | locally confirmed |
| `03 36` | S2C in public parsers | ping | medium |
| `10 36` | C2S | RSA public-key handshake | locally confirmed |
| `11 36` | S2C | RSA response/handshake | locally confirmed |
| `13 36` | C2S | first encrypted session packet; identification/session fields | structure confirmed, semantics open |
| `15 36` | S2C | login or server transfer | medium |
| `16 36` | S2C | game-server information | medium |
| `1A 36` | S2C | name check | public parser |
| `23 36` | S2C | zone | public parser |
| `33 36` | S2C | local player | high |
| `35 36` | S2C | summon spawn | local/parser |
| `40 36` | S2C | spawn variant | local/parser |
| `41 36` | S2C | spawn/summon | high |
| `42 36` | S2C | removal/death | high |
| `44 36` | S2C | player information | local/parser |
| `45 36` | S2C | player information | high |

## Family `37`: movement

| Opcode | Direction | Meaning |
|---|---|---|
| `1A 37` | S2C | movement |
| `1B 37` | S2C | movement |
| `1C 37` | S2C | movement |
| `1D 37` | S2C | movement-related |

The decrypted C2S stream contains high-volume `01 37`, `00 37`, `18 37`,
`07 37`, `03 37`, `0F 37`, and `13 37` packets. Their exact meanings are not
yet assigned. Multiple 28- to 61-byte bodies contain changing little-endian
float-like fields and timestamps, making movement/state updates a strong test
target rather than a confirmed label.

## Family `38`: combat and skills

| Opcode | Direction | Meaning |
|---|---|---|
| `02 38` | S2C | action/cast |
| `03 38` | S2C | NPC position |
| `04 38` | S2C | direct damage |
| `05 38` | S2C | damage over time |
| `06 38` | S2C | cast end/defense |
| `09 38` | S2C | skill cast |
| `0E 38` | S2C | target selected |
| `2A 38` | S2C | apply status |
| `2B 38` | S2C | apply-status variant |
| `2C 38` | S2C | remove status |
| `35 38` | S2C | summon spawn/skill sequence |
| `3D 38` | S2C | batch |

Decrypted C2S frequently includes `00 38`, `3A 38`, and `3C 38`. The latter two
were consistently opcode-only in the sampled traffic.

## Family `39`: lobby

| Opcode | Direction | Meaning |
|---|---|---|
| `01 39` | S2C | lobby handshake |
| `03 39` | S2C | lobby ping |
| `06 39` | S2C | account |
| `09 39` | S2C | server list |
| `0B 39` | S2C | character list |
| `0D 39` | S2C | join |
| `0F 39` | S2C | redirect |

## Other families

| Opcode | Direction | Meaning |
|---|---|---|
| `10 56` | C2S | opcode-only packet in the initial encrypted sequence |
| `1B 56` | S2C | unknown/feature-related |
| `00 61` | S2C | dungeon-run state |
| `01 61` | S2C | dungeon result |
| `00 8D` | S2C | HP update |
| `04 8D` | S2C | nickname/owner |
| `40 8D` | C2S | zlib-compressed UTF-16LE JSON-like payload |
| `2F 8D` | S2C | notice |
| `01 91` | S2C | NPC broadcast |
| `1B 92` | S2C | HP |
| `02 97` | S2C | party |
| `05 E0` | S2C | groggy/guard |

## Locally decrypted C2S distribution

The following snapshot combines two independently keyed sessions that stayed
synchronized for `94,188` frames and `1,127,118` RC4 body bytes. Frequency
alone does not establish meaning.

| Opcode | Frames | Observation |
|---|---:|---|
| `01 36` | 83,587 | client time/keepalive; body length 10 |
| `01 37` | 4,561 | unknown; frequent family `37` packet |
| `00 38` | 962 | unknown family `38` packet |
| `3A 38` | 865 | opcode-only in samples |
| `3C 38` | 865 | opcode-only in samples |
| `02 36` | 446 | unknown |
| `00 37` | 374 | unknown |
| `18 37` | 358 | unknown |
| `07 37` | 245 | unknown |
| `03 37` | 236 | unknown |
| `0F 37` | 220 | unknown |
| `13 37` | 214 | unknown |
| `A1 FF` | 147 | unknown; not LZ4 because the marker requires `FF FF` |
| `17 90` | 144 | stable 10-byte body in samples |
| `33 38` | 130 | short variable-length payload |
| `30 38` | 115 | short variable-length payload |
| `0B 37` | 114 | unknown |
| `0E 37` | 111 | 61-byte state-like payload in samples |

Both observed startup sequences begin with a 158-byte `13 36` body followed by
time packets and an opcode-only `10 56`. The `13 36` body contains printable
identification/session fields. Raw values are intentionally omitted because
they may include session tokens.
