# Generated Analysis Artifacts

This directory is reserved for locally generated JSON reports. Generated files
are ignored by Git because RSA, handshake, and decrypted-packet output may
contain private keys, session secrets, account values, or other sensitive data.

Typical commands:

```powershell
python tools/analyze_pcaps.py "C:\path\to\captures\*.pcapng" `
  --details --json artifacts\corpus-analysis.json

python tools/probe_tick_plaintext.py "C:\path\to\session.pcapng" `
  --json artifacts\tick-probe.json

python tools/locate_openssl_rsa.py --pid PROCESS_ID `
  --json artifacts\openssl-rsa-locator.json

python tools/locate_session_key.py --pid PROCESS_ID `
  --key-out artifacts\session-key.bin `
  --json artifacts\session-key-locator.json

python tools/find_x64_calls.py --pid PROCESS_ID `
  --target 0xRUNTIME_ADDRESS `
  --json artifacts\rsa-private-decrypt-xrefs.json

python tools/export_openssl_rsa.py --pid PROCESS_ID `
  --capture "C:\path\to\session.pcapng" `
  --fields-address 0xFIELDS_ADDRESS `
  --private-key "C:\local-secrets\session-key.pem" `
  --json artifacts\openssl-rsa-export.json

python tools/decrypt_handshake.py `
  --capture "C:\path\to\session.pcapng" `
  --private-key "C:\local-secrets\session-key.pem" `
  --json artifacts\handshake-plaintext.json

python tools/decrypt_c2s_rc4.py `
  "C:\path\to\session.pcapng" `
  --session-key artifacts\session-key.bin `
  --modulus-sha256 MODULUS_SHA256 `
  --frame-limit 0 --samples-per-opcode 3 --quiet `
  --json artifacts\c2s-rc4-decrypt.json

python tools/probe_legacy_aion_cipher.py `
  --capture "C:\path\to\session.pcapng" `
  --handshake-json artifacts\handshake-plaintext.json `
  --json artifacts\legacy-cipher-probe.json

python tools/probe_keystream_prf.py `
  --handshake-json artifacts\handshake-plaintext.json `
  --samples-json artifacts\tick-keystream-samples.json `
  --modulus-sha256 MODULUS_SHA256 `
  --json artifacts\keystream-prf-probe.json

python tools/probe_stream_ciphers.py `
  --handshake-json artifacts\handshake-plaintext.json `
  --samples-json artifacts\tick-keystream-samples.json `
  --modulus-sha256 MODULUS_SHA256 `
  --json artifacts\stream-cipher-probe.json

python tools/scan_process_rsa_public.py --pid PROCESS_ID `
  --json artifacts\current-rsa-public-scan.json
```

With `--frame-limit N`, the RC4 report stores the first `N` ciphertext and
plaintext bodies in full. `--samples-per-opcode N` retains additional plaintext
examples for every opcode. Use zero for both options when only aggregate
statistics are needed. Keep all such reports local.

The C2S report also includes aggregate opcode pairs, triples, and quadruples.
The latter omit `01 36` client-time packets so high-frequency keepalives do not
hide action sequences. Use `--sequence-limit 0` to retain every distinct
sequence or set a positive per-category limit for smaller reports.
