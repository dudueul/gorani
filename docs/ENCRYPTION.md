# Encryption: the byte-level specification (GV01, GV02, GV03, GK01, GW01, GC01, GB1)

> Copyright 2026- Seongwoo Hong. All rights reserved.
> Written from the code (`crates/formats/src/`, `web/src/vault/vault-crypto.ts`) as of commit ⑨c; the code is the authority.

## At a glance

| Format | What it is | Algorithms | Overhead | Opens with | Quantum-safe |
|---|---|---|---|---|---|
| **GV01** | sealing to a P-256 public key (ECIES) | ECDH P-256, HKDF-SHA256, AES-256-GCM | 81 B | the recipient's P-256 private half | no |
| **GV02** | content under a symmetric content key | AES-256-GCM | 32 B | the 32-byte content key | yes |
| **GV03** | hybrid post-quantum sealing | ECDH P-256 **and** ML-KEM-768 → HKDF → AES-256-GCM | 1,185 B | **both** private halves | yes |
| **GK01** | a hybrid private key's bytes (bundle) | container | — | — | — |
| **GW01** | a private key wrapped by an unlock secret | AES-256-GCM under the KEK | 32 B | the unlock secret | yes |
| **GC01** | a large file in frames | AES-256-GCM per 8 MiB frame, position+finality AAD | 28 B/frame | the content key | yes |
| **GB1** | the backup container | AES-256-GCM segments under a per-backup file key | ~28 B/1 MiB | the key file | yes |

The pattern everywhere: **content is GV02** (fast, symmetric, one fresh key per item) and only the small content key is sealed to a public key (GV03 in gorani — hybrid from birth). Rotation re-wraps keys, never content.

## The key hierarchy

```text
unlock secret (passkey PRF ‖ Argon2id password ‖ recovery code)
   ──▶ KEK ──GW01──▶ root private key (GK01 bundle: P-256 PKCS#8 ‖ ML-KEM seed ‖ P-256 public)
                       │ everything below is sealed to the root's public half (GV03)
                       ├─▶ files store key          (stores.files; private half sealed to the root)
                       ├─▶ family shared-area key   (one key, sealed to EVERY member's root)
                       ├─▶ parents' master key      (private half sealed to each parent's root — docs/FAMILY.md)
                       ├─▶ backup public key        (private half ONLY in the owner's key file)
                       └─▶ retired keys             (never deleted)
content key (32 random bytes per file version) ──GV02──▶ the bytes, preview, text
```

- All public halves + wrapped private copies live in the member's settings; the server can open nothing.
- Key ids: `base64(SHA-256(raw pub)[..12])` with `+/=` removed (16 chars); hybrid keys: `"pq"` + 14 chars of SHA-256(P-256 raw ‖ ML-KEM pub).

## Byte layouts (big-endian; AAD = GCM additional authenticated data)

### GV01/GV03 — sealing to a public key

```text
GV01 = "GV01" ‖ ephemeral P-256 public (65) ‖ nonce (12) ‖ ct ‖ tag (16)
       AAD = the whole header
       key = HKDF-SHA256(ikm = ECDH(eph, recipient), salt = eph pub, info = "gorani-vault-v1")
GV03 = "GV03" ‖ eph pub (65) ‖ ML-KEM ct (1088) ‖ nonce (12) ‖ ct ‖ tag
       ss_ec  = ECDH(eph priv, recipient P-256 pub)
       ss_kem = ML-KEM-768.Encaps(recipient ML-KEM pub)
       salt   = SHA-256(eph pub ‖ ML-KEM ct ‖ recipient P-256 pub ‖ recipient ML-KEM pub)
       key    = HKDF-SHA256(ikm = ss_ec ‖ ss_kem, salt, info = "gorani-vault-v3")
```

The GV03 salt binds both ciphertexts and both recipient halves — the "X-Wing" combiner: neither half can be swapped or replayed against another recipient, and an attacker must break **both** P-256 (a quantum computer) **and** ML-KEM-768 (a flaw in the new scheme) to open anything.

### GK01 / GW01 — key containers

```text
GK01 = "GK01" ‖ len(pkcs8):2 ‖ P-256 private PKCS#8 ‖ ML-KEM seed (64) ‖ P-256 public (65)
GW01 = "GW01" ‖ nonce (12) ‖ AES-256-GCM(KEK, key bytes) ‖ tag,   AAD = "GW01"
```

### Unlock methods (KEK per kind)

| Method | KEK | Strength |
|---|---|---|
| password | Argon2id(NFKC(password), salt, **64 MiB, t=3, p=4**) — the only KDF, cost bounded 19 MiB–1 GiB / 1–20 / 1–16 | whatever the password has |
| recovery | HKDF-SHA256(normalised code, salt, "gorani-recovery-v1") | ≈196 bits |
| passkey | HKDF-SHA256(WebAuthn PRF output, salt, "gorani-passkey-v1") | 256 bits inside the authenticator |
| device copy | HKDF-SHA256(device secret, salt, "gorani-device-v1") | the platform's TPM/Enclave/keyring |

### GC01 — chunked files (docs/VIDEO.md rides on this)

```text
object  = frame 0 ‖ frame 1 ‖ …        (every frame but the last: chunk + 28 bytes)
frame i = nonce (12) ‖ AES-GCM(content key, chunk i, AAD) ‖ tag (16)
AAD     = "GC01" ‖ i (8 BE) ‖ final (1)
```

Any frame opens alone → Range seeking, streaming downloads, on-demand desktop sync, and the media service worker's native-video streaming (docs/VIDEO.md).

### GB1 — backups

See `crates/formats/src/backup.rs` header + docs in that file: counter nonces, position+finality AAD, the file key sealed (GV03) into the header to the backup public key.

## What the server can read

Sizes, versions, times, folder shape, ids, the change feed's structure — and **nothing else**: names, types, folder names, dates-inside-documents are GV-sealed text; content keys are stored wrapped; the Worker refuses any unsealed byte or name before storing it (`worker/src/routes.rs`, `files_store.rs`).

## Verifying

`cargo test -p gorani-formats` (round-trips, tamper, reorder, truncate) and
`tests/unit/formats.test.mjs` + `tests/vectors` (crates/formats/tests/vectors.json):
the browser's TypeScript and the Rust reference implementation write the same
bytes, both directions, every commit. That cross-language guarantee is the
foundation the native clients stand on.