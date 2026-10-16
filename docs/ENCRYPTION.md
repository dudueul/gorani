# Encryption: the byte-level specification (GV01–GV04, GK01, GW01, GC01, GB2)

> Copyright 2026- Seongwoo Hong. All rights reserved.
> Written from the code (`crates/formats/src/`, `web/src/vault/vault-crypto.ts`) as of commit ⑨c; the code is the authority.

## At a glance

| Format | What it is | Algorithms | Overhead | Opens with | Quantum-safe |
|---|---|---|---|---|---|
| **GV01** | sealing to a P-256 public key (ECIES) | ECDH P-256, HKDF-SHA256, AES-256-GCM | 81 B | the recipient's P-256 private half | no |
| **GV02** | content under a symmetric content key | AES-256-GCM | 32 B | the 32-byte content key | yes |
| **GV03** | hybrid post-quantum sealing | ECDH P-256 **and** ML-KEM-768 → HKDF → AES-256-GCM | 1,185 B | **both** private halves | yes |
| **GV04** | placed, store-authenticated sealing — **every value a files store keeps** | GV03 + the store PSK in the key schedule + the value's place as AAD | 1,185 B | the store key, **in that place** | yes |
| **GK01** | a hybrid private key's bytes (bundle) | container | — | — | — |
| **GW01** | a private key wrapped by an unlock secret | AES-256-GCM under the KEK | 32 B | the unlock secret | yes |
| **GC01** | a large file in frames | AES-256-GCM per 8 MiB frame, position+finality AAD | 28 B/frame | the content key | yes |
| **GB2** | the backup container (header authenticated; GB1 before commit 25) | AES-256-GCM segments under a per-backup file key | ~28 B/1 MiB | the key file | yes |

The pattern everywhere: **content is GV02** (fast, symmetric, one fresh key per item) and only the small content key is sealed — into its place in the store (GV04, since commit 25; GV03 before). Key material sealed to a member's root (store records, case grants, the identity key) or to the team recovery key (recovery copies) stays GV03. Rotation re-seals keys, never content.

## The key hierarchy

```text
unlock secret (passkey PRF ‖ Argon2id password ‖ recovery code)
   ──▶ KEK ──GW01──▶ root private key (GK01 bundle: P-256 PKCS#8 ‖ ML-KEM seed ‖ P-256 public)
                       │ everything below is sealed to the root's public half (GV03)
                       ├─▶ files store key          (stores.files; private half sealed to the root)
                       ├─▶ case keys               (each sealed to every grantee's root, signed — docs/CASES.md)
                       ├─▶ identity signing key    (ECDSA P-256, sealed to the root — identity.ts)
                       ├─▶ backup public key        (private half ONLY in the owner's key file)
                       └─▶ retired keys             (never deleted)
content key (32 random bytes per file version) ──GV02──▶ the bytes, preview, text
```

- All public halves + wrapped private copies live in the member's settings (own store, identity) or the registry (case grants, recovery copies and shares); the server can open nothing.
- The team recovery key's private half is never stored whole: Shamir M-of-N shares, each sealed to a lead's root (docs/CASES.md › Recovery).
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

Decisions a security review should know about (considered, not overlooked):

- **GV01's 65-byte salt** is longer than HMAC-SHA256's block, so HKDF
  pre-hashes it — standard, well-defined HMAC behavior (RFC 2104), not a
  weakness. The raw salt is kept for GV01 byte compatibility; GV03 already
  standardizes on a 32-byte digest.
- **Domain separation** inside GV03: one `info` serves all purposes. That
  is deliberate — transposition is already defeated structurally: content
  keys are sealed to *store* public keys while store/master private keys
  are sealed to *root* public keys (different recipients → different
  keys), the whole header rides as AAD, and payload shapes differ (a 32-byte
  content key cannot parse as a GK01 bundle). Purpose tags inside the
  sealed payloads were considered and rejected: they change the wire format
  for defense-in-depth that shape checks already provide. **Revisited in
  commit 25:** that argument holds *between* key kinds, and fails *within*
  a store — two files' content keys have the same shape, the same
  recipient, and swap undetected. GV04 binds each store value's place
  (kind, item, version) as AAD: the purpose tag, adopted once the threat
  that needs it was named. A decision that is written down can be
  revisited with its reasons; one that is not just gets repeated.
- **One fresh content key per file version** (`model.ts › uploadOne`): the
  API tolerates a reused key, but the client never reuses one, so a key
  encrypts exactly one object's frames — see GC01 below.

The GV03 salt binds both ciphertexts and both recipient halves — the "X-Wing" combiner: neither half can be swapped or replayed against another recipient, and an attacker must break **both** P-256 (a quantum computer) **and** ML-KEM-768 (a flaw in the new scheme) to open anything.

### GV04 — placed, store-authenticated sealing (commit 25)

Everything a files store keeps sealed — file names, each version's content
key and type, music tags, folder names, share names, the store's secrets —
is GV04. The Worker refuses any other format in those columns.

```text
place     = lp("gorani-place-v1") ‖ lp(kind) ‖ lp(store) ‖ lp(item) ‖ lp(version)
            lp(x) = u32 BE length ‖ UTF-8;  version decimal, "" for none
store_psk = HKDF-SHA256(ikm  = ECDH(store private, store public) ‖ SHA-256(ML-KEM dk),
                        salt = "gorani-store-psk", info = "gorani-store-psk-v1")
GV04      = "GV04" ‖ eph P-256 (65) ‖ ML-KEM ct (1088) ‖ nonce (12) ‖ ct ‖ tag
  salt    = SHA-256(eph pub ‖ ML-KEM ct ‖ store P-256 pub ‖ store ML-KEM pub)   (GV03's)
  key     = HKDF-SHA256(ikm = ss_ec ‖ ss_kem ‖ store_psk, salt, info = "gorani-vault-v4")
  AAD     = header ‖ place
text      = "GV04:" + base64
```

| kind | item | version | the value |
|---|---|---|---|
| `file.name` | file id | — | a file's name (a rename re-seals into the same place) |
| `file.key` | file id | n | version n's content key |
| `file.type` | file id | n | version n's MIME type — for a malware sample, `application/x-gorani-sample; original=…` (commit 29e, `samples.ts`) |
| `file.music` | file id | n | version n's tag summary |
| `file.hash` | file id | n | version n's signed content hash (commit 29d, `content-hash.ts`) |
| `file.modified` | file id | n | version n's original modified date: the uploader's File.lastModified or mtime, ISO 8601 (39y) |
| `file.intake` | file id | — | an evidence file's signed intake record (commit 29g, `intake.ts`) |
| `custody.reason` | file id | n | custody link n's reason (commit 29g, `custody.ts`) |
| `folder.name` | folder id | — | a folder's name |
| `share.name` | share id | — | the owner's copy of a link's name |
| `store.secrets` | — | — | fingerprint + index keys |

`store` is the member id whose store it is. Code: `web/src/vault/places.ts`
+ `vault-crypto.ts › sealPlaced`; `crates/formats/src/placed.rs`.

Why each part (docs/SECURITY-REVIEW.md › O6):

- **The place, as AAD, stops moving.** GV03 values say nothing about where
  they belong, so the server could swap two files' content keys (with their
  objects) or names: "invoice.pdf" opened a malware sample. The place is
  never stored — the opener rebuilds it from what it is opening — so a
  value moved anywhere else fails authentication. Version numbers are in
  the key's place, so version 1's key cannot pose as version 2's.
- **The store PSK stops minting.** GV03 seals to a *public* key, which the
  server holds: it could invent a file — content key, bytes, name — and the
  file would appear in your store. The PSK is computable only from the
  store's private key (the self-ECDH construction of the record key below),
  so sealing into a store needs what opening needs. This is HPKE's PSK mode
  (RFC 9180 §5.1) in our own framing; a store "seals to itself" — the API
  takes the private key and derives the public halves from it.
- **Ids come first.** The client chooses file and folder ids (128 random
  bits, base64url) *before* sealing, because the places name them. The
  Worker used to mint file ids after the upload, when nothing could be
  bound to them any more; it now checks the shape and refuses an id that is
  taken (409). A new version is `base_version + 1`, so `base_version` is
  required.
- **Opening refuses everything else** — plain text, GV03, a value from
  another place, a value sealed with another store's PSK. A listing shows
  such a name as *unverified* instead of hiding it or failing the view.

The limits, stated: every holder of the store key holds the PSK, so GV04
says "a store-key holder sealed this, here" — not **who** (per-member
signatures are D5). And freshness is not covered: the server can still
answer with an older row (a rename undone, the newest version hidden);
what it shows is at least consistently what it claims to be.

### GK01 / GW01 — key containers

```text
GK01 = "GK01" ‖ len(pkcs8):2 ‖ P-256 private PKCS#8 ‖ ML-KEM seed (64) ‖ P-256 public (65)
GW01 = "GW01" ‖ nonce (12) ‖ AES-256-GCM(KEK, key bytes) ‖ tag,   AAD = "GW01"
```

### Authenticated store records (commit 24)

A store record — `{ keyId, publicKey, pqPublicKey, privateKeySealed }` in
the member's settings — is trusted only when its `mac` verifies under the
member's **record key**, which only the root's holder can derive
(web/src/vault/records.ts ⇄ crates/formats/src/records.rs; the `record`
vector proves the two agree):

```text
shared = ECDH(root P-256 private, root P-256 public)        root with itself; the public half from the BUNDLE
ikm    = shared (32) ‖ SHA-256(root ML-KEM-768 decapsulation key, FIPS 203 encoding)
key    = HKDF-SHA256(ikm, salt = "gorani-records", info = "gorani-records-v1") → HMAC-SHA256 key
mac    = base64(HMAC(key, len‖"gorani-store-record-v1" ‖ len‖name ‖ len‖keyId ‖ len‖P-256 raw (65)
                          ‖ len‖ML-KEM public ‖ len‖privateKeySealed))          len = u32 BE
```

Opening a record also checks that the opened private key reproduces the
record's public halves and key id, and that `privateKeySealed` is sealed
text. Own records are MAC'd at creation; records sealed to a member by
someone else are pinned (MAC'd) on first open — trust on first use. Case
keys (commit 26) do better: every copy is signed by its granter's identity
key and verified against an identity the grantee trusts (commit 27,
docs/CASES.md › Stage 4 as built); the family area's records keep the
first-use pin until stage 5 turns that area into a case.

### Unlock methods (KEK per kind)

| Method | KEK | Strength |
|---|---|---|
| password | Argon2id(NFKC(password), salt, **64 MiB, t=3, p=4**) — the only KDF, cost bounded 19 MiB–1 GiB / 1–20 / 1–16 | whatever the password has |
| recovery | HKDF-SHA256(normalised code, salt, "gorani-recovery-v1") | ≈196 bits |
| passkey | HKDF-SHA256(WebAuthn PRF output, salt, "gorani-passkey-v1") | 256 bits inside the authenticator |
| device copy | HKDF-SHA256(device secret, salt, "gorani-device-v1") | the platform's TPM/Enclave/keyring |

The KDF matches the secret's entropy, on purpose: memory-hardness (Argon2id)
protects low-entropy secrets — passwords; it adds nothing against a
196-bit uniform-random code, where single-step HKDF is already beyond
reach. The invariant that keeps this true: **recovery codes are
machine-generated, never chosen** (`generateRecoveryCode`, 40 characters of
a 30-character alphabet). If a user-chosen code is ever supported, it must
move behind Argon2id.

#### Managing them: Team › Unlock (commit 39l)

Setup makes a password and a recovery code, and offers a passkey while the
new root is still in hand. Afterwards Team › Unlock adds a passkey or a
password, changes a password, issues a new recovery code (it replaces the
old: the paper code stops working; shown once), and removes a method.

**Every change is confirmed with a method you already have.** The session's
root is non-extractable — it cannot hand out the bytes a new method must
wrap — so the panel opens the root again from the method you confirm with
(`methods.ts › confirmKeyBytes`), wraps the copy it needs, and wipes the
bytes. Someone at an unlocked, unattended screen therefore cannot add their
own way in (they would need a secret first), nor quietly remove yours.

The server checks what it can without holding a secret
(`member.rs › methods_refusal`, on `PUT members/<id>/vault`): an enabled
vault keeps at least one method; each method has a known kind, its wrap
and its salt; at most four passwords (the unlock screen tries no more —
O8). Each `vault.save` line in the member's trail names the kinds the vault
has after it (`methods:password,recovery,passkey`), so adding or removing
one is on the record.

A save changes only the field it is about (`settings-store.ts ›
updateSettings`: read the stored settings, change that field, write them
back; a vault whose root changed meanwhile is refused). Before 39l the
identity, pinned-store and settings saves each wrote back a whole copy, and
the copies drifted — a pin saved after a passkey was added would have put
the methods back as they were.

A passkey's relying party is the page's hostname (O15): moving the app to
another host means adding passkeys again; passwords and recovery codes are
unaffected.

### GC01 — chunked files (docs/VIDEO.md rides on this)

```text
object  = frame 0 ‖ frame 1 ‖ …        (every frame but the last: chunk + 28 bytes)
frame i = nonce (12) ‖ AES-GCM(content key, chunk i, AAD) ‖ tag (16)
AAD     = "GC01" ‖ i (8 BE) ‖ final (1)
```

Any frame opens alone → Range seeking, streaming downloads, on-demand desktop sync, and the media service worker's native-video streaming (docs/VIDEO.md).

Nonce rules, explicit: each frame carries a **fresh random 96-bit nonce**,
stored in the frame. Under one content key that is at most one object's
frames — a fresh content key is minted per file version (`model.ts ›
uploadOne`) — so the birthday bound stays absurdly far away (a 100 GB file
at 8 MiB chunks is ~12 800 frames; collision probability ≈ 10⁻²¹). Where
one key DOES span many encryptions by design — GB1 backup segments — the
nonces are counter-based instead (`backup.rs`: `0x00000000 ‖ seg, u64 BE`;
they can never repeat). If a caller ever reuses a content key across
objects (the API tolerates it; the client never does), the random-nonce
bound degrades gracefully but the per-version rule is the invariant to
keep.

### GB2 — backups (GB1 before commit 25)

```text
"GBAK2\n" ‖ headerLen (4 BE) ‖ header JSON ‖ segment 0 ‖ … ‖ final segment
header    = { format: "gorani-backup", v: 2, stamp, createdAt, kind, keyId, wrapped, seg, alg }
H         = SHA-256(magic ‖ headerLen ‖ header)
segment i = nonce (0x00000000 ‖ i, u64 BE) ‖ AES-256-GCM(fileKey, ≤ 1 MiB, AAD_i) ‖ tag
AAD_i     = "GBAK2" ‖ '2' ‖ 'A' ‖ final (1) ‖ i (8 BE) ‖ H (32)
```

Counter nonces (one key spans many segments — they can never repeat), all
twelve nonce bytes checked, position + finality + the header's hash in every
AAD: segments cannot be reordered, dropped, duplicated or cut, the file
cannot be cut down to its header, and the header cannot be relabelled. The
file key is sealed (GV03) into the header to the backup public key; only
the owner's key file opens it. Code + the "what GB2 fixed" story:
`crates/formats/src/backup.rs`; the browser's reader: `web/src/vault/backup.ts`.

### KDF bounds (commit 25)

Stored Argon2id settings are served by the server, so they are bounded both
ways before any run: memory 19–256 MiB, passes 2–10, lanes 1–8; salts 16–64
bytes; at most 4 password methods tried per unlock. gorani writes 64 MiB /
3 passes / 4 lanes (RFC 9106's second recommendation). `web/src/vault/kdf-bounds.ts`,
`crates/formats/src/unlock.rs › check_argon2`.

## What the server can read

Sizes, versions, its own times (when a file arrived or changed here), folder shape, ids, the change feed's structure — and **nothing else**: names, types, folder names, a file's own modified date (39y), dates-inside-documents are GV-sealed text; content keys are stored wrapped; the Worker refuses any unsealed byte or name before storing it (`worker/src/routes.rs`, `files_store.rs`).

## Verifying

`cargo test -p gorani-formats` (round-trips, tamper, reorder, truncate) and
`tests/unit/formats.test.mjs` + `tests/vectors` (crates/formats/tests/vectors.json):
the browser's TypeScript and the Rust reference implementation write the same
bytes, both directions, every commit. That cross-language guarantee is the
foundation the native clients stand on.