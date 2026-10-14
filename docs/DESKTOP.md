# Desktop: the native clients (Rust) — protocol and design

> Copyright 2026- Seongwoo Hong. All rights reserved.
> Status: the protocol is implemented on both sides — the server (commits ⑦/⑧) and the Rust client core with the `gorani-sync` CLI (commit ⑬), live-proven against the real worker (the api suites `client-live` and `client-cases`). Since commits 33a–33d the core signs in as its member, unlocks with the device's own copy, moves files up to 255 GiB, works in granted cases with signed evidence, and runs a sync engine the Linux shell mounts with FUSE (`api:linux-shell`, through a real kernel mount). What remains on this document: the Windows (Cloud Files API) and macOS (File Provider) shells, which mount the same engine but need their own platforms to build and test.

## What the client is

The same experience as OneDrive/iCloud Drive: every file listed without
being downloaded, opening fetches+decrypts on the spot, saving uploads as a
new version, changes elsewhere appear within seconds, "Free up space" drops
the local copy. Rust for the core (memory safety where a bug is a security
bug; one implementation shared by all platforms), platform shells for the
file-system integration:

| Platform | Shell | Mechanism |
|---|---|---|
| Windows | `clients/windows` | Cloud Files API (cfapi) — the OneDrive driver: placeholders, FETCH_DATA callbacks |
| Linux | `clients/linux` | FUSE mount (`~/Gorani`), on-demand reads — **built (commit 33d)**: `gorani-mount` |
| macOS | `clients/macos` | File Provider extension (Finder sidebar) |

The platform-neutral core (`clients/core`) owns: unlocking, the sealed
formats (imported from `crates/formats` — byte-identical with the Worker
and the browser), the local SQLite state, the sync engine, and the HTTP/
WebSocket client.

## The protocol (implemented server-side; the client consumes it)

```text
enrol   POST /api/v1/members/<m>/devices            name, platform, keyId, wrapped (GW01 of the root under the device secret), salt, protection
        → { deviceId, token }                        (the token is shown once; only its hash is stored)
unlock  POST /api/v1/members/<m>/devices/<id>/unlock x-gorani-device-token: <token>
        → { keyId, wrapped, salt, settings }         (the device's own wrapped root copy + the vault settings)
check   POST …/check                                 → { policy } (trusted / hours-locked / unused-days)
rekey   PUT  …/key                                   after a root rotation
leave   POST …/leave                                 uninstall: the wrapped copy is revoked
revoke  DELETE /api/v1/members/<id>/devices/<id>     from the web app
```

Per-file sync — exactly the surface the web app speaks:

```text
changes  GET …/files/changes?since=<cursor>   the journal, paged; every change took the next number of ONE counter (triggers)
live     (WebSocket) announces each new cursor
fetch    GET …/files/<id>  (Range: bytes=a-b) the sealed object; x-gorani-ck carries the wrapped content key
upload   whole: POST …/files (multipart, GV02-sealed, content key wrapped to the store public key)
         big:   POST …/files/uploads → PUT parts (one GC01 frame each) → complete (the object must add up)
meta     PATCH …/files/<id> { name (sealed), folderId } · DELETE (to Trash) · folders CRUD
safety   base_version on a version upload (409 names the current version); mass-change guards client-side
```

## Security model

```text
device secret = what this machine's security chip (and its user's login) produces — never stored in the clear
KEK           = HKDF-SHA256(device secret, salt, "gorani-device-v1")
device copy   = GW01(KEK, root private key)     ← stored on the SERVER, released only to that device's token
```

Neither half is enough alone: the server's copy needs the computer's chip
and its owner; the computer holds nothing it could open without asking.
Revoking deletes the copy — the computer never unlocks again. The screen
lock drops the root from memory (nothing is opened, sealed or pulled while
locked). Linux additionally keeps its local cache encrypted at rest (GL1:
64 KiB sealed blocks, position-bound) — once it has one (see 33d's limits).

**The machine key never leaves the chip.** Each platform keeps a key that
was created inside its security hardware and cannot be exported; what the
client stores is a blob or a handle only that chip can use, and the device
secret is the result of asking the chip to use it:

| Platform | The machine's key | The device secret | Presence | Status |
|---|---|---|---|---|
| Linux | the TPM 2.0 storage key (owner hierarchy, re-derived from the chip's seed) | a part SEALED to that key (`tpm2_create`/`tpm2_unseal`) and a part in the login keyring (Secret Service), combined by HKDF | the login (the keyring opens at sign-in) | **built — commit 34** |
| Windows | a TPM-backed RSA key behind Windows Hello (`KeyCredentialManager`, Microsoft Platform Crypto Provider) | SHA-256 of Hello's signature over a fixed challenge — RSA PKCS#1 v1.5 is deterministic, so the same key gives the same secret (an ECDSA signature would not) | the Hello PIN, face or fingerprint, at every unlock | designed; needs Windows to build and test |
| macOS | a Secure Enclave P-256 key (`kSecAttrTokenIDSecureEnclave`, access control `.userPresence`) | ECDH between the enclave key and a stored peer public key (`SecKeyCopyKeyExchangeResult`) | Touch ID or the login password | designed; needs macOS to build and test |

**The honest limit, on every platform** — the browser's too: while the
vault is open, the root is in the client's memory, and code running as the
user can ask the chip exactly as the client does. What the hardware buys:
a copy of the disk, a backup or the profile file opens nothing; unlocking
needs this machine (and, where the platform asks for it, the person); a
revoked device's chip opens nothing because the server's copy is gone.

### Commit 34 as built (Linux, and the CLI everywhere)

- `clients/core/src/devicekey.rs`: the device secret is made of **parts**,
  each held by a protector — `tpm` (sealed by the chip, the profile keeps
  the sealed blobs), `keyring` (the profile keeps a random reference), or
  `file` (the part in the clear, dev and CI only, never chosen silently).
  `secret = HKDF(salt "gorani-device-parts-v1", part₁ ‖ part₂…, kinds)`.
  Through `tpm2-tools` and `secret-tool` as subprocesses (the clevis way:
  no C library linked in); secrets cross pipes only, never argv or a file.
- `gorani-sync setup --protect auto|tpm|keyring|tpm+keyring|file` — `auto`
  takes everything the machine has, and refuses (pointing at `--protect
  file`) when it has nothing. The server records the label.
- `gorani-sync protect` moves an enrolled computer's secret to new
  protectors without enrolling again: the server's copy is re-wrapped,
  the old secret opens nothing, replaced keyring parts are forgotten. The
  new protectors are written down as *pending* before the server moves,
  so a run that dies in between still opens whichever copy the server
  holds, and the next run finishes it.
- `gorani-sync devices` lists every computer and what protects it;
  `gorani-sync revoke --device <id>` deletes a lost one's copy from any
  other. **Found on the way:** the web app had no devices screen — this
  document said "revoke … from the web app", and there was no way to
  revoke a lost laptop but the raw API. Commit 35 adds it: Team › Devices
  lists the member's computers with what protects each (a file-held secret
  flagged), when each was last seen, and Revoke.
- Not yet: a TPM PIN (an authorization value the chip's lockout would
  protect) or sealing to the boot state (a PCR policy); attestation of the
  protection label (the server records the client's word).
- `api:device-protect` runs it against a real software TPM (swtpm) and a
  real GNOME Keyring on a private D-Bus session: no secret in the profile;
  another TPM cannot load the blob; another login's keyring has no part;
  a machine with neither is refused; `protect` moves an in-file secret,
  finishes a run that died mid-way, forgets replaced parts; a revoked
  computer never unlocks again.

## Whose device

A member enrols their own devices only: since commit 27c no one — a lead
included — acts for another member's area, so the family edition's
"guardian access" (a parent enrolling a computer for a child with the
child's code) is gone. A team's shared work lives in cases; desktop sync of
a case is a member syncing the cases they are granted (docs/CASES.md).

## The desktop phase (commits 33+): what the core must do first

The shells mount the core; the core is not yet what they need. A review
before starting (commit 33, after D11/D12) found:

1. **It could not sign in outside dev mode.** The core sent an Access
   *service token* (`CF-Access-Client-Id/Secret`, PRODUCTION.md › 2.5 said
   so). Access accepts it — and hands the Worker a JWT with no `email`
   claim (service tokens have a `common_name`). The Worker takes identity
   from `email` and fails closed (auth.rs: "token has no email"), so every
   file call from a desktop was refused in production; `client-live`
   proved it only in dev mode, where the email is a header.
2. **It uploads whole files only** (≤ 48 MB, in memory) — D12's large
   files (chunk_for, streamed parts, resume) never reached it.
3. **It reaches the member's own area only.** Cases — where evidence
   lives — need the case key (a grant sealed to the member's root, hybrid)
   and, for evidence, the uploader's signature (the identity key, sealed
   under the root), the timestamp imprint and the intake record.

| Stage | What |
|---|---|
| 33a *(landed)* | **Sign in as the member.** The core sends a user Access token (`cf-access-token`, from `cloudflared access token -app=<server>` or the `GORANI_ACCESS_TOKEN` variable) — short-lived and bound to the member's SSO/MFA, so the Worker sees the member's email and every rule (own area, case grants) applies unchanged. The device token stays what it is: the release of this computer's wrapped root copy. |
| 33b *(landed)* | **Large files.** `push` streams from disk in GC01 frames at `chunk_for(size)`, parts with retry, and a resume journal on disk (sealed fields only, like the browser's); `pull` streams frame windows to disk and checks the signed hash. |
| 33c *(landed)* | **Cases.** Open a granted case's key from its grant; list, pull, push into it; on an evidence case, sign the content hash (and send the stamp imprint) with the member's identity key, and carry an intake record. |
| 33d *(landed)* | **The Linux shell** (`clients/linux`, FUSE): the engine first, against `wrangler dev` with an in-memory file system as the doc's testing pattern says; a real mount where the machine allows FUSE. |
| — | Windows (Cloud Files) and macOS (File Provider) need their platforms to build and test — not this repository's CI machine. |

### 33a as built

- `clients/core`: the profile's `accessTokenCmd` (or `GORANI_ACCESS_TOKEN`)
  gives the member's Access token, fetched once per process and sent as
  `cf-access-token`; a command that fails or prints nothing is an error,
  never an anonymous request. `gorani-sync setup --access-token-cmd
  "cloudflared access token -app=https://<host>"`.
- **A second, larger finding on the way.** `api:access` — the first suite
  to run the Worker with dev mode OFF, against a stub Access team — found
  that the Access path **panicked on every request with a token**:
  `auth.rs` aged its JWKS cache and checked expiry with
  `std::time::SystemTime`, which panics on `wasm32-unknown-unknown` (the
  platform gives std no clock). Dev mode never reached that code, so
  every suite passed while no production deployment could have served one
  authenticated request. It now uses the Workers clock (`worker::Date`).
- `api:access` keeps both honest: a member's token is the member; a
  service token's (no email) is refused, as the desktop's used to be; and
  missing, foreign-audience, expired, foreign-issuer, forged, unknown-key,
  non-ES256 and edited-after-signing tokens are each refused by name.

### 33b as built

- `clients/core/src/transfer.rs`: `push_frames` reads one frame from disk,
  seals it (GC01 at `chunk_for(size)`, the formats crate's own
  `seal_chunk`), PUTs it — three tries, 1 s then 4 s apart, for a dropped
  connection, a 5xx or a 429, none for any other refusal — and journals
  the part before reading the next. Memory is one chunk, whatever the file.
- **The journal** (`<profile>.uploads/<key>.json`, written then renamed):
  only what the server already holds — ids, the object key, the sealed
  completion fields, the parts' ETags. Its key is a length-prefixed
  SHA-256 of the member, the name, the size, the modified time and the
  file's SHA-256: no name in the clear, and a different file (or the same
  name with other bytes) never resumes into a stranger's upload. A resumed
  push opens the journalled content key in its place (O6), so the frames
  it adds are sealed under the SAME key as those already stored.
- `pull_frames` fetches 32 MiB windows by Range, opens every frame in its
  position (a reordered, altered or cut-short object fails), writes the
  plaintext to `<out>.part` while hashing it, checks the size and renames
  onto `--out` only then — a failed pull leaves nothing that looks done.
- `api:client-live` stops a 60 MiB push after 3 of 8 parts (a debug-build
  fault hook, `GORANI_TEST_STOP_AFTER_PARTS`), resumes it "from part 4 of
  8", checks the journal names no file, pulls it back streamed and compares
  bytes and SHA-256.

### 33c as built

```text
gorani-sync cases                      the grants, each opened to SAY whether it opens
gorani-sync ls   --case ir-2026-014    the case's feed, names opened in their places
gorani-sync pull --case … --id F       checked against what the uploader signed, BEFORE writing
gorani-sync push --case … --file P     signed; on evidence with --source --collector
                                       --method --collected-at [--notes]
```

- `clients/core/src/identity.rs` — the browser's `identity.ts`, natively:
  length-prefixed statements, identity key ids and full hybrid digests,
  the identity record's MAC under the root, ECDSA P-256 signatures in
  WebCrypto's P1363 encoding (a DER signature is refused, as the browser
  refuses it), and trust built from the member's OWN pins plus one hop of
  certificates. The CLI reads the identity the web app made; it creates,
  pins and certifies nothing (it never writes settings).
- `clients/core/src/cases.rs` — a case key opens only when (1) the grant is
  signed by someone the member trusts, (2) it opens under their root, (3)
  the signature names this case, this key's full digest and them, and (4)
  the key is the registry's (both public halves and the id). A grant from
  a lead the member never verified is listed by `cases` and named — and
  refused for any use. During a rotation's walk the CLI waits (values sit
  under two keys; the web app finishes the walk).
- **Evidence pushes** carry what the browser's do: the content hash signed
  by the member and sealed into version 1's place, its RFC 3161 imprint
  (SHA-256 of the signature), and the signed intake record — asked for
  before a large file is hashed, not after. Pushes into the member's own
  area are signed too when their vault has an identity.
- **Pulls decide before writing.** A record that does not open in its
  place, does not verify, or vouches for other bytes refuses the pull and
  writes nothing (the chunked path checks before `<out>.part` is renamed).
  Evidence that is unsigned or signed by someone the member has not
  verified is refused unless `--accept-unverified`; elsewhere it is written
  with a line saying what it is.
- Not yet in the CLI: checking the RFC 3161 token itself (the web app and
  `tools/verify-export.mjs` do), custody transfers, approvals, exports.
- `api:client-cases` runs the binary against a team built by the web app's
  own code — Rust verifies what TypeScript signed and the other way round;
  a deliberately mutated statement in Rust fails it.

### 33d as built

```text
gorani-mount ~/Gorani                    your own area, until Ctrl-C (or umount)
gorani-mount ~/Cases/ir-2026-014 --case ir-2026-014     a case (evidence: read-only)
gorani-mount script [--case C]           the same engine over JSON lines (tests; no FUSE)
```

- **The engine is the core's, not the shell's** (`clients/core/src/engine.rs`):
  the tree, names, reads, writes and conflicts are decided once, so the
  Windows and macOS shells will call the same methods. `clients/linux` is
  a thin FUSE adapter (`fuser` without libfuse: pure Rust, mounting
  through `/dev/fuse` as root or `fusermount3` otherwise).
- **It unlocks with this computer's copy** — the point of enrolment: the
  server releases the wrapped root only to the device's token, and only
  the device secret (never sent) opens it. Found on the way: the client's
  unlock call dropped the salt the copy needs, so no native client had
  ever unlocked this way; `gorani-sync` now does too when no `--secret` is
  typed.
- **The tree comes from the listing**, the change feed only says that
  something moved (the journal is pruned after its retention, so it cannot
  rebuild a tree from zero). A name opens only in its place; one that does
  not is shown as `⚠ unverified ‹id›`, never as what it claims to be.
- **Reads fetch only what they touch**: a chunked file's GC01 frames for
  the range asked; a whole file once, into a bounded in-memory cache.
- **Writes are held in memory** (≤ 48 MiB, so no plaintext is spooled to
  disk) and sent on close: a new file, or the version after the one that
  was opened. If the file moved on meanwhile, the bytes are saved beside
  it as `name (conflict <date time>).ext` — nothing is overwritten, nothing
  is lost. rename/move, mkdir/rmdir and unlink (to the Trash) map to the
  same API the web app uses.
- **What the shell will not do**: serve a malware sample (shown, mode 000,
  every open refused); write into an evidence case (an item needs its
  intake record, which a file system cannot ask for — `gorani-sync push
  --case` does); serve evidence it has not checked: each evidence file is
  verified against its uploader's signed hash at open (a chunked one is
  streamed through once), and a mismatch, a bad record or — unless the
  mount was started with `--accept-unverified` — an unverified signer
  refuses the open. A case on a read grant mounts read-only from the start
  (the server would refuse each save anyway). Mounted `noexec,nosuid,nodev`:
  a vault holds data, often hostile.
- **Honest limits, for now**: no offline cache (so nothing at rest to
  encrypt yet; GL1 arrives with one), files above 48 MiB are read-only
  through the mount, a rename over an existing file trashes the old one
  instead of making the moved bytes its next version, and changes made
  elsewhere appear on the next listing (≤ 3 s, no WebSocket yet).
- `api:linux-shell` drives the engine through `gorani-mount script` and
  then mounts it for real: Node's async `fs` reads, writes, renames and
  unlinks through the kernel, and the browser's own code checks what
  arrived.

## Testing (the pattern the port follows)

`tests/unit/formats.test.mjs` proves Rust ⇄ TS byte equality; the client
engine runs against `wrangler dev` exactly like `api:files`/`api:devices`
(a placeholder-driven in-memory file system, as Mailflare's engine test
does), then platform smoke tests against real machines.