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
- Not yet: attestation of the protection label (the server records the
  client's word). *(A TPM PIN and sealing to the boot state arrived in
  commit 36 — below.)*
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
  non-RS256 and edited-after-signing tokens are each refused by name.
- **39k — the same lesson again, one layer down.** The first real
  deployment (gorani.at.day) refused every request: *signature is not 64
  bytes*. `auth.rs` verified ES256 — and so did the suite's stub team,
  which signed what the code expected rather than what Access sends.
  Access signs **RS256** (RSA-2048: a 256-byte signature, the keys as `n`
  and `e` in the team's JWKS). The Worker now verifies RS256 with
  RustCrypto's `rsa` (verification only — its timing advisory is about
  private-key use), binds the key type to the algorithm (an ES256 token,
  HS256, or an RS256 header over a non-RSA key is refused), refuses keys
  under 2048 bits, and re-reads the JWKS when a token names a key it has
  not seen (Access rotates keys; at most once a minute). And the next
  wall, found reading Access's documentation instead of waiting for it:
  Access's `aud` is an **array** holding the application's tag — the
  Worker read only a string, so a correctly signed token would have
  failed as "audience does not match". Both forms are read now, and `nbf`
  is checked. The stub now
  serves RSA keys in Access's own response shape (`keys` beside
  `public_cert` / `public_certs`) and mints Access's own claims (`aud` an
  array, `nbf`, `identity_nonce`) — a stub is a claim about the real thing,
  and this one had never been checked against it.

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

### Commit 36 as built: a PIN, and the boot state

Two options of the TPM part, each a property of the sealed object itself
(`gorani-sync setup|protect --protect tpm --tpm-pin --tpm-pcrs 7`):

| option | unsealing needs | what it adds |
|---|---|---|
| `--tpm-pin` | this chip **and** the PIN | a person at the keyboard; the chip counts wrong PINs and locks itself out after a few (for its recovery time) — the right PIN too |
| `--tpm-pcrs 7` | this chip in the boot state it was sealed in (PCR 7: Secure Boot on, with these keys) | a disk moved under another OS, or the same machine booted with Secure Boot off, opens nothing |

- **The PIN never travels in argv** (readable by every user): unsealing
  reads it from stdin; sealing — where tpm2-tools wants a seekable file —
  from a 0600 file in the 0700 working directory on the per-user tmpfs,
  removed at once. It is asked on the terminal (twice when chosen, at
  least 6 characters), or taken from `GORANI_TPM_PIN` for automation.
- **Found on the way:** the storage key commit 34 sealed under was itself
  subject to the chip's lockout, so guessing one part's PIN would have
  locked out *every* part on the chip, PIN or not. New parts use a `noda`
  storage key (template 1, recorded per part as `srk`, so commit-34 blobs
  still load under theirs); parts without a PIN are `noda` too. The live
  suite proves a PIN lockout leaves them working.
- **A boot state that changes on purpose** (a firmware update changing the
  Secure Boot keys) stops the part unsealing — the message says how to
  recover: `gorani-sync protect --secret <password or recovery code>
  --tpm-pcrs 7` opens the root with the typed secret instead of the
  device copy and seals again to the state the machine is in now.
- The protection label carries the options: `tpm[pin,pcr:7]+keyring`, and
  Team › Devices says it in words.
- PCR 7 only, deliberately: PCRs 0–6 move with every firmware and boot
  loader update, and a part that dies at each one teaches people to turn
  the option off.

### Commit 37b: the same binary as a collector

`gorani-sync collector init|pin|whoami` and `gorani-sync collect` run an
unattended **collector** (docs/COLLECTORS.md) — a separate profile
(`~/.gorani-collector.json`), no member, no root, no store key:

```text
gorani-sync collector init --server https://files.example --id edr-1 \
    --pins ana:3F2A9C1B…,cy:…  --access-id <service token Client ID>
        → prints { id, publicKey, keyId, fingerprint } for the leads to register
gorani-sync collect --case ir-2026-014 --file triage.zip \
    --source WS-0412 --method "EDR live response" --collected-at 2026-10-15T08:30:00Z
```

A member decides what landed (commit 37c): `gorani-sync inbox --case C`
lists each item with this member's own verdict; `accept --case C --item I
[--name N]` re-reads and hashes the bytes (frame by frame), refuses an
unverified item, and files it with the member's signed hash and intake and
the collector's record; `reject --case C --item I --reason R` seals the
reason.

The device-secret machinery is commit 34's, reused: the identity key and the
service token's secret are sealed under a key from the device secret (TPM
and/or keyring), the profile — pins included — MAC'd under another. The
token's secret is read from `GORANI_COLLECTOR_SECRET` or asked for, never a
flag (argv shows in `ps`).

## Commit 39: Windows and macOS

Asked 2026-10-15: built and tested on **GitHub Actions** (hosted
`windows-latest` and `macos-latest` runners — `.github/workflows/clients.yml`;
this repository's own machine cannot build either), **File Provider** on
macOS (D16's choice), a paid Apple Developer team (its Team ID is a setting,
never in the repository), and all four parts in this phase:

| Stage | What |
|---|---|
| 39a | **The replica** (`clients/core/src/replica.rs`): what a shell that keeps real files on disk needs — items by server id, reads of one version, new files and versions from paths (whole or GC01 frames), conflicts kept, a diff to apply — over the server (`HttpRemote`) or in memory (`MemRemote`, what each platform's smoke test drives). One JSON protocol over either: `gorani-sync replica` speaks it on stdin/stdout, the macOS bridge across its C interface. CI builds and unit-tests the core on Windows and macOS. |
| 39b | **Windows**: a Cloud Files sync root (`clients/windows`) — placeholders, hydration on read, local saves uploaded, renames and deletes, server changes applied, plaintext dropped when the shell stops. |
| 39c | **macOS**: a File Provider extension and its host app (`clients/macos`) over the Rust core through a C bridge. |
| 39d | **The hardware device key**: Windows Hello (a TPM-backed key, its deterministic RSA signature) and the Secure Enclave (CryptoKit key agreement) as protectors. |
| 39e | **Explorer and Finder**: the navigation-pane entry and sync states (StorageProviderSyncRootManager), Finder decorations. |
| 39f | **Installers**: an MSIX and a signed, notarized app — signed in CI only when the signing secrets exist. |
| 39g | **Distribution** (asked 2026-10-15): Windows through the Microsoft Store as a private app (Microsoft signs it); beside it, unsigned builds — a Windows 11 MSIX, a Windows ZIP, the macOS CLI — whose users check a SHA256SUMS the release manager signs with their own key. |
| 39i | **Releases** (asked 2026-10-15): every build of main that changes the programs, and every `v*` tag, published to GitHub Releases as Latest — the newest 10 main builds kept — with SHA256SUMS signed in CI by a key held as an Actions secret; a Linux tarball joins the files. |
| 39n | **Duplicates** (asked 2026-10-16): the native clients tag what they upload exactly as the browser does (`area.rs › duplicate_tag`); `push` skips a file whose bytes are already in the area (`--duplicates skip|keep|ask`; asks on a terminal); the sync engines upload a copy anyway and log which file it duplicates — docs/DUPLICATES.md. |

### 39a as built

```text
gorani-sync replica [--case C]     one JSON request per line on stdin, one answer per line:
  {"op":"items"}                   the tree by id ("" is the top), names opened in their places
  {"op":"read","id","version","offset","len"}     bytes of THAT version only
  {"op":"create","parent","name","path"}          a new file from a local path
  {"op":"save","id","base","path"}                the version after `base` — or a conflict copy
  {"op":"mkdir"|"rename"|"trash"|"poll", …}
```

- **Reads of one version.** A placeholder made for version N has N's size
  and N's signed hash; filling it with N+1's bytes would corrupt it. The
  engine's `read_at` refuses ("changed on the server") and the shell's
  next poll updates the placeholder. The same rules as the mount: a sample
  is never readable, evidence is checked against its uploader's signed hash
  before a byte is served.
- **Uploads from paths**, because these shells keep real files: up to
  48 MiB read once and hashed and sealed from the same buffer; above, GC01
  frames — now also as a new VERSION through the multipart path (the core
  only sent new files that way) — re-hashed as they are sealed, so a file
  that changed after it was hashed is never completed under a signature
  for other bytes (`push_frames`' `expect`; the CLI's `push` checks it too).
- **One protocol, two remotes.** `HttpRemote` is the engine — the same
  naming, sample and evidence decisions as the Linux mount; `MemRemote`
  keeps the rules a shell depends on (versions, conflicts, samples,
  read-only areas, empty-folder trashing) and none of the crypto, so a
  Windows or macOS runner proves its placeholder layer without a server.
- `api:replica` drives it against `wrangler dev`: the tree by id, a range
  across GC01 frames, a stale version refused, new files and versions
  whole and framed (49 MiB), a conflict copy beside the browser's save,
  folders, renames, the Trash, polling, an evidence case read-only with a
  swapped record refused.

### 39b as built

```text
gorani-cloud <folder> [--case C] [--keep-local]    serve the area as a Cloud Files sync root
gorani-cloud free <file>                           drop one file's local bytes now
gorani-cloud unregister <folder>                   the folder stops being a sync root
```

| Part | File | What |
|---|---|---|
| the platform | `clients/windows/src/cf.rs` | every `unsafe` call to cldapi: register (PARTIAL hydration — a range read of a 255 GiB image fetches that range), connect (FETCH_DATA, NOTIFY_DELETE, NOTIFY_RENAME), placeholders with an identity `gorani1:<version>:<id>`, update/convert/dehydrate through an oplocked handle |
| names | `clients/windows/src/names.rs` | a server name as NTFS allows it (look-alikes for `<>:"/\|?*`, reserved device names, trailing dots), unique without case (" (id8)") |
| the folder's side | `clients/windows/src/watch.rs` | ReadDirectoryChangesW: new files and folders, edits — each event only a path to look at again |
| the decisions | `clients/windows/src/provider.rs` | the server → the folder (placed, moved, refreshed, removed — never a file the member changed and has not sent); the folder → the server; stop |

- **Deletes and renames are the server's first.** NOTIFY_DELETE and
  NOTIFY_RENAME are answered only after the server took them; a read-only
  area answers READ_ONLY_VOLUME and Explorer shows the refusal. A rename
  out of the folder (the Recycle Bin) is a trash.
- **A read is of the placeholder's version.** FETCH_DATA asks the replica
  for that version only, 4 MiB at a time; a refused read (a sample, a
  changed file, evidence whose hash does not match) fails for the range
  still owed.
- **Saves wait for the writer.** A changed file is sent once no handle
  holds it and nothing touched it for 1.5 s; a stale save becomes a
  conflict copy beside the other version, on both sides.
- **Stop drops the plaintext.** Every file in sync is dehydrated — the
  read-only ones too: the shell lifts the attribute for the moment, and the
  in-sync policy does not track it.

Found on the runner, each now a comment where it bites and an assertion in
`clients/windows/tests/cloud.rs`:

- the platform sends no rename/delete notification for the provider's own
  process (the smoke test renames and deletes through PowerShell);
- a FETCH_DATA failed for zero bytes is not taken — the reader waits out
  the platform's 60-second timeout;
- a rename clears a placeholder's in-sync state, even the provider's own:
  the shell marks its own moves in sync, and a path the member just renamed
  whose size and last-write time are unchanged is marked in sync, not sent
  again as a version;
- a read-only placeholder refuses the exclusive write open that
  dehydrating takes.

### 39c as built

```text
the extension (NSFileProviderReplicatedExtension)   queues, polls every 3 s, translates errors
        │  ProviderCore (GoraniKit)                  every decision — tested by `swift test`
        │  GoraniBridge                              the replica's JSON protocol, typed
        ▼  gorani_open / gorani_call / gorani_free   clients/macos/src/lib.rs (a static library)
the Rust core                                        keys, sealing, the server — nothing in Swift
```

- **Identifiers are server ids**; the area's top is the root container.
  A sample is listed without `allowsReading`; a read-only area's items have
  no write, rename, move or delete capabilities, and the core refuses them
  anyway.
- **Versions.** The content version is the item's version number (new
  bytes are fetched afresh); the metadata version adds the modified time
  and the sample flag. A save says which version it follows (the
  `baseVersion` the system hands over); a stale one is a conflict copy on
  the server and the item answered is theirs.
- **Anchors are generations.** ReplicaModel keeps the last 16 listings; a
  change enumeration answers from them, and an anchor it no longer has is
  expired — the system then enumerates everything again.
- **Fetch writes one version whole** into a file the system takes over
  (the replica's `download` op); a version that moved on meanwhile is
  fetched once more as the current one.
- **The profile** is `<app group container>/gorani-sync.json`, the group
  `$(TeamIdentifierPrefix)io.gorani` — enrolled with `gorani-sync setup
  --profile …`; the host app adds or removes the domain and shows the path.
- **The project is generated** (`xcodegen generate`, `project.yml`); the
  team is `GORANI_TEAM_ID` at build time, never in the repository.

CI on `macos-latest`: the bridge's Rust tests; the static library (and
the system libraries a program linking it needs); `swift test` over the
in-memory core — items, fetch, create/modify/delete, a stale save, changes
since an anchor, an expired anchor, a read-only area, the enumerators; and
an unsigned `xcodebuild` of the app with the extension inside, the core
linked into it.

### 39d as built

The device secret's parts (commit 34) in each system's own stores, under
the same words — `--protect tpm+keyring` is the machine's hardware and the
person's login on all three:

| word | Linux | Windows | macOS |
|---|---|---|---|
| the hardware: `tpm` (`enclave` on a Mac) | TPM 2.0 through tpm2-tools: the part sealed under the chip's storage key | a 2048-bit RSA key made in the TPM's CNG provider (Platform Crypto Provider), never exportable; the part encrypted to it (OAEP-SHA256) | a P-256 key made in the Secure Enclave (CryptoKit); the part agreed (ECDH, then HKDF) with a peer key whose private half is dropped at once |
| the login: `keyring` (also `dpapi`, `keychain`) | the Secret Service | DPAPI, user scope, with an entropy only this client passes | a generic password in the login Keychain |
| a person each unlock: `hello` / `presence` | — (`--tpm-pin`) | Windows Hello: the part is SHA-256 of its signature over a stored challenge — RSA PKCS#1 v1.5 signs alike each time, and setup asks twice to prove it | the enclave key made with user presence (Touch ID or the password) |
| what the profile keeps | the sealed blobs; an item reference | the key's name and the ciphertext; the DPAPI blob; the Hello key's name and challenge | the key's enclave-encrypted representation and the peer; an item reference |

- **`auto` never prompts**: the hardware and the login where both answer. A
  shell that starts at sign-in must not wait for a face, so a person's
  gesture is asked for only when chosen (`--protect tpm+keyring+hello`). A
  hardware store that answers but will not make a key leaves the login part
  alone, and says so; the label printed at setup is the truth.
- **What each does not do.** DPAPI's user keys open with the user's
  password and the disk, and a domain's backup key opens them on a
  domain-joined computer — so `auto` pairs DPAPI with the TPM wherever one
  answers. And as on Linux, code already running as the user can ask
  every store exactly as this client does; protectors defeat copies (a
  backup, a stolen disk, the profile), not malware in the session.
- **The Mac's helper.** CryptoKit is Swift's, so `gorani-keystore`
  (clients/macos/GoraniKit) does the enclave and Keychain work for the
  Rust client, which speaks to it as it speaks to tpm2-tools: parts on
  pipes only. It is found by `GORANI_KEYSTORE`, beside the program, or on
  PATH; the installer (39f) puts it beside `gorani-sync` and inside the
  File Provider extension. A debug build can stand a software key in for
  the enclave (CI's virtual Macs have none); such keys are marked
  `software:` and the client refuses them outside its own tests.
- **A profile from another system** says which system holds its part
  instead of failing obscurely: a profile does not move between computers.
- **Tests.** Windows' run on the runner with the core's unit tests: DPAPI
  round trip and a changed blob refused, a CNG key in the software provider
  (the TPM's same calls) held and deleted with its protector, the TPM's
  where the runner has one, Hello's "not set up" message, `auto` never
  asking a person. The Mac's: the helper built, then the client through it
  — the enclave (or its stand-in) agreeing the same part again and another
  peer not, the Keychain holding the part until forgotten, `auto`.

### 39e as built

What Explorer and Finder show of a Gorani folder:

- **Explorer** (`clients/windows/src/shell.rs`): the folder is registered
  through the shell's StorageProviderSyncRootManager as
  `Gorani!<the user's SID>!<area>` — its own entry in the navigation pane
  ("Gorani — <area>", "(read-only)" for an evidence case), the Status
  column's cloud and tick, "Always keep on this device" and "Free up
  space"; a malware sample carries a custom state ("Malware sample — never
  opened raw", a warning sign) and is marked in sync again after, so the
  shell's write is not taken for an edit. The policies are cldapi's own
  (cf.rs). Where the shell will not register it (a Server SKU, a
  policy), cldapi's registration alone still makes it a working folder —
  said once at start, with the reason; `gorani-cloud unregister` undoes
  whichever it got.
- **Finder** (`GoraniFileProviderItem.decorations`, the extension's
  `NSFileProviderDecorations`): a badge on a sample (warning), on every
  item of a read-only area (locked), and on a name that did not open in
  its place (warning) — named under the extension's bundle id.
- **Found on the runner** (Windows Server, a non-interactive session):
  `StorageFolder` refuses a `\\?\` path (the form `canonicalize` gives); a
  sample's state is refused while the placeholder is read-only (lifted for
  the write, as for every write the shell makes — cf.rs ›
  read_only_lifted); and the shell's queries — by id, by folder, the list —
  answer nothing for a root `Register` has just taken. The registration is
  real: the shell writes it down at `HKLM\…\Explorer\SyncRootManager\<id>\
  UserSyncRoots` (the user's SID naming the folder), so lookups — and
  `unregister`, which must remove that entry or leave a stale one in the
  navigation pane — fall back to reading it.
- **Tests**: the Windows smoke test finds the folder under its id and
  checks the shell's folder is this one (failing, where the shell supports
  sync roots, instead of only saying so), sees the sample stay in sync with
  its state shown, and proves `unregister` leaves nothing under the id.
  `swift test` checks each badge and that an ordinary file has none.

### 39f as built

`.github/workflows/package.yml` makes what a person installs, and installs
or runs it there, as they would:

| | Windows | macOS |
|---|---|---|
| what | an MSIX (`clients/windows/packaging`): gorani-cloud and gorani-sync, full trust, each a console command on PATH through an execution alias; its logos and Explorer's icon are the water deer (39h: rendered from `docs/assets/gorani.svg` by `tools/icons/render.mjs`) | Gorani.app (`clients/macos/packaging/package.sh`): the app, its File Provider extension, the CLI (`Contents/MacOS/gorani-sync`) and two copies of the keystore helper — the CLI's, and the extension's signed to inherit its sandbox |
| signed with secrets | (39f: `WINDOWS_CERT_PFX`, `WINDOWS_CERT_PASSWORD` — replaced in 39g: the Store signs its package, the unsigned builds carry a signed checksum) | `GORANI_TEAM_ID` (variable or secret), `APPLE_CERT_P12`, `APPLE_CERT_PASSWORD`: Developer ID, inside-out, hardened runtime, the app group `<team>.io.gorani`; notarized and stapled with `APPLE_API_KEY`, `APPLE_API_KEY_ID`, `APPLE_API_ISSUER_ID` |
| without them | signed with a throwaway certificate made and trusted on that runner only — so installing is tested as a signed package's would be | ad-hoc signed, for testing (Gatekeeper will not open it from a download) |
| checked | installed with Add-AppxPackage, both aliases answer, removed again | the bundled CLI answers, the helper probes, the extension's binary holds the core |

- **When**: release tags (`v*`), by hand, and when the packaging changes —
  not on every push.
- **The one outside tool.** XcodeGen (Homebrew) runs in a job that holds
  no secret; the signing job takes only the project it generated, and
  refuses one holding a script phase or a build rule — where a tampered
  generator could hide a command next to the signing identity.
- **The secrets** are read only in the steps that sign, never printed;
  the macOS identity lives in a throwaway keychain deleted when the step
  ends. They are never asked for: set them in the repository's settings
  when the certificates exist, and the next tag ships signed packages.
- **The Mac's helpers and the Keychain.** Both keystore copies are signed
  with one identifier, so the login Keychain's rule for the CLI's items
  admits the extension's helper too. Apple silicon only for now (the core
  is built for arm64).

### 39g as built

Asked 2026-10-15: Windows ships through the **Microsoft Store as a private
app** (personal Microsoft accounts in a known-user group; uploaded by hand),
and beside it **unsigned builds whose users verify a signed checksum** —
for Windows a ZIP and a Windows 11 MSIX, for macOS the CLI and its helper.
No code-signing certificate is bought for Windows; the 39f
`WINDOWS_CERT_PFX` path is gone.

| File | Identity | Signed by |
|---|---|---|
| `gorani-store.msix` (a workflow artifact, for Partner Center) | as Partner Center assigned it (variables `STORE_IDENTITY_NAME`, `STORE_PUBLISHER`, `STORE_PUBLISHER_NAME`); version `a.b.c.0` — the Store keeps the fourth number | Microsoft, on certification |
| `gorani-windows-x64-unsigned.msix` | `Gorani.Client`, publisher `CN=Gorani Unsigned, OID.2.25.311729368913984317654407730594956997722=1` — the OID Windows requires before `Add-AppxPackage -AllowUnsigned` (Windows 11, as administrator) will take a package, and which no signed package can carry | nobody: SHA256SUMS |
| `gorani-windows-x64.zip` | — | nobody: SHA256SUMS |
| `gorani-macos-arm64-cli.tar.gz` | — (ad-hoc, as the linker leaves it) | nobody: SHA256SUMS |
| `Gorani-macOS-arm64.zip` | Developer ID (39f) — in the release only when signed: unsigned, the extension cannot run | Apple's notarization, and SHA256SUMS |

**The checksum's trust** (as 39g built it — 39i moved the signing into
CI, below). `SHA256SUMS` lists every release file; on a tag
the workflow leaves a **draft** release holding them. The release manager
runs `tools/release/sign.sh <tag>` on their own machine: it downloads the
draft, checks each file against the list (and that nothing is unlisted or
missing), shows the list and asks, signs it (`ssh-keygen -Y sign`,
namespace `gorani-release`), checks that signature against the published
key (`tools/release/allowed_signers`), uploads `SHA256SUMS.sig` and only
then publishes. Users run `verify.sh` / `verify.ps1`: the signature by a
pinned key for the principal `release@gorani`, then every file. Why SSH
signatures: the tool is already on every Windows 11 and Mac (OpenSSH 8.1+),
the key can live on a hardware token, and nothing new is installed to
check a download. Why not GitHub's artifact attestations: in a private
repository they need GitHub Enterprise Cloud — and they would vouch for
the build, not for the person who approved the release.

**The mark** (39h): a cute water deer — no antlers, round ears, dark eyes,
two little tusks — drawn once in `docs/assets/gorani.svg` (the README opens
with it). `tools/icons/render.mjs` renders every icon from it with the
browser the e2e suite installs, and the images are committed so no build
machine needs a renderer: the web app's favicon, the MSIX logos and
Explorer's `gorani.ico` (beside the programs in the package and the ZIP —
shell.rs names it for the sync root), and the Mac app's icon set. Edit the
drawing, run the script, commit both.

**Tested** in package.yml, on every run: the unsigned MSIX installed with
`-AllowUnsigned`, both commands asked through their aliases, removed; the
ZIP unpacked and both programs asked; the Store package signed by a
throwaway certificate of the Store's publisher, installed, asked, removed
(when the variables exist); the macOS CLI unpacked, asked, the helper
probed; and on each platform the user's own check (`test-verify.sh` /
`.ps1`, a throwaway key) passing a signed list and refusing a changed
file, a list signed by another key, an edited list, an unsigned one, and
the right key signing for another purpose.

### 39i as built

Asked 2026-10-15: the built programs, unsigned, published to **GitHub
Releases** by CI for easy downloading, from tags and from main — each
build of main a new release. The release manager chose to hold the
release key as an **Actions secret** rather than sign by hand.

| | |
|---|---|
| **When** | a push to main that changes what the programs are built from (`clients/`, `crates/`, `Cargo.toml`, `Cargo.lock`, `tools/release/`, package.yml); every `v*` tag; by hand on either. A push of only the web app, the worker or the docs builds nothing: the programs would be the same |
| **Which release** | a tag `vX.Y.Z` → "Gorani vX.Y.Z"; main → "Gorani main · date · commit" on a tag `main-YYYYMMDD-commit` made by CI (the commit's own date, so a re-run names the same release and only replaces its files) |
| **Latest** | every new release is marked Latest, so `…/releases/latest/download/<file>` is always the newest build, from main or a tag |
| **Kept** | the newest 10 main builds; older ones are deleted with their tags. Releases from `v*` tags are never deleted, and the script deletes only tag names of its own exact form |
| **Files** | the 39g set, plus `gorani-linux-x64.tar.gz` (`gorani-sync`, `gorani-mount`; built on the runner's Ubuntu, so its glibc or newer) |

**The key in CI.** `tools/release/new-key.sh`, on the release manager's
machine, makes an Ed25519 key with no passphrase (CI has no one to type
one, and cannot use a hardware key), sets it as the secret
`RELEASE_SIGNING_KEY` with `gh` — the private half never shown, never
saved outside a temporary folder it removes — and writes the public half
into `tools/release/allowed_signers`, replacing any older key. The jobs
split the powers:

- **sign** holds the key and nothing that can write: it signs SHA256SUMS,
  then runs the user's own `verify.sh` against the committed
  `allowed_signers` — a key the repository does not pin is refused, since
  a signature nobody can check is worse than none. Without the secret it
  says so and the release goes out unsigned, which `verify.sh` refuses.
- **publish** can write releases and never sees the key
  (`tools/release/publish.sh`).
- Both run only for main and `v*` tags, never for a pull request; there
  `publish.sh --dry-run` reads the release list and prints what main
  would publish and delete. A started run on main or a tag is never
  cancelled by a newer push (it may be publishing); publishing itself
  runs one at a time.

**What the signature now proves.** That the files are the ones this
repository's CI built from main or a tag — wherever they were copied to
afterwards. It no longer proves that a person looked before signing (the
39g design), and anyone who can read the secret or change a workflow that
runs on main could sign. On a plan with environments for private
repositories (GitHub Pro, Team, Enterprise), move the secret into an
environment `release` limited to main and `v*` tags, and add
`environment: release` to the sign job: then no other branch's workflow
can reach the key. Rotate with `new-key.sh` when the key may have leaked.

## Commit 40: settings in a window

Until 40 every desktop setting was a flag typed once to `gorani-sync
setup`, and saved in the profile. Commit 40 gives the Windows and macOS
apps a Settings window and a tray or menu-bar icon (decided 2026-10-19:
Windows and macOS first, native per system, no new third-party UI code).
40a is the part both windows call, in the core, and the CLI calls it too.

### 40a as built: the settings layer (clients/core/src/settings.rs)

| Tab | What it does | The core's call |
|---|---|---|
| Account | the server URL; who is signed in; this computer's name; enrol with the vault password; sign out | `normalize_server`, `sign_in_with_cloudflared`, `whoami`, `enrol`, `sign_out` |
| Sync | the folder (Windows); the area, your own files or a case; start at login; keep local copies; pause | `AppSettings`, `cases`, `save` |
| This computer & devices | how this computer's key part is protected, and changing it; your other computers, and revoking them | `protection`, `protection_choices`, `session::protect`, `devices`, `revoke` |
| Advanced | an Access service token; accept files whose signature cannot be checked; the scanner command; the sign-in command itself | `save_sign_in`, `AppSettings` |

**Where it is kept.** The window's choices live in the profile, under
`app`, beside the enrolment: the device's name, folder, case,
startAtLogin, keepLocal, acceptUnverified, scanCommand and paused. The
key is left out while nothing is set, so a profile from before 40 reads
and writes unchanged.

**Who you are comes from the server.** `whoami` asks `GET /api/v1/me`
with the sign-in. It needs no member id, so `setup` no longer asks for
one: the member is the signed-in person's own account, and the window
shows "Signed in as …". An address with no account is told that a lead
adds it in Team › People. `--member` still names one explicitly.

**One server per computer.** A computer's wrapped copy of the root and
its token exist on one server. A new server URL is therefore "sign out
there, then enrol here", and the window does both, in that order.
Enrolling over an enrolled profile is refused ("sign out first"),
because it would leave the first copy on a server with nothing on this
computer left to revoke it. An enrolment the server accepted but this
computer could not save gives its copy straight back.

**Signing out** (`gorani-sync signout`, Account › Sign out) runs in this
order:

1. **The server.** `POST …/devices/<id>/leave`, with this computer's own
   token: the server deletes its wrapped copy. If the server cannot be
   reached, the rest still happens, and the person is told to revoke the
   computer from another one (Team › Devices).
2. **The key parts here.** Keyring and Keychain items and CNG keys are
   forgotten.
3. **The files.** The profile, and its journal of unfinished uploads,
   are deleted.

The Windows app also unregisters its folder.

**Signing in.** The Access token now:

- **Is fetched again shortly before it expires.** Until 40a it was
  fetched once per process, so a shell left running past the Access
  session (a day by default) was refused until restarted. The client now
  reads the JWT's `exp`, only to schedule the next fetch, never to trust
  it, and fetches again two minutes before. Without a readable `exp` it
  fetches every 15 minutes, and after a failure every minute, so signing
  in again is picked up quickly.
- **Can be fetched from a path with spaces.** The command is split as a
  command line, with quotes grouping. Windows installs cloudflared under
  `C:\Program Files (x86)`, which the old whitespace split cut in three.
- **Is signed into by the window.** `sign_in_with_cloudflared` runs
  `cloudflared access login <server>`, which opens the browser at the
  team's sign-in, then proves the token command works and keeps it.
- **Never flashes a console.** Commands run from the windows open none on
  Windows.

**Checked before saving.** The server must be `https://`; plain `http://`
is allowed only for this machine (`wrangler dev`), since anything else
would send both tokens in the clear. Also checked: a case id's shape,
that the folder is a full path, that the scanner command splits, and the
device name.

**The CLI** gained:

- `whoami`;
- `signout`;
- `settings [--set key=value …]`, which shows or changes what the window
  keeps (an empty value unsets).

`accept` uses the saved scanner when `--scan` names none.

### 40b as built: the Windows app (clients/windows/src/app/)

`gorani.exe` is a window program: the Start menu's **Gorani**. It holds
the tray icon, the Settings window, and the sync itself: the Cloud Files
folder that `gorani-cloud` serves, run here on a thread of its own. It is
written with the `windows` crate alone, with no other UI code.

| Part | What it does |
|---|---|
| The tray icon | The water deer, its tooltip saying where the sync stands. Its menu: Open the Gorani folder, Open Gorani in the browser, Pause/Resume syncing, Settings…, Quit. A double-click opens the folder. |
| Settings › Account | Server; Sign in with Cloudflare Access (runs `cloudflared access login`; also signs in again when the session ran out); "Signed in as … — member …". Not enrolled: this computer's name, its protection (the menu of `protection_choices`), the vault password, Enrol. Enrolled: where and how, Change server…, Sign out…. |
| Settings › Sync | The folder (Browse…); Show: My files, or a case (Refresh opens the titles with each case's key); start at sign-in; keep downloaded files; Pause; Save. |
| Settings › This computer & devices | Its protection, and Change it to (`session::protect`); your computers, Refresh, Revoke selected…. |
| Settings › Advanced | The sign-in command; an Access service token; accept unverified files; the scanner `gorani-sync accept` uses. |

**What it does on its own:**
- **At start:** a computer that is not enrolled, or has no folder,
  opens its Settings. An enrolled one with a folder starts syncing and
  says so once. It says nothing when Windows started it at sign-in.
- **One instance:** starting it again opens the running one's Settings.
- **Enrolling** proposes `%USERPROFILE%\Gorani` and starts syncing there.

**Folders.** Gorani takes only a new or empty folder, or the one it has
already (`appmodel::folder_ok`). Signing out removes what it put in its
folder: the placeholders and the folders they leave empty. A folder that
already held someone's files would lose them. Each area has a folder of
its own, so changing the area asks for a new folder (one is suggested).
Otherwise the old area's placeholders would look like new files to the
other area. A folder given up for another is unregistered and emptied
the same way.

**Signing out** stops the sync, sending what is left; unregisters the
folder and removes its placeholders; then runs `settings::sign_out`.
Whole files, which are copies kept by "Keep downloaded files", stay,
and the person is told how many.

**Start at sign-in.** From the package (MSIX), the manifest declares a
startup task, off at install. Settings turns it on through Windows, and
Task Manager › Startup apps can always turn it off again: Windows does
not let an app overrule that, and Settings says so. From the ZIP, it is
the per-user Run key (`"…\gorani.exe" --background`).

**How it is built:**
- **Threads.** The window thread draws and decides. The sync thread owns
  the running folder and posts what happened as messages. Each job that
  waits on the network or a person (sign-in, enrolment, the device list,
  the cases' titles, a protection change) gets a thread of its own, so the
  window never waits. The window's state is a thread-local, borrowed for
  a moment and never across a message box, a menu or the folder picker:
  those run a message loop that can re-enter the window procedure.
- **The vault password** is read once, out of its box (which is
  emptied), and wiped with the enrolment.
- **The manifest** (`src/app/gorani.exe.manifest`) is embedded by
  link.exe itself (build.rs): Common Controls 6 and per-monitor DPI
  awareness. The window lays itself out again when it moves to a screen
  of another DPI.

**What is checked:**
- **Words and rules** (status lines, the tooltip's 127-character limit,
  folder names for cases, the icon chosen from gorani.ico, `folder_ok`)
  live in `appmodel.rs`, with no Win32 in them, and are tested on every
  system.
- **In CI, `gorani --self-test`** makes the real Settings window without
  showing it: every control must exist, every tab arrange, the protection
  menu fill, the layout survive 144 dpi, and the window go cleanly.
- **The package check** runs `gorani --version` through its alias.

What CI cannot do is look at the window, or enrol against a real Access
deployment. The first run on a real PC is that check.

## Testing (the pattern the port follows)

`tests/unit/formats.test.mjs` proves Rust ⇄ TS byte equality; the client
engine runs against `wrangler dev` exactly like `api:files`/`api:devices`
(a placeholder-driven in-memory file system, as Mailflare's engine test
does), then platform smoke tests against real machines.