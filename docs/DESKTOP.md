# Desktop: the native clients (Rust) — protocol and design

> Copyright 2026- Seongwoo Hong. All rights reserved.
> Status: the protocol is implemented on both sides — the server (commits ⑦/⑧) and the Rust client core with the `gorani-sync` CLI (commit ⑬), live-proven against the real worker (the api suite `client-live`). What remains on this document: the platform shells (Windows Cloud Files API, Linux FUSE, macOS File Provider) that mount the same core.

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
| Linux | `clients/linux` | FUSE mount (`~/Gorani`), on-demand reads |
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
device secret = TPM signature behind Windows Hello ‖ Secure Enclave agreement ‖ keyring+TPM pair (Linux)
KEK           = HKDF-SHA256(device secret, salt, "gorani-device-v1")
device copy   = GW01(KEK, root private key)     ← stored on the SERVER, released only to that device's token
```

Neither half is enough alone: the server's copy needs the computer's TPM
and its owner; the computer holds nothing it could open without asking.
Revoking deletes the copy — the computer never unlocks again. The screen
lock drops the root from memory (nothing is opened, sealed or pulled while
locked). Linux additionally keeps its local cache encrypted at rest (GL1:
64 KiB sealed blocks, position-bound).

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
| 33c | **Cases.** Open a granted case's key from its grant; list, pull, push into it; on an evidence case, sign the content hash (and send the stamp imprint) with the member's identity key, and carry an intake record. |
| 33d | **The Linux shell** (`clients/linux`, FUSE): the engine first, against `wrangler dev` with an in-memory file system as the doc's testing pattern says; a real mount where the machine allows FUSE. |
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

## Testing (the pattern the port follows)

`tests/unit/formats.test.mjs` proves Rust ⇄ TS byte equality; the client
engine runs against `wrangler dev` exactly like `api:files`/`api:devices`
(a placeholder-driven in-memory file system, as Mailflare's engine test
does), then platform smoke tests against real machines.