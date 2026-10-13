# Desktop: the native clients (Rust) — protocol and design

> Copyright 2026- Seongwoo Hong. All rights reserved.
> Status: the server side of this protocol is complete and tested (commits ⑧/⑦); the client port is the next commit.

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

## Guardian access

A parent enrols a device **for a child** with the child's guardian
enrolment code (docs/FAMILY.md) — the child's password is never involved.
Parents act for any member at the API layer; children only for themselves.

## Testing (the pattern the port follows)

`tests/unit/formats.test.mjs` proves Rust ⇄ TS byte equality; the client
engine runs against `wrangler dev` exactly like `api:files`/`api:devices`
(a placeholder-driven in-memory file system, as Mailflare's engine test
does), then platform smoke tests against real machines.