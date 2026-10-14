# Security review (commit 23): what a zero-trust design still let through

> Copyright 2026- Seongwoo Hong. All rights reserved.
> A worked example of reviewing a real codebase. The design documents
> describe a careful system; the review asks the only question that matters:
> **does the code do what the documents say?** Each finding below names the
> file, the failure, the fix (or the proposal) and — for teaching — *why it
> happened*. Regression tests: `tests/api/security.test.mjs` and the extended
> unit suites.

## How the review was run

1. **Read every document first** (README, docs/*). Write down every claim
   that is a security property ("revoking deletes the copy", "the restore
   only fills restore keys", "the size is honest", "the cache only holds
   immutable objects").
2. **Read the server end to end**, in request order: authentication →
   routing/scope → Durable Object → storage. Every value from a client is
   followed until it becomes a key, a SQL row, or an S3 path.
3. **Read the clients** for what they trust from the server.
4. **Reproduce**, then fix, then **prove the refusal** with a test that
   fails on the old code (the house style in docs/TESTS.md).

The pattern behind most findings: the *design* was right, and a single
line of glue in between quietly disagreed with it.

## Severity scale

| Level | Meaning here |
|---|---|
| Critical | Breaks the zero-trust promise: key material leaves its zone, or one member can destroy or redirect another's data |
| High | A privilege boundary (member/parent/device/stranger) can be crossed, or a security control is silently off |
| Medium | Defense-in-depth gone, integrity not checked, or a resource/cost exposure |
| Low | Information disclosure, hygiene, configuration that does not apply |

## Fixed in this commit

### Server (worker/)

| # | Sev | Finding | Fix | Why it happened |
|---|---|---|---|---|
| S1 | Critical | **Share-id hijack.** Share ids are minted by the client; the registry index was `INSERT OR REPLACE`, and copies live at `shares/<id>` (one namespace for all members). A member who had seen a link could mint the same id, re-point the public link to their DO, and complete a multipart upload over the original sealed copy. | `family.rs › share_index_put` is write-once (409). `routes.rs › share_create` claims the id *before* any S3 call and releases it if a later step fails. | "Upsert" is the convenient default; an index of *ownership* must be write-once. |
| S2 | High | **Any Access identity could revoke any device.** `wiped`/`leave` carried on after *any* 403 from `device_auth`, including "wrong device token". Device routes skip member scope by design (the token is the authority). | `devices.rs › device_token_ok` separates "is this the token?" from "what state is the device in?". | One error channel (403) carried two meanings (bad token, revoked). |
| S3 | High | **Revoking kept the wrapped root copy**; destroying the vault kept every device's copy. docs/DESKTOP.md: "Revoking deletes the copy". | `revoke_copy` blanks `wrapped` + `salt`; `vault_destroy` shreds all device copies. | The flag (`revoked_at`) was implemented; the shredding it stood for was not. |
| S4 | High | **Restore fill could overwrite live objects.** Its key check was `starts_with("files/<member>/")` — which every live object matches. In-place overwrite bypassed versions and Trash, and broke the cache's "keys are immutable" invariant. | Shape `files/<m>/<file>/r-<id>` only, a version row must point at it, and write-once. | A prefix check is an allow-list of *everything under* the prefix. |
| S5 | Medium | Restore built object keys from the **actor's** id (wrong for a parent acting for a child), upserted over existing versions, reassigned owners and replaced the files secrets. | The router sends `x-gorani-member`; restore fills gaps only (an existing version keeps its object unless it is gone from storage), `COALESCE(owner, ?)`, secrets only into an empty slot. | The DO cannot read its own name, so a helper guessed it. |
| S6 | Medium | `GET /api/v1/family` (all emails + 100 audit lines) answered **any** authenticated identity, member or not. | Members only (an empty registry stays readable for the bootstrap screen). | Authentication ("someone signed in") was mistaken for authorization ("a member signed in"). |
| S7 | Medium | Ids from URLs and bodies flowed into DO names and S3 keys unvalidated, and objects were written **before** the DO checked anything. A parent could also address `members/<anything>` and create empty Durable Objects. | One allow-list for every path segment (`[A-Za-z0-9_-]{1,64}`) right after authentication; member ids by the registry rule; the addressed member must exist. Body ids (`fileId`, restore ids) use the same rule. | Validation lived in some handlers; forty handlers is forty chances to forget. |
| S8 | Medium | Multipart **size check failed open** (`if let Some(head)`), and a refused object was "aborted" after completion — a no-op that left it in the bucket. | Missing HEAD = refusal; refused completed objects are deleted; `chunk` is required; part numbers 1–10000; overflow-safe `div_ceil`. | "Check if you can" reads like a check. |
| S9 | Medium | **The declared size was never verified** for whole-file uploads (ARCHITECTURE-DEEP's diagram says "size honest"). Sizes drive listings and the duplicate check. | `size == sealed length − 32` (GV02 overhead) or 400. | A diagram is not a test. |
| S10 | Medium | Share copies were marked ready with any claimed size. | Same "must add up" rule as uploads. | — |
| S11 | Low | Two Range parsers with different return shapes; the share route's returned `(start, end)` into a `(offset, length)` slot. | One parser. | Duplicated code drifts. The old test only asked for `bytes=0-…`, where the bug is one byte. |
| S12 | Low | `share_create` called `vault_gate()?` and dropped its answer — shares from a paused vault. | Read the answer. | `?` propagates errors, not refusals carried in `Ok`. |
| S13 | High | **The audited could erase the audit.** `POST …/housekeeping` took `auditKeep`/`journalDays` from any member. | Knobs only under `GORANI_DEV=1` (tests); production uses deployment defaults. | A test hook shipped as an API. |
| S14 | Low | The public health line named the bucket and echoed config errors. | One bit: configured or not. | — |
| S15 | Medium | Plain-`http://` S3 endpoints were accepted. With `UNSIGNED-PAYLOAD`, the body integrity is TLS's job. | `https://` required outside dev. | — |
| S16 | Low | `CompleteMultipartUpload` can answer 200 with an `<Error>` body. | Treated as failure. | A documented S3 trap. |
| S17 | Medium | `?version=n` downloads always served the **current** version (`req.path()` never contains the query). | Read the query from the URL. | For forensics, "the version you asked for" is the whole point. |
| S18 | Low | Trash purge deleted `files` rows but left versions (wrapped keys, object keys), music blobs and contributor rows — forever. | Dependent rows purged. | SQLite in DOs runs without foreign keys. |
| S19 | Low | Abandoned multipart uploads were never aborted (documented, not built) — billed storage. | Housekeeping aborts uploads older than 2 days and un-ready shares. Also set a bucket lifecycle rule (below). | — |
| S20 | Medium | Backup download buffered the `.gbak` twice in a 128 MB isolate and cached it at the edge past its retention; `s3::get` cached every object the backup job read. | Manifest-only DO answer, streamed + uncached download; `s3::get` uncached. | A cache added for one read path was applied to all. |
| S21 | Medium | One email could belong to two members; "who is calling" depended on row order. | Emails are unique across members (409). | — |
| S22 | Low | `CACHE_MAX_OBJECT_MB`/`CACHE_TTL_DAYS` sat at the top level of wrangler.jsonc, which wrangler ignores with a warning. | Moved into `vars`. | Read your deploy warnings. |
| S23 | Low | The JWKS `alg` was parsed and never checked. | Must be ES256 when present. | — |
| S24 | Medium | The public share page had no security headers. | `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `nosniff`. Full CSP: see O1. | — |

### Clients (clients/, web/)

| # | Sev | Finding | Fix |
|---|---|---|---|
| C1 | Critical | **The CLI sent the device secret to the server.** It stored it in `access_secret`, which `api.rs` sends as `CF-Access-Client-Secret` whenever an Access id is set. Server copy + device secret = the root. | Separate `device_secret` (never sent); `--access-secret` for the real Access secret; old profiles' `accessSecret` reads into `device_secret`. |
| C2 | High | `gorani-sync pull` counted frames with floor division: an empty or shortened body "opened" to 0 bytes and overwrote `--out`. | Uses `chunked::open_chunked` (final-flag bound) + size check before writing. |
| C3 | High | The profile (device token + device secret) was written world-readable. | 0600 at creation, atomic rename. |
| C4 | High | Image previews used the **stored** MIME for blob URLs: `image/svg+xml` (or anything) on the app origin. | Raster allow-list for blob types. |
| C5 | — | Web: open/preview/media/info called `GET …/files/keys` (the route is POST) → 404. The unit test's fake server answered the GET. | `model.ts › keysFor` POSTs `{ ids }`; the fake now enforces POST. **Lesson: a mock of the tested layer agreed with the bug.** |
| C6 | — | Web: chunked files (> 48 MB) were opened with the GV02 opener and could never open. | `openChunkedStream` (order + final flag checked). |
| C7 | — | Web: the music library requested `/files/music`. | Member-scoped path. |
| C8 | Medium | `chunked::open_chunked` could underflow on short input (a panic → abort in the worker profile). | `checked_sub`. |

### O1, fixed in commit 24 — a CSP that is actually delivered

The finding: `index.html` said the Worker sends a strict CSP with Trusted
Types. Nothing did — static assets are served by the platform without
running the Worker, and there was no `_headers` file. The fix, and what it
turned up:

| # | Sev | What | Fix |
|---|---|---|---|
| O1 | Critical | No CSP / security headers on the SPA or the share page. | `web/public/_headers`: `default-src 'none'`, scripts/styles from `'self'` only (+`'wasm-unsafe-eval'` for Argon2id), `blob:` only for images/media, `frame-ancestors 'none'`, `require-trusted-types-for 'script'`, `trusted-types lit-html default`; nosniff, DENY framing, no-referrer, COOP/CORP same-origin, Permissions-Policy, HSTS. Worker responses: `lib.rs › harden` (nothing-renders CSP, `no-store`) on every route. |
| O1a | — | **Trusted Types needed a policy for our own script URLs**: `new Worker(url)` (generated by Vite) and the media service worker's registration are sinks too. | A *default* policy (`web/src/lib/trusted-types.ts`) that admits exactly `/sw-media.js` and flat `/assets/*.js` chunks — and has no `createHTML`, so any `innerHTML = string` fails closed. Unit-tested allow-list. |
| O1b | — | Two `innerHTML` sinks (the new-folder prompt, the share page's icon); five `style="…"` attributes (blocked by `style-src 'self'`). | DOM building / `textContent`; Tailwind classes and Lit `styleMap` (CSSOM — allowed). |
| O1c | — | **Icons rendered as escaped markup text** — `icon()` returned an SVG *string*. | SVG elements built with `createElementNS` from a data table (no parsing; no `unsafeSVG` exception needed). |
| O1d | High | **The share page was never served.** The Worker fetched `/s.html` from its own public origin — a subrequest the platform refuses — so `/s/f/<id>` was a bare 500. No test had opened a link. | The `ASSETS` binding. `api:shares` and `e2e:app` now open a real link. |
| O1e | — | The share page shipped **without a stylesheet** (it sat in `public/`, copied verbatim, Tailwind classes and no CSS). Its code was an inline module. | A Vite entry (`s.html` + `src/styles/share.css`), code in `/s.js`; its own CSP with `trusted-types 'none'`. Also: the link secret is removed from the address bar after reading, a refused claim stops the download, an empty file still verifies its one frame, downloads are always `application/octet-stream`. |
| O1f | Low | Unhandled Worker errors returned their internal message (object keys, endpoints, SQL) and no security headers. | Logged in full, answered `{"error":"internal error"}` with the hardened headers. |

How it is proven: `e2e:app` asserts the headers on `/`, on an SPA fallback
path, on the API and on the share page; records every
`securitypolicyviolation` in every session and fails on any; and checks that
`innerHTML` with a plain string is refused (and reported) — the policy is
enforced, not just sent.

### O2 + O4, fixed in commit 24 — Lock means locked

| # | Sev | What | Fix |
|---|---|---|---|
| O2 | Critical | **Lock did not lock.** `session.lock()` cleared a cache and called listeners nobody registered; the explorer stayed on screen, the bridge kept the opened store key, the media worker kept every content key, blob URLs of decrypted files stayed live. No idle lock while the tab was visible. | `lock()` is a state: `locked` is set synchronously, every later key request throws, the device hold is deleted, THEN listeners run (once). The shell subscribes and the app swaps in the lock screen; unmounting disposes the model and index, tells the media worker `media-forget-all`, revokes every tracked blob URL (`lib/blob-urls.ts`) and locks the session. The bridge refuses keys once locked. |
| O2a | — | Auto-lock: hidden-only, 10 minutes, and its cleanup discarded (listeners stacked per session). | D15: **15 idle minutes or 5 hidden**, decided by a pure `autoLockDue()` (unit:lock, boundaries both ways) and driven by `watchAutoLock`, whose cleanup the shell calls. |
| O4 | High | The device hold outlived its window on disk (`exp` was only checked, never acted on). | An expired, keyless or undecryptable hold is deleted the moment it is read; the window is 5 minutes (= the hidden lock) and fixed, not sliding (the doc claimed sliding). |
| O2b | — | The viewer's "Close (esc)" never worked (the handler sat on an element nothing focused); downloads started one browser save per 8 MiB frame; the shell rendered the explorer twice. | Focus the overlay on open; collect frames into one Blob; one render. |

Proven by unit:lock (the rule, idempotent lock, keys refused, listener
order) and e2e:app: with a decrypted image open, Lock → the image's blob:
URL no longer loads, the shell is unmounted, no hold remains; a faked clock
shows 14 idle minutes open and 15 locked. (A side effect worth teaching:
the CSP's `connect-src 'self'` already stops page scripts from `fetch`ing a
blob: URL at all.)

### O3, fixed in commit 24 — store-key records authenticated

| # | Sev | What | Fix |
|---|---|---|---|
| O3 | High | **A server could make clients seal to its own key.** Sealing needs only a public key, so whoever writes the settings row could mint a key pair, seal its private half to the victim's root, and swap the record; web and CLI opened it and sealed every later upload to the attacker. | A MAC under a record key derived from the root alone (ECDH of the root with its own public half from the bundle + the ML-KEM secret, HKDF, HMAC; ENCRYPTION.md › Authenticated store records), plus consistency checks (the opened key must reproduce the record's public halves and id) and strict opening (unsealed "key material" refused). Own records are MAC'd at setup; others are pinned on first open and saved. |
| O3a | High | The CLI sealed names and content keys with the record's public JWK directly (`seal_for_files`, `files_public`) — the verification in `files_store` was never on the sealing path. Found by the new swap step in `api:client-live`. | `Session::files_public` derives the public half from the VERIFIED private key; the duplicate helper is gone. |

Proven by unit:records (substitution, swapped halves, mismatched pairs,
unsealed keys, foreign MACs — each refused; pinning), the `record` vector
(TypeScript's MAC verified and recomputed by Rust), api:client-live (the
real binary refuses to push through a swapped record), and e2e:app (setup
creates the MAC; a seeded record is pinned and saved).

**What it does not cover — stated, not hidden:** a record sealed to you by
someone else is trusted on its FIRST open; a substitution before that is
not caught. Member public keys handed to others (to seal TO you) and the
parents' master public key are likewise server-supplied. Both need member
identity keys with verified fingerprints — the D2/D4 redesign.

### O5, fixed in commit 24 — a rotation that leaves nothing behind

| # | Sev | What | Fix |
|---|---|---|---|
| O5 | High | **Member removal left data readable.** `files/reseal` re-wrapped each file's *living* version and its name only; older versions' content keys and types, folder names, music tags, share names and the files secrets stayed sealed to the old store key — which the departing member keeps. | `GET files/sealed?kind=` lists every value sealed to the store (six kinds, paged by rowid); `PUT files/reseal { items }` writes exact rows (sealed text only, batch validated before any write); the old form is refused. The client walk is `web/src/vault/rotation.ts › resealStore` (idempotent: already-new values are skipped, values under neither key stop the walk), with `opensAnything` as the proof step. |

Proven by api:rotation: a store holding every kind (two versions, a
folder, tags, secrets, a share) — the old key opens 9 values before and
**0** after; the new key opens all 9; version 1 still decrypts to its
original bytes (via `?version=1`, the S17 fix); a second walk re-seals
nothing; the old form and unsealed values are refused.

### O19, fixed in commit 25 — the store that hung after a restart

Found while preparing O6, by asking what the suites never do: **restart**.

| # | Sev | What | Fix |
|---|---|---|---|
| O19 | Critical | **Every member store hung after its first wake-up.** Both Durable Objects ran their whole `MIGRATIONS` list in the constructor, every time, with `.expect(..)`. `CREATE TABLE IF NOT EXISTS` repeats harmlessly; `ALTER TABLE … ADD COLUMN` does not — the second run fails ("duplicate column name"), the `expect` panics, and a panicking wasm Worker never answers: the runtime cancels the request as hung. A DO is constructed again after every eviction (idle, deploy, host move), so in production each member store would stop answering minutes after first use. The registry survived only because its list has no `ADD COLUMN` yet. | `worker/src/schema.rs`: a **migration ledger** (`schema_ledger(n)`) — each statement runs once, recorded by its index, so the lists are append-only history. A store from before the ledger is recognised by the one forgivable error (`ADD COLUMN` meeting its own column); anything else stops the migration. A failed migration no longer panics: the DO keeps the error and answers every request with a 500 that names it. |

Why no test saw it: every suite starts from a fresh SQLite directory and
keeps one dev server for its whole run, so each DO was constructed exactly
once. `api:restart` now writes through both DOs, stops the server, and
starts a second (and a third) on the same directory — the probe that found
the bug, kept as its regression test. The lesson generalises: **a
constructor is a code path that runs on every wake-up, not once** — test
the second run.

### O6, fixed in commit 25 — a value opens only where it was sealed, and only a key holder seals

| # | Sev | What | Fix |
|---|---|---|---|
| O6 | High (was Medium) | **Moving.** A sealed value carried no notion of where it belonged: the server could swap two files' content keys (each with its object) or names, so "invoice.pdf" opened a malware sample and evidence item A was shown as item B — every value still opened. | **GV04** (docs/ENCRYPTION.md › GV04): each store value is sealed into its *place* — store, kind, item id, version — bound as AAD and rebuilt by the opener, never read off the server. A key moved to another file or version, or a name moved to another file, fails to open. |
| O6a | High | **Minting** (found while scoping O6 — the reason the severity rose). GV03 seals to a PUBLIC key and the server holds it: it could invent a file outright — make up a content key, encrypt bytes of its choosing, seal the key and a name — and the file appeared in the store as if a member had uploaded it. Binding ids alone would not have stopped this (the place is public information). | GV04's key schedule mixes in the **store PSK**, computable only from the store's private key (self-ECDH ‖ a hash of the ML-KEM secret — the record key's construction, now one shared helper). Sealing into a store needs what opening needs: there is no public-key path in any more — the bridge does not even keep the public half. |
| O6b | — | The Worker minted file ids AFTER the upload, so nothing sealed could name its file. | Ids are client-chosen (128 random bits; `file_id`, multipart `newFileId`), shape-checked, and a taken id is a 409. `base_version` is required for versions (the key is sealed for `base + 1`). Downloads say which version they are (`x-gorani-version`): the key's place depends on it. |
| O6c | Low | A refused music blob was checked after the file and version rows were inserted; the 400 made the Worker delete the object, leaving rows that pointed at nothing. | Every refusal before the first write (`files_store.rs › file_put / file_version_put`). |
| O6d | — | The upload dialog's "add as a version" answer was a dead parameter (`asVersion`, never read): it stored a new file like "keep both". | Removed; the comment says what the answers do. |

Proven, both directions and end to end:

- `cargo test -p gorani-formats` (placed.rs): a value opens only in its place (another file, store, kind or version fails); GV03 and a foreign store's GV04 are refused; place encoding is unambiguous.
- `unit:formats`: the cross-language vector — the browser seals a name and a key into places, Rust derives the same PSK and opens them (and nowhere else); Rust seals, the browser opens.
- `api:security` block 9: the server-as-attacker swaps a malware sample's name and key into an invoice's rows through its own write path — both refuse to open as the invoice — and mints a file with GV03 (refused by the store) and with another store's PSK (stored, never opens).
- `unit:explorer`: swapped names show as *unverified*, the listing does not crash, the moved key does not open.
- `api:rotation`: the walk re-seals each value in its row's place; a value moved between rows stops the walk instead of being laundered into the wrong place under the new PSK.
- `unit:family`: after a member leaves, a value they seal with the old key does not open under the new one — rotation revokes writing as well as reading.

The limits, stated: GV04 proves "a holder of this store's key sealed this,
here" — not *who* (per-member signatures over each upload are D5), and not
*freshness* (the server can still serve an older row; it is at least
consistently what it claims to be).

### O7 + O8, fixed in commit 25 — the backup's label, and what a stored KDF may ask

| # | Sev | What | Fix |
|---|---|---|---|
| O7 | Medium | **GB1 authenticated the segments, not the header** — and the header is what a restore believes (`stamp`, `kind`). Anyone holding the bytes (the bucket, a download folder, an offline copy) could relabel one backup as another and nothing failed. The header did not even say *when* it was made. | **GB2** (`crates/formats/src/backup.rs`, `web/src/vault/backup.ts`): H = SHA-256(magic ‖ headerLen ‖ header) ends every segment's AAD; the writer emits the prefix itself so H is of exactly the bytes written; the header carries a sealed `createdAt`. Change one header byte and nothing opens. |
| O7a | Medium | **A backup cut down to its header parsed as a valid, EMPTY backup** in both readers (zero segments, zero entries, no error). | The writer always emits a final segment; both readers require one. |
| O7b | Low | The Rust reader compared the last 8 bytes of each stored nonce and rebuilt the rest: 4 bytes per segment were free to change. | All 12 bytes are compared against the counter nonce (both readers). |
| O8 | Medium | **Argon2 bounds**: the floor allowed one pass at 19 MiB (below OWASP's 19 MiB / 2 passes); the ceiling allowed 1 GiB, 20 passes, 16 lanes — and every password method was tried, so a server serving a padded settings row (or a share link's `kdf`) could freeze a phone for minutes. Salts had no length check. | `web/src/vault/kdf-bounds.ts` (+ the Rust twin in `unlock.rs`): m 19–256 MiB, t 2–10, p 1–8; salts 16–64 bytes; at most 4 password methods tried per unlock (`MAX_PASSWORD_METHODS`). Vault methods, device copies and share links all pass through it; the module has no imports so the share page carries it cheaply. |

The honest scope of O7: the **Worker writes backups** (it holds the
backup public key, by design: the server writes backups and never opens
them), so a malicious *server* could still write a whole false backup with
any header it likes. What GB2 adds is integrity at rest — against whoever
can change bytes but cannot run the Worker. A forged backup's contents are
still bounded by O6: it can only replay genuine placed values, never mint
new ones (that takes the store's PSK). Per-member signatures over backups
are D5.

Proven by: `cargo test -p gorani-formats` (relabelled header, header-only
truncation, a flipped nonce byte — each refused; an honestly empty backup
still round-trips; the bounds both ways; a real method in 5th place is
never reached, inside the cap it opens), `api:backup` (the browser reader
refuses a relabelled `createdAt` and a header-only file from the real
Worker), `unit:kdf-bounds` (the same bounds and cap in TypeScript, plus a
share link's `kdf`).

Upgrade note: backups written before commit 25 are GB1 and hold GV03
values, which a GV04 store refuses — restore them with the release that
wrote them, then take a fresh backup (docs/PRODUCTION.md › Backups).

### O9 + O10, fixed in commit 25 — a backup that streams and tells the truth; retention that cannot orphan

| # | Sev | What | Fix |
|---|---|---|---|
| O9 | Medium | **The backup job held the whole backup in memory** — every object read whole (`s3::get`), the container concatenated, one PUT — so a store larger than the isolate (128 MB) could not be backed up at all; and **one missing object aborted the run** with nothing written. | The job streams (`worker/src/backup.rs`): rows and objects (read chunk by chunk via `stream_uncached`) feed the GB2 writer, whose output ships as 8 MiB multipart parts — memory is one part plus one segment, whatever the store's size. A missing object is **recorded**: its entry says `"missing": true`, the manifest counts it (`backups.missing`, the first column added under the O19 ledger), the response lists it, the audit says so — and a restore skips it by name instead of minting an empty object. An object whose length changes mid-read aborts the run (the entry format announces the length first; a backup must never be wrong) and frees its parts. `s3::get` is gone. |
| O10 | Medium | **Retention could orphan objects.** Housekeeping and the backup prune deleted the rows FIRST — the only pointers to the objects — then the S3 deletes, every result discarded (`let _ =`). A failed delete left an object nothing would ever find again. And the cron fan-out ignored every answer: a member whose pass returned 500 nightly looked healthy. | A **deletion outbox** (`pending_deletes`, migration v8): each object key (or multipart upload) is queued in the same pass that removes its row, and leaves the queue only when storage confirms (204, or 404 — already gone). Failures stay queued with attempts and the error, retried every night, visible at `GET …/storage/pending`. A pass with failed deletes answers 503; the fan-out visits every member regardless, then fails the scheduled event naming each failure (`console_error!`). |
| O10a | Low | The audit listing never selected the `details` column: every readable detail (retention outcomes, device names, backup counts) was written and then listed as null. | Selected. Found by the O10 test asking the audit what happened. |

Proven by `api:backup` § 7 (a 9 MiB file pushes the container past one
part; an object removed behind the Worker's back is listed, counted,
marked in its entry, and skipped by the restore; the streamed object
round-trips byte for byte) and `api:cron` § 4 (the stub refuses DELETE
with 503: the manifest rows are pruned on schedule, both keys wait in the
outbox with the error, the objects are still in storage, the audit says
`deletesFailed:2`; storage recovers and the next pass empties the outbox).
The stub gained a fault-injection route for it (`POST /__fault`,
tests/lib/s3stub.mjs).

The honest ceiling: one container is at most 10 000 parts × 8 MiB ≈ 78
GiB. Past that — and for D12's 255 GB files — backups must become
manifests of object references rather than copies (a decision, recorded
in DECISIONS.md › D12).

### O11, fixed in commit 25 — the media worker, which had never worked

| # | Sev | What | Fix |
|---|---|---|---|
| O11 | Medium | **Scope**: registered at "/media/"; a service worker receives the fetches of the pages it controls, and the app page is "/" — `<video src=/media/…>` never reached it. Streaming had never worked; large videos fetched a path the Worker does not serve. | Scope "/" (`web/src/lib/media-worker.ts`); the fetch handler claims only `/media/` paths and returns without `respondWith` for everything else (no pass-through); an unregistered `/media/` path is a 404, never a fall-through to the app's HTML. The old "/media/" registration is retired on upgrade. |
| O11a | Medium | The worker begins with an `import` but was registered as a classic worker: the script failed to evaluate and the worker never installed. | `type: "module"`; where module service workers are unsupported, the registration fails and the viewer falls back to a decrypted blob. |
| O11b | Medium | **Wrong AAD** on the whole-file path: the magic alone (4 bytes) instead of GV02's 16-byte header — no whole-file media could ever decrypt. | `sealed.subarray(0, 16)`, plus a size check. |
| O11c | Low | Answers were the whole frame span (starting before the requested offset) and always `video/mp4`; the worker fetched the CURRENT version, not the one its key was opened for. | `cutToRange` (unit-tested) serves exactly the asked bytes with an honest Content-Range; the file's own type; `?version=` from the registration. The page waits for the worker's acknowledgement before the player's first request. |
| O11d | — | The worker's fetches carried no identity on the dev server (a service worker cannot read the page's localStorage). | The bridge's `identityHeaders()` ride the registration — empty in production, where Access's cookie rides every same-origin fetch. |

Keys are forgotten on viewer close and on Lock (commit 24, O2). Proven by
`e2e:app` (a 9 MiB video plays through the worker: the page is
controlled, `bytes=1000-1999` comes back as exactly those decrypted bytes
with `Content-Range: bytes 1000-1999/9437184` and `video/mp4`; after the
viewer closes the same URL is a 404; other requests are untouched) and
`unit:media-frames` (exact cuts). The chunked (GC01, > 48 MB) path shares
the frame math; an e2e over 48 MB is left to the live suite's budget.

### O12–O18, fixed in commit 25 — links, limits, reads, and the small ones

| # | Sev | What | Fix |
|---|---|---|---|
| O12 | Medium | **Share limits were cooperative**: `/data` served the copy to anyone with the link — no claim needed, so "2 downloads" was the page's courtesy. | A claim spends one download and returns a token (256-bit, stored as SHA-256, one hour); `/data` serves only to a live token of that share (`x-gorani-share-token` — a header, not a URL). One claim = one download session (Range pieces included). Revoking the link kills its tokens. |
| O12a | High | **A one-download link could never be downloaded**: `/data` re-ran the claim's own check (`downloads_left > 0`) after the claim had spent the last one. Every link's final download failed. | `/data` checks the token and the share's state, not the count. Found by writing O12's test. |
| O13 | Medium | No rate limiting on the public share routes or the device-token checks. | The Workers rate-limiting binding (wrangler.jsonc › `ratelimits`): 60/min per caller + link on `/s/*`, 30/min per caller + device on token checks; 429 + `Retry-After`. It fails OPEN on a limiter error (a flood mitigation, not a security boundary — the secrets are) and is per-location and approximate, so the WAF rules in PRODUCTION.md are the second layer. |
| O14 | Medium | Reads were not audited — only writes. | The read log (D10): the download route sends the READER to the DO, whose object lookup records one merged row per reader × version × client × 5 minutes — before the edge cache, so a cached read is still on record. `GET …/reads[?file=]`; the clients label themselves (`x-gorani-client`: web, media, cli). Share claims land in the owner's audit. |
| O15 | Low | Passkey `rp.id` was "the last two host labels": `workers.dev` (a public suffix — no passkey could be created) on a workers.dev deploy, `co.uk` on others; and the unlock call used the browser's default (the hostname), so on any subdomain an enrolled passkey could never unlock. | `rp.id` = `location.hostname`, stated on both calls. |
| O16 | Low | `S3Config` and `DeviceProfile` derived `Debug`: `{:?}` printed the S3 secret, the device token, the Access secret and the device secret. | Hand-written `Debug` with `[redacted]`; a test checks no key appears. |
| O17 | Low | The share page ran a vendored Argon2 with no recorded provenance and no integrity check. | Subresource Integrity on the script tag; the sha256 in NOTICE; `unit:vendored` proves the file is hash-wasm 4.12.0's build byte for byte and that NOTICE, `s.html` and the built page agree. (The separate share *origin* is a deployment decision — PRODUCTION.md › Share links.) |
| O18 | Low | The first member was created by any authenticated caller — a race on a fresh deploy. | A `BOOTSTRAP_TOKEN` secret, presented once (`x-gorani-bootstrap`): checked in the Worker (constant time), applied by the registry only while it is empty, and the first member must be a parent. Production without the secret refuses to bootstrap; the dev server without it bootstraps freely. A client-sent verdict is overwritten; a non-object body is a 400, not a panic. |

Proven by: `api:shares` (no token / a forged token → 403; the claim's token
serves data and Range; **the last download downloads**; a revoked link's
token dies), `api:security` § 10 (the 71st request a minute on one link is
429 with `Retry-After`, another link is untouched; device-token guessing is
cut off), `api:files` / `api:cache` (two downloads in a window are one
merged line; a parent's read is the parent's; a cache HIT is still a read
on record), `api:bootstrap` (new, its own server with the secret set),
`unit:vendored` (new), the Rust tests for `bootstrap_allowed` and the
redacted `Debug`.

## Still open

None of the review's findings. What remains is the product roadmap in
docs/DECISIONS.md (D2/D4 roles, cases and quorum recovery — roles, cases and
signed grants and the M-of-N recovery ceremony landed in commits 26–27,
closing O3's trust-on-first-use gap for case keys and removing the family
master key and the parent act-for rule — D5 custody, D6 Object Lock, D7 retention, D8
samples, D11 partner sign-in, D12 large files) and the operational controls
below.

## Operational controls (outside the code)

For any S3-compatible bucket (MinIO, AWS S3, B2, Wasabi):

- **Block all public access**; bucket policy denies anything but the
  Worker's access key. `tests/api/s3-live.test.mjs` checks that anonymous
  reads are refused.
- **A dedicated access key** limited to this bucket and to the actions the
  worker uses: `GetObject`, `PutObject`, `DeleteObject`,
  `AbortMultipartUpload`, `ListMultipartUploadParts`, `ListBucket` (not
  `PutBucketPolicy`, not `DeleteBucket`).
- **Lifecycle rule**: `AbortIncompleteMultipartUpload` after 2 days (the
  bucket-side twin of S19).
- **Versioning + object lock** are worth weighing for a security-operations
  store (tamper-evidence) — they conflict with crypto-shredding by design;
  see the questions in the PR.
- **Server-side encryption** (SSE-S3/SSE-KMS) adds nothing to
  confidentiality here (objects are already sealed) but is often a
  compliance checkbox; it is free to enable.
- Rotate the S3 key on a schedule; `wrangler secret put` + redeploy.
