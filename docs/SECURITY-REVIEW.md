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

## Open findings (proposals — need a decision)

| # | Sev | Finding | Proposal |
|---|---|---|---|
| O6 | Medium | Content is not bound to its file id: the server can swap (key, object) pairs between files undetected. | Bind file id + version in the AAD (format v-next). |
| O7 | Medium | GB1: header outside the AAD; nonce prefix not compared. | Hash the header into each segment's AAD; compare full nonce. |
| O8 | Medium | Argon2 bounds: floor below OWASP (t=1 at 19 MiB), ceiling lets a server freeze a phone. | t ≥ 2 floor; ~256 MiB / t ≤ 10 ceiling; cap methods tried. |
| O9 | Medium | The backup job is in memory and one missing object aborts the run. | Multipart streaming; record missing objects. |
| O10 | Medium | Cron ignores non-2xx and S3-delete failures (manifest row removed, `.gbak` orphaned). | Collect failures, fail the pass, delete rows only after the object. |
| O11 | Medium | Media service worker: keys never forgotten, scope cannot control `/`, wrong AAD on the whole-object path. | Scope `/` (handle `/media/` only), forget on close/lock, fix AAD. |
| O12 | Medium | Share download limits are cooperative: `/data` does not decrement. | Claim returns a one-time data token. |
| O13 | Medium | No rate limiting on device-token and share endpoints. | Cloudflare WAF rate-limiting rules on `/s/*` and `/devices/*`. |
| O14 | Medium | Reads/downloads are not audited (only writes are). | Audit download/share-access events (see questions). |
| O15 | Low | Passkey `rp.id` = last two host labels (`workers.dev` is a public suffix). | `location.hostname`. Latent: no caller yet. |
| O16 | Low | `S3Config`/`DeviceProfile` derive `Debug` (secret printed by `{:?}`). | Manual `Debug` with redaction. |
| O17 | Low | Share page on the vault's origin; vendored Argon2 without SRI or a recorded hash. | Separate share origin; SRI + hash in NOTICE. |
| O18 | Low | Bootstrap: the first member is created by *any* authenticated caller (a race on a fresh deploy). | A one-time `BOOTSTRAP_TOKEN` secret. |

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
