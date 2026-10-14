# Custody, write-once storage, retention and samples (D5–D8)

> Copyright 2026- Seongwoo Hong. All rights reserved.
> The design for docs/DECISIONS.md › D5 (chain of custody), D6 (write-once
> storage), D7 (retention) and D8 (malware samples), written before the
> code, as docs/CASES.md was for D2/D4. Cases (`case:<id>`, kind
> `evidence` or `working`) are the unit everything here attaches to.

## What changes, in one paragraph

A case's files must be able to stand up later — in an incident review, an
insurer's audit, a court. That needs four properties gorani did not have:
the record of who did what **cannot be quietly edited** (a hash chain,
checkpointed outside the database); evidence **cannot be quietly replaced
or deleted** (S3 Object Lock, signed hashes, RFC 3161 timestamps); evidence
**outlives the people and the defaults** that would prune it (retention by
kind); and a malware sample **cannot go off** on an analyst's laptop (never
rendered, delivered zipped under the industry's "infected" password).

## Build order (each stage green on its own)

| Stage | Decision | What |
|---|---|---|
| 1 *(landed: commit 29, `api:audit`)* | D7 + D5.3 | the audit leaves the area database: an outbox ships each line to a per-area **audit Durable Object** that hash-chains it, keeps it 7 years with no line cap, and checkpoints daily to object storage; `…/audit/verify` |
| 2 *(landed: commit 29b, `api:retention`)* | D7 | retention by kind: evidence keeps every version and refuses deletion; working areas prune non-current versions after a year |
| 3 *(landed: commit 29c, `api:objectlock`)* | D6 | Object Lock on evidence objects (COMPLIANCE mode, the case's retention) |
| 4 *(landed: commit 29d, `api:hashes`)* | D5.1 | the uploader signs SHA-256 of the plaintext (identity key, stage 4 of CASES.md) — stored beside the version, verified on open |
| 5 *(landed: commit 29e, `api:samples`)* | D8 | samples: a readable flag; the viewer refuses them; download as a zip encrypted with "infected" |
| 6 *(landed: 29f `api:approvals`, 29g `api:custody`)* | D5.6 / D5.7 | intake record (sealed) at upload; signed custody transfers; the two-person rule for export, legal-hold release and case deletion |
| 7 *(29h landed: `api:export`; 29i: `api:siem`)* | D5.8 / D5.5 / D5.4 | signed export package and a re-verification job; RFC 3161 timestamps; the SIEM feed |

## Stage 1 — the audit, tamper-evident

```text
area DO (member:<id>, case:<id>, the registry)
   audit() ──INSERT──▶ local outbox (the old `audit` table, same transaction as the action)
                └─ship (end of request; cron)──▶ audit DO (audit:<area>)
                                                   line_n.hash = SHA-256(line_{n-1}.hash ‖ canonical(line_n))
                                                   daily: { area, date, seq, hash } ──▶ S3 audit-checkpoints/<area>/<date>.json
```

- **Why an outbox, not a direct call**: the line must exist if the action
  did — the outbox row commits with the action, in the area's own SQLite;
  shipping can fail and retry (the same pattern as the deletion outbox,
  O9). A line is deleted from the outbox only after the audit DO
  acknowledges it, idempotently (by the outbox id).
- **Canonical line**: length-prefixed fields (seq, at, actor, action,
  target, details, details_sealed) — one spelling, like every signed
  statement since commit 27.
- **Verification** (`GET …/audit/verify`, the area's audience): the audit
  DO recomputes the chain from its base; the Worker compares the chain at
  each checkpoint's sequence number with the checkpoint object in storage.
  An edit to any line, a deletion in the middle, a reordering — each breaks
  the chain at that line or disagrees with a checkpoint.
- **What it does not stop**: someone with the database AND the bucket can
  rewrite both consistently — which is why the checkpoints get Object Lock
  (stage 3) and, for evidence cases, an external timestamp (stage 7).
  Truncating the tail after the last checkpoint is visible only as "the
  last day is missing" — checkpoints are daily, and the SIEM feed (stage 7)
  is the copy that leaves the deployment.
- **Retention**: 7 years. Pruning older lines moves the chain's BASE
  (the hash of the last pruned line is kept), so the remaining chain still
  verifies.

### Stage 1 as built

- `worker/src/audit.rs` — `GoraniAuditDO`, the `canonical`/`link` pair (a
  Rust unit test; `api:audit` recomputes the chain in JavaScript from the
  API's lines, so the spelling is pinned across languages), checkpoints,
  verification, the 7-year prune. `s3::list` reads the bucket's own word on
  which checkpoints exist.
- The outbox: `member.rs` and `family.rs` ship after every request (the
  area's name is remembered from the Worker's `x-gorani-member`, since not
  every caller sends it — a device token's routes, the cron's knock); a
  read lists what is still pending first, marked `"pending": true`.
- The housekeeping knob `auditKeep` is gone (ignored): the area database no
  longer prunes its audit — it would delete lines before they were chained.
- `GET …/audit/verify` for each area's audit audience; the registry's for
  leads and auditors. Statuses per checkpoint: `ok`, `mismatch` (the chain
  and the bucket disagree), `missing` (the bucket names lines the chain no
  longer has), `pruned` (older than the retention).

## Stage 2 — retention by kind, as built

- The case's kind travels into its own store when it is opened
  (`routes.rs › case_open` writes `{ case, kind }` into the case store's
  settings); no route rewrites a case's settings afterwards, so the kind is
  fixed for the case's life.
- **Evidence** (`files_store.rs › evidence_refusal`): a file or folder is
  never trashed — 409 — so the trash purge has nothing to purge; the
  version retention skips the store entirely. Files still gain versions,
  are renamed and moved, and the audit records each.
- **Working** (members' own areas and working cases): `housekeeping`'s
  version retention prunes versions older than the window (deployment
  default 365 days; `versionDays` only under `GORANI_DEV`) that are not a
  file's current version — objects into the deletion outbox first, then the
  rows (the O10 order).
- What stage 3 adds underneath: the evidence OBJECTS become write-once in
  the bucket itself, so the rule holds even against a credential that
  bypasses the Worker.

## Stage 3 — write-once evidence (D6), the design

```text
evidence version recorded (upload, version, restore)
   └─ the store's lock pass ── PUT <object>?retention (COMPLIANCE, created + EVIDENCE_RETAIN_DAYS)
                                  ok  → file_versions.locked_until = that date
                                  err → stays NULL; the next request / the nightly pass retries
```

- **Why after the write, not with it**: S3 can take the lock headers on the
  PUT itself, but a multipart upload with Object Lock then needs a checksum
  on every part and in the completion — a second upload protocol. One
  `PutObjectRetention` after the object exists works for both paths; the
  window between the write and the lock is one request, and a version
  whose lock has not landed yet is visible (`locked_until` NULL) and
  retried until it does.
- **COMPLIANCE, not GOVERNANCE**: nobody — no Worker credential, no bucket
  owner, no root — shortens or removes a COMPLIANCE retention before it
  ends. That is the point (D6), and the reason it is opt-in:
  `OBJECT_LOCK = "on"` only for a bucket created with Object Lock enabled.
  Evidence opened while it is off is locked the moment it is turned on (the
  pass locks every version still NULL).
- **Content-MD5**: S3 and MinIO demand an integrity checksum on a retention
  write. gorani computes MD5 for exactly that header (crates/s3, with the
  RFC 1321 vectors) — an integrity check S3 asks for, never a security
  primitive.
- **R2** has no per-object retention through the Workers binding; its
  bucket-lock rules (prefix `cases/`, age-based) are the equivalent, set
  on the bucket (docs/PRODUCTION.md). The pass records `bucket-rule` for
  such versions instead of retrying forever.
- **Audit checkpoints** (stage 1) get the same retention, 7 years, when
  `OBJECT_LOCK` is on.
- **What a versioned bucket really does**: a DELETE without a version id
  adds a delete marker — the locked version stays, recoverable, and an
  overwrite adds a new version above it. The test stub models the part
  that matters to gorani: a locked object cannot be deleted.

### Stage 3 as built

- `crates/s3`: `retention_xml` and `md5` (RFC 1321 vectors; the constant
  table written out, not computed from `sin` — a platform's libm may round
  differently). `worker/src/s3.rs › put_retention` (Content-MD5, unsigned;
  R2 → `bucket-rule`).
- `member.rs › lock_pass`: after every request to an evidence store, and in
  the nightly pass (which fails loudly — 503 — while any lock is failing),
  every version with `locked_until` NULL is locked until its creation +
  `EVIDENCE_RETAIN_DAYS` (default 2557, seven years).
- `audit.rs › checkpoint_area` locks each checkpoint for the audit's 7
  years.
- Opt-in: `OBJECT_LOCK = "on"` (wrangler.jsonc vars) — docs/PRODUCTION.md
  says how to create the bucket so that it can be.
- `tests/lib/s3stub.mjs` speaks `?retention` (checks the Content-MD5, never
  shortens a COMPLIANCE date, refuses DELETE of a locked key) and fault
  rules can match a query (`retention`), so a suite can fail the lock and
  not the upload.

## Stage 4 — the uploader signs what they uploaded (D5.1), the design

```text
uploader's browser:  h = SHA-256(plaintext)        (before sealing — what the evidence IS)
                     s = sign(identity key, "gorani-content-hash-v1" ‖ area ‖ file ‖ version ‖ h ‖ size)
                     record = { sha256: h, size, signer, signature: s }
                     sealed into the place file.hash(area, file, version)   (GV04 — the server cannot read it)
server:              stores it beside the version (file_versions.hash_sealed); an evidence
                     upload WITHOUT one is refused
any reader:          opens the record in its place, verifies the signature against an
                     identity they trust (stage 4 of CASES.md), recomputes SHA-256 of what
                     they decrypted, and compares
```

- **Why sealed, not readable**: a plaintext hash is a fingerprint of the
  content — with it, the server could confirm "this case holds the file
  with hash X" (a known document, a known sample) without the key.
  Zero-trust means the server learns nothing it could not learn from
  ciphertext lengths. An investigator who needs to look a hash up (a
  malware sample in a reputation service) reads it from their own client.
- **Why signed by a person, not the server**: the claim worth having in a
  review is "Bo uploaded exactly these bytes" — only Bo's key can make it.
  The record names the signer; it rides in exports (stage 7) for anyone
  with the case key to verify independently.
- **Where it is required**: evidence cases (the Worker refuses an upload or
  a version without it). Elsewhere it is sent when the client can sign and
  verified when present.

### Stage 4 as built

- `web/src/vault/content-hash.ts` — `signContentHash` (the uploader:
  statement `gorani-content-hash-v1 ‖ area ‖ file ‖ version ‖ SHA-256 ‖
  size`, signed with the identity key, the record sealed into
  `file.hash(area, file, version)`), `checkContentHash` (the reader: open
  in this version's place, then the signer's trust, then the key id, then
  the signature, then the bytes) and `sha256Stream` (hash-wasm, because a
  chunked download never holds its plaintext whole).
- What a check reports, and why each is separate: `verified`; `unsigned`
  (no record); `invalid` (the record does not open here — moved — or its
  signature fails: someone holding the case key re-sealed it); `untrusted`
  (a signer this reader never verified, or a key that is not the signer's
  current identity — re-enrolled since); `mismatch` (a trusted signer
  vouched for OTHER bytes). Only a trusted signer can produce a mismatch.
- The Worker (`files_store.rs › hash_refusal`): the form field `hash` on
  every upload path (whole, multipart completion, new version); GV04 text
  or a 400; required in an evidence store, checked before the first write
  (the Worker then deletes the object it already put). Stored in
  `file_versions.hash_sealed` (migration v12); handed back with the key
  (`files/keys`) and with the bytes (`x-gorani-hash`, any version);
  walked by a rotation (kind `hash`) and carried by backups and restores.
- The web app: `model.ts` signs every upload while the member's identity
  is open (the shell passes it in when the team context opens), checks the
  record on every download (the toast says the result), offers "Verify
  signature" in both explorers, and refuses to COPY a file whose own check
  fails — the copier's fresh signature would launder altered bytes.
- Not yet: the sync client (`clients/core`) works in the member's own
  area only, where the hash is optional; when it gains cases it must sign
  too. A re-enrolled member's earlier signatures read as `untrusted` until
  the signed export (stage 7) carries signers' past keys.

## Stage 5 — malware samples (D8), the design

```text
upload as a sample:  sealed type = "application/x-gorani-sample; original=<mime>"   (GV04, per version)
                     form field sample=1 → files.sample = 1                          (readable: the server enforces)
mark as a sample:    PATCH files/<id> { sample: true, types: { <n>: <sealed>, … } } — one way, every version
any reader:          sample = the flag OR the sealed type says so
                     the viewer, previews, thumbnails and the media worker refuse it;
                     a download is <name>.zip, ZipCrypto under the password "infected"
```

- **Two marks, for two jobs.** The readable flag lets the SERVER enforce
  what it can: a sample is never shared by link (409 — D11's partners get
  the case instead), the flag shows in listings, the change is audited.
  The sealed type lets the CLIENT refuse to render even when the server
  lies: a server that clears the flag cannot clear the type (GV04 — it
  cannot seal into the store), and a server that SETS the flag on a normal
  file only makes the client more careful. The client treats a file as a
  sample if either says so — the safe direction is the only one a server
  can push.
- **One way.** A sample never becomes a normal file again (`sample: false`
  is refused): to "unmark", someone uploads a new file, on the record.
  Marking re-seals every version's type in the same request — the DO
  refuses a mark that leaves a version unmarked.
- **Never rendered, anywhere in this app.** The viewer shows a refusal
  panel instead of a mode; `preview` and `mediaHandle` return nothing
  (no bytes decrypted for rendering); audio tags are not parsed at upload
  (a parser is an attack surface too); a COPY of a sample is a sample.
- **Downloads zipped with "infected".** The industry convention
  (MalwareBazaar, VirusShare, vendor exchanges): desktop antivirus would
  otherwise quarantine the sample mid-investigation, or a double-click
  would run it. ZipCrypto (traditional PKWARE encryption), stored, UTF-8
  names — the one every unzip tool and Windows Explorer opens. It is NOT
  confidentiality (ZipCrypto is broken, and the password is public); the
  sample's confidentiality is the vault's job, which ends at the analyst's
  machine. Up to 4 GiB (no ZIP64 — refused above, said plainly). The signed
  content hash (stage 4) is checked before the zip is made, and the
  plaintext's SHA-256 is in the toast, for the reputation lookup.
- **The sync client** (`gorani-sync pull`) refuses to write a sample to
  disk raw.

### Stage 5 as built

- `web/src/vault/samples.ts` — the mark (`sampleType`, `isSampleType`,
  `originalType`) and `zipEncrypted`: CRC-32, ZipCrypto (keys advance on
  the plaintext byte; the 12-byte header ends with the CRC's high byte, the
  wrong-password check), stored, UTF-8 names. `unit:explorer` opens what it
  writes with Python's `zipfile` — an independent reader — and checks a
  wrong password is refused.
- The Worker (`files_store.rs`): `files.sample` (migration v13), set by the
  upload form field `sample=1`; in listings, `files/keys` and file rows;
  `share_create` refuses a sample (409); `file_mark_sample` — one way,
  every version's type re-sealed in the same request, validated whole
  before anything is written; audited as `file.upload.sample` /
  `file.sample`. `files/sealed?kind=version&file=<id>` lists one file's
  versions (the mark's walk).
- The model (`model.ts › renderPolicy`): `normal`, `sample` (the flag OR
  the sealed type), or `unverified` (a type that is missing or does not
  open in its place — refused like a sample, because garbling the sealed
  mark is the one way a server could try to hide it). Only `normal` is
  previewed, played (`mediaHandle`) or opened in the viewer, which shows a
  refusal panel instead (`mode.ts › "refused"`). Downloads of anything not
  `normal` are `<name>.zip` under "infected", the toast carries SHA-256 and
  the signature check; uploads as samples skip the audio-tag parser; a copy
  of a sample is a sample.
- The explorers: "Upload malware samples…" (Windows skin), "Mark as
  malware sample…" in both context menus (a confirm says it cannot be
  undone), "Share…" disabled for samples.
- `gorani-sync pull` refuses a sample (either mark) and writes nothing
  (`api:client-live` › 4b).
- Not yet: ZIP64 (samples over 4 GiB are refused, not zipped); the desktop
  shells (docs/DESKTOP.md) must route their downloads through the same zip.

## Stage 6 — intake, custody transfers, the two-person rule (D5.6 / D5.7), the design

Two commits: **29f** the two-person rule and the legal hold it releases;
**29g** the intake record and signed custody transfers.

### 29f — the two-person rule, and a legal hold

```text
requester (a manager of the case, or a lead)
   POST /cases/<id>/approvals { id, action, signature }      s1 = sign(stmt("gorani-approval-v1", id, action, case, requester))
second lead (not the requester)
   POST /cases/<id>/approvals/<aid>/approve { signature }    s2 = sign(stmt("gorani-approve-v1", id, action, case, requester, approver))
                                                              → the action runs in the same request, once
```

- **Which actions**: `case.close` for an EVIDENCE case (a working case
  still closes with one manager), `hold.release`, and — stage 7 —
  `case.export`. A direct `POST …/close` on an evidence case answers 409
  and names the approval route.
- **What the server enforces** (policy, like read-only grants): the
  requester may request; the approver is a lead, active, and not the
  requester; a request is approved once, executes once, and expires after
  7 days; the requester may cancel. **What the signatures add**: who asked
  and who agreed, verifiable by any client against its own trust — the
  registry stores the signatures and, as everywhere since commit 27,
  verifies none of them.
- **Legal hold** (`POST /cases/<id>/hold`, a manager or a lead): placing a
  hold is ONE person — adding protection never waits for a second; lifting
  it is a `hold.release` approval. While a case is held its store refuses
  trash (409), its housekeeping prunes no versions and purges nothing, and
  the nightly pass does the same. The Worker tells the case store (an
  internal call, like the kind at opening); the registry is the record.

#### 29f as built

- `worker/src/family/approvals.rs` — the registry's `approvals` table
  (migration v6, with `cases.hold_at/hold_by`); request, list, approve,
  withdraw; `case_hold`. The approve call re-checks that the action is
  still possible, runs it, records who agreed, and audits both
  (`approval.approve`, then the action itself naming the approval).
- `web/src/vault/approvals.ts` — `requestApproval` (the id chosen before
  signing), `approveRequest` (checks the REQUEST's signature against the
  approver's trust before signing its own), `verifyApproval` (both
  signatures, two different people).
- The hold in the case store (`member.rs › is_held, sync_hold`): told by
  the Worker after the registry records a change (`routes.rs ›
  tell_case_hold`), and again by every nightly pass, which sends each case
  store the registry's word (`case-holds`) before it purges. A held store
  refuses trash (`files_store.rs › evidence_refusal`) and its housekeeping
  gates every purge query with `AND 0` — it matches nothing.
- The Team panel: "Place a legal hold", "Ask to lift the hold", "Ask to
  close" (evidence), and each pending request with its signature's verdict
  as THIS member's client sees it; "Agree" only for a different lead, only
  when the request verifies.
- Not yet: approvals expire after 7 days by the clock; `case.export` joins
  in stage 7.

### 29g — intake and custody transfers

```text
evidence upload (version 1):  intake = { source, collector, method, collectedAt, notes }
                              signed: stmt("gorani-intake-v1", area, file, source, collector, method, collectedAt, notes)
                              sealed into file.intake(area, file)     — required on evidence, like the hash
custody, per evidence file:   custodian = the uploader, then each accepted transfer's receiver
   offer   (the custodian)    stmt("gorani-custody-offer-v1", area, file, seq, from, to, SHA-256(reason))
   accept  (the receiver)     stmt("gorani-custody-accept-v1", area, file, seq, from, to)
```

- **The intake record** says where the item came from — the half of
  provenance the content hash (stage 4) cannot: a disk imaged from which
  host, by whom, with which tool, when. Sealed (it names hosts and
  people), signed by the uploader, in its own place per file (it describes
  the acquisition, not a version).
- **Custody** is a chain per evidence file, kept in the case's store: one
  pending offer at a time; only the current custodian offers, only the
  named receiver (holding a grant on the case) accepts, both sign. The
  reason is sealed (the case key); its digest is in the offer statement.
  The chain verifies on any client: every link's two signatures, every
  `from` the previous `to`.
- **What it does not do**: custody here is a RECORD of responsibility, not
  an access control — everyone granted on the case still reads the file.
  That is what the read log (O14) and the grants are for.

#### 29g as built

- `web/src/vault/intake.ts` — `signIntake` (source, collector and method
  required; the signed statement lists every field) and `checkIntake`
  (open in this file's place, then the signer's trust and key, then the
  signature). The Worker takes the form field `intake` on new files (whole
  and multipart), refuses one that is not sealed, and requires it in an
  evidence store (`files.intake_sealed`, migration v14); `files/keys`
  hands it back. Versions carry hashes, not intake: an item is acquired
  once.
- `worker/src/custody.rs` + `web/src/vault/custody.ts` — the chain per
  evidence file (`custody` table): offer (the custodian, link number
  `seq` signed, no gaps, one open offer), accept (only the person named;
  a read-only grantee too — the case route asks only Read), withdraw (the
  offerer). `verifyChain` walks it: both signatures per link, every `from`
  the previous `to`, the reason opening in its place with the digest the
  offer signed; withdrawn links are skipped.
- Rotation walks both (kinds `intake`, `custody`); backups carry the
  intake in each file entry and every custody link as its own entry; a
  restore fills custody links into gaps only.
- The web app: an intake dialog once per evidence upload batch
  (`ui/files/intake-dialog.ts`), signed per file; a copy inside an
  evidence case gets an automatic intake naming its source; "Custody…" in
  both explorers shows the chain as this client verified it and offers
  the one action open to the member (accept, or hand over).

## Stage 7 — export, re-verification, the SIEM, trusted time (D5.8 / D5.4 / D5.5), the design

Three commits: **29h** the signed export package and re-verification;
**29i** the SIEM feed; **29j** RFC 3161 timestamps.

### 29h — the signed export, and re-verifying what is kept

```text
two leads   case.export approval (stage 6's rule: one asks, a second agrees)
exporter    POST /cases/<id>/export { approval }  → the registry consumes it, once; audited
            the exporter's browser: every file, every version — decrypted, re-hashed, each
            signature, intake record and custody chain checked; the whole audit trail
            manifest.json = { case, approval (both signatures), files, versions, hashes,
                              records, custody, audit lines, the signers' public keys }
            manifest.sig  = sign(stmt("gorani-export-v1", case, export id, SHA-256(manifest.json)))
            package.zip   = manifest.json, manifest.sig, evidence/<file>/v<n>/<name>, VERIFY.txt
anyone      tools/verify-export.mjs package.zip — Node only, no gorani code, no network
```

- **Plaintext, on purpose**: a package is for someone OUTSIDE the vault
  (counsel, an insurer, a court). It carries the evidence decrypted, with
  every hash a recipient can recompute with `sha256sum`, and every
  signature verifiable with the public keys it names. Samples stay zipped
  under "infected" inside it (stage 5).
- **Why the export needs two people**: an export is the moment evidence
  leaves the system's controls. The server cannot stop a grantee from
  downloading files one by one — but only an approved, consumed export
  produces a package bearing two leads' signatures.
- **What the recipient decides**: whether the exporter's key is who it
  claims — the manifest names the fingerprint, compared out of band. The
  verifier reports every check; it trusts nothing it was not shown.
- **Re-verification** (D5.8's second half): "Re-verify the case" re-hashes
  every stored version against its signed hash, client-side, and records
  the result in the case's audit (`case.reverify`, counts only). The
  nightly pass flags evidence cases whose last re-verification is older
  than `REVERIFY_DAYS` (default 30) — the server cannot re-hash (it has no
  key), but it can notice nobody did.

#### 29h as built

- The registry: `case.export` joins the two-person actions (approved like
  the others; nothing runs at approval); `POST /cases/<id>/export
  { approval }` spends it — once, within a week, run by one of the two
  people who agreed — and audits `case.export` (migration v7:
  `approvals.consumed_at/by`).
- `web/src/vault/export.ts › buildExport`: walks every file and version
  (decrypt, SHA-256, `checkContentHash`), every intake record and custody
  chain, the whole audit trail (`GET …/audit/lines?after=` — new: oldest
  first, a page at a time, with the chain's base), the identities named;
  writes `manifest.json` (problems recorded, never hidden), signs it,
  zips it with the evidence (`web/src/vault/zip.ts` — stored, now
  multi-entry; samples nested under "infected") and `VERIFY.txt`.
- `tools/verify-export.mjs` — a second implementation in plain Node: its
  own zip reader and ZipCrypto, its own statement encoding, ECDSA through
  `node:crypto`; reports every check and exits non-zero on any failure.
- `reverifyCase` walks the same way and `POST …/reverify { checked,
  failed }`; the store keeps the last run (`vault › reverified`) and the
  audit line; `GET …/reverify` says whether one is overdue
  (`REVERIFY_DAYS`, default 30), and the nightly pass logs every overdue
  evidence store.
- The Team panel: "Ask to export", "Export now" on an approved export for
  the two people, "Re-verify now" with the last run's result per evidence
  case.
- Not yet: a package is built in memory (D12's large-file work will
  stream it); ZIP64 (4 GiB) as everywhere.

### 29i — the SIEM feed

- Every line the audit DOs chain (stage 1) is also queued for the SIEM
  when `SIEM_URL` is set; the queue drains after each append and in the
  nightly pass, oldest first, with the chain's own hash on every event (a
  SIEM can check continuity), retried until acknowledged.
- Formats: `ndjson` (one JSON object per line — Elastic, Sentinel's data
  collection endpoints, any log shipper) and `splunk-hec` (`{ "event": … }`
  per line, `Authorization: Splunk <token>`). `SIEM_TOKEN` is a secret.
- Sealed details never leave (they are sealed); readable fields do —
  the same fields the audit view shows.

#### 29i as built

- The trail is the queue. Each audit DO keeps a cursor (`meta ›
  siem_cursor`, never below the chain's base) naming the last line the
  collector acknowledged; nothing is copied into a second table that could
  disagree with the first.
- Delivery is the DO's own **alarm**: an append arms it (1 s) unless one is
  set, so a burst of lines goes in one batch and a failing collector's
  backoff (1 s doubling to an hour, `meta › siem_backoff`) is never cut
  short by new lines. Each run sends up to 20 batches of 500 lines, oldest
  first, and re-arms at once while lines remain. The cursor moves only on
  a 2xx, and only forward — the alarm and the nightly pass may both be
  sending (a DO takes other events while it awaits a fetch), so a line can
  arrive twice, never zero times. The `gorani.seq` on every event is how
  the SIEM drops the second.
- The nightly pass (`cron.rs`) also drains every area and the registry,
  and reports an area whose lines are still undelivered as a failure, like
  a lock or a delete.
- An event: `@timestamp`, `gorani { area, seq, hash }`, `actor`, `action`,
  `target`, `details`, and `sealed` (true when the line had sealed
  details — their value never leaves). `splunk-hec` wraps each in `{ time,
  host: "gorani", source: "gorani:<area>", sourcetype: "gorani:audit",
  event }` with `Authorization: Splunk <token>`; `ndjson` sends
  `Authorization: Bearer <token>` when a token is set.
- The trail's area is learned from the append (`ship` names it) or from
  the nightly pass, so trails whose lines predate 29i are delivered with
  their names too — from the base of the chain, the whole retained trail.
- Not yet: no per-area opt-out, and no SIEM-side checker for the hash
  chain (a SIEM rule over `gorani.seq` gaps is the cheap version; the
  checkpoints in the bucket remain the proof).

### 29j — RFC 3161 timestamps

- **What is stamped**: SHA-256 of each evidence version's SEALED hash
  record and of each daily audit checkpoint — never the content hash
  itself (a timestamp authority would learn the evidence's fingerprint).
  The stamp proves the signed record existed at that time; the record
  proves what it was.
- The Worker asks `TSA_URL` (an RFC 3161 TimeStampReq over HTTP) after the
  version is recorded, like the lock pass: retried until it lands, the
  token stored beside the version.
- Verification is the client's and the export's: parse the token
  (CMS SignedData), check the message imprint, the TSA's signature, and
  its certificate against a pinned TSA certificate.
