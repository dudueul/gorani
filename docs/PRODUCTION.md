# Production: deploying gorani (MinIO + Cloudflare)

> Copyright 2026- Seongwoo Hong. All rights reserved.

## 1. Object storage (MinIO — or R2, the priority path)

**Storage priority.** When `wrangler.jsonc` binds an R2 bucket (uncomment
the `r2_buckets` block), every object operation uses the binding: an
in-process call from the Worker into R2 — no SigV4 signing, no HTTP hop,
no egress fees. Any S3-compatible endpoint keeps working through the
signed adapter whenever the binding is absent; the choice is per
deployment, made at boot. In dev, `tests/api/r2.test.mjs` runs the
generated twin config (`wrangler.r2.jsonc`) against workerd's local R2
simulator so both branches stay tested.

1. Run MinIO on your NAS, fronted by TLS (Caddy/nginx or MinIO's own cert
   manager): `https://minio.example.com`. It must be publicly reachable —
   the Worker signs requests to it over HTTPS.
2. Create a bucket `gorani`, policy **private** (no anonymous access).
3. Create a dedicated access key scoped to that bucket — and to the
   object actions the worker uses (Get/Put/DeleteObject,
   AbortMultipartUpload, ListBucket); never bucket-admin rights.
4. Add a lifecycle rule: abort incomplete multipart uploads after 2 days
   (the worker's housekeeping sweeps its own, this catches the rest).
5. Prove it: `GORANI_LIVE_S3=1 S3_ENDPOINT=… S3_REGION=… S3_BUCKET=…
   S3_ACCESS_KEY_ID=… S3_SECRET_KEY=… node tests/api/s3-live.test.mjs`
   against a dedicated test bucket — it checks that anonymous reads are
   refused, and that a signed list works, before it writes anything. Add
   `GORANI_LIVE_S3_LOCK=1` for a bucket with Object Lock (below): it locks
   ONE small object for ONE day and asks the server to delete it. More:
   docs/SECURITY-REVIEW.md › Operational controls.

`wrangler.jsonc` vars: `S3_ENDPOINT`, `S3_REGION` (any string MinIO
accepts, e.g. `us-east-1`), `S3_BUCKET`. The endpoint must be `https://`
— the worker refuses anything else outside `wrangler dev` (the signatures
use UNSIGNED-PAYLOAD, so body integrity is TLS's job); a bare host
(`s3.example.com`, as provider consoles print it) means `https://`.
Secrets (`wrangler secret put`): `S3_ACCESS_KEY_ID`, `S3_SECRET_KEY`
(`S3_SECRET_ACCESS_KEY`, the AWS spelling, is read too). The worker signs
SigV4 with path-style addressing (`https://endpoint/bucket/key`) —
verified against golden vectors in `crates/s3`.

### A hosted S3 provider: IDrive e2

Nothing in gorani is provider-specific; these are the points where e2's
console differs from the MinIO steps above.

- **Endpoint and region**: e2 gives each region its own host, shown on the
  bucket's page — e.g. `s3.eu-central-1.idrivee2.com` with region
  `eu-central-1`. Use the region the host names; SigV4 signs it into the
  scope, and a wrong one is refused as a bad signature, not a bad region.
- **The bucket**: create it with **Object Lock enabled** if it will hold
  evidence (e2 offers it only at creation; it turns versioning on), and
  set **no default retention** — gorani locks each evidence object itself,
  and a bucket default would lock working files and the purge with them.
  Leave it private; gorani uses no ACLs (e2 does not support them).
- **The key**: an access key limited to that one bucket. The worker needs
  object read/write/delete, multipart and list; nothing at bucket level.
- **Lifecycle**: the 2-day rule for incomplete multipart uploads (step 4),
  and — because an Object Lock bucket is versioned — a rule expiring
  NONCURRENT versions after a few days, where e2 offers one: a delete in a
  versioned bucket only hides the object (a delete marker), so purged
  working files would otherwise stay billed. Locked versions are immune
  to such a rule until their retention ends; that is the point.
- **Prove it** with step 5, then once with `GORANI_LIVE_S3_LOCK=1`
  (it reads the bucket's Object Lock and versioning settings first, and
  writes nothing if they are not what gorani expects).
- **What was probed** (2026-10-14, bucket `gorani-dev`, eu-central-1):
  anonymous list, read and write all answered with a 302 to e2's homepage
  (a refusal — no S3 answer — but not the 403 AWS gives; `api:s3-live`
  accepts either); path-style SigV4 accepted; a bucket created with Object Lock reports it
  enabled, versioning on, no default retention; the Worker's exact
  `PutObjectRetention` (COMPLIANCE, Content-MD5) answers **204** (AWS: 200
  — the Worker accepts both); the retention reads back as COMPLIANCE; both
  shortening it and deleting the locked version are refused with **400
  InvalidRequest** (AWS: 403), and the version survives. Not yet run from a
  deployed Worker: the full `api:s3-live` against e2, which the sandbox
  this was written in could not route the Worker to.
- **Cost shape**: e2 bills storage only, with egress included up to a
  multiple of what is stored (check the current terms) — the edge cache
  (below) matters less for the bill here than for latency.

Part-size rule (both backends): a multipart upload's parts are GC01
frames, and every part but the last must be ≥ 5 MiB. The chunk the client
picks is the part size; the init route refuses smaller plans with an
honest 400 (before a single part is uploaded). The clients' default chunk
is 8 MiB.

### Object caching (the Workers Cache API)

Every blob read goes through the edge cache (`worker/src/cache.rs`), keyed
by **storage span** — never by member or URL. Ciphertext is
recipient-independent, so one entry serves the whole family and every
share link; object keys are version-unique, so entries are immutable: a
month of TTL needs no invalidation, and deleted content's stale entries
open to nothing (crypto-shredding destroyed the key).

| Read | Behavior |
|---|---|
| Whole GET, object ≤ `CACHE_MAX_OBJECT_MB` (256 MB) | One entry; any later Range is sliced **by the platform** from the cached body |
| Range on a GC01 object, frame-aligned (the media worker's shape) | Frame-span entry (`key?frames=a-b`) — deterministic on replays, and exactly what future HLS segments would ask |
| Anything else (oversized objects, stray ranges, writes) | Bypass; `x-gorani-cache: bypass` says so |

Billing arithmetic per backend: **R2** saves Class B read operations (the
free tier is 10 M/month); **external S3** saves real egress fees; **MinIO**
saves NAS bandwidth and latency. Responses carry `x-gorani-cache:
hit|miss|bypass` for observability. Two physical notes: the cache is
per-POP (family members on different continents warm their own copies),
and bodies stream through `cache.put` — the worker never buffers a blob,
so the size gate protects the plan's cacheable-object limit, not worker
memory.

## 2. Cloudflare Access (the perimeter)

1. Enable Access on the Worker (one-click modal or manual app).
2. `wrangler secret put POLICY_AUD` and `TEAM_DOMAIN` from the modal — the
   Worker verifies every request's JWT (issuer, audience, expiry, signature
   against the team JWKS) and **fails closed** when they are missing.
3. People: an Allow policy for the family (One-time PIN / GitHub / your
   IdP). Each member's Access email is registered on their member row
   (`POST /api/v1/family/members` with `emails`).
4. **Bypass for the public share surface**: the Access application needs an
   exception for `/s/*` (and `/s.html`) — the share pages authenticate with
   the link's fragment secret, not Access. Same for `/api/healthz`.
5. Desktop clients sign in as their **member** (commit 33a): install
   `cloudflared` on the computer and set the profile's `accessTokenCmd` to
   `cloudflared access token -app=https://<your gorani host>` (or export
   `GORANI_ACCESS_TOKEN`). The client sends the member's short-lived token
   as `cf-access-token`; Access validates it and the Worker receives the
   member's JWT — email included. *(Commit 33a also fixed the Worker's
   Access path itself, which panicked on every token — `std::time` on
   wasm; see docs/DESKTOP.md › 33a. Until commit 33a this step said to
   give each computer a service token: Access accepts one, but its JWT has
   no email, so the Worker — which takes identity from the email — refused
   every desktop request. A service token identifies a machine, not a
   member.)*
6. **Where each computer keeps its device secret** (commit 34): the secret
   that opens the server's copy of the root lives in the TPM and/or the
   user's login keyring, never in the profile file. On Linux install
   `tpm2-tools` and `libsecret-tools` (`secret-tool`), and add each user
   to the `tss` group so they may use `/dev/tpmrm0`; `gorani-sync setup`
   then picks `tpm+keyring` by itself. A computer with neither is refused
   unless the person types `--protect file` (dev and CI) — and an already
   enrolled computer moves to the TPM with `gorani-sync protect`. For
   evidence workstations add `--tpm-pin --tpm-pcrs 7` (commit 36): the
   TPM part then needs a PIN — guessing it locks the chip out — and the
   machine's Secure Boot state; after a firmware update that changes that
   state, `gorani-sync protect --secret <recovery code> --tpm-pcrs 7`
   seals it again.
   `gorani-sync devices` shows what protects each computer (the client's
   word, recorded by the server — not attested), and `gorani-sync revoke
   --device <id>` deletes a lost one's copy from any other — as does the
   web app's Team › Devices tab (commit 35), which flags a computer whose
   secret sits in a file.

7. **Collectors** (commit 37, docs/COLLECTORS.md) — the one place a
   service token IS the identity. For each machine that drops evidence
   (an acquisition server, an EDR export):
   - In Zero Trust › Access › Service Auth, create a **service token**
     for it. Its Client ID is what the JWT carries as `common_name`; the
     Client Secret is shown once. Give the Access application a policy
     with the action **Service Auth** that includes that token (one token
     per machine; never share one between collectors).
   - On the machine: `gorani-sync collector init --server https://<host>
     --id <id> --pins <lead>:<fingerprint>,… --access-id <Client ID>`,
     with the Client Secret in `GORANI_COLLECTOR_SECRET` or typed when
     asked (never a flag). Pins are the leads whose fingerprints you
     compared at the machine; it believes a case's inbox key only through
     them. It prints `{ id, publicKey, keyId, fingerprint }`.
   - In the web app, Team › Collectors: one lead registers it (pasting
     that JSON and the Client ID), a SECOND lead compares the fingerprint
     with the machine's screen and approves. Then a case's manager makes
     the case's inbox key (Team › Cases) and grants the collector the
     case. `gorani-sync collector whoami` on the machine checks it all
     end to end.
   - The Worker lets a collector reach `/api/v1/collect/…` only, and asks
     the registry on every request — revoking it in Team › Collectors (or
     deleting the service token in Access) stops it at once.
   - A collector holds no case key: it cannot read what it, or anyone,
     put in a case. What a compromised one leaks is what it collects from
     then on; what it can forge is items in an inbox — which members'
     clients name as unverified unless the collector's signature holds,
     and which a person accepts or rejects.

## 3. Deploy

```sh
npm install && npm --prefix web install
npm run deploy          # builds web/ + the Rust worker (worker-build)
```

First-run bootstrap (commit 25, O18): set a one-time secret first —

```sh
openssl rand -base64 32 | npx wrangler secret put BOOTSTRAP_TOKEN
```

— then sign in through Access and `POST /api/v1/family/members` with your
parent member and the header `x-gorani-bootstrap: <that token>`. Without the
secret a production deployment refuses to bootstrap at all; without the
header nobody becomes the first member (the race the token closes: whoever
got through Access first used to become a parent). The first member must
be a parent; after it exists the token is meaningless (delete the secret
if you like). Then `PUT /api/v1/family/master` with the generated master
public half, and create each vault from the UI (commit ⑨'s setup screen).

**Rate limits** (O13) are in `wrangler.jsonc › ratelimits` (60/min per
caller + share link, 30/min per caller + device). They are per Cloudflare
location and approximate — add a WAF rate-limiting rule as the second,
edge-wide layer, e.g. `http.request.uri.path wildcard "/s/f/*"` → 120
requests / 1 minute per IP → block for 10 minutes; and the same for
`/api/v1/members/*/devices/*`.

**Share links on their own hostname** (O17, recommended for a SecOps
deployment): the recipient page runs a stranger's password through code
on the same origin as the vault. Give `/s/*` its own hostname (a second
Worker route, e.g. `share.example.com/s/*`, with no Access application in
front) and keep the vault's hostname behind Access with `/s/*` excluded
from the app's links — the page's CSP already forbids framing and inline
code, so the separation is about cookies and storage, not script.

Schema changes ride the deploy: each Durable Object migrates itself on its
next wake-up through an append-only ledger (`worker/src/schema.rs`). Add new
statements at the END of `MIGRATIONS`, never edit or reorder a shipped one.
A store whose migration fails answers every request with a 500 naming the
failed statement (it does not hang) — look for `member store schema:` in
the Worker's logs.

### Write-once evidence (commit 29c, D6)

Object Lock can only be enabled when a bucket is CREATED. For evidence:

- **MinIO**: `mc mb --with-lock alias/gorani` (a new bucket; versioning is
  enabled with it). Then set `OBJECT_LOCK = "on"` in `wrangler.jsonc`.
- **AWS S3**: create the bucket with "Object Lock" enabled (it enables
  versioning). No default retention — gorani sets each evidence object's
  retention itself, so working files keep their Trash and purge.
- **IDrive e2** (and other hosted S3): the same — Object Lock at creation,
  no default retention (see › A hosted S3 provider: IDrive e2).
- **R2**: no per-object retention through the Workers binding; add a
  bucket lock rule for the prefix `cases/` with the retention you need
  (it then applies to working cases too — a stricter default), and
  `audit-checkpoints/`.

With `OBJECT_LOCK = "on"`, every evidence version gets a **COMPLIANCE**
retention until its creation + `EVIDENCE_RETAIN_DAYS` (2557 by default):
nobody — not the Worker's credential, not the bucket owner, not root —
can delete it or shorten that date. Choose the number with your legal
counsel before turning it on; it cannot be taken back for objects already
locked. Evidence uploaded while it was off is locked on the next request to
its case. A lock that fails is retried; the nightly pass reports any still
failing (HTTP 503 from the member pass, logged as a cron failure).

A bucket with Object Lock is **versioned**. Two consequences: a purge of a
working file removes it from gorani's view and leaves a noncurrent version
behind (add a lifecycle rule that expires noncurrent versions — it cannot
touch a version still under retention); and a credential that skips the
Worker can still add a delete marker above an evidence object — the
locked version stays and can be restored, but the Worker answers 404 for
it until someone does. The lock protects versions, not the current
pointer; `tests/api/s3-live.test.mjs` with `GORANI_LIVE_S3_LOCK=1` proves
the version part against the real server.

**Re-verification** (commit 29h): a client re-hashes an evidence case's
files against their signatures ("Re-verify now" in Team › Cases); the
nightly pass logs every evidence case not re-verified for `REVERIFY_DAYS`
(a `wrangler.jsonc` var, default 30). **Exports** need a two-person
approval and are checked by the recipient with `tools/verify-export.mjs`
(Node only) — hand it to them with the package.

### The SIEM feed (commit 29i, D5.4)

Set `SIEM_URL` (and `SIEM_FORMAT`) in `wrangler.jsonc` and the token as a
secret — `wrangler secret put SIEM_TOKEN` — and every audit line is POSTed
there as it is chained:

- **Elastic / OpenSearch / a log shipper** (Vector, Fluent Bit, Logstash's
  `http` input): `SIEM_FORMAT = "ndjson"`, one event per line,
  `Authorization: Bearer <token>`.
- **Splunk**: `SIEM_FORMAT = "splunk-hec"`, `SIEM_URL =
  "https://<host>:8088/services/collector"`, a HEC token;
  sourcetype `gorani:audit`, source `gorani:<area>`.
- **Microsoft Sentinel**: a Logs Ingestion data collection endpoint needs
  an Entra token, not a static one — put a shipper in front (ndjson in,
  the DCR API out).

What arrives: `@timestamp`, `actor`, `action`, `target`, the readable
`details`, `sealed` (whether the line had sealed details — never their
value), and `gorani { area, seq, hash }`. Delivery is at least once:
dedupe on `(gorani.area, gorani.seq)`, and alert on a gap in `seq` — the
chain has none, so a gap means lines were lost on the way or dropped by
retention. A collector that is down loses nothing: each trail retries with
backoff (up to an hour), and the nightly pass logs every area still
behind (`<area>: SIEM: … not yet delivered`). The first deploy with
`SIEM_URL` set sends every trail from the start of its retained chain.

### Trusted timestamps (commit 29j, D5.5)

Set `TSA_URL` in `wrangler.jsonc` to an RFC 3161 authority's HTTP
endpoint — a commercial TSA (DigiCert, Sectigo, GlobalSign — some are free
for low volume, others want an account: `wrangler secret put
TSA_AUTHORIZATION` with the header value they give you), a national
qualified TSA if your evidence must meet eIDAS, or your own (`openssl ts`
behind a small HTTP server is what the test suite uses). The Worker must
be able to reach it. Each evidence version costs one request, each audit
trail one a night.

Then, once: a lead opens Team › People › Timestamp authority, presses
"Read the authority's certificate", **compares the certificate SHA-256
with the one the authority publishes on its own site**, and certifies.
Until a lead does, stamps are stored but every reader reports them
"uncertified". When the authority rotates its key, certify the new one
(keep the old certification — tokens it signed stay valid); if a key is
compromised, Withdraw it.

Evidence uploaded before `TSA_URL` was set (or before commit 29j) is
stamped when someone with write access re-verifies the case (Team ›
Cases › Re-verify now): the stamp then dates the signature as of that day.
The nightly pass logs `evidence version(s) … still without a trusted
timestamp` while a TSA is failing; the alarm keeps retrying (backoff up to
an hour). By hand, a token checks with OpenSSL: save it (base64 → DER) and
`openssl ts -verify -in token.der -token_in -digest <imprint> -CAfile
tsa.pem` — the imprint is SHA-256 of the version's `hashRecord.signature`
(base64-decoded) or of the checkpoint's bytes.

### Upgrading across commit 29 (the audit trails)

`wrangler.jsonc` gains the `AUDIT` Durable Object binding and migration
tag `v2` (`GoraniAuditDO`); a deploy applies both. Existing audit lines
ship from each area's outbox to its new trail on the area's next request
(or the nightly pass) — nothing is lost; the chain starts at the first
line shipped. From the first nightly pass on, the bucket holds
`audit-checkpoints/<members|cases|registry>/…/<date>.json`: put those
under Object Lock (docs/CUSTODY.md › stage 3) or at least a bucket policy
that denies `DeleteObject` and overwrites to the Worker's key — the
checkpoints are what makes a rewritten trail detectable, and only if the
same credential cannot rewrite both. Verify any trail with
`GET /api/v1/members/<id>/audit/verify` (or `/cases/<id>/…`,
`/family/audit/verify`).

## 4. Backups

> **Upgrading across commit 25:** backups written before it are GB1 and
> hold GV03 values, which a GV04 store refuses. Keep the old release (or a
> checkout of it) to restore those, and take a fresh backup right after
> upgrading — the new one is the one you will restore from.

1. In the app, generate the backup key pair and **download the key file** —
   the only copy of the private bundle; the server stores the public half.
2. `POST /api/v1/members/<id>/backup/run` writes `backups/<stamp>.gbak` —
   sealed twice over (the objects are already GV-sealed; the GB2 container
   wraps them under a key only your key file opens, and authenticates its
   own header — when it was made, which kind — so a copy cannot be
   relabelled at rest). The job streams into a multipart upload, so memory
   does not bound the backup — one container holds up to ~78 GiB. An object
   missing from storage is listed in the run's answer and counted in the
   manifest (`missing`); a nonzero count means investigate the bucket, not
   that the backup is fine. Runs are created on
   purpose — by the owner in the app — not silently by the server: the
   in-memory job is sized for on-demand runs, and a daily full copy is a
   storage-economics decision a family should make knowingly.
3. **The nightly pass** (`wrangler.jsonc › triggers › crons`, default
   03:17 UTC, worker/src/cron.rs) maintains both ends of retention for
   every member: the deployment-default housekeeping (trash, journal,
   audit, dead shares) and backup-manifest pruning (the newest 7 `.gbak`
   runs survive; older rows and their S3 objects go). The audit trail
   records each pass under the actor `cron`. The retention knobs
   (`trashDays`, `auditKeep`, …) are deployment defaults: the HTTP route
   honours them only on the dev server, so no member can shorten their own
   audit trail. Deletions go through an **outbox** (commit 25): an object
   leaves `pending_deletes` only when storage confirms it, so a failing
   bucket delays deletion instead of orphaning objects — and fails the
   scheduled event (look for `gorani cron:` errors). `GET
   /api/v1/members/<id>/storage/pending` shows what is waiting and why.
4. Keep the key file offline. Losing it loses the backups, not the vault.

## 5. Growth

`GET /api/v1/members/<id>/vault-stats` reports `dbSize` — the Durable
Object's SQLite size. Strategy: retention (built), the reserved
`GoraniFilesDO` split, sharding — see `docs/ARCHITECTURE.md › Growth`.

## 6. Known gaps

- Collectors (commit 37): a large drop does not resume (a stopped one is
  sent again as a new item); the store can withhold an inbox item, which
  only the collector's own log (`~/.gorani-collector.log`) shows; and the
  store verifies no signature, so a writer on the case could file an item
  their client would call unverified — under their own name, on the trail.

- Worker request caps: uploads are chunked — 8 MiB frames, growing to
  32 MiB for files over 156 GiB (docs/LARGE-FILES.md) — and each part is
  streamed through the Worker, never buffered. A part is at most one
  64 MiB frame, under every plan's request-body limit (100 MB on Free and
  Pro). A *restore* of very large backups is client-driven for the same
  reason.
- The backup job buffers one container in memory — right for family scale;
  multipart streaming is the documented next step.