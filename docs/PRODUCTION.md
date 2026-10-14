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
3. Create a dedicated access key scoped to that bucket.

`wrangler.jsonc` vars: `S3_ENDPOINT`, `S3_REGION` (any string MinIO
accepts, e.g. `us-east-1`), `S3_BUCKET`. Secrets (`wrangler secret put`):
`S3_ACCESS_KEY_ID`, `S3_SECRET_KEY`. The worker signs SigV4 with path-style
addressing (`https://endpoint/bucket/key`) — verified against golden
vectors in `crates/s3`.

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
5. Desktop clients (commit ⑬): give each computer an Access **service
   token** with a Service Auth policy — the client sends
   `CF-Access-Client-Id/Secret`; the Worker receives the resulting JWT.

## 3. Deploy

```sh
npm install && npm --prefix web install
npm run deploy          # builds web/ + the Rust worker (worker-build)
```

First-run bootstrap: sign in through Access, `POST /api/v1/family/members`
with your parent member (the first member is created by any authenticated
caller), `PUT /api/v1/family/master` with the generated master public half,
then create each vault from the UI (commit ⑨'s setup screen).

## 4. Backups

1. In the app, generate the backup key pair and **download the key file** —
   the only copy of the private bundle; the server stores the public half.
2. `POST /api/v1/members/<id>/backup/run` writes `backups/<stamp>.gbak` —
   sealed twice over (the objects are already GV-sealed; the GB1 container
   wraps them under a key only your key file opens). Runs are created on
   purpose — by the owner in the app — not silently by the server: the
   in-memory job is sized for on-demand runs, and a daily full copy is a
   storage-economics decision a family should make knowingly.
3. **The nightly pass** (`wrangler.jsonc › triggers › crons`, default
   03:17 UTC, worker/src/cron.rs) maintains both ends of retention for
   every member: the deployment-default housekeeping (trash, journal,
   audit, dead shares) and backup-manifest pruning (the newest 7 `.gbak`
   runs survive; older rows and their S3 objects go). The audit trail
   records each pass under the actor `cron`. 4. Keep the key file offline.
   Losing it loses the backups, not the vault.

## 5. Growth

`GET /api/v1/members/<id>/vault-stats` reports `dbSize` — the Durable
Object's SQLite size. Strategy: retention (built), the reserved
`GoraniFilesDO` split, sharding — see `docs/ARCHITECTURE.md › Growth`.

## 6. Known gaps

- Password-protected share links: GS01's Argon2id path is built; the
  packaged recipient page lands soon.
- Worker request caps: uploads are chunked (8 MiB frames); a *restore* of
  very large backups is client-driven for the same reason.
- The backup job buffers one container in memory — right for family scale;
  multipart streaming is the documented next step.