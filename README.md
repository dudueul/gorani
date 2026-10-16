# Gorani

> Copyright 2026- Seongwoo Hong. All rights reserved.

<p align="center"><img src="docs/assets/gorani.svg" width="180" alt="Gorani: a cute water deer (고라니), round ears, dark eyes and two little tusks"></p>

A zero-trust, end-to-end encrypted file store for a security-operations
team (it began as a family NAS — docs/FAMILY.md is that history). Files are
sealed in the browser (Lit + WebCrypto) or the native Rust clients before
the server sees a byte; a Rust Cloudflare Worker holds ciphertext, wrapped
keys and just enough readable structure to sync and browse; object storage
is any S3-compatible bucket (MinIO over public HTTPS). Least privilege by
key custody: every member has their own area, a case's key is sealed only
to the people granted it, every grant is signed, and recovering a lost key
takes several leads together — never one (docs/CASES.md).

**Status: built, self-proving — and reviewed.** The commit-23 security
review ([docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md)) fixed 32
findings and lists the open ones with proposals; read it before deploying.
The SecOps product decisions that follow from it are in
[docs/DECISIONS.md](docs/DECISIONS.md).
34 green commits from the scaffold
through the vault, explorer, streaming, shares, backups, retention, native
clients (live-tested), the family hierarchy, ownership, the R2-priority
storage path, the nightly cron, the music library, and a browser e2e. The
build order is the lesson plan — see [docs/COURSE.md](docs/COURSE.md), the
architecture map is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (duplicate
detection: [docs/DUPLICATES.md](docs/DUPLICATES.md)), and
NOTICE lists the Apache-2.0-derived portions.

**The app:** https://gorani.at.day (behind Cloudflare Access). **Desktop
downloads:** the [Releases](https://github.com/dudueul/gorani/releases/latest)
page — Latest is always the newest build (Windows, macOS, Linux; unsigned,
with a signed SHA256SUMS). Check before running anything:
[docs/INSTALL.md](docs/INSTALL.md).

## Stack

| Side | What |
|---|---|
| Web | Lit 3, TypeScript, Tailwind v4, Vite — no framework, no SSR, Trusted Types enforced |
| Worker | Rust (workers-rs, wasm32), Durable Object `GoraniMemberDO` (SQLite) |
| Storage | Priority: Cloudflare R2 via binding (no signing, no egress). Otherwise any S3-compatible endpoint (MinIO, B2, Wasabi) via SigV4 — chosen per deployment at boot |
| Clients | Rust — Windows (Cloud Files API), Linux (FUSE), macOS (File Provider) |
| Crypto | Hybrid post-quantum from day one: P-256 + ML-KEM-768, AES-256-GCM, Argon2id |

## Development

```sh
npm install && npm --prefix web install   # root + web deps
npm run build                             # web → web/dist
cargo check --workspace --target wasm32-unknown-unknown   # Rust worker
npm run dev                               # wrangler dev (serves assets + worker)
```

Deploy: configure `wrangler.jsonc` vars + `wrangler secret put` (see
`.dev.vars.example`), create the private S3 bucket, then `npm run deploy`.

## Tests

`node tests/run.mjs` — the harness lands with the code it tests; each commit
stays green. See [tests/README.md](tests/README.md).