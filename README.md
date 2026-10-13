# Gorani

> Copyright 2026- Seongwoo Hong. All rights reserved.

A zero-trust, end-to-end encrypted family NAS. Files are sealed in the
browser (Lit + WebCrypto) or the native Rust clients before the server sees
a byte; a Rust Cloudflare Worker holds ciphertext, wrapped keys and just
enough readable structure to sync and browse; object storage is any
S3-compatible bucket (MinIO over public HTTPS). Family key hierarchy: a
parents' master key opens the children's areas — never the reverse.

**Status: commit ① (scaffold).** The build order is the lesson plan — see
[docs/COURSE.md](docs/COURSE.md), the architecture map is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and NOTICE lists the
Apache-2.0-derived portions.

## Stack

| Side | What |
|---|---|
| Web | Lit 3, TypeScript, Tailwind v4, Vite — no framework, no SSR, Trusted Types enforced |
| Worker | Rust (workers-rs, wasm32), Durable Object `GoraniMemberDO` (SQLite) |
| Storage | Any S3-compatible endpoint (MinIO, B2, Wasabi, R2 S3 API) via SigV4 |
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