# Gorani — the course

> Copyright 2026- Seongwoo Hong. All rights reserved.

Gorani is a zero-trust, end-to-end encrypted family NAS: every file is sealed
in the browser or the native clients before the server sees a byte, the
server (a Rust Cloudflare Worker) holds ciphertext and wrapped keys only, and
object storage is any S3-compatible bucket — MinIO over public HTTPS.

This repository is also a **teaching artifact**: it shows how a real-world
app of this kind is constructed, layer by layer. Every source file opens with
a header that says what it is, why it exists and which spec section it
implements; every commit is a self-contained, green-build lesson. This file
is the index: what to read, in what order, and what to build yourself.

## How to read this repository

| # | Lesson | Where | You learn |
|---|--------|-------|-----------|
| 1 | The trust map | docs/ARCHITECTURE.md | Who can read what, and why that is a design decision, not an accident |
| 2 | Why each runtime gets its language | docs/ARCHITECTURE.md §Languages | TS+WebCrypto in the browser (non-extractable keys), Rust on the server and in clients, WASM only for key-free media parsing |
| 3 | The dependency budget | web/package.json, NOTICE | Why ~12 runtime packages, why Trusted Types, why the supply chain is part of the threat model |
| 4 | The sealed formats | crates/formats/ (commit ②), docs/ENCRYPTION.md | GV1/GV2/GV3/GK1/GW1 byte by byte; how to read a crypto spec |
| 5 | Chunked files | crates/formats/ GC1 (commit ③) | 8 MiB authenticated frames; seeking into the middle of a video without the rest |
| 6 | A family key hierarchy | shared family model (commit ④), docs/FAMILY.md | Parents' master key, dual-sealed kids' store keys, why kids *cannot* open parents |
| 7 | Speaking S3 from a Worker | worker/src/s3/ (commit ⑤) | SigV4 by hand, streaming, multipart |
| 8 | Durable Objects as per-member databases | worker/src/store/ (commit ⑥) | SQLite in a DO, change feeds, tombstones, journals |
| 9 | The vault in the browser | web/src/vault/ (commit ⑨) | Passkey PRF, Argon2id, non-extractable keys, auto-lock |
| 10 | A file explorer without a framework | web/src/ui/ (commit ⑨) | Lit, stores, virtualization |
| 11 | Streaming encrypted video | web/src/media/, crates/media/ (commit ⑩) | `.hlsmeta` sidecars, MSE, client-side fMP4 assembly |
| 12 | Native clients | clients/ (commits ⑬–⑭) | The same protocol in Rust; platform file-system APIs |
| 13 | Encrypted backups | GB1 (commit ⑫) | Incremental sealed archives; key files |

Each lesson's commit passes `npm run typecheck`, its tests, and
`cargo check --workspace` — try `git log --oneline` and re-read the tree at
each tag to watch the app being constructed.

## Conventions

- Every source file begins: `// Copyright 2026- Seongwoo Hong. All rights reserved.`
- Durable Object classes are always prefixed `Gorani*DO` (`GoraniMemberDO`, …).
- Sealed formats are named GV* (values), GC1 (chunked files), GB1 (backups),
  GK1/GW1 (key containers) — gorani's own names for layouts shared with
  Mailflare's MFV* (byte layouts identical; see NOTICE for provenance).
- Family model: readable member names; the shared "Family" area is
  parents-write, all-read.