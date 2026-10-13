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

The drawn version of lesson 1: [ARCHITECTURE-DEEP.md](ARCHITECTURE-DEEP.md) — Mermaid diagrams of every flow (unlock, upload, streaming, family graph, backup, growth).

| # | Lesson | Where | You learn |
|---|--------|-------|-----------|
| 1 | The trust map | docs/ARCHITECTURE.md | Who can read what, and why that is a design decision, not an accident |
| 2 | Why each runtime gets its language | docs/ARCHITECTURE.md §Languages | TS+WebCrypto in the browser (non-extractable keys), Rust on the server and in clients, WASM only for key-free media parsing |
| 3 | The dependency budget | web/package.json, NOTICE | Why ~12 runtime packages, why Trusted Types, why the supply chain is part of the threat model |
| 4 | The sealed formats | crates/formats/ (②), docs/ENCRYPTION.md | GV01/GV02/GV03/GK01/GW01 byte by byte; how to read a crypto spec |
| 5 | Chunked files | crates/formats/ GC01 (③) | 8 MiB authenticated frames; seeking into the middle of a video without the rest |
| 6 | A family key hierarchy | web/src/vault/family.ts (④), docs/FAMILY.md | Parents' master key, dual-sealed kids' store keys, why kids *cannot* open parents |
| 7 | Speaking S3 from a Worker | crates/s3 + worker/src/s3.rs (⑤) | SigV4 by hand, golden vectors, streaming, multipart |
| 8 | Durable Objects as per-member databases | worker/src/member.rs (⑥) | SQLite in a DO, trigger-only change feeds, tombstones, journals |
| 9 | The vault in the browser | web/src/vault/ (⑨) | Passkey PRF, Argon2id, non-extractable keys, device hold, auto-lock |
| 10 | A file explorer without a framework | web/src/ui/ (⑨b) | Lit, one sealed model, two native-OS skins (Windows 11 + Finder) |
| 11 | The local index | web/src/vault/index*.ts (⑨c) | Instant search, untrackable (encrypted snapshots), unlock-gated keys |
| 12 | Streaming encrypted video | public/sw-media.js (⑩b) | A scoped service worker; the browser's own player; GC1 range decrypt |
| 13 | Encrypted backups | crates/formats/backup.rs + worker/src/backup.rs (⑫) | GB1 containers; the key file; restore |
| 14 | Shares and requests | GS01/GR01 + worker routes (⑪) | The fragment secret as credential; download counters |
| 15 | Growth | worker housekeeping + docs/ARCHITECTURE.md › Growth (13) | Retention levers; the reserved GoraniFilesDO split; why not PlanetScale |
| 16 | Native clients | clients/ (⑬–⑭, next) | docs/DESKTOP.md is the protocol contract |

Each lesson's commit passes `npm run typecheck`, its tests, and
`cargo check --workspace` — try `git log --oneline` and re-read the tree at
each tag to watch the app being constructed.

## How to read the tests

Tests are teaching material — each is an argument that runs. docs/TESTS.md maps every suite to the lesson it proves and states the house style (real paths, refusal-paired assertions, named behaviors).

## Conventions

- Every source file begins: `// Copyright 2026- Seongwoo Hong. All rights reserved.`
- Durable Object classes are always prefixed `Gorani*DO` (`GoraniMemberDO`, …).
- Sealed formats are named GV01/GV02/GV03 (values), GC01 (chunked files, commit ③), GB01 (backups),
  GK01/GW01 (key containers) — gorani's own names for layouts shared with
  Mailflare's MFV* (byte layouts identical; see NOTICE for provenance).
- Family model: readable member names; the shared "Family" area is
  parents-write, all-read.