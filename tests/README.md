# Tests

> Copyright 2026- Seongwoo Hong. All rights reserved.

The harness grows with the code it tests; every commit is green. Runner:
`node tests/run.mjs [group]`.

| Group | Arrives | What it proves |
|---|---|---|
| `unit:formats` | ② | Every GV* format round-trips; Rust (crates/formats) and the browser TS open each other's vectors — byte equality between languages |
| `unit:chunked` | ③ | GC1 frames: reorder/drop/truncate fails to open |
| `unit:family` | ④ | Parents open kids' keys; kids cannot open parents' or siblings'; rotations keep everything readable |
| `api:s3` | ⑤ | The SigV4 adapter against a real MinIO container (put/get/range/multipart/abort) |
| `api:files`, `api:vault`, `api:devices` | ⑥–⑧ | The Worker over miniflare: refusals of unsealed input, change feed, devices, shares |
| `e2e:*` | ⑨+ | Playwright against `wrangler dev`: unlock, explorer, viewer, music, streaming, backups |
| `client:*` | ⑬–⑭ | The Rust core's sync engine against the dev server, and platform smoke tests |

Principles (from the course): tests are part of the teaching material — each
group's file header explains the attack or failure it exists to catch.