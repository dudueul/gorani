# Tests

> Copyright 2026- Seongwoo Hong. All rights reserved.

The harness grows with the code it tests; every commit is green.

```sh
node tests/run.mjs            # everything: rust, unit, api, e2e
node tests/run.mjs unit       # one group at a time
node tests/run.mjs api
```

Groups:

| Group | Runs | Needs |
|---|---|---|
| `rust` | `cargo test` on the pure crates (`gorani-formats`, `gorani-s3`) | a Rust toolchain |
| `unit` | the browser-side modules under Node (`tests/unit/*.test.*`) | Node only |
| `api` | the real Worker under `wrangler dev` + DOs + the S3 stub (`tests/api/*.test.*`) | wrangler; each suite gets a fresh server |
| `e2e` | the real SPA in Playwright's chromium (`tests/e2e/*.test.*`) | `npm i -D playwright` — the suite **skips with a notice** when it is absent, so a browser-less checkout stays green |

Per-suite notes, the lesson each one teaches, and the house style live in
[docs/TESTS.md](../docs/TESTS.md) — that file is the map; this one is just
how to run it.

Two details worth knowing before debugging a failure:

- The api suites spawn async on purpose: the runner process owns the S3
  stub's event loop, and a synchronous spawn would freeze it (the worker's
  storage calls would starve — found the fun way, see commit 15).
- workerd logs errors to observability traces, not stderr; suites that
  need the reason query `/cdn-cgi/local/explorer/api/local/observability/query`
  before their server exits (see `api:r2`'s failure path).

Principles (from the course): tests are part of the teaching material —
each suite's header explains the behavior it proves, walks the real path
(no mocks of the tested layer), and asserts the refusal, not just the
success.