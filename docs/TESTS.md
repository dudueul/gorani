# Tests as teaching material

> Copyright 2026- Seongwoo Hong. All rights reserved.
> The runner: `node tests/run.mjs` (rust / unit / api / e2e). Every suite's header states the behavior it proves; this doc teaches how to READ them — and how to write the next one.

## The exemplary pattern (every suite follows it)

A test in gorani is an **argument that runs**. Three rules make it teach:

1. **Name the behavior, not the function.** `api:ownership — first-uploader owner, contributors trail, duplicate details` tells you the property before you open the file.
2. **Walk the real path.** Suites drive the real worker (`wrangler dev` + DOs + the S3 stub) or the real crypto (vault-crypto/chunked-file in Node) — never a mock of the thing under test. Mocks of the tested layer make tests lie.
3. **Assert the refusal, not just the success.** Every security property is proven BOTH ways: the right key opens, the wrong one is refused with the honest status (403/404/410/400). A refusal untested is a promise unkept.

## The suites, and the lesson each one teaches

| Suite | Teaches | Read it when you want to learn |
|---|---|---|
| `rust: formats` | Byte-format round-trips + the three tamper classes (byte flip, truncation, reordering) | how AEAD misuse becomes "opens to nothing" |
| `unit:formats` | TS ⇄ Rust **cross-language vectors** — both implementations seal, both open | how two implementations stay byte-identical forever |
| `unit:family` | The key-graph denials (child→parent/sibling/master) and rotations | why hierarchy is structural, not policy |
| `unit:index` | The unlock-gated snapshot: foreign root ⇒ noise; flipped byte ⇒ GCM failure | deriving keys from roots so IndexedDB is sealed |
| `unit:session` | Three unlock kinds open ONE root; adding a method requires the old one | the confirmation rule as a running argument |
| `unit:media-frames` | Range→frame math, AAD binding, open-ended windows — the worker's own file | why the player can seek multi-GB videos |
| `unit:explorer` | The model's sealed round trips (upload/download/duplicate/copy) with REAL crypto + fake server | model/view separation: Node drives the UI's brain |
| `unit:viewer-modes` | The mode table + the mime rules that keep stored content inert | security decisions as pure, testable functions |
| `unit:links` | GS01/GR01 derivations; id-bound AAD; password-gated keys | how "the key lives in the fragment" actually works |
| `api:family` | Bootstrap, parents-only, master-once, last-parent guard | the registry's lifecycle through real HTTP |
| `api:files` | Sealed-in boundary: unsealed bytes/names refused 400 **before storage**; feed, versions+409, Range, chunked multipart | the worker's contract, end to end |
| `api:r2` | The R2 binding as the storage priority: same sealed contract over the binding (in-process, no SigV4), on workerd's local simulator | one contract, two backends |
| `api:devices` | Enrol/token-once/unlock/rekey/revoke + crypto-shredding | the native device lifecycle |
| `api:shares` | The recipient's walk (meta→claim→data) + exhaustion/revocation/expiry | fragment-secret authentication, honest statuses |
| `api:backup` | Key file (private never crosses the wire) → job → download → decrypt → restore round trip | the container the server cannot open |
| `api:housekeeping` | Retention levers with forced clocks; the growth metric | bounding the unbounded |
| `api:cron` | The nightly pass fired like production fires it: fan-out over the registry, backup prune to 7, the `cron` actor in the audit | maintenance without an identity |
| `unit:music` + `api:music` | Tag parsing byte by byte (ID3v2.3/2.4, FLAC) and the sealed-blob feed's contract — the server stores ciphertext with a size | metadata without surveillance |
| `e2e:app` | The SPA in a real browser (Playwright): boot, in-browser vault setup, password + recovery unlock, a sealed upload through the file picker, the decrypted listing, the wrong-password refusal | the product surface, finally watched — non-extractable keys as shipped |
| `api:client-live` | The REAL native binary: enrol, ls (opened names), zero-trust spot checks | two independent implementations agreeing over the wire |
| `unit:trusted-types` | The default policy's allow-list: same-origin app scripts only — no data:, blob:, javascript:, foreign or query-altered URLs | what "which code may this page start?" looks like as a function |
| `unit:lock` | The auto-lock rule at its boundaries (15 idle / 5 hidden) and the lock's semantics (locked for good, one lock, listeners after the hold is gone) | security decisions as pure functions; ordering as a property |
| `unit:records` | Authenticated store records, written as the attack: substitution, swapped halves, mismatched pairs, unsealed keys, foreign MACs — each refused; first-use pinning | how a MAC under a root-derived key stops "seal to my key instead" |
| `api:rotation` | A store rotation that leaves nothing behind: the old key opens 0 of 9 sealed values after the walk, the new key all 9, an old version still decrypts, a second walk is a no-op | proving a revocation instead of asserting it |
| `api:security` | The review's regression suite (docs/SECURITY-REVIEW.md): registry scope, id validation before S3, write-once share ids, exact Range, device-token reports, write-once restore fill, a quiet health line | how a security fix earns its keep: the test fails on the old code |
| `api:s3-live` | **Opt-in** (`GORANI_LIVE_S3=1` + `S3_*`): the same contract against a REAL bucket — private-bucket check, signed round trips, exact Range, multipart + size refusal, share copy, purge | what the stub cannot prove: a real server checking SigV4 and the part rules |

## Writing the next suite (the house style)

```text
1. Header comment: what behavior, which doc/lesson it belongs to.
2. Real path first: wrangler dev (api) or real crypto (unit) — no mocks of the tested layer.
3. Success + refusal per property (the pair is the point).
4. Deterministic: fresh DO state per run, forced clocks, no sleeps you can't justify.
5. The failure message names the property ("owner never reassigned"), not the assert.
```

Runs: `node tests/run.mjs` (everything), `node tests/run.mjs api` (worker only), `node tests/run.mjs unit` (no server). Suites must stay fast: the whole run is minutes.

## A lesson from the review: the fake that agreed with the bug

`unit:explorer` drives the UI's model against a fake server. Until commit 23
the fake answered `GET …/files/keys` — but the real worker only has
`POST …/files/keys`, so the shipped app could not open, preview or inspect
a single file, and every test stayed green. Rule 2 above ("walk the real
path") is not a style preference: a fake must enforce the real contract
(method, path, body), or it becomes a second implementation that can agree
with the bug. The fake now asserts the method.