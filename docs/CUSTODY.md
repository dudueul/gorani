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
| 1 | D7 + D5.3 | the audit leaves the area database: an outbox ships each line to a per-area **audit Durable Object** that hash-chains it, keeps it 7 years with no line cap, and checkpoints daily to object storage; `…/audit/verify` |
| 2 | D7 | retention by kind: evidence keeps every version and refuses deletion; working areas prune non-current versions after a year |
| 3 | D6 | Object Lock on evidence objects (COMPLIANCE mode, the case's retention) |
| 4 | D5.1 | the uploader signs SHA-256 of the plaintext (identity key, stage 4 of CASES.md) — stored beside the version, verified on open |
| 5 | D8 | samples: a readable flag; the viewer refuses them; download as a zip encrypted with "infected" |
| 6 | D5.6 / D5.7 | intake record (sealed) at upload; signed custody transfers; the two-person rule for export, legal-hold release and case deletion |
| 7 | D5.8 / D5.5 / D5.4 | signed export package and a re-verification job; RFC 3161 timestamps; the SIEM feed |

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
