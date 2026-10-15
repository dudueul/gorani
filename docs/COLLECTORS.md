# Collectors and case inboxes — unattended evidence intake

> Copyright 2026- Seongwoo Hong. All rights reserved.
> Status: designed (decisions below, 2026-10-15); built in stages 37a–37d —
> 37a landed (registry, the service-token path, Team › Collectors).

## The problem

An acquisition server, an EDR drop or a collection script has to put
evidence into a case **with no person signed in**. Access gives such a
machine a *service token*, whose JWT carries a `common_name` and no email —
which the Worker refuses, rightly: every rule here is a member's rule.

The obvious fix is wrong in this design. Sealing anything into a case's
places takes the case's **private** key (GV04: a store seals to itself, with
a secret only its private key computes — commit 25). A robot that can write
into a case therefore holds the key that reads the whole case, everything
collected before it included. A compromised collector would be a breach of
every case it serves.

## Decisions (asked 2026-10-15)

| Question | Decision |
|---|---|
| Model | **Drop box.** A collector holds only a case's *inbox* PUBLIC key. What it sends is sealed to that key and lands in the case's inbox. It cannot read anything — not even what it sent. A person accepts each item into the case. |
| Who registers a collector | **Two leads.** One asks, a second approves. A machine identity that feeds evidence into cases is high-value. |
| Who signs | **The collector and the accepting analyst.** The collector signs the content hash and intake at collection, with its own identity key (protected on its machine like any device secret). The analyst who accepts signs again. Custody shows both. |

## The pieces

```text
collector      a registry entry: id, name, the Access service token's common_name,
               an identity key (P-256; its private half on the collector's machine,
               protected by its TPM like a device secret — devicekey.rs)
registration   request  lead A signs stmt("gorani-collector-v1", id, common_name, key id, A)
               approve  lead B (not A) signs stmt("gorani-collector-approve-v1", id, common_name, key id, A, B)
               → active. Both signatures name the collector, its token and its key:
                 the server cannot attach two leads' agreement to a collector of its own.
               A member trusts a collector's key when BOTH signatures verify under leads
               the member trusts.
drop grant     a case manager lets a registered collector drop into a case (one person:
               a drop only adds to an inbox that people review)
inbox key      per case, a hybrid key pair made by a case manager:
               public halves + stmt("gorani-inbox-v1", case, inbox key digest) signed by them,
               in the registry; the private half SEALED UNDER THE CASE KEY (anyone on the
               case opens the inbox; a case-key rotation re-seals it)
drop           the collector checks the inbox key's signature against the leads it pins
               (and the one-hop certificates they made), then sends:
                 object  the bytes under a fresh content key (GV02 whole, GC01 frames large)
                 ck      the content key sealed to the inbox public key (GV03)
                 meta    sealed to the inbox public key: name, type, size, SHA-256, intake,
                         and the collector's signature over
                         stmt("gorani-collect-v1", case, item, SHA-256, size, intake digest)
                 stamp   SHA-256 of that signature — the RFC 3161 imprint (29j), stamped at
                         collection time
               The signature travels sealed: in the clear it would let the server test a
               guess ("is this the known file X?") — the reason content hashes are sealed.
accept         an analyst with write access opens the item with the inbox key, checks the
               collector's signature against their own trust, reads the content and checks
               its SHA-256, then files it: a new file in the case — name, type and content
               key sealed into the case's places, their own signed content hash and an
               intake record carrying the collector's fields — and the collector's sealed
               record kept beside it (`file.collection`), so exports carry both signatures.
               The bytes do not move: the version points at the inbox object.
reject         with a reason, audited; on an evidence case the object stays (write-once).
```

## What the server can and cannot do

- **Read collected evidence**: no — sealed to a key whose private half only
  case members can open.
- **Substitute its own inbox key**: the collector refuses a key not signed by
  someone its pinned leads vouch for.
- **Register a rogue collector**: not with two leads' signatures naming it;
  members' clients refuse a collector whose registration does not verify.
- **Drop forged evidence into an inbox**: anyone can send bytes, but an item
  without a valid signature by a trusted collector shows as unverified, and
  acceptance is a person's decision.
- **Hide an item**: a server can withhold inbox items (as it can withhold
  any file); the audit trail and the collector's own log are the check.

## 37a as built

- `worker/src/auth.rs`: an Access JWT with an email is a member; one with
  a `common_name` and no email is a **collector** identity (dev mode:
  `x-gorani-dev-collector`); one with neither is no one.
- `worker/src/routes.rs`: the ONE place the router looks at the kind of
  identity, before any member rule — a collector reaches
  `/api/v1/collect/…` and nothing else; a member cannot use those routes.
  Each collector request asks the registry which ACTIVE collector the token
  is (`collector-auth`), so a pending, revoked or unknown token is refused
  before any drop route runs. `GET /api/v1/collect/whoami` is the first
  route; the drops arrive in 37b.
- `worker/src/family/collectors.rs` (registry migration v9): request by a
  lead (the key id must be the key's), approval by another lead within 7
  days, revocation by any lead, drop grants by a case's manager (not on a
  closed case), one live collector per service token, every step on the
  registry's chained trail.
- `web/src/vault/collectors.ts`: the statements, request and approval (the
  approver's client checks the request's signature and the key id first),
  and the verdict a member's client reaches on each collector: counted only
  when active and both signatures verify under that member's own trust, by
  two different people.
- Team › Collectors: the list with each verdict in words, registration
  (paste what the collector's machine printed), approval (with the key's
  fingerprint to compare), revocation, and granting a managed case.

## Stages

| Stage | What |
|---|---|
| 37a | Registry: collectors (two-lead registration, revocation), drop grants; the service-token path in `auth.rs` (a collector identity, refused everywhere but the drop routes); Team › Collectors. |
| 37b | Inbox keys (create, rotate with the case key); the collector client: `gorani-sync collector init` (identity key under TPM/keyring), `collect` (whole and chunked drops). |
| 37c | Accept and reject (web and CLI), the `file.collection` record, audit events. |
| 37d | Export and `verify-export` carry and check the collection record; PRODUCTION.md (service tokens, Access policy for collectors). |
