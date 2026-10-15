# Collectors and case inboxes — unattended evidence intake

> Copyright 2026- Seongwoo Hong. All rights reserved.
> Status: designed (decisions below, 2026-10-15); built in stages 37a–37d —
> 37a landed (registry, the service-token path, Team › Collectors); 37b
> landed (inbox keys, drops, the collector client); 37c landed (accept and
> reject, in the web app and the CLI).

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
                         stmt("gorani-collect-v1", case, item, collector, SHA-256, size,
                              name, type, source, method, collected-at, notes)
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

## 37b as built

- **Inbox keys** (`worker/src/family/inbox.rs`, registry migration v10;
  `web/src/vault/inbox.ts`): a case manager makes a hybrid pair in the
  browser, signs `stmt("gorani-inbox-v1", case, key digest)`, and seals the
  private half under the case key into place `case.inbox(area, key id)`
  (crates/formats › placed.rs, places.ts). A new key RETIRES the previous
  one — kept, because items stay sealed to the key they arrived under. A
  member opens an inbox key only with the case key, and only if it is the
  key the registry's public halves describe (a real private half paired
  with public halves of the server's would have collectors seal to the
  server). A case-key rotation must carry every inbox key re-sealed under
  the new key, in the same commit as the grants — the registry refuses a
  set one short or one long (`family.rs › case_rekey`, `cases.ts ›
  rotateCase`).
- **The drop routes** (`routes.rs › route_collector`): `GET
  /api/v1/collect/cases/<case>/inbox-key` (the current key, its signature
  and the registry's identities), `POST …/items` (whole, GV02), `POST
  …/items/uploads`, `PUT …/uploads/<u>/<n>`, `POST …/uploads/<u>/complete`
  (GC01 frames, the size checked against the frames). Every request asks
  the registry again — grant, open case, and for the record step the
  CURRENT key — so a revoked grant or a rotated key stops drops at once.
  The object key is `<case prefix>/inbox/<collector>/<item>`: an item id is
  the collector's choice, so one collector's ids can never name another's
  objects, and an id whose object exists is refused BEFORE anything is
  written (storage would overwrite it; a refused record would then delete
  the original).
- **The case store** (`worker/src/inbox.rs`, member migration v16):
  `inbox_items` holds the sealed key and record, the stamp imprint, and
  what became of the item. Stamps (stamps.rs) and the evidence lock pass
  (member.rs › lock_pass) cover inbox objects as they cover versions.
  Members read the inbox at `GET /api/v1/cases/<case>/inbox` and an item's
  bytes at `…/inbox/<item>` (Range passes through; the read is logged as
  `inbox:<item>`, which no file id can spell).
- **The collector** (`clients/core/src/collector.rs`, `gorani-sync
  collector …`): `init` makes the identity key and a device secret held by
  the TPM and/or keyring (devicekey.rs), seals the key and the service
  token's secret under it, and MACs the profile — pins included — with a
  second key from the same secret, so an edited profile is refused.
  `collect` asks `whoami` (the token must be registered with THIS key),
  checks the inbox key's signature against its pins plus one-hop
  certificates (identity.rs › trust_rules, the members' own rules), then
  seals, signs, stamps and sends — and appends a line to its own log.
  Pins may be fingerprints (128 bits), resolved to full key ids against
  the registry at use.

- **Team › Cases** shows each case's inbox key (who made it, how many are
  retired) and gives its managers "Make the inbox key" / "New inbox key".

Limits, as built: a large drop does not resume — a stopped one is sent
again as a new item (the stray upload is swept like a member's); the
collector learns the registry's identity list (public keys and
certificates — what it needs to check a manager's signature); and the
store can still WITHHOLD an item, which only the collector's own log shows.

What a member's client checks before calling an item verified
(`inbox.ts › openInboxItem`): the sealed record names this case, this item,
the collector that dropped it and the size the store counted; the collector
is one two leads the MEMBER trusts registered (collectors.ts); its
signature verifies over every field; the stamp imprint is over that
signature; and, after decryption, the bytes hash to what it signed
(`checkInboxContent`). Each failure is reported as what failed.

## 37c as built

```text
accept   POST /api/v1/cases/<case>/inbox/<item>/accept   (write)
         { fileId, name, type, ck, hash, stamp, intake, collection }
reject   POST /api/v1/cases/<case>/inbox/<item>/reject   (write)   { reason }
```

- **Only a verified item is accepted** (`inbox.ts › acceptInboxItem`,
  `clients/core/src/inbox.rs › accept`): the collector counted by the
  accepting member, its signature over every field, the stamp over that
  signature — and the bytes, re-read from the store and decrypted as they
  stream, hashing to what it signed. What cannot be tied to a collector the
  member trusts is turned away, not filed.
- **The file is an ordinary evidence file**, with two signatures over the
  same bytes: the accepter's content hash (and its timestamp imprint) and
  intake record — whose `collector` is `collector:<id>`, its other fields
  the collector's — and the collector's own record, sealed with the case
  key into place `file.collection(area, file)` and returned by `files/keys`
  as `collection` (`checkCollection` verifies it against the file's bytes).
  The version points at the inbox object: nothing is copied, and the
  store's own size and frame size are used, not the client's.
- **Once.** The store claims the item before anything awaits — two people
  accepting at once cannot make two files of one item — and releases the
  claim if the file is refused (an evidence file without its hash or
  intake, a closed case).
- **Rejecting** seals the reason into place `inbox.reject(area, item)` (it
  may name what the item is); an evidence case keeps the object
  (write-once), a working case's is deleted.
- Both new sealed values join the rotation walk (`files/sealed` kinds
  `collection` and `reject`): a case-key rotation leaves nothing that opens
  under the old key.
- The decider is the Worker's word (`by`: the member id it authenticated),
  not the client's. The store, as everywhere, checks shapes and policy and
  verifies no signature: a writer COULD file an item their client would
  call unverified — by sending a forged decision, under their own name, on
  the case's trail. The client's checks are what stop honest mistakes; the
  trail and both signatures are what make a dishonest one visible.
- **Team › Cases › Inbox** lists each item with this member's verdict,
  Accept (enabled only for a verified item) and Reject (asks for the
  reason). The CLI: `gorani-sync inbox|accept|reject --case C`.

## Stages

| Stage | What |
|---|---|
| 37a | Registry: collectors (two-lead registration, revocation), drop grants; the service-token path in `auth.rs` (a collector identity, refused everywhere but the drop routes); Team › Collectors. |
| 37b | Inbox keys (create, rotate with the case key); the collector client: `gorani-sync collector init` (identity key under TPM/keyring), `collect` (whole and chunked drops). |
| 37c | Accept and reject (web and CLI), the `file.collection` record, audit events. |
| 37d | Export and `verify-export` carry and check the collection record; PRODUCTION.md (service tokens, Access policy for collectors). |
