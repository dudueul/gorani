# Roles, cases and quorum recovery (D2 + D4)

> Copyright 2026- Seongwoo Hong. All rights reserved.
> The design for docs/DECISIONS.md › D2 (who can do what) and D4 (recovery),
> written before the code, as every decision here is. It replaces the
> family hierarchy of docs/FAMILY.md, which stays as the migration source
> until the last stage below removes it.

## What changes, in one paragraph

A family had parents and children, and one master key that let any parent
open any child's area. A security-operations team needs the opposite
default: **nobody reads an area they were not granted**, a case's data is
readable by exactly the people on the case, and recovering a lost key takes
**several** leads acting together — never one. The cryptography stays the
same envelope scheme (seal the small key, never the content); what changes
is *who the small keys are sealed to*.

## Roles

| Role | Registry | Own area | Cases | Audit |
|---|---|---|---|---|
| **lead** | adds, changes and deactivates members; creates cases; grants and revokes | read/write | those granted (a lead is not on every case by default) | reads every audit and read log |
| **analyst** | — | read/write | those granted: read/write | reads own |
| **auditor** | — | read/write | those granted: **read only** (the server refuses their writes) | reads every audit and read log |
| **external** | — | **none** | those granted, with an expiry | — |

Rules worth stating because they are easy to get wrong:

- **A lead is not a superuser of content.** Leads manage *who may hold
  which key*; they do not hold every key. A lead reads a case only if a
  grant seals the case key to them. (The family's master key gave parents
  every child's content — exactly the property D2 removes.)
- **Read-only cannot be cryptographic** with one store key: whoever can open
  a case can also seal into it (GV04's PSK is derived from the same private
  key). So auditors' read-only is a **server rule**, and every write is
  attributed by the D5 signature; a write the server let through from an
  auditor would still be visibly theirs. Confidentiality is crypto;
  attribution of writes is signatures; the policy is the server's.
- **External responders** get no personal area and no registry view; their
  grants carry an expiry the server enforces, and the case key rotates when
  they leave (the rotation walk of O5, per case).

## Areas and their keys

```text
member root (personal vault, as today)
   └── own area key ("files" store) ─── sealed to: the member's root
                                                 + the team recovery key (D4)
case C key (one hybrid store key per case)
   └── sealed to: each granted member's root (one copy per grant)
                + the team recovery key
team recovery key (one per team)
   └── private half: never whole at rest — Shamir-split M-of-N, each share
       sealed to one lead's root
```

- A **case** is a store exactly like a member's own area — the same rows,
  GV04 places (`store` = the case id), change feed, backups — living in its
  own Durable Object (`case:<id>`), addressed as `/api/v1/cases/<id>/…`.
- A **grant** is a row (case, member, permission, expiry) in the registry
  plus a sealed copy of the case key to the member's root, authenticated by
  the granting lead's identity signature (below). Revoking a grant deletes
  the copy and rotates the case key (the departed member kept the old one).
- The **recovery copy** of every area key replaces the family's guardian
  copy: sealed to the team recovery PUBLIC key, which anyone can do; opened
  only by a quorum.

## Member identity keys (closes O3's trust-on-first-use gap)

Each member gets a signing key pair (ECDSA P-256 — WebCrypto, non-
extractable in the browser), its private half sealed to their own root, its
public half in the registry with a **fingerprint** a lead verifies out of
band when the member joins (read aloud, compared on screen). From then on:

- a key copy sealed to you *by someone else* (a case grant) carries the
  sealer's signature over (case id, key id, your member id); your client
  verifies it against the registry's key for the sealer, so a server cannot
  substitute a case key before your first open — the O3 gap;
- D5's "hash at upload, signed" uses the same key.

## Recovery: M-of-N leads (D4)

**Shamir secret sharing** over GF(2⁸) splits the recovery key's private
bundle into N shares, any M of which reconstruct it and any M−1 of which
reveal nothing (information-theoretically, not computationally).

The ceremony, for "member X lost every unlock method" or "case C has no
remaining grantee":

1. The **coordinator** (a lead) opens a ceremony: their browser makes an
   ephemeral key pair and posts its public half with the request (target,
   reason). The audit records it; every lead sees it.
2. **M leads approve**: each opens their own share (sealed to their root)
   and re-seals it to the ceremony's ephemeral public key. The server holds
   M sealed shares it cannot open.
3. The coordinator's browser opens the M shares, combines them, opens the
   target's recovery copy, re-seals the area key to its new holder (X's new
   root, or a new grantee), posts that, and **wipes** the recovery key and
   the ephemeral key. The ceremony closes; the shares submitted to it are
   deleted.

The honest limit: Shamir needs the shares to meet in one place, so the
coordinator's browser holds the whole recovery key for the length of step
3. Removing that needs threshold cryptography (MPC), which is out of scope;
the mitigations are procedural — the coordinator is a lead, the ceremony is
audited and visible to all leads, and the recovery key is **rotated** after
any ceremony (new shares to the current leads, every recovery copy
re-sealed) so a key that existed whole once does not stay valid.

### The protocol, concretely (stage 5)

Everything the ceremony depends on is either SIGNED by a trusted identity
(stage 4) or VERIFIED against something that is. Each row closes a way a
server that controls the registry could otherwise win:

| Piece | Made by | Signed / checked | Without it, the server… |
|---|---|---|---|
| **recovery key** (hybrid pair; public halves, full digest, threshold M, holders) | a lead's browser | the lead signs `"gorani-recovery-v1" ‖ digest ‖ M ‖ holders` | …publishes its OWN recovery public key and collects every recovery copy |
| **shares** (Shamir M-of-N of the private bundle, one per holder) | the same browser | each sealed to the holder's TRUSTED root (`trustedRoot`) | …gets a share sealed to a root of its own |
| **recovery copies** (an area key sealed to the recovery public key) | whoever holds the area key: the member, a case's manager | sealed only after the recovery record's signature verifies against a trusted identity | …see the first row |
| **ceremony** (target, reason, ephemeral public key, its digest) | the coordinator's browser | the coordinator signs `"gorani-ceremony-v1" ‖ id ‖ target ‖ reason ‖ ephemeral digest ‖ recovery key id`; approvers verify before re-sealing their share | …swaps the ephemeral key for its own and collects M shares — the whole recovery key |
| **combine** | the coordinator's browser | the reconstructed key's digest must equal the SIGNED recovery digest | …feeds a wrong share; Shamir would silently produce a wrong key (shamir.ts › Integrity) |
| **outcome** — case: a manage grant for a new holder; member: their area key sealed to the new root they enrolled | the coordinator's browser | the grant is signed (stage 4); the new root is read aloud as a fingerprint between the member and the coordinator | …redirects the outcome to a root of its own |

After any completed ceremony the registry marks the recovery key
**rotation required**: it existed whole in one browser. A lead rotates it
(new key, new shares); every holder of an area key re-seals their copy the
next time they unlock (a copy names the recovery key id it was sealed to,
so a stale one is visible, and leads see the coverage).

A member who lost every unlock method **re-enrols** first: their browser
(signed in through Access, so the registry knows who they are) makes a new
root, unlock methods and identity, and posts them as a DRAFT. The ceremony
for that member names the draft's root digest; completing it writes the
draft as the member's vault settings with the recovered area key sealed to
the new root — the only path by which a vault's root can change.

## Migration from the family model

| Family | Team |
|---|---|
| parent | lead |
| child | analyst |
| a child's own area | the member's own area |
| the family shared area | a case named "shared" with every member granted |
| the parents' master key (one key, every parent holds it whole) | the team recovery key (no lead holds it whole) |
| guardian copy of a child's store key (sealed to the master) | recovery copy (sealed to the recovery key) |
| a parent acting for a child | gone — leads manage keys, not other people's areas |

The registry's role column is rebuilt under the migration ledger (O19): the
old CHECK constraint allowed only parent/child.

## Build order (each stage green on its own)

1. **Shamir** (landed: commit 26b, `unit:shamir`) — `web/src/vault/shamir.ts`, pure, with its tests.
2. **Roles** (landed: commit 26c, `api:roles`) — the registry's four roles (parent→lead, child→analyst);
   auditor writes refused; externals see only their grants. Transitional
   rule: a lead may still act for a member's own area (the parent rule)
   until stage 5 removes it.
3. **Cases** (landed: commit 26d, `api:cases`) — the registry's cases and
   grants; `case:<id>` stores; `/api/v1/cases/<id>/files/…`; the client's
   case-key grant and revoke (revoke = rotate + the reseal walk). What the
   build settled, below in **Stage 3 as built**.
4. **Identity keys** (landed: commit 27a, `unit:identity`, `api:cases` §0b/§3b)
   — signing keys and fingerprints; signed grants. What the build settled,
   below in **Stage 4 as built**.
5. **Recovery** — the team recovery key, shares to leads, recovery copies,
   the ceremony (landed: commit 27b, `api:recovery`; the protocol above is
   what was built); then the parent act-for rule and the master key go
   (27c).
6. **UI** — the case list, grant dialog, ceremony screens.

## Stage 3 as built

**One abstraction, not two stores.** An *area* is a member id or
`case:<id>` (worker/src/area.rs, web/src/lib/area.ts); the DO instance, the
object-key prefix (`files/<member>/…`, `cases/<case>/…`) and the GV04
`store` all follow from it. Member ids cannot contain `:`, so the
namespaces cannot meet. The Worker rewrites `/api/v1/cases/<id>/<rest>` to
the member routes with the area, after one check:

| The request | Needs |
|---|---|
| any GET of files, storage, backups; `POST files/keys` | a grant (read, write or manage) |
| any other files write | write or manage — and not an auditor; refused on a closed case |
| `PUT files/reseal`, the backup key and runs, restores, retention | manage |
| `GET audit`, `GET reads` | a grant, or the lead/auditor audit view |
| `files/shares…`, devices, vault settings, vault destruction | — (a case has none: 404) |

**Routes** (management, all the registry's policy):

| Route | Who |
|---|---|
| `POST /api/v1/cases` `{id, kind, keyId, publicKey{ec,kem}, keySealed, titleSealed}` | a lead; becomes the first manager |
| `GET /api/v1/cases` | each caller's own grants (with key copies); leads and auditors also see every case's structure, without keys; externals do not see other grantees |
| `PUT /api/v1/cases/<id>/grants/<member>` `{permission, keySealed, keyId, expiresAt?}` | a manager; the copy must name the current key |
| `DELETE /api/v1/cases/<id>/grants/<member>` | a manager; never the last manager; sets "rotation required" |
| `PUT /api/v1/cases/<id>/key` then `POST …/key/done` | a manager: the two steps of a rotation |
| `POST /api/v1/cases/<id>/close` | a manager; the case becomes read-only |
| `GET /api/v1/members/<id>/root` | any non-external member: the public halves a grant is sealed to |

**Decisions the build made:**

- **A rotation commits before it walks.** A member store's runbook walks
  first and then switches settings — survivable there because the member
  keeps their old key. A case's key lives only in grants, so a walk that
  ran first and crashed would leave half the case sealed to a key that
  existed only in the dead tab. So: commit the new key (each grantee's old
  copy moves to `prev_key_sealed`), walk, prove the old key opens nothing
  (rotation.ts › opensAnything), then `key/done` drops the old copies. A
  tab that dies mid-walk resumes from the grants (`rotateCase` sees
  `rotating`). While a walk runs, readers fall back to the previous key.
- **Ended grants count as a revoke.** An external whose grant or own
  access expired, or a deactivated member, kept their copy; the case lists
  `rotationRequired` until a rotation drops those grants with the old key;
  the listing leaves them out of `grantees` (nobody seals the new key to
  someone who left), and the last-manager guard counts live managers only
  — a deactivated lead's grant would leave a case nobody can manage.
- **Externals have a vault root, not an area.** A grant is sealed to a
  root, so an external sets up their own vault (unlock methods, root) —
  and still has no files beside it.
- **No public links from a case**, evidence or working: a case shares by
  grant. D11 decides whether working cases get links later.
- **The O3 gap is still open for grants**: a copy sealed to you by someone
  else is checked for consistency against the registry's public halves for
  the case (`openCaseKey`), not for authenticity — a server that replaced
  both before your first open is not caught. Stage 4's signed grants close
  it; `GET …/root` is likewise the server's word until fingerprints.

## Stage 4 as built

`web/src/vault/identity.ts` is the client half; the registry's migration v4
holds the public half.

**Three records, three owners:**

| Record | Where | Who can write it | What protects it |
|---|---|---|---|
| identity (public key, root digest, self-signature) | registry `identities` | the member, once (a reset — by them or a lead — first) | the self-signature over (member, key id, root digest) |
| certificate (a lead's signature over the same three) | registry `identity_certs` | leads, naming the CURRENT key and root | the lead's signature |
| pins (the identities this member verified) + the sealed private key | the member's vault settings, `identity` | the member's client | an HMAC from the member's root (records.ts' key, its own domain) |

**The trust rule** (`buildTrust`), evaluated by every client for itself: an
identity counts if its key id matches its key and its self-signature
verifies, AND it is pinned — or certified by a member whose identity is
pinned. **One hop**: a certificate from someone trusted only through a
certificate counts for nothing. The intended practice: each member compares
fingerprints with a lead when they join, both ways (the lead certifies the
member; the member pins the lead), and from then on trusts whomever that
lead verified.

**What is signed** — statements, length-prefixed under a domain string, so
no signature can be replayed as another kind:

```text
identity  "gorani-identity-v1" ‖ member ‖ identity key id ‖ root digest
cert      "gorani-cert-v1"     ‖ member ‖ identity key id ‖ root digest
grant     "gorani-grant-v1"    ‖ case   ‖ case key digest ‖ grantee
```

Digests are full SHA-256 over the public halves; the short `keyId`s are
labels (~84 bits), too short to sign against a server that can grind.

**What it closes:**

- A substituted case-key copy (the server's own key, sealed to you): the
  signature over (case, the key's digest, you) cannot verify — refused
  before you use it. A real signature replayed from another grant names
  another grantee and another key.
- A substituted ROOT when a manager seals (`GET …/root` is the server's
  word): the root's digest must be the one the grantee's trusted identity
  names (`trustedRoot`).
- A resumed rotation handed an unsigned old key: the previous copy keeps its
  signature (`prev_signature`) and is verified like the current one.

**Departed members.** Their identities stay listed, flagged inactive: what
they signed while on the team (a grant, the recovery key's record) must
still verify, or the team could not run a ceremony for the case its lead
left behind (`api:recovery` does exactly that). The registry takes no new
signature from them; the limit is a colluding server presenting a new one
as old — re-pin and rotate the recovery key after a lead leaves (the
recovery record reports it as owed).

**What it does not:** rollback — a validly signed OLDER grant replayed to a
member who never saw the newer key (identity.ts › the honest limits); and
the registry's role column is still the server's word (who is a lead), which
is why trust flows from pins, not from roles. The family area's store
records keep their trust-on-first-use pin until stage 5 replaces the family
area with a case.

## What this does NOT change

The formats (GV04, GC01, GB2), the zero-trust boundary (the server holds no
key that opens anything), the lock, the read log, the sharing rules of
D11 (stage 3 lets cases refuse anonymous links in evidence areas).
