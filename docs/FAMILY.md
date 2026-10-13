# Family: the key hierarchy, walked through

> Copyright 2026- Seongwoo Hong. All rights reserved.
> The code twin is `web/src/vault/family.ts`; the behavioral test is `tests/unit/family.test.mjs`.

Gorani is a family NAS: several members, each with a full vault, and a
**one-way hierarchy** — parents can open the children's areas; children can
never open the parents' or each other's. No new cryptography: the same
envelope scheme as everything else (seal the *small* key, never the
content), plus exactly two wrappers.

## The graph

```text
parents' master key pair (one per family)
    private half ──sealed GV03──▶ to each parent's root     (parent.settings.masterSealed)
    public half  ◀──every child's files-store PRIVATE key is sealed to it──┐
                   (child.settings.guardian.storeSealed, beside the child's own copy)
family shared area: ONE store key, its private half sealed to every member's root
                    (each member's settings hold their own copy: stores["family"])
```

## Worked example (what the test proves)

Two parents (Mom, Dad) and two children (Jinu, Sora):

1. **Creation.** Each parent's vault: hybrid root + password + recovery
   methods. Each child's vault: hybrid root + a single **enrolment/recovery
   code** (one secret, three uses: the child unlocks with it, a parent
   enrolls a device with it, a parent regains the vault with it — the
   child's password never leaves the child).
2. **A file lands in Jinu's area**, sealed under Jinu's files-store key:
   content key wrapped (GV03) to Jinu's store public half.
3. **Mom opens it**: unlock her root → unwrap the master (`masterSealed`) →
   unwrap Jinu's store key (`guardian.storeSealed`) → unwrap the content
   key → open. Dad's chain is independent and reaches the same key.
4. **The denials that must stay denials** — each is a property of the key
   graph, not a policy check:
   - Jinu's root cannot open Mom's store key (sealed to Mom's root only).
   - Jinu cannot open Sora's store key — neither the child's own copy nor
     the guardianship copy (sealed to the master, which Jinu cannot reach).
   - Jinu cannot open the master through their own root.
5. **The family shared area**: one store key, sealed to all four roots —
   everyone reads (crypto), only parents write (the server's role policy).
6. **Jinu's store key rotates** (compromised laptop): a parent alone can do
   it — both required publics are public halves — and the content keys
   re-wrap to the new store key without re-encrypting anything.
7. **Dad is revoked**: the master rotates; the master's private re-seals to
   Mom's root; each child's store bundle re-seals to the new public half.
   Two small seals per member; no file is re-encrypted.
8. **A guardian code enrols Mom's laptop** for Jinu's area (the desktop
   client enrols exactly as it would for any member) — and can regain
   Jinu's vault without knowing Jinu's password.

## Registry (readable structure, `GoraniFamilyDO`)

Member ids, readable names, roles, Access emails, active flags; the master's
PUBLIC half; the share index (share id → owner). Bootstrap: the first member
is created by any authenticated caller (the family deploys behind Cloudflare
Access); after that, parents only. The last parent cannot be deactivated.

## API scoping (routes.rs)

A member acts for themselves; a **parent acts for any member** — the API
twin of the key hierarchy. The DOs re-check nothing about identity, only
data rules; the routing layer owns who-may-call-whose.