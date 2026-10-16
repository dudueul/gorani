# Decisions: gorani for day-to-day security operations

> Copyright 2026- Seongwoo Hong. All rights reserved.
> The product decisions taken after the commit-23 security review
> (docs/SECURITY-REVIEW.md). Each entry records the choice, the
> alternatives that were on the table, and what the choice obliges the code
> to do. Teaching note: write these down *before* building — a decision
> that only lives in a chat cannot be reviewed, and the next person will
> re-litigate it.

## D1 — What the product is

**Evidence areas + working areas.** Evidence areas (malware samples, pcaps,
disk images, IR artifacts) are write-once, hashed at upload, and every
access is logged. Working areas (runbooks, reports, notes) are editable and
versioned. *Rejected:* evidence-only, docs-only, staying a family NAS.

## D2 — Who can do what

**Roles + per-case access.** Lead / analyst / auditor (read-only + audit) /
external responder. A case is a folder with its own key, sealed to each
member granted on it: least privilege per incident. Replaces the
parent/child hierarchy (which becomes a migration source, then goes).
*Rejected:* mapping parent/child to lead/analyst (too coarse); a flat team.
**Design: docs/CASES.md** (roles table, case keys, identity keys, the
staged build).

## D3 — Sign-in

**Cloudflare Access + the organisation's SSO + phishing-resistant MFA
(hardware keys / passkeys).** The vault unlock stays a separate
passkey-or-password step — signing in proves *who*, unlocking proves
*possession of the key*.

## D4 — Recovery

**M-of-N leads quorum** (Shamir secret sharing of the recovery key, e.g. 2
of 3 leads). No single insider can open everyone's data; recovery still
works with a lead away. *Rejected:* a single admin master (today's
"parent"), KMS escrow, no recovery. **Design: docs/CASES.md › Recovery**
(the ceremony, and its honest limit: the shares meet in one browser).

## D5 — Chain of custody (evidence areas)

All eight:

1. **Hash at upload, signed** — SHA-256 of the plaintext, signed by the
   uploader's key, stored beside the object.
2. **Audit every read** — view, download, preview, share access.
3. **Tamper-evident audit** — hash-chained lines, daily checkpoint anchored
   outside the database.
4. **Audit to the SIEM** — Splunk / Sentinel / Elastic.
5. **Trusted timestamps (RFC 3161)** — each evidence hash countersigned by
   an external timestamp authority.
6. **Intake record + custody transfers** — a sealed intake form at upload
   (case, source, collector, method, collected-at); each handoff a signed
   transfer naming both parties.
7. **Two-person rule** — export, legal-hold release and case deletion need
   a second lead's signed approval.
8. **Signed export package + re-verification** — export = manifest (files,
   hashes, signatures, timestamps, custody log) signed by the exporter; a
   scheduled client-side job re-hashes stored evidence and alerts on
   mismatch.

## D6 — Write-once storage

**S3 Object Lock on evidence objects** for the case's retention; working
areas keep Trash and purge. Requires the bucket to be created with Object
Lock enabled. Crypto-shredding remains available for working areas only.

## D7 — Retention

**Evidence: every version, for the case's life + retention. Working docs:
versions kept 1 year. Audit: 7 years, no line cap** — the audit moves out
of the member database (the 500-line family cap goes).

**Delete forever (39v): a lead's act, or the owner's.** Deleted files wait
30 days in the Trash, where a lead can restore them. Delete forever (and
Empty Trash) skips that wait, so it is offered only to a lead, anywhere,
and to a member in their own area. An analyst with a write grant on a
case still moves things to the Trash. It takes every version's bytes from
the bucket and revokes the file's share links. Evidence and a legal hold
refuse it, as they refuse the Trash.
*Rejected:* anyone who can trash (one mistake, or one insider, and the
Trash's safety net is gone); leaving share links live until they expire
(a deleted file would still be downloadable). **Design: docs/TRASH.md.**

## D8 — Malware samples

**Marked as samples, never rendered.** The viewer refuses to preview a
sample; downloads arrive as a password-protected zip (the industry
"infected" convention) so desktop antivirus does not quarantine them
mid-investigation.

## D9 — Storage

**Self-hosted MinIO** behind TLS, with Object Lock. The Worker signs
(SigV4); the R2 binding stays as the alternative transport. Operations own
durability, patching and backups — see PRODUCTION.md.

## D10 — Edge cache and read audit

**Keep the edge cache; audit at the Worker before the cache lookup.**
Every read is authorized and audited by the Worker (one merged "read" event
per person × file × device every few minutes, not one per chunk); warm
chunks then come from the edge without touching MinIO. Evidence is
Object-Locked, so a cached copy can never outlive a deletion.

## D11 — Sharing

**Partners sign in.** External responders and partner CERTs get guest
accounts behind Access with per-case grants. Anonymous links are disabled
in evidence areas; in working areas they require a password, expire within
7 days, and every access is audited.

*As built (commit 30):* guest accounts are the `external` role, which
expires and sees only its grants (stages 2–3 of CASES.md). A case has no
link route at all (`routes.rs › case_need`), and a malware sample is never
linked (D8). The server refuses a link without its password's Argon2id
parameters, with parameters outside what a recipient's page accepts
(`kdf-bounds.ts`), that expires more than 7 days out, or that allows
other than 1–100 downloads (`files_store.rs › share_policy_refusal`). It
never sees the password itself; the dialog generates one (80 bits) or
takes the owner's own of 8+ characters. Every claim of a download is
audited (`share.claim`).

*Inbound (commit 38, asked 2026-10-15):* the other direction — someone
outside the team SENDING files in — is an upload link (docs/REQUESTS.md),
and it is allowed into a member's folders and into cases, evidence
included, because nothing leaves by it: the sender seals to the area's
inbox key and can read nothing back. A link needs a password, lives at
most 30 days, takes at most 1000 files, locks after ten wrong passwords;
a case's is made by a manager. Each item waits for a person to accept or
reject it, and is filed as a malware sample (D8) unless that person
decides otherwise. Scanning is local (the CLI's `--scan` hook) or a
hash-only lookup at MalwareBazaar on request.

## D12 — File size

**Up to 255 GB per file.** S3 allows 10 000 parts, so 255 GiB needs parts
of at least 26.1 MiB — 32 MiB, rounded up to a power of two:
adaptive chunk sizes (8 MiB default, larger for large files), resumable
uploads, and the CLI as the path for very large images.

Consequence for backups (recorded with O9, commit 25): the streaming
backup job copies every object into ONE container, at most 10 000 × 8 MiB
≈ 78 GiB. A store holding 255 GB files cannot be copied into one .gbak;
backups of such stores become **manifests** — the rows plus a reference to
each object (key, size, its sealed hash), with the objects themselves
protected by the bucket's own versioning / Object Lock (D6). The copy
format stays for stores that fit.

*The design:* docs/LARGE-FILES.md — adaptive chunks, streamed parts and
uploads (31a), resumable uploads (31b), streaming downloads and export
with ZIP64 (31c).

## D13 — Formats

**Clean break.** There is no production data; v-next formats (store-key
authentication O3, content bound to its file O6, backup header integrity
O7) replace the current ones without migration code. (Done in commits
24–25: store records carry MACs; store values are GV04; backups are GB2.
Schema changes — not formats — DO migrate, through the ledger of O19.)

## D14 — Compliance targets

**SOC 2 / ISO 27001, ISO/IEC 27037 (digital evidence), CJIS.** Open point
to resolve before a CJIS claim: CJIS requires FIPS 140-validated crypto
modules. Browser WebCrypto (AES-GCM, ECDH P-256, HKDF) runs in the
platform's module; **ML-KEM-768 (@noble/post-quantum) and Argon2id
(hash-wasm) are not FIPS-validated today.** Options when it matters: run
the hybrid with the FIPS-validated half as the compliance boundary, or
switch to a validated ML-KEM implementation once available (FIPS 203).

## D15 — Lock

**Idle lock after 15 minutes**, and when the tab has been hidden for more
than 5. Within CJIS's 30-minute session-lock ceiling.

## D16 — Clients

**Web + CLI + desktop sync** (Windows Cloud Files, macOS File Provider,
Linux FUSE). Large evidence images go through the CLI/desktop path.

## Build order

The open findings first, in the agreed order — **O1 CSP → O2 Lock → O3
store-key authentication → O5 old versions on removal** — then the
remaining open findings, then D2/D4 (roles, cases, quorum), then D5–D8
(custody), then D11/D12, then the desktop shells.
