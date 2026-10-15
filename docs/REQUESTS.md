# Upload links — outsiders send files into a folder or a case

> Copyright 2026- Seongwoo Hong. All rights reserved.
> Status: designed (decisions below, 2026-10-15); built in stages 38a–38d.

## The problem

Someone outside the team — a client, a partner's analyst, a victim's IT
person — needs to hand over files. A share link sends files OUT; nothing
let a stranger send files IN. `web/src/vault/request-crypto.ts` (commit ③)
kept the link cryptography of the original design, with no routes, page or
screen behind it, and that design no longer fits: it had the uploader's
browser seal "to your files key, exactly like your own uploads". Since
commit 25 (GV04) sealing into a store takes the store's PRIVATE key — a
stranger's browser cannot have it. The collectors hit the same wall
(docs/COLLECTORS.md); their answer is the one used here: the uploader seals
to an INBOX public key, and a person files each item with their own key.

## Decisions (asked 2026-10-15)

| Question | Decision |
|---|---|
| Destination | **Your folders and cases.** A link targets a folder of the member's own area, or a case. A member's area gets an inbox key of its own, as a case has. |
| Filing | **Review each.** Items wait in the inbox; a person accepts or rejects each, as with collectors. |
| Uploader | **Link + password.** The server checks a token derived from the link secret and the password, locks the link after repeated wrong passwords, and enforces expiry and file and byte limits. |
| Untrusted content | **Samples until accepted.** Accepting files an item as a malware sample (D8: the viewer refuses it, downloads are zipped under "infected") unless the person accepting chooses otherwise. |
| Scanning | **A local scanner hook and an opt-in hash lookup.** `gorani-sync accept --scan <cmd>` runs a scanner (ClamAV, or any command) on the decrypted bytes and refuses on a hit; a "Check hash" asks MalwareBazaar (abuse.ch) about the SHA-256 only, through the Worker, which holds the Auth-Key. |

Why scanning lives on the accepting member's side: the server holds
ciphertext only — no server-side or Cloudflare scanner can see a byte of
it. Plaintext exists in the accepting member's browser or CLI, and nowhere
else.

## The pieces

```text
area inbox key   a member's own area: a hybrid pair made in their browser, the private half
                 sealed under their files key into place store.inbox(member, key id) — in
                 their store (member migration v18), re-sealed by a store-key rotation.
                 A case keeps its inbox keys in the registry (docs/COLLECTORS.md).
link             /s/r/<id>#<secret>.<inbox key digest>
                 secret   32 random bytes: the view and send tokens and the note key derive
                          from it (request-crypto.ts); the server stores SHA-256 of each token
                 digest   the inbox key's full hybrid digest — the uploader's page refuses a
                          key the server serves if it does not hash to it, so a server that
                          substituted a key of its own would be caught before a byte is sealed
                 password mixed into the SEND token: needed to upload, not to read the note
record           in the target area's store: folder, inbox key id, token hashes, the note
                 (sealed with the note key — the uploader reads it, the server cannot), a
                 label (sealed with the store key — the owner's list), expiry, limits,
                 counters, failed attempts, lock, revocation; the registry maps id → area
upload           the uploader's browser: each file under a fresh content key (GV02 whole,
                 GC01 frames large), the key and a record { request, item, name, type, size,
                 SHA-256, the uploader's name and note } sealed to the inbox public key (GV03).
                 No signature: an outsider has no identity key. The record says what the
                 link-holder claimed; the link says who could have sent it.
inbox            the item lands beside collectors' items, from `request:<id>`
accept           a member with write access, after looking (and scanning): a new file in the
                 link's folder — name, type and key placed with the store key, their own
                 signed content hash and intake, the uploader's record beside it — as a
                 SAMPLE unless they choose otherwise
```

## What the server can and cannot do

- **Read uploads**: no — sealed to an inbox key whose private half only the
  area's owner (or the case's members) opens.
- **Substitute its own inbox key**: the uploader's page checks the key
  against the digest in the link's fragment, which never reaches it.
- **Upload without the password**: it holds hashes of the tokens, not the
  secret; a brute force needs the link — and the link locks.
- **Plant files**: anyone holding the link and the password can send bytes;
  so can the server, into its own inbox. Items are never filed without a
  person, and are filed as samples by default.
- **Withhold an item**: as with collectors, it can; the uploader's page
  shows what it sent.

## Stages

| Stage | What |
|---|---|
| 38a | Area inbox keys and the member's own inbox (list, read, accept, reject — as cases have). |
| 38b | Upload links: the record and index, the owner's routes, the public routes, the upload page. |
| 38c | Accepting an outsider's item (as a sample by default), the CLI's `--scan` hook, the MalwareBazaar lookup. |
| 38d | Tests (API, browser) and the docs. |
