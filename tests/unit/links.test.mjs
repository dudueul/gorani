// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Share links (GS01) and file requests (GR01): the key material lives in the
 * URL fragment, the server stores only sealed bytes and token hashes. These
 * tests are the behaviors the server's routes will rely on (commit ⑪):
 * password-gated opens, id binding, and tokens that change with the password.
 */

import assert from "node:assert/strict";
import { shareKeys, sealShareMeta, openShareMeta, newShareId, newShareSecret, newShareKdf, isSealedShareMeta, isShareId, isShareSecret } from "../../web/src/vault/share-crypto.ts";
import { requestKeys, sealRequestNote, openRequestNote, tokenHash, newRequestId, newRequestSecret, isSealedRequestNote } from "../../web/src/vault/request-crypto.ts";

// ── share links ─────────────────────────────────────────────────────
const id = newShareId();
const secret = newShareSecret();
assert.ok(isShareId(id) && isShareSecret(secret));

// No password: the secret alone derives both keys.
const keys = await shareKeys(id, secret);
const meta = { name: "가족사진.jpg", type: "image/jpeg", size: 123456, modified: "2026-10-13T01:02:03Z" };
const sealedMeta = await sealShareMeta(keys.meta, id, meta);
assert.ok(isSealedShareMeta(sealedMeta));
assert.deepEqual(await openShareMeta(keys.meta, id, sealedMeta), meta);

// With a password: the same secret is not enough — the link needs it too.
const kdf = newShareKdf();
const pwKeys = await shareKeys(id, secret, "FamilyPhotos2026", kdf);
const pwSealed = await sealShareMeta(pwKeys.meta, id, meta);
assert.notEqual(sealedMeta, pwSealed, "the password is in the key");
assert.deepEqual(await openShareMeta(pwKeys.meta, id, pwSealed), meta);
await assert.rejects(() => shareKeys(id, secret, null, kdf), /needs its password/);
await assert.rejects(() => openShareMeta(keys.meta, id, pwSealed), /Wrong password/);
await assert.rejects(() => openShareMeta(pwKeys.meta, id, pwSealed, undefined).catch((e) => { throw e; }).then(() => shareKeys(id, secret, "wrong-password", kdf)).then((k) => openShareMeta(k.meta, id, pwSealed)), /Wrong password/);

// The id is bound into the salt and the AAD: move the meta under another id and it opens nothing.
const otherId = newShareId();
assert.notEqual(otherId, id);
await assert.rejects(() => openShareMeta(keys.meta, otherId, sealedMeta));

// ── file requests ───────────────────────────────────────────────────
const rid = newRequestId();
const rsecret = newRequestSecret();
const open = await requestKeys(rid, rsecret);
const gated = await requestKeys(rid, rsecret, "drop-box-2026");

// The view and note keys are the same either way; only the send token changes.
assert.equal(open.view, gated.view);
const note = "Leave the photos here — thank you!";
const sealedNote = await sealRequestNote(open.note, rid, note);
assert.ok(isSealedRequestNote(sealedNote));
assert.equal(await openRequestNote(gated.note, rid, sealedNote), note);
assert.notEqual(open.send, gated.send, "the password changes the send token");

// Tokens hash to stable hex (what the server stores instead of secrets).
const h1 = await tokenHash(open.view);
const h2 = await tokenHash(open.view);
assert.equal(h1, h2);
assert.match(h1, /^[0-9a-f]{64}$/);

// The id binds the note, as it binds the share meta.
await assert.rejects(() => openRequestNote(open.note, newRequestId(), sealedNote));

console.log("ok  links: share + request key material");