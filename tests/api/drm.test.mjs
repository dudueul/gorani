// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:drm — protected copies, the server's half (commit 40b, docs/DRM.md).
 *
 * Its own server, with a DRM_KEY_SECRET and throwaway FairPlay credentials
 * made when the suite starts (tests/lib/fairplay-client.mjs: a fresh RSA
 * key, a random ASK — nothing of Apple's). The suite is the lead's browser
 * (it packages the copy with the same WebAssembly engine, from the plaintext
 * it uploaded) and the player (it builds SPCs and opens CKCs with a second,
 * JavaScript implementation of the protocol):
 *
 *   1. only a lead protects; the key material comes back once, and the
 *      copy is uploaded in parts and completed with its layout — a layout
 *      that does not tile what was uploaded is refused and the copy deleted;
 *   2. the original goes to the lead and nobody else on the case: the
 *      analyst and the external are refused, with the reason;
 *   3. everyone on the case plays: the playlist names the key by `skd://`
 *      and addresses one object by byte ranges that tile it; the media
 *      route returns exactly the bytes packaged; the certificate is served;
 *   4. the license: an SPC for this copy's key gets a CKC that opens to
 *      the very key the lead packaged with, HDCP Type 0 required; an SPC
 *      for another key is refused; every license is in the case's trail;
 *   5. a view-only link (from the lead's own area): its claim needs the
 *      proof derived from the link's secret and password; the session's
 *      signed URLs play and a forged one does not; the license needs the
 *      session's token; the link has nothing to download; revoking it ends
 *      the next license;
 *   6. protection off: the original is everyone's again, the copy gone.
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { startDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith } from "../../web/src/vault/vault-crypto.ts";
import { mediaEngine } from "../../web/src/lib/media-engine.ts";
import { indexVideo } from "../../web/src/lib/video-index.ts";
import { member, vouch, openCase, signedHash } from "../lib/team.mjs";
import { videoFixture, mediaWasm } from "../lib/video-fixtures.mjs";
import { throwawayCredentials, buildSpc, openCkc, dHash, TAG, HDCP_TYPE0 } from "../lib/fairplay-client.mjs";

// The JavaScript player agrees with the published D-function vectors first:
// a second implementation is only a check if it is right on its own.
assert.equal(Buffer.from(dHash(Buffer.from("a4c411c54d94727143504aece5613da8c6ee6dd2", "hex"))).toString("hex"), "3a24a068c116842f10fac5c86cb1cb5c");

const fps = throwawayCredentials();
const dev = await startDev({ vars: { DRM_KEY_SECRET: crypto.randomBytes(32).toString("hex"), ...fps.vars } });
const enc = new TextEncoder();
const engine = await mediaEngine(mediaWasm());
const clip = new Uint8Array(fs.readFileSync(videoFixture("h264-high.mp4")));

/** Upload the clip as a new file into `area` (its sealer seals the fields). */
async function upload(who, sealer, base) {
	const ck = newContentKey();
	const id = sealer.newId();
	const fields = { file_id: id, name: await sealer.fileName(id, "clip.mp4"), type: await sealer.fileType(id, 1, "video/mp4"), ck: await sealer.fileKey(id, 1, ck), size: String(clip.length), hash: await signedHash(who, sealer, id, 1, clip) };
	const boundary = `d${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const r = await fetch(`${dev.base}${base}/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...(await sealWith(await importContentKey(ck), clip)), ...enc.encode(`\r\n--${boundary}--\r\n`)]) });
	assert.equal(r.status, 200, await r.text());
	return id;
}

/** The lead's browser: package the clip with `material`, as one object and its layout. */
async function packageClip(material) {
	const found = await indexVideo(async (o, l) => clip.slice(o, Math.min(o + l, clip.length)), clip.length, null, engine);
	const p = found.index.protect(material);
	try {
		const init = p.init();
		const parts = [init];
		const segments = [];
		let at = init.length;
		for (let n = 0; n < found.index.segments.length; n++) {
			const joined = Buffer.concat(p.plan(n).map(([o, l]) => clip.subarray(o, o + l)));
			const seg = p.segment(n, joined);
			segments.push([at, seg.length, found.index.segments[n][1]]);
			at += seg.length;
			parts.push(seg);
		}
		return { bytes: Buffer.concat(parts), layout: { init: [0, init.length], segments } };
	} finally {
		p.drop();
		found.index.drop();
	}
}

/** Protect `file` in `base` as `who`: start, upload in one part, complete. */
async function protect(who, base, file, { layout: forged } = {}) {
	const start = await api(dev.base, "POST", `${base}/files/${file}/drm`, { email: who.email, body: { version: 1 } });
	assert.equal(start.status, 200, start.text);
	const material = new Uint8Array(Buffer.from(start.json.material, "base64"));
	assert.equal(material.length, 48);
	const copy = await packageClip(material);
	const put = await fetch(`${dev.base}${base}/files/${file}/drm/1/parts/1`, { method: "PUT", headers: { "x-gorani-dev-email": who.email, "content-length": String(copy.bytes.length) }, body: copy.bytes });
	const putText = await put.text();
	assert.equal(put.status, 200, putText);
	const { etag } = JSON.parse(putText);
	const done = await api(dev.base, "POST", `${base}/files/${file}/drm/1/complete`, { email: who.email, body: { parts: [{ partNumber: 1, etag }], layout: forged ?? copy.layout } });
	return { done, material, copy, kid: start.json.kid };
}

const get = (who, path, headers = {}) => fetch(`${dev.base}${path}`, { headers: { "x-gorani-dev-email": who.email, ...headers } });

try {
	const ana = await member(dev, "ana", "lead");
	const bo = await member(dev, "bo", "analyst", { by: ana });
	const tomorrow = new Date(Date.now() + 86_400_000).toISOString();
	const eve = await member(dev, "eve", "external", { by: ana, extra: { expiresAt: tomorrow } });
	await vouch(dev, ana, [bo, eve]);
	const kase = await openCase(dev, ana, "film-c1", "A case with a video", [[bo, "write"], [eve, "read", tomorrow]]);
	const file = await upload(ana, kase.sealer, kase.base);

	// ── 1. Only a lead protects; a lying layout is refused ────────────
	const notLead = await api(dev.base, "POST", `${kase.base}/files/${file}/drm`, { email: bo.email, body: { version: 1 } });
	assert.equal(notLead.status, 403, notLead.text);
	assert.match(notLead.json.error, /only a lead protects/);
	const forged = await protect(ana, kase.base, file, { layout: { init: [0, 100], segments: [[100, 50, 4]] } });
	assert.equal(forged.done.status, 400, forged.done.text);
	assert.match(forged.done.json.error, /layout does not match/);
	const { done, material, copy, kid } = await protect(ana, kase.base, file);
	assert.equal(done.status, 200, done.text);
	assert.equal(kid, Buffer.from(material.subarray(16, 32)).toString("hex"), "the key id is the material's middle third");
	const state = await api(dev.base, "GET", `${kase.base}/files/${file}/drm`, { email: bo.email });
	assert.equal(state.json.protected, true);
	assert.equal(state.json.original, false, "bo plays the copy");
	assert.equal(state.json.copies[0].state, "ready");
	assert.equal(state.json.copies[0].segments, copy.layout.segments.length);
	assert.ok(!state.text.includes("keySealed") && !state.text.includes(start64(material)), "no key material in what the app reads");

	// ── 2. The original: the lead's only ──────────────────────────────
	assert.equal((await get(ana, `${kase.base}/files/${file}`)).status, 200, "the lead downloads the original");
	for (const who of [bo, eve]) {
		const r = await get(who, `${kase.base}/files/${file}`);
		assert.equal(r.status, 403, `${who.id}: the original is refused`);
		assert.match((await r.json()).error, /protected/);
	}

	// ── 3. Everyone on the case plays ─────────────────────────────────
	const pl = await get(eve, `${kase.base}/files/${file}/drm/1/playlist`);
	assert.equal(pl.status, 200, await pl.clone().text());
	assert.equal(pl.headers.get("content-type"), "application/vnd.apple.mpegurl");
	const text = await pl.text();
	assert.ok(text.includes(`#EXT-X-KEY:METHOD=SAMPLE-AES,URI="skd://${kid}",KEYFORMAT="com.apple.streamingkeydelivery"`), text);
	const ranges = [...text.matchAll(/BYTERANGE[=:]"?(\d+)@(\d+)/g)].map((m) => [Number(m[2]), Number(m[1])]);
	assert.equal(ranges.length, copy.layout.segments.length + 1, "the map and every segment");
	let at = 0;
	for (const [offset, length] of ranges) {
		assert.equal(offset, at, "the ranges tile the object");
		at += length;
	}
	assert.equal(at, copy.bytes.length);
	const [o, l] = ranges[2];
	const media = await get(bo, `${kase.base}/files/${file}/drm/1/media`, { range: `bytes=${o}-${o + l - 1}` });
	assert.equal(media.status, 206);
	assert.deepEqual(Buffer.from(await media.arrayBuffer()), copy.bytes.subarray(o, o + l), "the media route serves the packaged bytes");
	const cert = await get(bo, "/api/v1/drm/fairplay/certificate");
	assert.deepEqual(Buffer.from(await cert.arrayBuffer()), fps.cert);

	// ── 4. The license ────────────────────────────────────────────────
	for (const who of [bo, eve]) {
		const { spc, session } = buildSpc(fps, `skd://${kid}`);
		const r = await fetch(`${dev.base}${kase.base}/files/${file}/drm/1/license`, { method: "POST", headers: { "x-gorani-dev-email": who.email }, body: spc });
		assert.equal(r.status, 200, await r.clone().text());
		const opened = openCkc(session, new Uint8Array(await r.arrayBuffer()));
		assert.deepEqual(new Uint8Array(opened.key), material.subarray(0, 16), `${who.id}: the CKC carries the key the copy was packaged with`);
		const hdcp = opened.tllvs.find(([t]) => t === TAG.HDCP_ENFORCEMENT)?.[1];
		assert.equal(hdcp && Buffer.from(hdcp).readBigUInt64BE(0), HDCP_TYPE0, "HDCP Type 0 required (docs/DRM.md › Decisions)");
	}
	const other = buildSpc(fps, `skd://${"00".repeat(16)}`);
	const wrong = await fetch(`${dev.base}${kase.base}/files/${file}/drm/1/license`, { method: "POST", headers: { "x-gorani-dev-email": bo.email }, body: other.spc });
	assert.equal(wrong.status, 400, "an SPC for another key gets nothing");
	assert.match((await wrong.json()).error, /may not have/);
	const trail = await api(dev.base, "GET", `${kase.base}/audit`, { email: ana.email });
	const actions = (trail.json.lines ?? trail.json.audit ?? trail.json).map?.((x) => x.action) ?? [];
	for (const a of ["drm.protect", "drm.ready", "drm.license"]) assert.ok(actions.includes(a), `${a} in the case's trail (${actions.join(", ")})`);

	// ── 5. A view-only link from the lead's own area ──────────────────
	const own = await upload(ana, ana.sealer, "/api/v1/members/ana");
	const mine = await protect(ana, "/api/v1/members/ana", own);
	assert.equal(mine.done.status, 200, mine.done.text);
	const shareId = crypto.randomBytes(18).toString("base64url");
	const proof = crypto.randomBytes(32).toString("base64url");
	const claimHash = crypto.createHash("sha256").update(proof).digest("base64url");
	const link = {
		id: shareId, fileId: own, version: 1, drm: true, claimHash,
		nameSealed: await ana.sealer.shareName(shareId, "clip.mp4"),
		metaSealed: Buffer.concat([Buffer.from("GS01"), crypto.randomBytes(40)]).toString("base64"),
		kdf: { m: 19 * 1024, t: 2, p: 1, salt: crypto.randomBytes(16).toString("base64") },
		expiresAt: new Date(Date.now() + 86_400_000).toISOString().replace(/\.\d+Z$/, "Z"), downloadsLeft: 3,
	};
	const noProof = await api(dev.base, "POST", "/api/v1/members/ana/files/shares", { email: ana.email, body: { ...link, claimHash: undefined } });
	assert.equal(noProof.status, 400, "a view-only link carries its claim hash");
	const made = await api(dev.base, "POST", "/api/v1/members/ana/files/shares", { email: ana.email, body: link });
	assert.equal(made.status, 200, made.text);
	const meta = await (await fetch(`${dev.base}/s/f/${shareId}/meta`)).json();
	assert.equal(meta.viewOnly, true);
	const claim = (body) => fetch(`${dev.base}/s/f/${shareId}/claim`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
	assert.equal((await claim({})).status, 403, "the link's path alone claims nothing");
	assert.equal((await claim({ proof: crypto.randomBytes(32).toString("base64url") })).status, 403, "nor a wrong password");
	const session = await (await claim({ proof })).json();
	assert.ok(session.token && session.playlist, JSON.stringify(session));
	const plUrl = `${dev.base}/s/f/${shareId}/${session.playlist}`;
	const linkPl = await (await fetch(plUrl)).text();
	assert.ok(linkPl.includes(`skd://${mine.kid}`), linkPl);
	const mediaPath = /\n(media\?[^\n]+)\n/.exec(linkPl)[1];
	const firstSeg = /#EXT-X-BYTERANGE:(\d+)@(\d+)/.exec(linkPl);
	const [len, off] = [Number(firstSeg[1]), Number(firstSeg[2])];
	const linkMedia = await fetch(`${dev.base}/s/f/${shareId}/drm/${mediaPath}`, { headers: { range: `bytes=${off}-${off + len - 1}` } });
	assert.equal(linkMedia.status, 206);
	assert.deepEqual(Buffer.from(await linkMedia.arrayBuffer()), mine.copy.bytes.subarray(off, off + len));
	const forgedUrl = plUrl.replace(/m=[0-9a-f]+/, `m=${"0".repeat(64)}`);
	assert.equal((await fetch(forgedUrl)).status, 403, "a URL the Worker did not sign plays nothing");
	const linkLicense = (token) => {
		const s = buildSpc(fps, `skd://${mine.kid}`);
		return fetch(`${dev.base}/s/f/${shareId}/drm/license`, { method: "POST", headers: token ? { "x-gorani-share-token": token } : {}, body: s.spc }).then(async (r) => ({ r, s }));
	};
	assert.equal((await linkLicense(null)).r.status, 403, "the license needs the session's token");
	const { r: lic, s } = await linkLicense(session.token);
	assert.equal(lic.status, 200, await lic.clone().text());
	assert.deepEqual(new Uint8Array(openCkc(s.session, new Uint8Array(await lic.arrayBuffer())).key), mine.material.subarray(0, 16));
	const data = await fetch(`${dev.base}/s/f/${shareId}/data`, { headers: { "x-gorani-share-token": session.token } });
	assert.equal(data.status, 409, "a view-only link has nothing to download");
	assert.equal((await api(dev.base, "DELETE", `/api/v1/members/ana/files/shares/${shareId}`, { email: ana.email })).status, 200);
	assert.equal((await linkLicense(session.token)).r.status, 403, "revoked: the next license is refused");

	// ── 6. Protection off ─────────────────────────────────────────────
	const notLeadOff = await api(dev.base, "DELETE", `${kase.base}/files/${file}/drm`, { email: bo.email });
	assert.equal(notLeadOff.status, 403);
	const unprotected = await api(dev.base, "DELETE", `${kase.base}/files/${file}/drm`, { email: ana.email });
	assert.equal(unprotected.status, 200, unprotected.text);
	assert.equal((await get(bo, `${kase.base}/files/${file}`)).status, 200, "the original is bo's again");
	assert.equal((await get(bo, `${kase.base}/files/${file}/drm/1/playlist`)).status, 404, "and the copy is gone");

	console.log("ok  api:drm — a lead protects (a lying layout refused); the original is the lead's, the case plays the copy: skd:// playlist tiling one object, the packaged bytes by range, the certificate; a license opens to the packaging key with HDCP Type 0, another key's SPC gets nothing, all in the trail; a view-only link claims with its proof only, plays by signed URLs (a forged one does not), licenses with its token, downloads nothing, and stops at revocation; protection off gives the original back");
} finally {
	await dev.close();
}

function start64(material) {
	return Buffer.from(material.subarray(0, 16)).toString("base64").slice(0, 16);
}
