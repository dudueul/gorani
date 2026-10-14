// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:ownership — strict ownership attribution (first uploader) + the
 * contributors trail + what the duplicate check tells the uploader, in a
 * store several people write to. Since commit 27c that store is a CASE
 * (a lead no longer writes into another member's own area):
 *
 *   Jinu uploads "bread.txt" (owner: jinu, contributors: jinu).
 *   Mom uploads the SAME bytes (a twin by fingerprint) → the duplicate
 *   check names the twin's owner and contributors, so the dialog can say
 *   "identical to a file Mom keeps".
 *   Mom pushes an edit to Jinu's file → contributor "mom" is added; the
 *   owner stays jinu (strict: first uploader, never reassigned).
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith } from "../../web/src/vault/vault-crypto.ts";
import { member, vouch, openCase } from "../lib/team.mjs";

const dev = await suiteDev();
const enc = new TextEncoder();

async function uploadFile(email, base, fields, file) {
	const boundary = `t${Math.random().toString(16).slice(2)}`;
	const head = new TextEncoder().encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const body = new Uint8Array([...head, ...file, ...new TextEncoder().encode(`\r\n--${boundary}--\r\n`)]);
	const r = await fetch(`${dev.base}${base}/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": email }, body });
	return { status: r.status, json: await r.json() };
}

try {
	// Two members and the case they share.
	const mom = await member(dev, "mom", "lead", { email: "mom@family.test" });
	const jinu = await member(dev, "jinu", "analyst", { by: mom, email: "jinu@family.test" });
	await vouch(dev, mom, [jinu]);
	const kitchen = await openCase(dev, mom, "kitchen", "Family kitchen", [[jinu, "write"]]);
	const store = kitchen.sealer; // both hold the case key — the same sealer
	const BASE = kitchen.base;
	const ck = newContentKey();
	const key = await importContentKey(ck);
	const plain = enc.encode("the family bread recipe");
	const sealed = await sealWith(key, plain);
	const bread = await store.newFile("bread.txt", "text/plain", ck);

	// ── 1. Jinu uploads: owner jinu, contributor jinu ───────────────────
	const up = await uploadFile("jinu@family.test", BASE, { ...bread.fields, size: String(plain.length) }, sealed);
	assert.equal(up.status, 200, JSON.stringify(up.json));
	const list = await api(dev.base, "GET", `${BASE}/files/list?folder=all`, { email: "jinu@family.test" });
	assert.equal(list.json.files[0].owner, "jinu", "strict ownership: first uploader");

	// ── 2. Mom uploads the SAME bytes (a twin) → the match names her ───
	const up2 = await uploadFile("mom@family.test", BASE, { ...(await store.newFile("bread copy.txt", "text/plain", ck)).fields, size: String(plain.length) }, sealed);
	assert.equal(up2.status, 200);
	const match = await api(dev.base, "GET", `${BASE}/files/match?size=${plain.length}`, { email: "mom@family.test" });
	assert.ok(match.json.files.length >= 2);
	// Strict attribution: EACH file names ITS first uploader — Jinu's copy
	// says jinu, Mom's twin says mom. The dialog shows these, so the uploader
	// knows exactly which file the twin is ("identical to Mom's copy").
	const byOwner = Object.fromEntries(match.json.files.map((f) => [f.id, f.owner]));
	assert.equal(byOwner[up.json.id], "jinu", "Jinu's copy: owner jinu");
	assert.equal(byOwner[up2.json.id], "mom", "Mom's twin: owner mom");
	assert.ok(match.json.files.every((f) => typeof f.contributors === "string" && f.contributors.length > 0), "contributors ride along");

	// ── 3. Mom pushes an edit to Jinu's file → contributor mom, owner unchanged
	// An edit pushed by Mom: a VERSION of Jinu's file (the version endpoint).
	const boundary = `v${Math.random().toString(16).slice(2)}`;
	const vhead = new TextEncoder().encode(
		[
			["ck", await store.fileKey(bread.id, 2, ck)],
			["type", await store.fileType(bread.id, 2, "text/plain")],
			["size", String(plain.length)],
			["base_version", "1"],
		]
			.map(([k, v]) => `--${boundary}
Content-Disposition: form-data; name="${k}"

${v}
`)
			.join("") + `--${boundary}
Content-Disposition: form-data; name="file"; filename="s"

`,
	);
	const vbody = new Uint8Array([...vhead, ...sealed, ...new TextEncoder().encode(`
--${boundary}--
`)]);
	const vres = await fetch(`${dev.base}${BASE}/files/${up.json.id}/versions`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": "mom@family.test" }, body: vbody });
	const v2 = { status: vres.status, json: await vres.json() };
	assert.equal(v2.status, 200, JSON.stringify(v2.json));
	const after = await api(dev.base, "GET", `${BASE}/files/list?folder=all`, { email: "jinu@family.test" });
	const stillJinu = after.json.files.find((f) => f.id === up.json.id);
	assert.equal(stillJinu.owner, "jinu", "ownership is never reassigned");
	const match2 = await api(dev.base, "GET", `${BASE}/files/match?size=${plain.length}`, { email: "mom@family.test" });
	const withMom = match2.json.files.find((f) => f.id === up.json.id);
	assert.ok(withMom.contributors.includes("mom@family.test"), `mom in contributors: ${withMom.contributors}`);
	assert.equal(withMom.owner, "jinu", "owner never reassigned");
	// Owner email is a member email; the UI resolves display names via the registry.

	console.log("ok  api:ownership — first-uploader owner, contributors trail, duplicate details (in a shared case)");
} finally {
	await dev.close();
}