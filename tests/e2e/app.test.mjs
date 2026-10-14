// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * e2e:app — the SPA itself, in a real browser (Playwright's chromium): the
 * boot flow, the setup screen (key generation in the browser), unlock by
 * recovery code and by password, a sealed upload through the file picker,
 * and the decrypted listing. This is the only suite where the browser's own
 * WebCrypto — non-extractable keys included — runs exactly as shipped.
 *
 * Identity in dev: the app attaches `x-gorani-dev-email` from localStorage
 * (web/src/lib/api.ts); the suite sets it per browser context, per member.
 * Skips when playwright or its chromium is missing (npm i -D playwright).
 */

import assert from "node:assert/strict";
import { startDev, api } from "../api/_dev.mjs";
import { createParentsMaster, createChildVault, createParentVault, createStoreKey, sealStoreKeyToMember, sealStoreKeyToMaster } from "../../web/src/vault/family.ts";
import { newContentKey, importContentKey, sealText, sealWith, wrapContentKey } from "../../web/src/vault/vault-crypto.ts";
import { sealChunked, DEFAULT_CHUNK } from "../../web/src/vault/chunked-file.ts";
import { newShareId, newShareSecret, newShareKdf, shareKeys, sealShareMeta } from "../../web/src/vault/share-crypto.ts";

/**
 * CSP + Trusted Types, watched (commit 24, docs/SECURITY-REVIEW.md › O1).
 * Every browser context records each `securitypolicyviolation` the page
 * raises; `assertNoViolations` fails the suite on any. A strict policy that
 * silently breaks a feature is found here, not by a user — and a policy that
 * is not delivered at all fails the header checks below.
 */
async function guardedContext(browser, email) {
	const ctx = await browser.newContext({ acceptDownloads: true });
	await ctx.addInitScript((e) => {
		if (e) localStorage.setItem("gorani-dev-email", e);
		globalThis.__csp = [];
		document.addEventListener("securitypolicyviolation", (v) => globalThis.__csp.push(`${v.effectiveDirective} ← ${v.blockedURI || "inline"} @ ${v.sourceFile}:${v.lineNumber}`));
	}, email);
	return ctx;
}
async function assertNoViolations(page, where) {
	const v = await page.evaluate(() => globalThis.__csp ?? []);
	assert.deepEqual(v, [], `${where}: the CSP blocked something the page needed`);
}

let chromium = null;
try {
	chromium = (await import("playwright")).chromium;
} catch {
	// not installed — the suite reports a skip rather than a failure
}
if (!chromium) {
	console.log("skip  e2e:app — install it with: npm i -D playwright");
	process.exit(0);
}

const dev = await startDev();
try {
	// ── seed: mom (password vault), jinu (recovery vault), sora (none) ──
	await api(dev.base, "POST", "/api/v1/family/members", { body: { id: "mom", name: "Mom", role: "parent", emails: ["mom@family.test"] } });
	const master = await createParentsMaster();
	await api(dev.base, "PUT", "/api/v1/family/master", { body: { keyId: master.keyId, publicKey: master.publicKey } });
	const mom = await createParentVault("correct horse battery staple 42");
	const momSaved = await api(dev.base, "PUT", "/api/v1/members/mom/vault", { body: { settings: { enabled: true, keyId: mom.keyId, publicKey: mom.publicKey, pqPublicKey: mom.pqPublicKey, methods: mom.methods, guardian: null } } });
	assert.equal(momSaved.status, 200, JSON.stringify(momSaved.json));
	await api(dev.base, "POST", "/api/v1/family/members", { body: { id: "jinu", name: "Jinu", role: "child", emails: ["jinu@family.test"] } });
	const jinu = await createChildVault();
	const filesStore = await createStoreKey();
	const own = await sealStoreKeyToMember(filesStore, { ec: jinu.publicKey, kem: jinu.pqPublicKey });
	const guardian = await sealStoreKeyToMaster(filesStore, master);
	const saved = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { body: { settings: { enabled: true, keyId: jinu.keyId, publicKey: jinu.publicKey, pqPublicKey: jinu.pqPublicKey, methods: jinu.methods, stores: { files: own }, guardian } } });
	assert.equal(saved.status, 200);
	await api(dev.base, "POST", "/api/v1/family/members", { body: { id: "sora", name: "Sora", role: "child", emails: ["sora@family.test"] } });

	const browser = await chromium.launch({ headless: true });

	// ── 0. The headers are DELIVERED (they were promised for 22 commits and
	// never sent: static assets bypass the Worker) ─────────────────────────
	{
		const app = await fetch(`${dev.base}/`);
		const csp = app.headers.get("content-security-policy") ?? "";
		assert.match(csp, /default-src 'none'/, "the app's CSP is sent (web/public/_headers)");
		assert.match(csp, /require-trusted-types-for 'script'/, "Trusted Types are required");
		assert.match(csp, /frame-ancestors 'none'/);
		assert.doesNotMatch(csp, /unsafe-inline|'unsafe-eval'/, "no inline script or eval allowance");
		assert.equal(app.headers.get("x-content-type-options"), "nosniff");
		const fallback = await fetch(`${dev.base}/some/deep/route`);
		assert.match(fallback.headers.get("content-security-policy") ?? "", /require-trusted-types-for/, "the SPA fallback (index.html for any path) carries the policy too");
		const apiRes = await fetch(`${dev.base}/api/healthz`);
		assert.match(apiRes.headers.get("content-security-policy") ?? "", /^default-src 'none'/, "Worker responses carry the nothing-renders policy (lib.rs › harden)");
		assert.equal(apiRes.headers.get("cache-control"), "no-store");
	}

	// ── 1. Sora: first run — the setup screen generates keys in-browser ─
	{
		const ctx = await guardedContext(browser, "sora@family.test");
		const page = await ctx.newPage();
		page.on("pageerror", (e) => console.error("PAGEERROR:", String(e).slice(0, 250)));
		page.on("response", (r) => { if (r.url().includes("/api/") && r.status() >= 400) console.error(`HTTP ${r.status()} ${r.request().method()} ${r.url().replace(dev.base, "")}`); });
		await page.goto(dev.base);
		await page.getByText("Who's opening?").waitFor({ timeout: 30_000 });
		await page.getByRole("button", { name: /Sora/ }).click();
		await page.getByPlaceholder("Password (12+ chars)").fill("sora's very long password!");
		await page.getByPlaceholder("Repeat it").fill("sora's very long password!");
		await page.getByRole("button", { name: "Create the vault" }).click();
		await page.getByText("Write this down — once").waitFor({ timeout: 30_000 });
		const codeShown = (await page.locator("code").first().textContent())?.trim() ?? "";
		assert.match(codeShown, /-/, "the recovery code is shown once, in the page");
		await page.getByRole("button", { name: "I wrote it down" }).click();
		// The lock screen: the vault this browser just created unlocks with
		// the password it was created with — setup to session in one tab.
		const pwInput = page.locator('input[type="password"]');
		await pwInput.waitFor({ timeout: 30_000 });
		await pwInput.fill("sora's very long password!");
		await page.getByRole("button", { name: "Unlock" }).click();
		await page.locator("gorani-win11 [data-upload]").first().waitFor({ state: "attached", timeout: 30_000 });
		assert.ok(await page.evaluate(() => isSecureContext && !!crypto.subtle), "the app runs in a secure context with WebCrypto");
		// Icons are SVG elements now (they used to render as escaped text).
		assert.ok(await page.locator("gorani-win11 svg").count() > 0, "file-type icons render as SVG, not as markup text");
		await assertNoViolations(page, "setup → unlock");
		// Trusted Types are ENFORCED, not just declared: a string → HTML sink
		// throws, because no policy the CSP allows will mint TrustedHTML —
		// and the refusal is reported (exactly one violation: this probe).
		const sink = await page.evaluate(() => {
			try {
				document.createElement("div").innerHTML = "<img src=x onerror=alert(1)>";
				return "allowed";
			} catch {
				return "blocked";
			}
		});
		assert.equal(sink, "blocked", "innerHTML with a plain string is refused (Trusted Types)");
		const reported = await page.evaluate(() => globalThis.__csp);
		assert.equal(reported.length, 1, `the probe's refusal is the only violation: ${JSON.stringify(reported)}`);
		assert.match(reported[0], /^require-trusted-types-for/);
		await ctx.close();
	}

	// ── 2. Jinu: unlock with the recovery code, upload via the picker ──
	{
		const ctx = await guardedContext(browser, "jinu@family.test");
		const page = await ctx.newPage();
		page.on("pageerror", (e) => console.error("PAGEERROR:", String(e).slice(0, 250)));
		page.on("response", (r) => { if (r.url().includes("/api/") && r.status() >= 400) console.error(`HTTP ${r.status()} ${r.request().method()} ${r.url().replace(dev.base, "")}`); });
		await page.goto(dev.base);
		await page.getByText("Who's opening?").waitFor({ timeout: 30_000 });
		await page.getByRole("button", { name: /Jinu/ }).click();
		await page.getByPlaceholder(/Recovery code/).fill(jinu.recoveryCode);
		await page.getByRole("button", { name: "Unlock" }).click();
		await page.locator("gorani-win11 [data-upload]").first().waitFor({ state: "attached", timeout: 30_000 });
		// A sealed upload through the file picker; the listing decrypts the
		// name in-browser — the whole round trip with no test-side crypto.
		await page.locator("gorani-win11 [data-upload]").first().setInputFiles({ name: "hello.txt", mimeType: "text/plain", buffer: Buffer.from("uploaded from the real browser") });
		await page.locator("text=hello.txt").first().waitFor({ timeout: 60_000 });
		// …and OPEN it: the viewer fetches the content key (POST files/keys —
		// the app used to send a GET there, so no file could ever be opened)
		// and decrypts in the page.
		await page.locator("text=hello.txt").first().dblclick();
		await page.locator("text=uploaded from the real browser").first().waitFor({ timeout: 30_000 });
		await assertNoViolations(page, "unlock → upload → open");
		await ctx.close();
	}

	// ── 3. Mom: a wrong password refuses; the right one unlocks ────────
	{
		const ctx = await guardedContext(browser, "mom@family.test");
		const page = await ctx.newPage();
		page.on("pageerror", (e) => console.error("PAGEERROR:", String(e).slice(0, 250)));
		page.on("response", (r) => { if (r.url().includes("/api/") && r.status() >= 400) console.error(`HTTP ${r.status()} ${r.request().method()} ${r.url().replace(dev.base, "")}`); });
		await page.goto(dev.base);
		await page.getByText("Who's opening?").waitFor({ timeout: 30_000 });
		await page.getByRole("button", { name: /Mom/ }).click();
		const pw = page.locator('input[type="password"]');
		await pw.waitFor({ timeout: 30_000 });
		await pw.fill("deliberately wrong password");
		await page.getByRole("button", { name: "Unlock" }).click();
		await page.locator("text=/try again|wrong|incorrect/i").first().waitFor({ timeout: 30_000 });
		await pw.fill("correct horse battery staple 42");
		await page.getByRole("button", { name: "Unlock" }).click();
		await page.locator("gorani-win11 [data-upload]").first().waitFor({ state: "attached", timeout: 30_000 });
		await assertNoViolations(page, "wrong password → right password");
		await ctx.close();
	}

	// ── 4. The public share page under its own strict CSP ──────────────
	// A password-protected link: the page runs /s.js, the vendored Argon2id
	// (WebAssembly — the reason for 'wasm-unsafe-eval'), decrypts in the tab
	// and hands over a download. Trusted Types with NO policy: the page must
	// do all of it through textContent/classList.
	{
		const storePublic = { ec: filesStore.publicKey, kem: filesStore.pqPublicKey };
		const plain = new TextEncoder().encode("the incident timeline, shared with a partner CERT");
		const ck = newContentKey();
		const boundary = `e2e${Date.now()}`;
		const fields = { ck: await wrapContentKey(storePublic, ck), name: await sealText(storePublic, "timeline.txt"), size: String(plain.length) };
		const sealed = await sealWith(await importContentKey(ck), plain);
		const head = new TextEncoder().encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
		const up = await fetch(`${dev.base}/api/v1/members/jinu/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": "jinu@family.test" }, body: new Uint8Array([...head, ...sealed, ...new TextEncoder().encode(`\r\n--${boundary}--\r\n`)]) });
		assert.equal(up.status, 200);
		const fileId = (await up.json()).id;
		const id = newShareId();
		const secret = newShareSecret();
		const kdf = newShareKdf();
		const keys = await shareKeys(id, secret, "partner-passphrase", kdf);
		const start = await api(dev.base, "POST", "/api/v1/members/jinu/files/shares", {
			email: "jinu@family.test",
			body: { id, fileId, version: 1, nameSealed: await sealText(storePublic, "timeline.txt"), metaSealed: await sealShareMeta(keys.meta, id, { name: "timeline.txt", type: "text/plain", size: plain.length, modified: null }), expiresAt: new Date(Date.now() + 86_400_000).toISOString(), downloadsLeft: 2, size: plain.length, kdf },
		});
		assert.equal(start.status, 200, JSON.stringify(start.json));
		const part = await fetch(`${dev.base}/api/v1/members/jinu/files/shares/${id}/parts/1`, { method: "PUT", headers: { "x-gorani-dev-email": "jinu@family.test" }, body: await sealChunked(keys.data, plain, DEFAULT_CHUNK) });
		const done = await api(dev.base, "POST", `/api/v1/members/jinu/files/shares/${id}/complete`, { email: "jinu@family.test", body: { parts: [{ partNumber: 1, etag: (await part.json()).etag }], size: plain.length } });
		assert.equal(done.status, 200, JSON.stringify(done.json));

		const ctx = await guardedContext(browser, null);
		const page = await ctx.newPage();
		page.on("pageerror", (e) => console.error("PAGEERROR:", String(e).slice(0, 250)));
		const res = await page.goto(`${dev.base}/s/f/${id}#${secret}`);
		const csp = res.headers()["content-security-policy"] ?? "";
		assert.match(csp, /trusted-types 'none'/, "the share page allows no Trusted Types policy at all");
		assert.match(csp, /script-src 'self' 'wasm-unsafe-eval'/);
		await page.getByPlaceholder("Password").fill("partner-passphrase");
		await page.getByRole("button", { name: "Unlock" }).click();
		await page.locator("#name", { hasText: "timeline.txt" }).waitFor({ timeout: 60_000 });
		assert.equal(new URL(page.url()).hash, "", "the link secret is gone from the address bar once read");
		const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Download" }).click()]);
		const got = await (await import("node:fs/promises")).readFile(await download.path());
		assert.equal(got.toString(), new TextDecoder().decode(plain), "the partner receives the exact plaintext");
		assert.equal(download.suggestedFilename(), "timeline.txt");
		await assertNoViolations(page, "share page: password → Argon2id → decrypt → download");
		await ctx.close();
	}

	await browser.close();
	console.log("ok  e2e:app — CSP + Trusted Types delivered and violation-free; setup, recovery + password unlock, sealed upload, open, refusal, password share page");
} finally {
	await dev.close();
}