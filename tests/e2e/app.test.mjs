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
import { createCodeVault, createVault, createStoreKey, sealStoreKeyToMember } from "../../web/src/vault/keys.ts";
import { newContentKey, importContentKey, sealWith } from "../../web/src/vault/vault-crypto.ts";
import { storeSealer } from "../lib/placed.mjs";
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
	await api(dev.base, "POST", "/api/v1/family/members", { body: { id: "mom", name: "Mom", role: "lead", emails: ["mom@family.test"] } });
	const mom = await createVault("correct horse battery staple 42");
	const momSaved = await api(dev.base, "PUT", "/api/v1/members/mom/vault", { body: { settings: { enabled: true, keyId: mom.keyId, publicKey: mom.publicKey, pqPublicKey: mom.pqPublicKey, methods: mom.methods } } });
	assert.equal(momSaved.status, 200, JSON.stringify(momSaved.json));
	await api(dev.base, "POST", "/api/v1/family/members", { body: { id: "jinu", name: "Jinu", role: "analyst", emails: ["jinu@family.test"] } });
	const jinu = await createCodeVault();
	const filesStore = await createStoreKey();
	const own = await sealStoreKeyToMember(filesStore, { ec: jinu.publicKey, kem: jinu.pqPublicKey });
	const saved = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings: { enabled: true, keyId: jinu.keyId, publicKey: jinu.publicKey, pqPublicKey: jinu.pqPublicKey, methods: jinu.methods, stores: { files: own } } } });
	assert.equal(saved.status, 200);
	await api(dev.base, "POST", "/api/v1/family/members", { body: { id: "sora", name: "Sora", role: "analyst", emails: ["sora@family.test"] } });

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
		// The setup screen authenticated the files-store record from birth
		// (records.ts, O3): a MAC under the new root's record key.
		const soraVault = await api(dev.base, "GET", "/api/v1/members/sora/vault", { email: "sora@family.test" });
		assert.match(soraVault.json.stores.files.mac ?? "", /^[A-Za-z0-9+/]{43}=$/, "the store record carries its MAC from setup");
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
		// Jinu's record was seeded by this test WITHOUT a MAC (as a record
		// sealed to a member by someone else arrives): the first open pinned
		// it, and the shell saved the pin (trust on first use, O3).
		const jinuVault = await api(dev.base, "GET", "/api/v1/members/jinu/vault", { email: "jinu@family.test" });
		assert.match(jinuVault.json.stores.files.mac ?? "", /^[A-Za-z0-9+/]{43}=$/, "the first open pinned the record and saved it");
		// …and OPEN it: the viewer fetches the content key (POST files/keys —
		// the app used to send a GET there, so no file could ever be opened)
		// and decrypts in the page.
		await page.locator("text=hello.txt").first().dblclick();
		await page.locator("text=uploaded from the real browser").first().waitFor({ timeout: 30_000 });
		await page.keyboard.press("Escape");
		await assertNoViolations(page, "unlock → upload → open");

		// ── Streaming media through the service worker (O11) ───────────
		// A video over the 8 MiB streaming threshold opens as /media/<id>,
		// answered by the media service worker with decrypted bytes. Before
		// commit 25 it was registered at scope "/media/" — it controlled no
		// page the app shows, so these requests never reached it — and its
		// whole-file path used the wrong AAD. Both would fail right here.
		const clip = Buffer.alloc(9 * 1024 * 1024);
		for (let i = 0; i < clip.length; i++) clip[i] = (i * 7) % 251;
		await page.locator("gorani-win11 [data-upload]").first().setInputFiles({ name: "clip.mp4", mimeType: "video/mp4", buffer: clip });
		await page.locator("text=clip.mp4").first().waitFor({ timeout: 120_000 });
		await page.locator("text=clip.mp4").first().dblclick();
		const video = page.locator("gorani-viewer video").first();
		await video.waitFor({ state: "attached", timeout: 30_000 });
		const mediaUrl = (await video.getAttribute("src")) ?? "";
		assert.match(mediaUrl, /^\/media\//, `streamed through the media worker, not a blob (src=${mediaUrl})`);
		assert.equal(await page.evaluate(() => Boolean(navigator.serviceWorker.controller)), true, "the media worker controls the app page (scope /)");
		const ranged = await page.evaluate(async (u) => {
			const r = await fetch(u, { headers: { Range: "bytes=1000-1999" } });
			return { status: r.status, range: r.headers.get("content-range"), type: r.headers.get("content-type"), bytes: Array.from(new Uint8Array(await r.arrayBuffer())) };
		}, mediaUrl);
		assert.equal(ranged.status, 206);
		assert.equal(ranged.range, `bytes 1000-1999/${clip.length}`, "exactly the asked range, honestly labelled");
		assert.equal(ranged.type, "video/mp4", "the file's own type, not a guess");
		assert.deepEqual(ranged.bytes, Array.from(clip.subarray(1000, 2000)), "the decrypted bytes, byte for byte");
		// Close the viewer: the worker forgets this file's key — the URL stops working.
		await page.keyboard.press("Escape");
		await page.waitForFunction(async (u) => (await fetch(u, { headers: { Range: "bytes=0-9" } })).status === 404, mediaUrl, { timeout: 10_000 });
		// Everything else still goes to the network untouched (the worker never answers it).
		assert.equal(await page.evaluate(async () => (await fetch("/api/healthz")).status), 200);
		await assertNoViolations(page, "streamed media");

		// ── Lock means locked (docs/SECURITY-REVIEW.md › O2) ───────────
		// An image opened in the viewer is a blob: URL over DECRYPTED bytes.
		// After Lock, that handle must stop resolving, the explorer must be
		// gone (not hidden), and no device hold may remain.
		const PNG_1x1 = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==", "base64");
		await page.locator("gorani-win11 [data-upload]").first().setInputFiles({ name: "pixel.png", mimeType: "image/png", buffer: PNG_1x1 });
		await page.locator("text=pixel.png").first().waitFor({ timeout: 60_000 });
		await page.locator("text=pixel.png").first().dblclick();
		const img = page.locator("gorani-viewer img").first();
		await img.waitFor({ timeout: 30_000 });
		const src = (await img.getAttribute("src")) ?? "";
		assert.match(src, /^blob:/, "the decrypted image is a blob: URL");
		// Probe with an <img> load (img-src allows blob:). Not fetch(): the CSP's
		// connect-src is 'self' only, so page scripts cannot read a blob: URL
		// back at all — a welcome side effect of the policy.
		const loads = (u) => page.evaluate((url) => new Promise((ok) => {
			const probe = new Image();
			probe.onload = () => ok(true);
			probe.onerror = () => ok(false);
			probe.src = url;
		}), u);
		assert.equal(await loads(src), true, "…which resolves while unlocked");
		// Lock WITH the image still open — the case that matters (an idle or
		// hidden-tab lock arrives while plaintext is on screen; the overlay
		// covers the header, so the click is dispatched to the button).
		await page.getByRole("button", { name: "Lock" }).dispatchEvent("click");
		await page.getByPlaceholder(/Recovery code/).waitFor({ timeout: 30_000 });
		assert.equal(await page.locator("gorani-shell").count(), 0, "the explorer is unmounted, not hidden");
		assert.equal(await loads(src), false, "the decrypted image's blob: URL no longer resolves");
		assert.equal(await page.evaluate(() => Object.keys(sessionStorage).filter((k) => k.startsWith("gorani-hold:")).length), 0, "no device hold left in the tab");
		await assertNoViolations(page, "lock");
		await ctx.close();
	}

	// ── 3. Mom: a wrong password refuses; the right one unlocks ────────
	{
		const ctx = await guardedContext(browser, "mom@family.test");
		const page = await ctx.newPage();
		// A controllable clock for the idle lock (Playwright fakes Date and
		// timers; WebCrypto and the network are untouched).
		await page.clock.install();
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
		// The idle lock (D15: 15 minutes): no input for 15 minutes — the
		// vault locks itself and the lock screen returns.
		await page.clock.fastForward("14:00");
		assert.equal(await page.locator("gorani-shell").count(), 1, "14 idle minutes: still open");
		await page.clock.fastForward("01:05");
		await page.locator('input[type="password"]').waitFor({ timeout: 30_000 });
		assert.equal(await page.locator("gorani-shell").count(), 0, "15 idle minutes: locked by itself");
		await ctx.close();
	}

	// ── 4. The public share page under its own strict CSP ──────────────
	// A password-protected link: the page runs /s.js, the vendored Argon2id
	// (WebAssembly — the reason for 'wasm-unsafe-eval'), decrypts in the tab
	// and hands over a download. Trusted Types with NO policy: the page must
	// do all of it through textContent/classList.
	{
		const store = await storeSealer(filesStore.bundle, "jinu");
		const plain = new TextEncoder().encode("the incident timeline, shared with a partner CERT");
		const ck = newContentKey();
		const boundary = `e2e${Date.now()}`;
		const fields = { ...(await store.newFile("timeline.txt", "text/plain", ck)).fields, size: String(plain.length) };
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
			body: { id, fileId, version: 1, nameSealed: await store.shareName(id, "timeline.txt"), metaSealed: await sealShareMeta(keys.meta, id, { name: "timeline.txt", type: "text/plain", size: plain.length, modified: null }), expiresAt: new Date(Date.now() + 86_400_000).toISOString(), downloadsLeft: 2, size: plain.length, kdf },
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
	console.log("ok  e2e:app — CSP + Trusted Types delivered and violation-free; setup, recovery + password unlock, sealed upload, open, Lock revokes plaintext handles, 15-minute idle lock, refusal, password share page");
} finally {
	await dev.close();
}