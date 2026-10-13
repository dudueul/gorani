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

	// ── 1. Sora: first run — the setup screen generates keys in-browser ─
	{
		const ctx = await browser.newContext();
		await ctx.addInitScript((email) => localStorage.setItem("gorani-dev-email", email), "sora@family.test");
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
		await ctx.close();
	}

	// ── 2. Jinu: unlock with the recovery code, upload via the picker ──
	{
		const ctx = await browser.newContext();
		await ctx.addInitScript((email) => localStorage.setItem("gorani-dev-email", email), "jinu@family.test");
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
		await ctx.close();
	}

	// ── 3. Mom: a wrong password refuses; the right one unlocks ────────
	{
		const ctx = await browser.newContext();
		await ctx.addInitScript((email) => localStorage.setItem("gorani-dev-email", email), "mom@family.test");
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
		await ctx.close();
	}

	await browser.close();
	console.log("ok  e2e:app — boot, in-browser setup, recovery + password unlock, sealed upload, decrypted listing, refusal");
} finally {
	await dev.close();
}