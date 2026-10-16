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
import { newContentKey, importContentKey, sealWith, sealText, wrapContentKey } from "../../web/src/vault/vault-crypto.ts";
import { inboxStatements } from "../../web/src/vault/inbox.ts";
import { sha256Hex } from "../../web/src/vault/content-hash.ts";
import { storeSealer } from "../lib/placed.mjs";
import { member, pinIdentity, trustOf } from "../lib/team.mjs";
import { approveCollector } from "../../web/src/vault/collectors.ts";
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
	const browser = await chromium.launch({ headless: true });

	// ── 00. A fresh deployment: the first lead, from the browser (39k) ────
	// Until commit 39k an empty registry showed "No members yet" and nothing
	// to do about it; the first lead needed a hand-made API call with the
	// bootstrap token. (This dev server sets no BOOTSTRAP_TOKEN, which dev
	// mode allows — api:bootstrap and api:access prove the token itself.)
	{
		const ctx = await guardedContext(browser, "mom@family.test");
		const page = await ctx.newPage();
		await page.goto(dev.base);
		await page.getByText("Create the first lead").waitFor({ timeout: 30_000 });
		await page.locator('input[name="member-id"]').fill("Mom!");
		await page.getByRole("button", { name: "Create" }).click();
		await page.getByText("Member id: 2–32 characters").waitFor();
		await page.locator('input[name="member-id"]').fill("mom");
		await page.locator('input[name="member-name"]').fill("Mom");
		// (A header carries Latin-1 only: a token with "—" in it never leaves
		// the page — the screen says so instead of fetch's TypeError.)
		await page.locator('input[name="bootstrap-token"]').fill("bad — token");
		await page.getByRole("button", { name: "Create" }).click();
		await page.getByText("letters, digits and + / =").waitFor();
		await page.locator('input[name="bootstrap-token"]').fill("any-token-dev-mode-allows");
		await page.getByRole("button", { name: "Create" }).click();
		// Straight into the new lead's own vault setup — no chooser (39l).
		await page.getByRole("button", { name: "Create the vault" }).waitFor({ timeout: 30_000 });
		await assertNoViolations(page, "the first-lead screen");
		await ctx.close();
		// Someone signed in whose email no account holds sees no one's
		// account — not a list of the team (39l: "Who's opening?" listed
		// every member to anyone through Access).
		const strangerCtx = await guardedContext(browser, "stranger@elsewhere.test");
		const stranger = await strangerCtx.newPage();
		await stranger.goto(dev.base);
		await stranger.getByText("no account in this team uses that address").waitFor({ timeout: 30_000 });
		assert.equal(await stranger.getByText("Mom").count(), 0, "no member's name is shown to a stranger");
		await strangerCtx.close();
		const team = await api(dev.base, "GET", "/api/v1/family", { email: "mom@family.test" });
		const first = team.json.members.find((m) => m.id === "mom");
		assert.equal(first?.role, "lead", "the first member is a lead");
		assert.deepEqual(first?.emails, ["mom@family.test"], "the first lead's email is the signed-in one, not a typed one");
	}

	// ── seed: mom (password vault), jinu (recovery vault), sora (none) ──
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
		// (The signed-in email opens its own account — no chooser since 39l.)
		{
			const card = await page.locator("gorani-setup section").first().boundingBox();
			const vp = page.viewportSize();
			assert.ok(card && Math.abs(card.x + card.width / 2 - vp.width / 2) < 4 && Math.abs(card.y + card.height / 2 - vp.height / 2) < vp.height * 0.2, `the setup card is centred, not in a corner (${JSON.stringify(card)})`);
		}
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
		// (The signed-in email opens its own account — no chooser since 39l.)
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

		// ── The context menus, in both explorers (commit 39l) ───────────
		// Reported as "all broken": the menu's position was a styleMap, whose
		// first render is a style ATTRIBUTE — refused by the CSP — so it opened
		// below the page, out of sight. Behind it: search answered with the
		// worker's envelope (every search threw); keys typed into the search
		// box drove the explorer (Delete trashed the selection); Escape closed
		// neither the share dialog nor Finder's Get Info; Rename did nothing in
		// Finder's column view; Custody… was offered where it cannot exist.
		// This suite never opened a menu — now it opens them, and the CSP
		// watcher (assertNoViolations) sees each.
		{
			await page.locator("gorani-win11 [data-upload]").first().setInputFiles({ name: "menu-a.txt", mimeType: "text/plain", buffer: Buffer.from("a file for the menus") });
			await page.locator("text=menu-a.txt").first().waitFor({ timeout: 60_000 });
			const row = (host, name) => page.locator(`${host} [data-item^="file:"]`, { hasText: name }).first();
			const openMenu = async (host, name) => {
				await row(host, name).click({ button: "right" });
				const menu = page.locator('gorani-menu [role="menu"]');
				await menu.waitFor({ timeout: 10_000 });
				const box = await menu.boundingBox();
				const vp = page.viewportSize();
				assert.ok(box && box.x >= 0 && box.y >= 0 && box.x + box.width <= vp.width && box.y + box.height <= vp.height, `${host}: the menu opens inside the window, at the pointer (${JSON.stringify(box)})`);
				return page.locator("gorani-menu");
			};
			const choose = async (host, name, label) => (await openMenu(host, name)).getByRole("menuitem", { name: label, exact: true }).click();

			// Windows: Rename, Download, Share, and what Custody… says outside a case.
			await choose("gorani-win11", "menu-a.txt", "Rename");
			const rename = page.locator("gorani-win11 input[data-renaming]");
			await rename.fill("menu-b.txt");
			await rename.press("Enter");
			await row("gorani-win11", "menu-b.txt").waitFor({ timeout: 30_000 });
			const download = page.waitForEvent("download");
			await choose("gorani-win11", "menu-b.txt", "Download");
			assert.equal((await download).suggestedFilename(), "menu-b.txt", "Download from the menu downloads the file");
			await choose("gorani-win11", "menu-b.txt", "Share…");
			await page.locator("gorani-share").waitFor({ state: "attached" });
			await page.keyboard.press("Escape");
			await page.locator("gorani-share").waitFor({ state: "detached" });
			const menu = await openMenu("gorani-win11", "menu-b.txt");
			assert.equal(await menu.getByRole("menuitem", { name: "Custody…", exact: true }).isDisabled(), true, "custody exists in an evidence case only — not offered in My files");
			await page.keyboard.press("Escape");
			await page.mouse.click(5, 5);

			// The search box: its keys are its own, and it finds.
			await row("gorani-win11", "menu-b.txt").click();
			const search = page.locator('gorani-win11 input[placeholder^="Search"]');
			await search.click();
			await search.pressSequentially("menu-b");
			await page.locator("gorani-win11 div.absolute button", { hasText: "menu-b.txt" }).first().waitFor({ timeout: 10_000 });
			await search.press("Backspace");
			await search.press("Home");
			await search.press("Delete");
			assert.equal(await search.inputValue(), "enu-", "Backspace, Home and Delete edit the search text");
			await search.fill("");
			await row("gorani-win11", "menu-b.txt").waitFor({ timeout: 5_000 });

			// Finder (column view): Get Info, Rename…, Move to Trash.
			await page.getByRole("button", { name: "Finder", exact: true }).click();
			await choose("gorani-finder", "menu-b.txt", "Get Info");
			await page.getByText("the server stored none of these values").waitFor();
			await page.keyboard.press("Escape");
			await page.getByText("the server stored none of these values").waitFor({ state: "detached" });
			await choose("gorani-finder", "menu-b.txt", "Rename…");
			const renameF = page.locator("gorani-finder input[data-renaming]");
			await renameF.fill("menu-c.txt");
			await renameF.press("Enter");
			await row("gorani-finder", "menu-c.txt").waitFor({ timeout: 30_000 });
			await choose("gorani-finder", "menu-c.txt", "Move to Trash");
			await row("gorani-finder", "menu-c.txt").waitFor({ state: "detached", timeout: 30_000 });
			await page.getByRole("button", { name: "Windows", exact: true }).click();
			await page.locator("gorani-win11 [data-upload]").first().waitFor({ state: "attached" });
			await assertNoViolations(page, "the context menus, both explorers");
		}

		// ── Navigation, both explorers (commit 39l) ──────────────────────
		// Reported as "completely broken: double-click and nothing moves".
		// Every folder was listed inside every folder (the listing carries the
		// whole tree, and all of it was shown), so a folder seemed to open into
		// itself; Home re-listed the folder you were in; the top breadcrumb was
		// ignored; the explorer could never hold the keyboard focus; Finder's
		// column view drew one column whatever was opened. And the place is now
		// in the address (#a=<area>&f=<folder>): the browser's Back/Forward
		// move between folders, a reload opens where you were.
		{
			const W = "gorani-win11";
			const F = "gorani-finder";
			const folderRow = (host, name) => page.locator(`${host} [data-item^="folder:"]`, { hasText: name }).first();
			const fileRow = (host, name) => page.locator(`${host} [data-item^="file:"]`, { hasText: name }).first();
			const crumbs = async () => (await page.locator(`${W} nav`).first().innerText()).replace(/\s+/g, " ").trim();
			const listed = async (host) => page.locator(`${host} [data-item]`).evaluateAll((els) => els.map((e) => e.textContent.replace(/\s+/g, " ").trim().split(" ")[0]));
			const newFolder = async (name) => {
				await page.locator(`${W} button`, { hasText: "New" }).first().click();
				await page.locator("gorani-menu").getByRole("menuitem", { name: /folder/i }).first().click();
				const input = page.locator("div.fixed input").last();
				await input.fill(name);
				await input.press("Enter");
				await folderRow(W, name).waitFor({ timeout: 15_000 });
			};
			// The address moves first, the screen when the listing lands — so
			// a test step waits on what the screen shows.
			const until = async (check, what) => {
				for (let i = 0; i < 100 && !(await check()); i++) await page.waitForTimeout(100);
				assert.ok(await check(), what);
			};
			const atTop = async () => {
				await page.locator(`${W} nav button`).first().click();
				await page.waitForFunction(() => !new URLSearchParams(location.hash.slice(1)).get("f"), null, { timeout: 10_000 });
				await until(async () => !/NavA/.test(await crumbs()), "the top crumb goes to the top");
			};

			await newFolder("NavA");
			await folderRow(W, "NavA").dblclick();
			await page.waitForFunction(() => new URLSearchParams(location.hash.slice(1)).has("f"), null, { timeout: 10_000 });
			await until(async () => /NavA/.test(await crumbs()), "double-click opens the folder");
			assert.deepEqual(await listed(W), [], "a new folder is empty — it does not list itself, or its siblings");
			const navA = await page.evaluate(() => new URLSearchParams(location.hash.slice(1)).get("f"));
			await newFolder("NavB");
			await page.locator(`${W} [data-upload]`).first().setInputFiles({ name: "inside.txt", mimeType: "text/plain", buffer: Buffer.from("in NavA") });
			await fileRow(W, "inside.txt").waitFor({ timeout: 30_000 });

			// Up, Back, Forward, the browser's own Back/Forward, the tree, the top crumb.
			await page.locator(`${W} button[title="Up one folder"]`).click();
			await folderRow(W, "NavA").waitFor();
			assert.equal(await folderRow(W, "NavB").count(), 0, "a subfolder is not listed at the top");
			await page.locator(`${W} button`, { hasText: "←" }).first().click();
			await folderRow(W, "NavB").waitFor({ timeout: 10_000 });
			await page.locator(`${W} button`, { hasText: "→" }).first().click();
			await folderRow(W, "NavA").waitFor({ timeout: 10_000 });
			await page.goBack();
			await fileRow(W, "inside.txt").waitFor({ timeout: 10_000 });
			await page.goForward();
			await folderRow(W, "NavA").waitFor({ timeout: 10_000 });
			await page.locator(`${W} aside button`, { hasText: "NavA" }).first().click();
			await fileRow(W, "inside.txt").waitFor({ timeout: 10_000 });
			await atTop();
			await folderRow(W, "NavA").waitFor();

			// The keyboard reaches the explorer: Enter opens, Backspace goes up.
			await folderRow(W, "NavA").click();
			await page.keyboard.press("Enter");
			await fileRow(W, "inside.txt").waitFor({ timeout: 10_000 });
			await fileRow(W, "inside.txt").click();
			await page.keyboard.press("Backspace");
			await folderRow(W, "NavA").waitFor({ timeout: 10_000 });

			// Move by drag and drop; delete a folder with what is in it; the
			// Trash; Restore; Home leaves the Trash for the top.
			await page.locator(`${W} [data-upload]`).first().setInputFiles({ name: "dragged.txt", mimeType: "text/plain", buffer: Buffer.from("dragged") });
			await fileRow(W, "dragged.txt").waitFor({ timeout: 30_000 });
			await fileRow(W, "dragged.txt").dragTo(folderRow(W, "NavA"));
			await fileRow(W, "dragged.txt").waitFor({ state: "detached", timeout: 10_000 });
			await folderRow(W, "NavA").click();
			await page.locator(`${W} button`, { hasText: "Delete" }).first().click();
			await folderRow(W, "NavA").waitFor({ state: "detached", timeout: 10_000 });
			await page.locator(`${W} aside button`, { hasText: "Trash" }).first().click();
			await folderRow(W, "NavA").waitFor({ timeout: 10_000 });
			await folderRow(W, "NavA").click({ button: "right" });
			await page.locator("gorani-menu").getByRole("menuitem", { name: "Restore", exact: true }).click();
			await page.locator(`${W} aside button`, { hasText: /^\s*Home\s*$/ }).first().click();
			await folderRow(W, "NavA").waitFor({ timeout: 10_000 });
			await folderRow(W, "NavA").dblclick();
			await fileRow(W, "dragged.txt").waitFor({ timeout: 10_000 });

			// A reload opens where you were (unlocking again if it asks).
			await page.reload();
			const pw = page.getByPlaceholder(/Recovery code/);
			await Promise.race([fileRow(W, "dragged.txt").waitFor({ timeout: 30_000 }), pw.waitFor({ timeout: 30_000 })]);
			if (await pw.count()) {
				await pw.fill(jinu.recoveryCode);
				await page.getByRole("button", { name: "Unlock" }).click();
			}
			await fileRow(W, "dragged.txt").waitFor({ timeout: 30_000 });
			assert.equal(await page.evaluate(() => new URLSearchParams(location.hash.slice(1)).get("f")), navA, "the address still names the folder");

			// Finder: columns open with a click, one per level; list view's
			// double-click and ⌃↑.
			await atTop();
			await page.getByRole("button", { name: "Finder", exact: true }).click();
			await page.locator(`${F} button[title="Columns"]`).click();
			await folderRow(F, "NavA").click();
			await page.locator(`${F} [data-column="1"]`).waitFor({ timeout: 10_000 });
			assert.match(await page.locator(`${F} [data-column="1"]`).innerText(), /NavB/, "the opened folder's contents are the next column — the column appears with them, never with the parent's");
			await page.locator(`${F} button`, { hasText: "‹" }).first().click();
			await page.locator(`${F} [data-column="1"]`).waitFor({ state: "detached", timeout: 10_000 });
			await page.locator(`${F} button[title="List"]`).click();
			await folderRow(F, "NavA").dblclick();
			await fileRow(F, "inside.txt").waitFor({ timeout: 10_000 });
			await fileRow(F, "inside.txt").click();
			await page.keyboard.press("Control+ArrowUp");
			await folderRow(F, "NavA").waitFor({ timeout: 10_000 });
			await page.locator(`${F} button[title="Columns"]`).click();
			await page.getByRole("button", { name: "Windows", exact: true }).click();
			await page.locator(`${W} [data-upload]`).first().waitFor({ state: "attached" });
			await assertNoViolations(page, "navigation, both explorers");
		}

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

		// ── A download streamed through the media worker (D12, 31c) ────
		// The app hands a chunked file this big to the worker only above
		// 256 MiB; the worker's half is driven here directly, with a small
		// chunked file (two 5 MiB frames): it decrypts window by window into
		// the browser's own download, hands back the plaintext's SHA-256, and
		// serves its URL once.
		{
			const sealer = await storeSealer(filesStore.bundle, "jinu");
			const chunk = 5 * 1024 * 1024;
			const plain = Buffer.alloc(chunk + 12_345);
			for (let i = 0; i < plain.length; i++) plain[i] = (i * 13) % 251;
			const ck = newContentKey();
			const file = await sealer.newFile("image.raw", "application/octet-stream", ck);
			const sealed = await sealChunked(await importContentKey(ck), plain, chunk);
			const who = { "x-gorani-dev-email": "jinu@family.test" };
			const start = (await api(dev.base, "POST", "/api/v1/members/jinu/files/uploads", { email: "jinu@family.test", body: { size: plain.length, chunk, newFileId: file.id } })).json;
			const parts = [];
			for (let p = 1; p <= start.parts; p++) {
				const r = await fetch(`${dev.base}/api/v1/members/jinu/files/uploads/${start.uploadId}/${p}?key=${encodeURIComponent(start.key)}`, { method: "PUT", headers: who, body: sealed.subarray((p - 1) * (chunk + 28), p * (chunk + 28)) });
				parts.push({ partNumber: p, etag: (await r.json()).etag });
			}
			const done = new FormData();
			for (const [k, v] of Object.entries({ key: start.key, size: String(plain.length), chunk: String(chunk), ck: file.fields.ck, name: file.fields.name, type: file.fields.type, parts: JSON.stringify(parts) })) done.append(k, v);
			assert.equal((await fetch(`${dev.base}/api/v1/members/jinu/files/uploads/${start.uploadId}/complete`, { method: "POST", headers: who, body: done })).status, 200);
			const [download] = await Promise.all([
				page.waitForEvent("download"),
				page.evaluate(async ({ ck, fileId, size, chunk }) => {
					const key = await crypto.subtle.importKey("raw", Uint8Array.from(atob(ck), (c) => c.charCodeAt(0)), "AES-GCM", false, ["decrypt"]);
					const url = `/media/dl/e2e-${Math.random().toString(36).slice(2)}`;
					const ack = new MessageChannel();
					const result = new MessageChannel();
					window.__dl = { url, done: new Promise((r) => (result.port1.onmessage = (e) => r(e.data))) };
					const acked = new Promise((r) => (ack.port1.onmessage = r));
					navigator.serviceWorker.controller.postMessage({ type: "download", url, memberId: "jinu", fileId, version: 1, key, chunk, size, name: "image.raw", headers: { "x-gorani-dev-email": "jinu@family.test" } }, [ack.port2, result.port2]);
					await acked;
					// A navigation, not <a download>: Chromium sends a download-attribute
					// request past the service worker; a navigation it intercepts,
					// and an attachment answer downloads while the page stays put.
					const a = document.createElement("a");
					a.href = url;
					document.body.append(a);
					a.click();
					a.remove();
				}, { ck: Buffer.from(ck).toString("base64"), fileId: file.id, size: plain.length, chunk }),
			]);
			assert.equal(download.suggestedFilename(), "image.raw");
			assert.deepEqual(await (await import("node:fs/promises")).readFile(await download.path()), plain, "the decrypted file, byte for byte, on disk");
			const sha256 = (await import("node:crypto")).createHash("sha256").update(plain).digest("hex");
			assert.deepEqual(await page.evaluate(() => window.__dl.done), { ok: true, sha256, size: plain.length }, "the plaintext's hash, back to the page");
			assert.equal(await page.evaluate(async () => (await fetch(window.__dl.url)).status), 404, "a download URL is used once");
			await assertNoViolations(page, "streamed download");

			// The other direction (31d): a download the PAGE produces as it goes
			// (the export package) — the worker asks for each chunk over its
			// port as the browser's download wants more, and passes it on.
			const pieces = [Buffer.from("PK — a package, "), Buffer.alloc(3 * 1024 * 1024, 7), Buffer.from(" written as it was made")];
			const [piped] = await Promise.all([
				page.waitForEvent("download"),
				page.evaluate(async (chunks) => {
					const url = `/media/dl/e2e-pipe-${Math.random().toString(36).slice(2)}`;
					const ack = new MessageChannel();
					const pipe = new MessageChannel();
					const acked = new Promise((r) => (ack.port1.onmessage = r));
					navigator.serviceWorker.controller.postMessage({ type: "pipe", url, name: "case-export.zip", mime: "application/zip" }, [ack.port2, pipe.port2]);
					await acked;
					const queue = [...chunks.map((c) => Uint8Array.from(atob(c), (x) => x.charCodeAt(0))), null];
					pipe.port1.onmessage = (e) => {
						if (!e.data?.pull) return;
						const next = queue.shift();
						if (next) pipe.port1.postMessage({ chunk: next.buffer }, [next.buffer]);
						else pipe.port1.postMessage({ done: true });
					};
					const a = document.createElement("a");
					a.href = url;
					document.body.append(a);
					a.click();
					a.remove();
				}, pieces.map((p) => p.toString("base64"))),
			]);
			assert.equal(piped.suggestedFilename(), "case-export.zip");
			const pipedBytes = await (await import("node:fs/promises")).readFile(await piped.path());
			assert.ok(pipedBytes.equals(Buffer.concat(pieces)), `the page's chunks, in order, on disk (${pipedBytes.length} bytes)`);
			await assertNoViolations(page, "piped download");
		}

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
		// (The signed-in email opens its own account — no chooser since 39l.)
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

	// ── 4b. Upload links (commit 38, docs/REQUESTS.md) ─────────────────
	// Rae makes a link in the explorer (her area's inbox key is made on the
	// way); a sender with no account opens it in a browser of their own,
	// under the share page's CSP — Trusted Types with no policy, the SHA-256
	// in WebAssembly — seals two files and sends them; Rae checks one and
	// accepts it, as a malware sample by default.
	{
		const rae = await member(dev, "rae", "analyst", { by: { email: "mom@family.test" } });
		const ctx = await guardedContext(browser, rae.email);
		const page = await ctx.newPage();
		page.on("pageerror", (e) => console.error("PAGEERROR:", String(e).slice(0, 250)));
		page.on("response", (r) => { if (r.url().includes("/api/") && r.status() >= 400) console.error(`HTTP ${r.status()} ${r.request().method()} ${r.url().replace(dev.base, "")}`); });
		await page.goto(dev.base);
		// (The signed-in email opens its own account — no chooser since 39l.)
		await page.getByPlaceholder(/Recovery code/).fill(rae.recoveryCode);
		await page.getByRole("button", { name: "Unlock" }).click();
		await page.locator("gorani-win11 [data-upload]").first().waitFor({ state: "attached", timeout: 30_000 });
		await page.locator('[data-test="files-requests"]').click();
		await page.locator('[data-test="requests-tab-links"]').click();
		await page.locator('[data-test="requests-label"]').fill("Partner CERT, case 77");
		await page.locator('[data-test="requests-note"]').fill("The pcap and the dropper, please.");
		// (The team context opens at unlock; until it does, making the inbox key says so.)
		for (let i = 0; i < 20; i++) {
			await page.locator('[data-test="requests-create"]').click();
			if (await page.locator('[data-test="requests-made-link"]').waitFor({ timeout: 3_000 }).then(() => true, () => false)) break;
		}
		const link = (await page.locator('[data-test="requests-made-link"]').textContent()).trim();
		const linkPassword = (await page.locator('[data-test="requests-made-password"]').textContent()).trim();
		assert.match(link, /\/s\/r\/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/);
		assert.equal((await api(dev.base, "GET", "/api/v1/members/rae/inbox-keys", { email: rae.email })).json.inboxKeys.length, 1, "her inbox key was made on the way");

		const sctx = await guardedContext(browser, null);
		const spage = await sctx.newPage();
		spage.on("pageerror", (e) => console.error("PAGEERROR (sender):", String(e).slice(0, 250)));
		const res = await spage.goto(link);
		assert.match(res.headers()["content-security-policy"] ?? "", /trusted-types 'none'/, "the upload page: no Trusted Types policy at all");
		await spage.locator('[data-test="request-note"]', { hasText: "The pcap and the dropper, please." }).waitFor({ timeout: 30_000 });
		assert.equal(new URL(spage.url()).hash, "", "the link's secret is gone from the address bar once read");
		await spage.locator('[data-test="request-files"]').setInputFiles([
			{ name: "capture.pcap", mimeType: "application/vnd.tcpdump.pcap", buffer: Buffer.from("pcap bytes from the partner") },
			{ name: "dropper.bin", mimeType: "application/octet-stream", buffer: Buffer.from("MZ not really a dropper") },
		]);
		await spage.locator('[data-test="request-sender"]').fill("Kim, Partner CERT");
		await spage.locator('[data-test="request-password"]').fill("not the password");
		await spage.locator('[data-test="request-send"]').click();
		await spage.locator('[data-test="request-status"]', { hasText: "not this link's" }).waitFor({ timeout: 30_000 });
		await spage.locator('[data-test="request-password"]').fill(linkPassword);
		await spage.locator('[data-test="request-send"]').click();
		await spage.locator('[data-test="request-status"]', { hasText: "Sent 2 files" }).waitFor({ timeout: 60_000 });
		const receipts = await spage.locator('[data-test="request-sent-file"]').allTextContents();
		assert.equal(receipts.length, 2);
		const pcapSha = await sha256Hex(Buffer.from("pcap bytes from the partner"));
		assert.ok(receipts.some((t) => t.includes(`SHA-256 ${pcapSha}`)), "the receipt is the SHA-256 of what left the sender's machine");
		await assertNoViolations(spage, "upload page: open → verify the key → seal → send");
		await sctx.close();

		// Rae reviews: the dialog again, freshly loaded.
		await page.getByRole("button", { name: "✕" }).click();
		await page.locator('[data-test="files-requests"]').click();
		const items = (await api(dev.base, "GET", "/api/v1/members/rae/inbox", { email: rae.email })).json.items;
		assert.equal(items.length, 2);
		const pcapItem = items.find((i) => i.size === "pcap bytes from the partner".length).id;
		await page.locator(`[data-test="requests-verdict-${pcapItem}"]`, { hasText: "An outsider's upload" }).waitFor({ timeout: 30_000 });
		await page.locator(`[data-test="requests-check-btn-${pcapItem}"]`).click();
		await page.locator(`[data-test="requests-check-${pcapItem}"]`, { hasText: "the bytes are what the sender declared" }).waitFor({ timeout: 30_000 });
		assert.equal(await page.locator(`[data-test="requests-sample-${pcapItem}"]`).isChecked(), true, "a sample unless she says otherwise");
		await page.locator(`[data-test="requests-accept-${pcapItem}"]`).click();
		await page.locator('[data-test="requests-notice"]', { hasText: "filed as a malware sample" }).waitFor({ timeout: 60_000 });
		const filed = (await api(dev.base, "GET", "/api/v1/members/rae/files/list?folder=root", { email: rae.email })).json.files;
		assert.deepEqual(filed.map((f) => f.sample), [true], "one file, a sample");
		await assertNoViolations(page, "upload links: make a link, review, check, accept");
		await ctx.close();
	}

	// ── 5. The team screens (commit 27, docs/CASES.md › Stage 6) ───────
	// Mom unlocked once already (section 3), which created and registered
	// her identity; this unlock must OPEN it (its MAC verifies under her
	// root). Then a case, opened from the Team panel and entered through
	// the area switcher, takes a browser upload sealed under the case key —
	// an EVIDENCE case, so the upload lands only if the browser signed its
	// content hash with mom's identity (commit 29d).
	{
		const ctx = await guardedContext(browser, "mom@family.test");
		const page = await ctx.newPage();
		page.on("pageerror", (e) => console.error("PAGEERROR:", String(e).slice(0, 250)));
		page.on("response", (r) => { if (r.url().includes("/api/") && r.status() >= 400) console.error(`HTTP ${r.status()} ${r.request().method()} ${r.url().replace(dev.base, "")}`); });
		await page.goto(dev.base);
		// (The signed-in email opens its own account — no chooser since 39l.)
		await page.locator('input[type="password"]').fill("correct horse battery staple 42");
		await page.getByRole("button", { name: "Unlock" }).click();
		// The Team button enables once the team is open (identity opened or
		// created, recovery copy checked).
		const teamButton = page.locator('[data-test="team-button"]:not([disabled])');
		await teamButton.waitFor({ timeout: 30_000 }).catch(async (e) => {
			console.error("PAGE:", (await page.content()).replace(/<style[\s\S]*?<\/style>/g, "").replace(/\s+/g, " ").slice(0, 4000));
			throw e;
		});
		const ids = (await api(dev.base, "GET", "/api/v1/family/identities", { email: "mom@family.test" })).json.identities;
		assert.equal(ids.filter((e) => e.member === "mom").length, 1, "mom's identity is registered, once");
		// Two of mom's computers (commit 34): one whose device secret the TPM
		// and the login keyring hold, one whose secret sits in a file.
		const vaultRow = (await api(dev.base, "GET", "/api/v1/members/mom/vault", { email: "mom@family.test" })).json;
		const rootKeyId = (vaultRow.settings ?? vaultRow).keyId;
		const enrolDevice = async (name, protection) => {
			const r = await api(dev.base, "POST", "/api/v1/members/mom/devices", { email: "mom@family.test", body: { name, platform: "linux", keyId: rootKeyId, wrapped: "GW01:e2e-placeholder", salt: "c2FsdHNhbHRzYWx0c2FsdA==", protection } });
			assert.equal(r.status, 200, r.text);
			return r.json.deviceId;
		};
		const desk = await enrolDevice("mom's desktop", "tpm+keyring");
		const oldLaptop = await enrolDevice("old laptop", "file");
		const vaultPc = await enrolDevice("evidence workstation", "tpm[pin,pcr:7]+keyring"); // commit 36
		await teamButton.click();
		const fp = (await page.locator('[data-test="my-fingerprint"]').textContent())?.trim() ?? "";
		assert.match(fp, /^([0-9A-F]{4} ){7}[0-9A-F]{4}$/, "the fingerprint people read to each other");
		assert.equal(fp.replace(/ /g, ""), ids.find((e) => e.member === "mom").keyId.slice(0, 32).toUpperCase(), "…is the registered identity's");
		// Team › People › Members (39l): a lead adds an account, changes it
		// and deactivates it from the web app — the registry's rules, its
		// refusals shown in its own words. (Until 39l only an API call could.)
		await page.locator('[data-test="members"]').waitFor({ timeout: 30_000 });
		const adder = page.locator('[data-test="member-add"]');
		await adder.locator('input[name="new-member-id"]').fill("kai");
		await adder.locator('input[name="new-member-name"]').fill("Kai");
		await adder.locator('input[name="new-member-emails"]').fill("Kai@Family.test, kai.alt@family.test");
		await adder.getByRole("button", { name: "Add member" }).click();
		await page.locator('[data-test="member-kai"]').waitFor({ timeout: 30_000 });
		assert.match(await page.locator('[data-test="member-detail-kai"]').textContent(), /Analyst · kai@family\.test, kai\.alt@family\.test/, "addresses stored as Access compares them (lower case)");
		await adder.locator('input[name="new-member-id"]').fill("kai2");
		await adder.locator('input[name="new-member-emails"]').fill("kai@family.test");
		await adder.getByRole("button", { name: "Add member" }).click();
		await page.locator('[data-test="team-error"]', { hasText: "already belongs to another member" }).waitFor({ timeout: 30_000 });
		await page.locator('[data-test="member-edit-kai"]').click();
		const kaiEditor = page.locator('[data-test="member-editor-kai"]');
		await kaiEditor.locator('select[name="edit-role"]').selectOption("external");
		await kaiEditor.locator('input[name="edit-expires"]').fill("2099-12-31");
		await kaiEditor.getByRole("button", { name: "Save" }).click();
		await page.locator('[data-test="member-detail-kai"]', { hasText: "External" }).waitFor({ timeout: 30_000 });
		const kai = (await api(dev.base, "GET", "/api/v1/family", { email: "mom@family.test" })).json.members.find((m) => m.id === "kai");
		assert.deepEqual([kai.role, kai.expiresAt], ["external", "2099-12-31T23:59:59.999Z"], "a day means the end of that day, UTC");
		// Mom cannot sign herself out by editing her own address away.
		await page.locator('[data-test="member-edit-mom"]').click();
		await page.locator('[data-test="member-editor-mom"] input[name="edit-emails"]').fill("someone-else@family.test");
		await page.locator('[data-test="member-editor-mom"]').getByRole("button", { name: "Save" }).click();
		await page.locator('[data-test="team-error"]', { hasText: "the address you are signed in with" }).waitFor({ timeout: 30_000 });
		await page.locator('[data-test="member-editor-mom"]').getByRole("button", { name: "Cancel" }).click();
		page.once("dialog", (d) => void d.accept());
		await page.locator('[data-test="member-deactivate-kai"]').click();
		await page.locator('[data-test="member-detail-kai"]', { hasText: "deactivated" }).waitFor({ timeout: 30_000 });
		assert.equal((await api(dev.base, "GET", "/api/v1/me", { email: "kai@family.test" })).json.member, null, "a deactivated member is nobody at sign-in");
		assert.equal(await page.locator('[data-test="member-edit-kai"]').count(), 0, "…and is not edited back into use");
		await assertNoViolations(page, "Team › People › Members");
		// The Devices tab: what protects each computer, and revoking a lost one.
		await page.getByRole("button", { name: "Devices" }).click();
		const deskProtection = page.locator(`[data-test="device-protection-${desk}"]`);
		await deskProtection.waitFor({ timeout: 30_000 });
		assert.equal((await deskProtection.textContent()).trim(), "Protected by the TPM + the login keyring");
		assert.match(await page.locator(`[data-test="device-protection-${oldLaptop}"]`).textContent(), /⚠ Protected by a file/, "a file-held secret is flagged");
		assert.equal((await page.locator(`[data-test="device-protection-${vaultPc}"]`).textContent()).trim(), "Protected by the TPM, with a PIN, sealed to the boot state (PCR 7) + the login keyring", "a TPM part's PIN and boot state, in words");
		page.once("dialog", (d) => void d.accept());
		await page.locator(`[data-test="device-revoke-${oldLaptop}"]`).click();
		await page.locator(`[data-test="device-revoked-${oldLaptop}"]`).waitFor({ timeout: 30_000 });
		const devicesAfter = (await api(dev.base, "GET", "/api/v1/members/mom/devices", { email: "mom@family.test" })).json;
		assert.deepEqual([devicesAfter.find((d) => d.id === oldLaptop)?.revoked, devicesAfter.find((d) => d.id === desk)?.revoked], [true, false], "the lost laptop is revoked from the web app; the desktop is not");

		await page.getByRole("button", { name: "Cases" }).click();
		await page.locator('[data-test="case-id"]').fill("ir-e2e");
		await page.locator('[data-test="case-title"]').fill("Browser case");
		await page.locator('[data-test="case-kind"]').selectOption("evidence");
		await page.locator('[data-test="case-open"]').click();
		await page.locator('[data-test="case-enter-ir-e2e"]').waitFor({ timeout: 30_000 });
		assert.ok((await page.locator('[data-test="case-ir-e2e"]').textContent()).includes("Browser case"), "the sealed title opens in the panel");
		await page.locator('[data-test="case-enter-ir-e2e"]').click();
		await page.locator("gorani-win11 [data-upload]").first().waitFor({ state: "attached", timeout: 30_000 });
		assert.equal(await page.locator('[data-test="area"]').inputValue(), "case:ir-e2e", "the explorer is on the case");
		await page.locator("gorani-win11 [data-upload]").first().setInputFiles({ name: "case-note.txt", mimeType: "text/plain", buffer: Buffer.from("sealed under the case key") });
		// An evidence upload asks for its intake record first (commit 29g).
		const fillIntake = async (source, method) => {
			await page.locator('[data-test="intake-dialog"]').waitFor({ timeout: 30_000 });
			await page.locator('[data-test="intake-source"]').fill(source);
			await page.locator('[data-test="intake-method"]').fill(method);
			await page.locator('[data-test="intake-submit"]').click();
		};
		await fillIntake("mom's laptop, Downloads", "browser upload, as received");
		await page.locator("text=case-note.txt").first().waitFor({ timeout: 60_000 });
		const listed = await api(dev.base, "GET", "/api/v1/cases/ir-e2e/files/list?folder=all", { email: "mom@family.test" });
		assert.equal(listed.json.files.length, 1, "the upload landed in the CASE's store");
		const keyed = await api(dev.base, "POST", "/api/v1/cases/ir-e2e/files/keys", { email: "mom@family.test", body: { ids: [listed.json.files[0].id] } });
		assert.match(keyed.json.keys[listed.json.files[0].id].hash ?? "", /^GV04:/, "…carrying the browser's signed content hash, sealed (the evidence case requires it)");
		assert.match(keyed.json.keys[listed.json.files[0].id].intake ?? "", /^GV04:/, "…and its intake record, sealed and signed in the browser");
		assert.equal((await api(dev.base, "GET", "/api/v1/members/mom/files/list?folder=all", { email: "mom@family.test" })).json.files?.length ?? 0, 0, "…not in mom's own area");
		await page.locator("text=case-note.txt").first().dblclick();
		await page.locator("text=sealed under the case key").first().waitFor({ timeout: 30_000 });
		await page.keyboard.press("Escape");
		// A malware sample (commit 29e), uploaded through its own input: an
		// HTML dropper the viewer must NOT open — the refusal panel shows
		// instead, and the page stays violation-free.
		await page.locator("gorani-win11 [data-upload-sample]").setInputFiles({ name: "dropper.html", mimeType: "text/html", buffer: Buffer.from("<script>alert('pwned')</script>") });
		await fillIntake("phishing mail attachment, ticket 4711", "saved from the mail gateway's quarantine");
		await page.locator("text=dropper.html").first().waitFor({ timeout: 60_000 });
		const afterSample = await api(dev.base, "GET", "/api/v1/cases/ir-e2e/files/list?folder=all", { email: "mom@family.test" });
		assert.equal(afterSample.json.files.find((f) => f.sample)?.sample, true, "the server lists it as a sample");
		await page.locator("text=dropper.html").first().dblclick();
		await page.locator('[data-test="viewer-refused"]').waitFor({ timeout: 30_000 });
		assert.equal(await page.locator("text=pwned").count(), 0, "nothing of the sample is rendered");
		await page.keyboard.press("Escape");
		// The legal hold and the two-person rule (commit 29f), from the Team
		// panel: one person places the hold; closing the EVIDENCE case is
		// only ASKED for — the request shows its signature verified in this
		// browser, and no "Agree" for the person who asked.
		await teamButton.click();
		await page.getByRole("button", { name: "Cases" }).click();
		page.once("dialog", (d) => void d.accept());
		await page.locator('[data-test="hold-place-ir-e2e"]').click();
		await page.locator('[data-test="hold-ir-e2e"]').waitFor({ timeout: 30_000 });
		await page.locator('[data-test="ask-case.close-ir-e2e"]').click();
		const asked = page.locator('[data-test^="approval-"]').first();
		await asked.waitFor({ timeout: 30_000 });
		assert.match(await asked.textContent(), /case\.close asked by .*signature verified/s, "the request's signature verifies in the browser");
		assert.equal(await asked.locator('[data-test^="approve-"]').count(), 0, "no Agree for the person who asked");
		const reqs = await api(dev.base, "GET", "/api/v1/cases/ir-e2e/approvals", { email: "mom@family.test" });
		assert.equal(reqs.json.approvals[0].status, "pending", "the case stays open until a second lead agrees");
		// Re-verification (commit 29h), in the browser: both versions — the
		// note and the sample — re-hashed against their signatures, and the
		// run recorded where the nightly pass reads it.
		await page.locator('[data-test="reverify-now-ir-e2e"]').click();
		await page.locator("text=all 2 versions re-hashed and verified").first().waitFor({ timeout: 60_000 });
		const rv = await api(dev.base, "GET", "/api/v1/cases/ir-e2e/reverify", { email: "mom@family.test" });
		assert.deepEqual([rv.json.overdue, rv.json.last?.checked, rv.json.last?.failed], [false, 2, 0], "the store recorded it");
		// The case's inbox key (commit 37b): mom, its manager, makes it here —
		// signed by her browser, the private half sealed under the case key.
		await page.locator('[data-test="inbox-ir-e2e"]').filter({ hasText: "no key" }).waitFor({ timeout: 30_000 });
		await page.locator('[data-test="inbox-key-ir-e2e"]').click();
		await page.locator('[data-test="inbox-ir-e2e"]').filter({ hasText: "made by" }).waitFor({ timeout: 30_000 });
		const inboxKeys = (await api(dev.base, "GET", "/api/v1/cases", { email: "mom@family.test" })).json.cases.find((c) => c.id === "ir-e2e").inboxKeys;
		assert.deepEqual([inboxKeys.length, inboxKeys[0].signedBy, inboxKeys[0].retiredAt], [1, "mom", null], "one current key, signed by mom");
		assert.match(inboxKeys[0].privateSealed, /^GV04:/, "its private half is placed under the case key");
		// Collectors (commit 37a): mom registers one through the form — her
		// browser signs the registration — and a second lead approves it.
		// The tab then says whether MOM's client counts it: not yet, since
		// she never verified the lead who approved.
		const cpair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
		const cjwk = await crypto.subtle.exportKey("jwk", cpair.publicKey);
		await page.getByRole("button", { name: "Collectors" }).click();
		await page.locator('[data-test="collector-id"]').fill("edr-e2e");
		await page.locator('[data-test="collector-name"]').fill("EDR drop");
		await page.locator('[data-test="collector-cn"]').fill("e2e0000.access");
		await page.locator('[data-test="collector-key"]').fill(JSON.stringify({ publicKey: { kty: cjwk.kty, crv: cjwk.crv, x: cjwk.x, y: cjwk.y } }));
		await page.locator('[data-test="collector-request"]').click();
		const verdict = page.locator('[data-test="collector-verdict-edr-e2e"]');
		await verdict.waitFor({ timeout: 30_000 });
		assert.match(await verdict.textContent(), /not counted: the collector is pending/);
		const ana = await member(dev, "ana", "lead", { by: { email: "mom@family.test" } });
		const regIds = (await api(dev.base, "GET", "/api/v1/family/identities", { email: ana.email })).json.identities;
		await pinIdentity(dev, ana, { id: "mom", record: { keyId: regIds.find((e) => e.member === "mom").keyId } });
		const asAna = async (method, path, body) => {
			const r = await api(dev.base, method, path, { email: ana.email, body });
			if (r.status >= 400) throw new Error(`${r.status} ${r.text}`);
			return r.json;
		};
		const pendingRow = (await asAna("GET", "/api/v1/family/collectors")).collectors.find((c) => c.id === "edr-e2e");
		await approveCollector(asAna, ana.signer, await trustOf(dev, ana), pendingRow);
		await teamButton.click(); // back to the files…
		await teamButton.click(); // …and a fresh Team panel
		await page.getByRole("button", { name: "Collectors" }).click();
		await page.locator('[data-test="collector-verdict-edr-e2e"]').filter({ hasText: "ana, who approved it" }).waitFor({ timeout: 30_000 });
		assert.match(await page.locator('[data-test="collector-verdict-edr-e2e"]').textContent(), /⚠ not counted: ana, who approved it, is not an identity you verified/, "active, but not counted by a member who never verified its approver");
		// Its drop (commit 37c), signed with the collector's key and sealed to
		// the case's inbox key: mom's inbox lists it, says why SHE does not
		// believe it (and offers no Accept), and turns it away with a reason.
		assert.equal((await api(dev.base, "PUT", "/api/v1/cases/ir-e2e/collectors/edr-e2e", { email: "mom@family.test" })).status, 200);
		const ik = (await api(dev.base, "GET", "/api/v1/cases", { email: "mom@family.test" })).json.cases.find((c) => c.id === "ir-e2e").inboxKeys[0];
		const dropped = new TextEncoder().encode("collected by a machine mom has not verified");
		const dck = newContentKey();
		const dm = { case: "ir-e2e", item: "e2e-drop", collector: "edr-e2e", name: "triage.txt", type: "text/plain", size: dropped.length, sha256: await sha256Hex(dropped), source: "WS-1", method: "script", collectedAt: "2026-10-15T09:00:00Z", notes: "" };
		const dsig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, cpair.privateKey, inboxStatements.collect(dm)))));
		const dform = new FormData();
		for (const [k, v] of Object.entries({ item_id: "e2e-drop", inbox_key_id: ik.keyId, size: String(dropped.length), ck: await wrapContentKey(ik.publicKey, dck), meta: await sealText(ik.publicKey, JSON.stringify({ ...dm, signature: dsig })) })) dform.append(k, v);
		dform.append("file", new Blob([await sealWith(await importContentKey(dck), dropped)]));
		const drop = await fetch(`${dev.base}/api/v1/collect/cases/ir-e2e/items`, { method: "POST", headers: { "x-gorani-dev-collector": "e2e0000.access" }, body: dform });
		assert.equal(drop.status, 200, await drop.text());
		await page.getByRole("button", { name: "Cases" }).click();
		await page.locator('[data-test="inbox-show-ir-e2e"]').click();
		const dv = page.locator('[data-test="inbox-verdict-e2e-drop"]');
		await dv.waitFor({ timeout: 30_000 });
		assert.match(await dv.textContent(), /⚠ unverified: collector edr-e2e is not one you count/, "mom does not count the collector, so she does not count its item");
		assert.equal(await page.locator('[data-test="inbox-accept-e2e-drop"]').isDisabled(), true, "no accepting what you cannot tie to a collector you trust");
		page.once("dialog", (d) => void d.accept("not a collector we verified"));
		await page.locator('[data-test="inbox-reject-e2e-drop"]').click();
		await page.locator('[data-test="inbox-item-e2e-drop"]').filter({ hasText: "rejected" }).waitFor({ timeout: 30_000 });
		const rejectedRow = (await api(dev.base, "GET", "/api/v1/cases/ir-e2e/inbox", { email: "mom@family.test" })).json.items.find((i) => i.id === "e2e-drop");
		assert.equal(rejectedRow.status, "rejected");
		assert.match(rejectedRow.rejected.reason, /^GV04:/, "the reason went sealed");
		await assertNoViolations(page, "team panel, case open, upload and preview");
		await ctx.close();
	}

	// ── 6. Lost every way in: re-enrol, and read the fingerprint ───────
	{
		const ctx = await guardedContext(browser, "jinu@family.test");
		const page = await ctx.newPage();
		page.on("pageerror", (e) => console.error("PAGEERROR:", String(e).slice(0, 250)));
		await page.goto(dev.base);
		// (The signed-in email opens its own account — no chooser since 39l.)
		await page.locator('[data-test="lost-methods"]').click();
		await page.getByPlaceholder("New password (12+ chars)").fill("jinu's brand new password");
		await page.getByPlaceholder("Repeat it").fill("jinu's brand new password");
		await page.getByRole("button", { name: "Re-enrol" }).click();
		const shown = (await page.locator('[data-test="reenrol-fingerprint"]').textContent({ timeout: 60_000 }))?.trim() ?? "";
		assert.match(shown, /^([0-9A-F]{4} ){7}[0-9A-F]{4}$/, "the new root's fingerprint, to read to the coordinating lead");
		const still = await api(dev.base, "GET", "/api/v1/members/jinu/vault", { email: "jinu@family.test" });
		assert.equal(still.json.keyId, jinu.keyId, "nothing changed yet — only a ceremony can re-root the vault");
		await assertNoViolations(page, "re-enrol");
		await ctx.close();
	}

	// ── Team › Unlock (39l): a passkey from setup, a password changed, a
	// new recovery code, a passkey removed — every change confirmed with a
	// method already held, and a wrong confirmation opens nothing. ────────
	// On localhost: a passkey's relying party is the page's hostname, and
	// WebAuthn refuses an IP address as one. Chromium's virtual
	// authenticator, with the PRF extension, stands in for Touch ID or
	// Windows Hello and answers by itself.
	{
		assert.equal((await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "pat", name: "Pat", role: "analyst", emails: ["pat@family.test"] } })).status, 200);
		const base = dev.base.replace("127.0.0.1", "localhost");
		const ctx = await guardedContext(browser, "pat@family.test");
		const page = await ctx.newPage();
		page.on("pageerror", (e) => console.error("PAGEERROR:", String(e).slice(0, 250)));
		const cdp = await ctx.newCDPSession(page);
		await cdp.send("WebAuthn.enable");
		await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
		const stored = async () => (await api(dev.base, "GET", "/api/v1/members/pat/vault", { email: "pat@family.test" })).json.methods;
		const kinds = async () => (await stored()).map((m) => m.kind).sort();
		await page.goto(base);
		await page.getByRole("button", { name: "Create the vault" }).waitFor({ timeout: 30_000 });
		await page.getByPlaceholder("Password (12+ chars)").fill("pat's first long password");
		await page.getByPlaceholder("Repeat it").fill("pat's first long password");
		await page.getByRole("button", { name: "Create the vault" }).click();
		await page.locator('[data-test="setup-passkey"]').click();
		await page.locator('[data-test="setup-passkey-note"]', { hasText: "A passkey was added" }).waitFor({ timeout: 60_000 });
		assert.deepEqual(await kinds(), ["passkey", "password", "recovery"], "setup offers a passkey, and saves it beside the password and the code");
		await page.getByRole("button", { name: "I wrote it down" }).click();
		// The unlock screen tries the passkey by itself: nothing typed.
		const teamButton = page.locator('[data-test="team-button"]:not([disabled])');
		await teamButton.waitFor({ timeout: 60_000 });
		await teamButton.click();
		await page.getByRole("button", { name: "Unlock", exact: true }).click();
		await page.locator('[data-test="methods"]').waitFor({ timeout: 30_000 });
		const form = page.locator('[data-test="method-change"]');
		// A new password, confirmed with the passkey (the default when one is enrolled).
		const pw1 = (await stored()).find((m) => m.kind === "password");
		await page.locator(`[data-test="method-change-${pw1.id}"]`).click();
		await form.locator('input[name="new-password"]').fill("pat's second long password");
		await form.locator('input[name="new-password-again"]').fill("pat's second long password");
		await form.locator('[data-test="method-apply"]').click();
		await page.locator('[data-test="methods-status"]', { hasText: "Your password was changed" }).waitFor({ timeout: 60_000 });
		assert.ok(!(await stored()).some((m) => m.id === pw1.id), "the old password's method is gone, not kept beside the new one");
		// A wrong confirmation opens nothing and changes nothing.
		const before = JSON.stringify(await stored());
		await page.locator('[data-test="method-new-recovery"]').click();
		await form.locator('select[name="confirm-kind"]').selectOption("password");
		await form.locator('input[name="confirm-secret"]').fill("pat's first long password");
		await form.locator('[data-test="method-apply"]').click();
		await page.locator('[data-test="methods-error"]', { hasText: "does not open this vault" }).waitFor({ timeout: 60_000 });
		assert.equal(JSON.stringify(await stored()), before, "nothing was saved");
		// The right one: a new recovery code, shown once, replacing the old.
		await form.locator('input[name="confirm-secret"]').fill("pat's second long password");
		await form.locator('[data-test="method-apply"]').click();
		const codeBox = page.locator('[data-test="method-code"]');
		await codeBox.waitFor({ timeout: 60_000 });
		const newCode = ((await codeBox.locator("code").textContent()) ?? "").trim();
		assert.equal((await stored()).filter((m) => m.kind === "recovery").length, 1, "one recovery code: the new one replaced the old");
		await codeBox.getByRole("button", { name: "I wrote it down" }).click();
		// The passkey removed, confirmed with that new code.
		const pk = (await stored()).find((m) => m.kind === "passkey");
		await page.locator(`[data-test="method-remove-${pk.id}"]`).click();
		await form.locator('select[name="confirm-kind"]').selectOption("recovery");
		await form.locator('input[name="confirm-secret"]').fill(newCode);
		await form.locator('[data-test="method-apply"]').click();
		await page.locator('[data-test="methods-status"]', { hasText: "The method was removed" }).waitFor({ timeout: 60_000 });
		assert.deepEqual(await kinds(), ["password", "recovery"]);
		const trail = (await api(dev.base, "GET", "/api/v1/members/pat/audit", { email: "pat@family.test" })).json.filter((l) => l.action === "vault.save").map((l) => l.details);
		assert.ok(trail.includes("methods:password,recovery,passkey") && trail.includes("methods:password,recovery"), `each save's ways in, in the trail: ${JSON.stringify(trail)}`);
		await assertNoViolations(page, "Team › Unlock");
		// Lock: the old password is refused, the new one opens.
		await page.getByRole("button", { name: "Lock", exact: true }).dispatchEvent("click");
		const pw = page.locator('input[type="password"]');
		await pw.waitFor({ timeout: 30_000 });
		await pw.fill("pat's first long password");
		await page.getByRole("button", { name: "Unlock" }).click();
		await page.locator("text=/try again|wrong|incorrect|does not open/i").first().waitFor({ timeout: 30_000 });
		await pw.fill("pat's second long password");
		await page.getByRole("button", { name: "Unlock" }).click();
		await page.locator("gorani-win11 [data-upload]").first().waitFor({ state: "attached", timeout: 30_000 });
		await ctx.close();
	}

	await browser.close();
	console.log("ok  e2e:app — CSP + Trusted Types delivered and violation-free; setup, recovery + password unlock, sealed upload, open, Lock revokes plaintext handles, 15-minute idle lock, refusal, password share page, an upload link (made in the explorer, sent through by a signed-out browser, checked and accepted as a sample), team panel (with Devices: protection shown, a lost laptop revoked; Collectors: registered through the form, approved by a second lead, its verdict this member's own) + case upload, a sample refused by the viewer, intake records, a legal hold and a two-person request, re-verification, re-enrol");
} finally {
	await dev.close();
}