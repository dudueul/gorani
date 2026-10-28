// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * e2e:phone — the web app on a phone (commit 41b, docs/PHONE.md), in
 * Chromium as a Pixel 7: a 412-pixel-wide touch screen, a mobile browser.
 * Real touches, sent through the browser's own input pipeline (the
 * DevTools protocol), so a long-press is a finger held still and a swipe
 * is a finger that travels — the browser's gesture detection included.
 *
 * What it proves, in order:
 *   - the phone gets the touch explorer, not a desktop simulation, and
 *     no screen of it is wider than the phone (no sideways scrolling);
 *   - a field is 16 px (smaller, and iOS zooms into it and stays zoomed);
 *   - rows a thumb can hit (56 px), upload, New folder through its prompt;
 *   - tap opens a file; a swipe opens the next one and the one before;
 *   - a long-press opens the item's actions as a sheet: Rename… (the old
 *     name in the field), Move to › a folder (the submenu in place), ‹ up;
 *   - Select, two rows, Zip: one zip with both files and the check report;
 *   - Delete to the Trash and back out of it;
 *   - Music, Movies and Team in one column; ☰ → Lock;
 *   - the same window made wide is the desktop look again;
 *   - Add to Home Screen: the manifest (standalone, icons that exist) and
 *     the head's links — under the app's CSP, with no violation anywhere.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { startDev } from "../api/_dev.mjs";
import { createCodeVault, createStoreKey, sealStoreKeyToMember } from "../../web/src/vault/keys.ts";

let playwright = null;
try {
	playwright = await import("playwright");
} catch {
	// not installed — a skip, not a failure
}
if (!playwright) {
	console.log("skip  e2e:phone — install it with: npm i -D playwright");
	process.exit(0);
}
const { chromium, devices } = playwright;

const dev = await startDev({ persist: "e2e-phone" });
try {
	// ── seed: the first lead, Rin, with a recovery-code vault and a files store
	const boot = await fetch(`${dev.base}/api/v1/family/members`, {
		method: "POST",
		headers: { "content-type": "application/json", "x-gorani-dev-email": "rin@phone.test", "x-gorani-bootstrap": "any-token-dev-mode-allows" },
		body: JSON.stringify({ id: "rin", name: "Rin", role: "lead" }),
	});
	assert.ok(boot.ok, `the first lead: ${boot.status} ${await boot.text()}`);
	const rin = await createCodeVault();
	const own = await sealStoreKeyToMember(await createStoreKey(), { ec: rin.publicKey, kem: rin.pqPublicKey });
	const vault = await fetch(`${dev.base}/api/v1/members/rin/vault`, {
		method: "PUT",
		headers: { "content-type": "application/json", "x-gorani-dev-email": "rin@phone.test" },
		body: JSON.stringify({ settings: { enabled: true, keyId: rin.keyId, publicKey: rin.publicKey, pqPublicKey: rin.pqPublicKey, methods: rin.methods, stores: { files: own } } }),
	});
	assert.equal(vault.status, 200);

	const browser = await chromium.launch({ headless: true });
	const ctx = await browser.newContext({ ...devices["Pixel 7"], acceptDownloads: true });
	await ctx.addInitScript(() => {
		localStorage.setItem("gorani-dev-email", "rin@phone.test");
		globalThis.__csp = [];
		document.addEventListener("securitypolicyviolation", (v) => globalThis.__csp.push(`${v.effectiveDirective} ← ${v.blockedURI || "inline"} @ ${v.sourceFile}:${v.lineNumber}`));
	});
	const page = await ctx.newPage();
	page.on("pageerror", (e) => console.error("PAGEERROR:", String(e).slice(0, 250)));
	const noViolations = async (where) => assert.deepEqual(await page.evaluate(() => globalThis.__csp ?? []), [], `${where}: the CSP blocked something`);
	/** Nothing on screen is wider than the phone: no sideways scrolling. */
	const fits = async (where) => {
		const { scroll, width } = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, width: innerWidth }));
		assert.ok(scroll <= width, `${where}: ${scroll}px of content in a ${width}px-wide phone`);
	};
	const cdp = await ctx.newCDPSession(page);
	const centre = async (locator) => {
		const b = await locator.boundingBox();
		assert.ok(b, "on screen");
		return { x: b.x + b.width / 2, y: b.y + b.height / 2 };
	};
	/** A finger held still on `locator` for `ms`. */
	const longPress = async (locator, ms = 750) => {
		const at = await centre(locator);
		await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [at] });
		await page.waitForTimeout(ms);
		await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
	};
	/** A finger that travels `dx` sideways across `locator`, in steps. */
	const swipe = async (locator, dx) => {
		const at = await centre(locator);
		await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [at] });
		for (let i = 1; i <= 8; i++) await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: at.x + (dx * i) / 8, y: at.y + i }] });
		await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
	};
	const row = (name) => page.locator('[data-test="phone-row"]', { has: page.locator(`[data-name]:text-is("${name}")`) });
	const sheet = page.locator("gorani-sheet");
	const choose = async (label) => {
		await sheet.getByRole("menuitem", { name: label, exact: true }).tap();
	};

	// ── unlock, on a phone ─────────────────────────────────────────────
	await page.goto(dev.base);
	const code = page.getByPlaceholder(/Recovery code/);
	await code.waitFor({ timeout: 30_000 });
	assert.equal(await code.evaluate((el) => getComputedStyle(el).fontSize), "16px", "a field is 16 px on a phone — iOS zooms into anything smaller");
	assert.equal(await code.getAttribute("autocapitalize"), "off", "the phone's keyboard does not capitalise a recovery code");
	await fits("the unlock screen");
	await code.fill(rin.recoveryCode);
	await page.getByRole("button", { name: "Unlock" }).tap();
	await page.locator('[data-test="phone"]').waitFor({ timeout: 30_000 });
	assert.equal(await page.locator("gorani-win11, gorani-finder").count(), 0, "no desktop simulation on a phone");
	assert.equal(await page.locator('[data-test="area"]').count(), 0, "the desktop header is not drawn");
	await page.locator('[data-test="phone-title"]', { hasText: "Rin" }).waitFor();
	await fits("the explorer");

	// ── upload, New folder ─────────────────────────────────────────────
	await page.locator('[data-test="phone"] [data-upload]').setInputFiles([
		{ name: "a.txt", mimeType: "text/plain", buffer: Buffer.from("first file, from a phone") },
		{ name: "b.txt", mimeType: "text/plain", buffer: Buffer.from("second file, from a phone") },
		{ name: "c.txt", mimeType: "text/plain", buffer: Buffer.from("third file, from a phone") },
	]);
	await row("c.txt").waitFor({ timeout: 60_000 });
	const rowBox = await row("a.txt").boundingBox();
	assert.ok(rowBox && rowBox.height >= 56, `a row a thumb can hit (${rowBox?.height}px)`);
	await page.locator('[data-test="phone-new-folder"]').tap();
	const prompt = page.getByPlaceholder("New folder");
	await prompt.fill("Trip");
	await page.getByRole("button", { name: "Create" }).tap();
	await row("Trip").waitFor({ timeout: 30_000 });

	// ── tap opens; a swipe opens the next ──────────────────────────────
	await row("a.txt").locator("button").first().tap();
	const viewer = page.locator("gorani-viewer [data-viewer-root]");
	await viewer.getByText("first file, from a phone").waitFor({ timeout: 30_000 });
	await page.locator('[data-test="viewer-position"]', { hasText: "1 / 3" }).waitFor();
	await swipe(viewer.locator("main"), -220);
	await viewer.getByText("second file, from a phone").waitFor({ timeout: 30_000 });
	await page.locator('[data-test="viewer-position"]', { hasText: "2 / 3" }).waitFor();
	await swipe(viewer.locator("main"), 220);
	await viewer.getByText("first file, from a phone").waitFor({ timeout: 30_000 });
	await fits("the viewer");
	await page.locator('[data-test="viewer-close"]').tap();
	await viewer.waitFor({ state: "detached" });

	// ── long-press: the item's sheet ───────────────────────────────────
	await longPress(row("b.txt").locator("button").first());
	await sheet.locator('[data-test="sheet-heading"]', { hasText: "b.txt" }).waitFor({ timeout: 10_000 });
	await page.waitForTimeout(200); // the finger is up: nothing else opened under it
	assert.equal(await sheet.count(), 1, "one sheet — the browser's own long-press menu did not open another");
	assert.equal(await viewer.count(), 0, "the long-press did not also open the file");
	await choose("Rename…");
	const rename = page.getByPlaceholder("b.txt");
	assert.equal(await rename.inputValue(), "b.txt", "Rename starts from the name");
	await rename.fill("bee.txt");
	await page.getByRole("button", { name: "Rename" }).tap();
	await row("bee.txt").waitFor({ timeout: 30_000 });
	// Move to › Trip: the submenu opens in the sheet, with a way back.
	await row("bee.txt").locator('[data-test="phone-row-menu"]').tap();
	await choose("Move to");
	await sheet.locator('[data-test="sheet-back"]').waitFor();
	await choose("Trip");
	await row("bee.txt").waitFor({ state: "detached", timeout: 30_000 });
	await row("Trip").locator("button").first().tap();
	await page.locator('[data-test="phone-title"]', { hasText: "Trip" }).waitFor({ timeout: 30_000 });
	await row("bee.txt").waitFor({ timeout: 30_000 });
	await page.locator('[data-test="phone-back"]').tap();
	await page.locator('[data-test="phone-title"]', { hasText: "Rin" }).waitFor({ timeout: 30_000 });
	// Messages come and go, two at a time at most on a phone.
	assert.ok((await page.locator('[data-test="toasts"] > div').count()) <= 2, "the newest two toasts only");
	await page.locator('[data-test="toasts"]').getByText("Moved 1 item").waitFor({ state: "detached", timeout: 8_000 });

	// ── Select, two rows, Zip ──────────────────────────────────────────
	await page.locator('[data-test="phone-select"]').tap();
	await row("a.txt").locator("button").first().tap();
	await row("c.txt").locator("button").first().tap();
	await page.locator('[data-test="phone-title"]', { hasText: "2 selected" }).waitFor();
	const zipped = page.waitForEvent("download");
	await page.locator('[data-test="phone-zip"]').tap();
	const z = await zipped;
	assert.match(z.suggestedFilename(), /^gorani-\d{4}-\d{2}-\d{2}\.zip$/);
	const read = spawnSync("python3", ["-I", "-c", "import zipfile,sys,hashlib; z=zipfile.ZipFile(sys.argv[1]); print(' '.join(z.namelist())); print(hashlib.sha256(z.read('c.txt')).hexdigest())", await z.path()], { encoding: "utf8" });
	if (read.error) console.log("  (python3 not found: the phone's zip was not opened)");
	else {
		assert.equal(read.status, 0, read.stderr);
		const [names, sha] = read.stdout.trim().split("\n");
		assert.equal(names, "a.txt c.txt gorani-check.txt", "the two picked files and the report");
		assert.equal(sha, createHash("sha256").update("third file, from a phone").digest("hex"));
	}
	await page.locator('[data-test="phone-title"]', { hasText: "Rin" }).waitFor({ timeout: 10_000 });

	// ── Delete to the Trash, and back out of it ───────────────────────
	await page.locator('[data-test="phone-select"]').tap();
	await row("c.txt").locator("button").first().tap();
	await page.locator('[data-test="phone-delete"]').tap();
	await row("c.txt").waitFor({ state: "detached", timeout: 30_000 });
	await page.locator('[data-test="phone-folder-menu"]').tap();
	await choose("Trash");
	await page.locator('[data-test="phone-title"]', { hasText: "Trash" }).waitFor({ timeout: 30_000 });
	await row("c.txt").waitFor({ timeout: 30_000 });
	await page.locator('[data-test="phone-back"]').tap();
	await page.locator('[data-test="phone-title"]', { hasText: "Rin" }).waitFor({ timeout: 30_000 });
	await noViolations("the explorer on a phone");

	// ── Music, Movies, Team: one column each ──────────────────────────
	await page.locator('[data-test="phone-tab-music"]').tap();
	await page.locator("gorani-music").getByText(/library is empty|Music/).first().waitFor({ timeout: 30_000 });
	await fits("Music");
	await page.locator('[data-test="phone-tab-movies"]').tap();
	await page.locator('[data-test="movies-empty"], [data-test="movies"]').first().waitFor({ timeout: 30_000 });
	await fits("Movies");
	await page.locator('[data-test="phone-tab-team"]').tap();
	await page.locator('[data-test="team"]').waitFor({ timeout: 30_000 });
	await page.locator('[data-test="team-tab-status"]').tap();
	await page.locator('[data-test="status"]').waitFor({ timeout: 30_000 });
	await fits("Team › Status");
	await page.locator('[data-test="team-tab-people"]').tap();
	await fits("Team › People");
	await page.locator('[data-test="phone-tab-files"]').tap();
	await page.locator('[data-test="phone"]').waitFor({ timeout: 30_000 });
	await noViolations("Music, Movies, Team");

	// ── the same window, wide: the desktop look again ─────────────────
	await page.setViewportSize({ width: 1024, height: 768 });
	await page.locator("gorani-win11").waitFor({ timeout: 10_000 });
	assert.equal(await page.locator('[data-test="phone"]').count(), 0, "a wide window has no phone layout");
	await page.setViewportSize(devices["Pixel 7"].viewport);
	await page.locator('[data-test="phone"]').waitFor({ timeout: 10_000 });

	// ── ☰ → Lock ───────────────────────────────────────────────────────
	await page.locator('[data-test="phone-account"]').tap();
	await sheet.getByRole("menuitem", { name: "My files" }).waitFor();
	assert.equal(await sheet.getByRole("menuitem", { name: "My files" }).getAttribute("aria-checked"), "true", "the open area is ticked");
	await choose("Lock");
	await page.getByPlaceholder(/Recovery code/).waitFor({ timeout: 30_000 });
	await noViolations("Lock from the phone");

	// ── Add to Home Screen ─────────────────────────────────────────────
	const link = page.locator('link[rel="manifest"]');
	assert.equal(await link.getAttribute("href"), "/manifest.webmanifest");
	assert.equal(await link.getAttribute("crossorigin"), "use-credentials", "fetched with the Access cookie, or Access answers it with a sign-in page");
	assert.match((await page.locator('meta[name="viewport"]').getAttribute("content")) ?? "", /viewport-fit=cover/);
	const manifest = await page.evaluate(async () => {
		const r = await fetch("/manifest.webmanifest", { credentials: "include" });
		return { status: r.status, type: r.headers.get("content-type"), body: await r.json() };
	});
	assert.equal(manifest.status, 200);
	assert.equal(manifest.body.display, "standalone", "opens with no browser bar");
	assert.equal(manifest.body.start_url, "/");
	const icons = [...manifest.body.icons.map((i) => i.src), await page.locator('link[rel="apple-touch-icon"]').getAttribute("href")];
	assert.ok(manifest.body.icons.some((i) => i.purpose === "maskable"), "a maskable icon for Android's shapes");
	for (const src of icons) {
		const r = await page.evaluate(async (u) => {
			const res = await fetch(u);
			return { status: res.status, type: res.headers.get("content-type"), size: (await res.arrayBuffer()).byteLength };
		}, src);
		assert.equal(r.status, 200, `${src} is served`);
		assert.match(r.type ?? "", /^image\/png/, `${src} is a PNG`);
		assert.ok(r.size > 1000, `${src} is a real picture`);
	}
	// The browser itself reads the manifest — under the app's CSP (manifest-src 'self').
	const parsed = await cdp.send("Page.getAppManifest");
	assert.deepEqual(parsed.errors, [], `the browser's own manifest parser: ${JSON.stringify(parsed.errors)}`);
	await noViolations("the manifest");

	await ctx.close();
	await browser.close();
	console.log("ok  e2e:phone — the touch explorer (rows, upload, New folder, tap, swipe, long-press sheet, rename, move, Select + Zip, Trash), Music/Movies/Team in one column, wide = desktop again, ☰ Lock, Add to Home Screen — no sideways scrolling, no CSP violation");
} finally {
	await dev.close();
}
