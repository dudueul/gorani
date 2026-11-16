// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * e2e:signin — the desktop apps' browser sign-in (commit 40c,
 * docs/DESKTOP.md › 40c) in a real browser, where it broke.
 *
 * The hand-off is a form POST from the server's https page to the app on
 * http://127.0.0.1, and the app takes it only when the browser names the
 * server as the form's Origin (clients/core/src/signin.rs › judge). Which
 * Origin a browser sends there depends on the page's referrer policy, so it
 * is checked in Chromium, not assumed — the earlier tests sent the Origin
 * themselves, with fetch, and passed while every real sign-in was refused:
 *
 *   - the Worker's page (fetched from the dev server, served at an https
 *     origin as production serves it): the button posts, the Origin is the
 *     server's, the Referer is the origin alone, the state and token arrive;
 *   - the same page with the policy it had (no-referrer), and with none
 *     (the browser's default): Origin null — the refusal people saw.
 *
 * The listener here is a stand-in that records what arrives. The app's own
 * listener is checked over real sockets in its Rust tests (signin.rs) and
 * through the CLI in api:client-live.
 */

import assert from "node:assert/strict";
import http from "node:http";
import { startDev } from "../api/_dev.mjs";

let chromium = null;
try {
	chromium = (await import("playwright")).chromium;
} catch {
	// not installed — a skip, not a failure
}
if (!chromium) {
	console.log("skip  e2e:signin — install it with: npm i -D playwright");
	process.exit(0);
}

/** The server, as production has it: an https origin (served by the test, never looked up). */
const SERVER = "https://gorani.test";

/** A stand-in for the app's listener: what arrives, recorded; answered as the app answers. */
function listener() {
	const got = [];
	const server = http.createServer((req, res) => {
		let body = "";
		req.on("data", (d) => (body += d));
		req.on("end", () => {
			got.push({ method: req.method, path: req.url, origin: req.headers.origin ?? "(none)", referer: req.headers.referer ?? "(none)", form: new URLSearchParams(body) });
			res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
			res.end("<!doctype html><title>Signed in — Gorani</title><h1>Signed in</h1>");
		});
	});
	return new Promise((ok) => server.listen(0, "127.0.0.1", () => ok({ port: server.address().port, got, close: () => new Promise((done) => server.close(done)) })));
}

const dev = await startDev({ persist: "e2e-signin" });
const browser = await chromium.launch({ headless: true });
try {
	/** The Worker's page served at SERVER (with `policy` as its referrer policy when given;
	 * "" for none at all), its button pressed: what reached the listener. */
	const handOff = async (policy) => {
		const app = await listener();
		const state = "S".repeat(43);
		const res = await fetch(`${dev.base}/api/v1/desktop/sign-in?port=${app.port}&state=${state}`, { headers: { "x-gorani-dev-email": "jinu@family.test" } });
		const html = await res.text();
		assert.equal(res.status, 200, html);
		const headers = Object.fromEntries(res.headers);
		if (policy === "") delete headers["referrer-policy"];
		else if (policy) headers["referrer-policy"] = policy;
		const ctx = await browser.newContext();
		const tab = await ctx.newPage();
		await tab.route(`${SERVER}/**`, (route) => route.fulfill({ status: 200, headers, body: html }));
		await tab.goto(`${SERVER}/api/v1/desktop/sign-in?port=${app.port}&state=${state}`);
		await tab.getByRole("button", { name: "Sign in Gorani" }).click();
		await tab.getByRole("heading", { name: "Signed in" }).waitFor({ timeout: 15_000 });
		await ctx.close();
		await app.close();
		assert.equal(app.got.length, 1, "one hand-off");
		return { served: headers["referrer-policy"] ?? "(none)", state, ...app.got[0] };
	};

	// The Worker's page as it is served now.
	const now = await handOff(null);
	assert.equal(now.served, "origin", "the page asks the browser to name its origin");
	assert.deepEqual([now.method, now.path], ["POST", "/gorani-sign-in"]);
	assert.equal(now.origin, SERVER, "Chromium names the server as the form's Origin: what the app takes");
	assert.equal(now.referer, `${SERVER}/`, "…and the Referer is the origin alone: the state in the page's address stays there");
	assert.equal(now.form.get("state"), now.state, "the state the app made");
	assert.match(now.form.get("token") ?? "", /^dev:/, "the sign-in the page carried (dev mode's stand-in)");

	// The page as it was: no-referrer. And with no policy, the browser's default.
	const before = await handOff("no-referrer");
	assert.equal(before.origin, "null", "no-referrer: the browser withholds the Origin, and the app refused every hand-off");
	const unset = await handOff("");
	assert.equal(unset.origin, "null", "the default (strict-origin-when-cross-origin) does the same: https to http is a downgrade");

	console.log("ok  e2e:signin — in Chromium, the server's sign-in page (served at an https origin) posts to the app on 127.0.0.1 naming the server as its Origin, the state and token with it, and a Referer of the origin alone; under no-referrer (the page as it was) and under the browser's default, the Origin is null — what every real sign-in sent before");
} finally {
	await browser.close();
	await dev.close();
}
