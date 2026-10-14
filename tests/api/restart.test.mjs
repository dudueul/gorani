// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:restart — state survives a restart, and so does the code that opens it.
 *
 * Every other suite starts from a fresh SQLite directory and keeps ONE dev
 * server for its whole run, so each Durable Object is constructed exactly
 * once. Production is the opposite: a DO is constructed again every time the
 * runtime evicts it (idle, deploy, host move). The constructor ran every
 * migration again — and the second `ALTER TABLE … ADD COLUMN` panicked, so
 * every member store hung on its first request after a wake-up (commit 25,
 * worker/src/schema.rs).
 *
 * This suite is the restart the others never do: write through both DOs,
 * stop the server, start a second one on the SAME directory, and read and
 * write again. It brings its own servers (tests/run.mjs › ownServer).
 */

import assert from "node:assert/strict";
import { startDev, api } from "./_dev.mjs";

const sealedName = (s) => "GV03:" + Buffer.from(`not-really-sealed:${s}`).toString("base64"); // the shape check is all the DO applies

let dev = await startDev({ persist: "restart" });
try {
	const first = await api(dev.base, "POST", "/api/v1/family/members", { body: { id: "mom", name: "Mom", role: "parent", emails: ["mom@family.test"] } });
	assert.equal(first.status, 200, first.text);
	const folder = await api(dev.base, "POST", "/api/v1/members/mom/files/folders", { body: { name: sealedName("before") } });
	assert.equal(folder.status, 200, folder.text);
	const before = await api(dev.base, "GET", "/api/v1/members/mom/files/list");
	assert.equal(before.json.folders.length, 1);
} finally {
	await dev.close();
}

// The same SQLite directory, a brand-new runtime: every DO is constructed
// again and walks its migrations against tables that already exist.
dev = await startDev({ persist: "restart", keepState: true });
try {
	const family = await api(dev.base, "GET", "/api/v1/family");
	assert.equal(family.status, 200, `the registry after a restart: ${family.text}`);
	assert.deepEqual(
		family.json.members.map((m) => m.id),
		["mom"],
	);
	// The member store: the request that used to hang until the runtime
	// cancelled it ("your Worker's code had hung").
	const after = await api(dev.base, "GET", "/api/v1/members/mom/files/list");
	assert.equal(after.status, 200, `the member store after a restart: ${after.text}`);
	assert.equal(after.json.folders.length, 1, "the folder written before the restart is still there");
	// And it still takes writes (the triggers, the change feed, the audit).
	const more = await api(dev.base, "POST", "/api/v1/members/mom/files/folders", { body: { name: sealedName("after") } });
	assert.equal(more.status, 200, more.text);
	const changes = await api(dev.base, "GET", "/api/v1/members/mom/files/changes?since=0");
	assert.equal(changes.status, 200, changes.text);
	assert.equal(changes.json.changes.filter((c) => c.kind === "folder.put").length, 2, "the change feed spans the restart");
} finally {
	await dev.close();
}

// A third start: the ledger now has every migration recorded, so nothing
// runs at all — the steady state of every wake-up from here on.
dev = await startDev({ persist: "restart", keepState: true });
try {
	const again = await api(dev.base, "GET", "/api/v1/members/mom/files/list");
	assert.equal(again.status, 200, again.text);
	assert.equal(again.json.folders.length, 2);
} finally {
	await dev.close();
}

console.log("ok  api:restart — both stores open, read and write after two restarts on the same state");
