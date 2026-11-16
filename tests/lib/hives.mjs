// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Three real Windows registry hives (commit 42k), fetched when a test
 * needs them: regipy's own test data (MIT licence), from one pinned
 * commit, each checked by SHA-256 twice — the download and the hive it
 * decompresses to — and kept in tests/.cache/hives/ (git-ignored), so the
 * network is used once.
 *
 *   NTUSER.DAT   786 KB    a Windows 7 user's hive: lf lists, format 1.3
 *   SYSTEM       11.8 MB   lh and ri lists, big data, the ShimCache
 *   SOFTWARE     37.7 MB   the same, and 50 keys deleted but still there
 *
 * They are not kept in this repository (50 MB raw, 5.7 MB compressed:
 * more than the rest of it), and nothing in them is made up: they are a
 * real machine's, as forensic tools are tested on. Offline, or without
 * curl or xz, `sampleHive` gives null and the test says it skipped.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const CACHE = path.join(ROOT, "tests/.cache/hives");

export const REGIPY_COMMIT = "c6de929abc37d8315d1c31aba5e937db636f3303";
const BASE = `https://raw.githubusercontent.com/mkorman90/regipy/${REGIPY_COMMIT}/regipy_tests/data`;

/** Each hive: its download (xz) and the hive itself, by SHA-256. */
export const HIVES = {
	"NTUSER.DAT": { xz: "4de0403ce4e1361db9a3f489262d8f48614223440cabe65b64f508e05c8e1aeb", raw: "6a38fcea924113963e4931725cc4c2f4f10e1240234cb1867d101a1cd92cd439" },
	SYSTEM: { xz: "e19c910ff457a4ef81a3b4d7f6206ec8a7e8fa82b6e40a6c93e40699b02a52bb", raw: "e178813e4643e8ccf4d1ccc505ddc128041b6135277417b98219dfe3167450c3" },
	SOFTWARE: { xz: "e0db74a30c97c86c025255d5c12f3f1865c1df82cfb28484617c89c7c2793018", raw: "c2e1a391d6be9740e79da7944e012ad9ac878902db38ec7fc225a2a68d262a1b" },
};

const sha256 = (b) => createHash("sha256").update(b).digest("hex");

/** Why the last `sampleHive` gave null (for the skip notice). */
export let unavailable = "";

/**
 * The hive's bytes, or null when it cannot be had here (and `unavailable`
 * says why). A download or a hive whose hash differs is an error, not a
 * skip: that is a changed file, not a missing one.
 */
export function sampleHive(name) {
	const want = HIVES[name];
	if (!want) throw new Error(`no sample hive ${name}`);
	const hive = path.join(CACHE, name);
	if (fs.existsSync(hive)) {
		const b = new Uint8Array(fs.readFileSync(hive));
		if (sha256(b) === want.raw) return b;
		fs.rmSync(hive); // (a damaged cache is fetched again)
	}
	fs.mkdirSync(CACHE, { recursive: true });
	const xz = `${hive}.xz`;
	// curl, not fetch: it goes through the proxy a sandbox or a company sets.
	const got = spawnSync("curl", ["-fsSL", "--max-time", "300", "-o", xz, `${BASE}/${name}.xz`], { encoding: "utf8" });
	if (got.error || got.status !== 0) {
		unavailable = `could not fetch ${name} (${got.error?.message ?? got.stderr.trim().split("\n").pop() ?? `curl exited ${got.status}`})`;
		fs.rmSync(xz, { force: true });
		return null;
	}
	const packed = fs.readFileSync(xz);
	if (sha256(packed) !== want.xz) {
		fs.rmSync(xz, { force: true });
		throw new Error(`${name}.xz from regipy ${REGIPY_COMMIT.slice(0, 7)} is not the file pinned here (SHA-256 ${sha256(packed)})`);
	}
	const out = spawnSync("xz", ["-dc", xz], { maxBuffer: 64 * 1024 * 1024 });
	if (out.error || out.status !== 0) {
		unavailable = `could not decompress ${name}.xz (${out.error?.message ?? `xz exited ${out.status}`})`;
		return null;
	}
	const b = new Uint8Array(out.stdout);
	if (sha256(b) !== want.raw) throw new Error(`${name} decompressed to a hive other than the one pinned here`);
	fs.writeFileSync(hive, b);
	fs.rmSync(xz, { force: true });
	return b;
}

/**
 * A walk of a whole hive, as one SHA-256: every key's path and last write,
 * every value's name, type and data, in the order the hive keeps them.
 * Pinned in the tests to the walk python-registry agreed with, key for key
 * and byte for byte, when this was written.
 */
export function walkDigest(hive) {
	const h = createHash("sha256");
	let keys = 0;
	let values = 0;
	const walk = (k, p) => {
		keys++;
		h.update(`${p}\t${k.written}\n`);
		for (const v of hive.values(k)) {
			values++;
			h.update(`\t${v.name}\u0000${v.type}\u0000${v.data ? sha256(v.data) : "-"}\n`);
		}
		for (const s of hive.subkeys(k)) walk(s, `${p}\\${s.name}`);
	};
	walk(hive.root, hive.root.name);
	return { keys, values, digest: h.digest("hex") };
}
