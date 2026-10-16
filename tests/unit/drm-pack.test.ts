// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:drm-pack — protected copies, packaged the way a lead's browser
 * packages them, checked against ffmpeg (commit 40a, docs/DRM.md).
 *
 * The page's whole path: index the original with the WebAssembly engine,
 * open a packager with a key, build the protected init and every protected
 * segment from the same planned blocks the player reads, and write them
 * one after another — the single object the Worker serves. Then three
 * checks per file, each with ffmpeg as the independent reader:
 *
 *   1. **It opens with the key.** ffmpeg's `-decryption_key` decrypts the
 *      copy; every packet of every track equals the original's packet,
 *      byte for byte, and every decoded video frame equals the original's.
 *      (So the subsample maps, `tenc`, `senc` and the pattern are all read
 *      the way we wrote them.)
 *   2. **It is locked without it.** Undecrypted, the video packets and the
 *      audio packets differ from the original's.
 *   3. **The slice headers stay clear.** ffmpeg's `trace_headers` prints
 *      every syntax element of every parameter set and slice header; on
 *      the UNDECRYPTED copy the trace is identical to the original's. Had
 *      the packager taken one byte too few as a header, the first encrypted
 *      block would start inside it and the trace would differ.
 *
 * The fixtures cover every slice-header path crate::nal has: CAVLC, CABAC
 * with B-pyramid, weighted prediction and four slices, interlaced, in-band
 * parameter sets, HEVC with WPP entry points, HEVC Main 10 with three
 * slices a frame and in-band parameter sets, and HEVC without WPP or SAO.
 * Then the refusals: a codec FairPlay cannot play, wrong key material.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { mediaEngine } from "../../web/src/lib/media-engine.ts";
import { indexVideo } from "../../web/src/lib/video-index.ts";
import type { ReadAt } from "../../web/src/vault/video-meta.ts";
import { videoFixture, mediaWasm } from "../lib/video-fixtures.mjs";

const OUT = path.resolve(import.meta.dirname, "../output/drm");
fs.mkdirSync(OUT, { recursive: true });

const engine = await mediaEngine(mediaWasm());
const local = (bytes: Uint8Array): ReadAt => async (o, l) => bytes.slice(o, Math.min(o + l, bytes.length));

/** ffmpeg's output and its log, separately: hashes come on stdout; the
 * header trace, and a locked copy's decoding complaints, on stderr. */
function ffmpeg(args: string[]): { out: string; log: string } {
	const r = spawnSync("ffmpeg", ["-hide_banner", "-nostdin", "-nostats", ...args], { encoding: "utf8", maxBuffer: 256 << 20 });
	if (r.status !== 0) throw new Error(`ffmpeg ${args.join(" ")}: ${r.stderr.slice(-2000)}`);
	return { out: r.stdout, log: r.stderr };
}

/** Per stream, the md5 of each packet (`-c copy`) or decoded frame, in
 * order: framemd5's sixth field (side data, when a packet has any — skip
 * samples, encryption info — follows with hashes of its own). */
function hashes(file: string, { key, decode = false, stream }: { key?: string; decode?: boolean; stream: "v" | "a" }): string[] {
	const { out } = ffmpeg(["-loglevel", "error", ...(key ? ["-decryption_key", key] : []), "-i", file, "-map", `0:${stream}`, ...(decode ? [] : ["-c", "copy"]), "-f", "framemd5", "-"]);
	return out
		.split("\n")
		.filter((l) => l && !l.startsWith("#"))
		.map((l) => l.split(",")[5]!.trim());
}

/** The trace of every parameter set and slice header, without addresses. */
function trace(file: string): string[] {
	const { log } = ffmpeg(["-loglevel", "info", "-i", file, "-map", "0:v", "-c", "copy", "-bsf:v", "trace_headers", "-f", "null", "-"]);
	return log
		.split("\n")
		.filter((l) => l.includes("[trace_headers"))
		.map((l) => l.replace(/^.*\[trace_headers @ 0x[0-9a-f]+\]\s*/, ""))
		// a packet's own line keeps its size, not its times: the copy starts
		// at zero where the original's edit list shifted it
		.map((l) => l.replace(/^(Packet: \d+ bytes(?:, key frame)?).*$/, "$1"));
}

/** Package `file` as the page does; returns the copy's path and its key (hex). */
async function packageCopy(name: string, file: Uint8Array): Promise<{ out: string; key: string; segments: number }> {
	const found = await indexVideo(local(file), file.length, null, engine);
	assert.ok(found?.index, `${name}: indexed`);
	const index = found.index;
	const material = new Uint8Array(randomBytes(48));
	const key = Buffer.from(material.slice(0, 16)).toString("hex");
	const p = index.protect(material);
	try {
		const parts = [p.init()];
		for (let n = 0; n < index.segments.length; n++) {
			const joined = joinPlan(file, p.plan(n));
			const seg = p.segment(n, joined);
			// the same samples, plus the video's senc/saiz/saio
			assert.ok(seg.length > index.segment(n, joined).length, `${name}: segment ${n} carries its subsample maps`);
			parts.push(seg);
		}
		const out = path.join(OUT, name);
		fs.writeFileSync(out, Buffer.concat(parts));
		return { out, key, segments: index.segments.length };
	} finally {
		p.drop();
		index.drop();
	}
}

function joinPlan(file: Uint8Array, plan: [number, number][]): Uint8Array {
	return Buffer.concat(plan.map(([o, l]) => file.subarray(o, o + l)));
}

const FIXTURES = ["h264-baseline.mp4", "h264-high.mp4", "h264-interlaced.mp4", "h264-inband.mp4", "hevc-main.mp4", "hevc-main10.mp4", "hevc-nowpp.mp4"];

for (const name of FIXTURES) {
	const original = videoFixture(name);
	const bytes = new Uint8Array(fs.readFileSync(original));
	const { out, key, segments } = await packageCopy(name, bytes);
	assert.ok(segments > 1, `${name}: more than one segment`);

	// 1. With the key: every packet and every frame is the original's.
	for (const stream of ["v", "a"] as const) {
		const want = hashes(original, { stream });
		const got = hashes(out, { key, stream });
		assert.equal(got.length, want.length, `${name}: ${stream} packet count`);
		assert.deepEqual(got, want, `${name}: every ${stream} packet decrypts to the original's`);
	}
	assert.deepEqual(hashes(out, { key, stream: "v", decode: true }), hashes(original, { stream: "v", decode: true }), `${name}: every decoded frame is the original's`);

	// 2. Without it: locked.
	const lockedVideo = hashes(out, { stream: "v" });
	const clearVideo = hashes(original, { stream: "v" });
	const sameVideo = lockedVideo.filter((h, i) => h === clearVideo[i]).length;
	assert.equal(sameVideo, 0, `${name}: no video packet is left as it was (${sameVideo} of ${clearVideo.length} were)`);
	const lockedAudio = hashes(out, { stream: "a" });
	const clearAudio = hashes(original, { stream: "a" });
	const sameAudio = lockedAudio.filter((h, i) => h === clearAudio[i]).length;
	// an AAC packet shorter than 16 bytes (digital silence) has no whole block to encrypt
	assert.ok(sameAudio <= clearAudio.length / 20, `${name}: audio packets are encrypted (${sameAudio} of ${clearAudio.length} unchanged)`);

	// 3. The headers stay clear: the trace of the locked copy is the original's.
	const want = trace(original);
	const got = trace(out);
	assert.ok(want.some((l) => /slice_type/.test(l)), `${name}: the trace shows slice headers`);
	assert.equal(got.length, want.length, `${name}: trace length`);
	const firstDiff = got.findIndex((l, i) => l !== want[i]);
	assert.equal(firstDiff, -1, `${name}: slice headers stay clear — first difference at trace line ${firstDiff}:\n  original: ${want[firstDiff]}\n  copy:     ${got[firstDiff]}`);
	console.log(`ok ${name}: ${segments} segments, ${clearVideo.length} video and ${clearAudio.length} audio packets, ${want.length} trace lines`);
}

// ── Refusals ───────────────────────────────────────────────────────
{
	const vp9 = new Uint8Array(fs.readFileSync(videoFixture("vp9-opus.mp4")));
	const found = await indexVideo(local(vp9), vp9.length, null, engine);
	assert.ok(found?.index);
	assert.throws(() => found.index!.protect(new Uint8Array(48)), /FairPlay plays H\.264 or HEVC video with AAC, AC-3 or E-AC-3 audio; this file has vp09/, "VP9 + Opus is refused with the reason");
	found.index.drop();

	const h264 = new Uint8Array(fs.readFileSync(videoFixture("h264-baseline.mp4")));
	const again = await indexVideo(local(h264), h264.length, null, engine);
	assert.throws(() => again!.index!.protect(new Uint8Array(32)), /48 bytes/, "key material of the wrong length is refused");
	assert.ok(engine.alive, "a refusal is an answer, not a trap");
	again!.index!.drop();
}

console.log("unit:drm-pack ok");
