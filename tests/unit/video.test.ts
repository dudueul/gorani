// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:video — the in-page player's pipeline, on real MP4s (commit 39p,
 * docs/VIDEO.md): the box walk, the WebAssembly engine, the sidecar, and
 * the plaintext reader over GC01 frames — everything but the browser's
 * MediaSource, which e2e:app drives.
 *
 *   1. the walk finds the moov at the end and at the front, and refuses
 *      boxes that do not fit the file;
 *   2. the engine indexes both; the duration is ffprobe's, the codecs are
 *      the ones MSE is asked for, every segment builds as moof + mdat, and
 *      the planned blocks are exactly what the segment needs (one byte
 *      short is refused);
 *   3. the sidecar survives its JSON (and a malformed one is refused), a
 *      sidecar pointing at the wrong place is corrected, a fragmented file
 *      is described but not indexed, a non-MP4 is nothing;
 *   4. through GC01 frames (sealed here, small frames so a segment spans
 *      several) the reader returns the very same bytes, keeps frames it
 *      just opened, and the segments built from it equal the plain ones;
 *   5. a moov the engine cannot read is refused with its reason, and the
 *      engine goes on to index the next video;
 *   6. music in MP4 (39w) — an M4A, AAC or Opus — is indexed and cut into
 *      segments as a film is, under an audio/mp4 type; an MP3 is not the
 *      engine's, and is left to the media worker.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import { mediaEngine, MediaEngine } from "../../web/src/lib/media-engine.ts";
import { indexVideo } from "../../web/src/lib/video-index.ts";
import { FrameReader } from "../../web/src/lib/frame-reader.ts";
import { layoutOf, parseBoxHeader, parseVideoMeta, segmentAt, nextSegment, topBoxes, mseType, type ReadAt } from "../../web/src/vault/video-meta.ts";
import { sealChunked, openChunk } from "../../web/src/vault/chunked-file.ts";
import { newContentKey, importContentKey } from "../../web/src/vault/vault-crypto.ts";
import { videoFixture, mediaWasm, probeDuration } from "../lib/video-fixtures.mjs";
import { isMp4 } from "../../web/src/ui/files/model.ts";

const wasm = mediaWasm();
const engine = await mediaEngine(wasm);
const local = (bytes: Uint8Array): ReadAt => async (o, l) => bytes.slice(o, Math.min(o + l, bytes.length));

// ── 1. The walk ────────────────────────────────────────────────────
const endFile = new Uint8Array(fs.readFileSync(videoFixture("h264-aac-moov-end.mp4")));
const fastFile = new Uint8Array(fs.readFileSync(videoFixture("h264-aac-faststart.mp4")));
const endBoxes = await topBoxes(local(endFile), endFile.length);
const fastBoxes = await topBoxes(local(fastFile), fastFile.length);
assert.equal(endBoxes[0]!.type, "ftyp");
assert.ok(endBoxes.findIndex((b) => b.type === "moov") > endBoxes.findIndex((b) => b.type === "mdat"), "ffmpeg's default: moov after mdat");
assert.ok(fastBoxes.findIndex((b) => b.type === "moov") < fastBoxes.findIndex((b) => b.type === "mdat"), "faststart: moov first");
assert.equal(layoutOf(endBoxes)?.layout, "regular");
assert.throws(() => parseBoxHeader(new Uint8Array([0, 0, 0x10, 0, 0x6d, 0x6f, 0x6f, 0x76]), 0, 100), /does not fit the file/, "a box larger than the file is refused");
assert.throws(() => parseBoxHeader(new Uint8Array([0, 0, 0, 4, 0x66, 0x72, 0x65, 0x65]), 0, 100), /does not fit/, "a box smaller than its header is refused (the walk would never move)");

// ── 2. The engine ──────────────────────────────────────────────────
for (const [name, file] of [["moov at the end", endFile], ["faststart", fastFile]] as const) {
	const found = await indexVideo(local(file), file.length, null, engine);
	assert.ok(found?.index, `${name}: indexed`);
	const { index, meta } = found;
	const seconds = probeDuration(name === "faststart" ? videoFixture("h264-aac-faststart.mp4") : videoFixture("h264-aac-moov-end.mp4"));
	assert.ok(Math.abs(index.summary.durationMs / 1000 - seconds) < 0.25, `${name}: duration ${index.summary.durationMs} ms ≈ ffprobe's ${seconds} s`);
	assert.match(index.summary.codecs, /^avc1\.[0-9a-f]{6},mp4a\.40\.2$/i, `${name}: the codecs MSE is asked for (${index.summary.codecs})`);
	assert.equal(meta.width, 320);
	assert.equal(meta.height, 180);
	assert.equal(mseType(meta.codecs!, true), `video/mp4; codecs="${meta.codecs}"`);
	const segs = index.segments;
	assert.ok(segs.length >= 2, `${name}: more than one segment (${segs.length})`);
	assert.equal(segs[0]![0], 0, "the first segment starts at 0");
	const end = segs[segs.length - 1]![0] + segs[segs.length - 1]![1];
	assert.ok(Math.abs(end - seconds) < 0.25, `${name}: the segments cover the film (${end} s)`);
	const init = index.init();
	assert.equal(String.fromCharCode(...init.subarray(4, 8)), "ftyp", "the init segment starts with ftyp");
	for (let n = 0; n < segs.length; n++) {
		const blocks = index.plan(n);
		const joined = new Uint8Array(blocks.reduce((a, [, l]) => a + l, 0));
		let at = 0;
		for (const [o, l] of blocks) {
			joined.set(file.subarray(o, o + l), at);
			at += l;
		}
		const seg = index.segment(n, joined);
		assert.equal(String.fromCharCode(...seg.subarray(4, 8)), "moof", `${name}: segment ${n} is a moof…`);
		const moofSize = new DataView(seg.buffer, seg.byteOffset).getUint32(0);
		assert.equal(String.fromCharCode(...seg.subarray(moofSize + 4, moofSize + 8)), "mdat", "…then its mdat");
		if (n === 0) assert.throws(() => index.segment(n, joined.subarray(1)), /bytes given/, "one byte short is refused, not guessed at");
	}
	// The player's choice of what to append next.
	assert.equal(segmentAt(segs, 0), 0);
	assert.equal(nextSegment(segs, [], 0, 30), 0, "nothing buffered: the first");
	assert.equal(nextSegment(segs, [[0, segs[0]![1]]], 0, 30), 1, "the first buffered: the second");
	assert.equal(nextSegment(segs, [[0, end]], 0, 30), -1, "all of it buffered: nothing");
	index.drop();
}

// ── 3. The sidecar ─────────────────────────────────────────────────
const made = (await indexVideo(local(endFile), endFile.length, null, engine))!;
made.index?.drop();
assert.equal(made.changed, true, "made here: worth writing back");
const roundTrip = parseVideoMeta(JSON.stringify(made.meta));
assert.deepEqual(roundTrip, made.meta, "the sidecar survives its JSON");
assert.equal(parseVideoMeta(JSON.stringify({ ...made.meta, moov: [-1, 5] })), null, "a malformed sidecar is refused");
assert.equal(parseVideoMeta("not json"), null);
const reused = (await indexVideo(local(endFile), endFile.length, made.meta, engine))!;
assert.equal(reused.changed, false, "a good sidecar is used as it is — one read of the moov");
reused.index?.drop();
const wrong = (await indexVideo(local(endFile), endFile.length, { ...made.meta, moov: [0, made.meta.moov![1]] }, engine))!;
assert.equal(wrong.changed, true, "a sidecar pointing at the wrong place is corrected…");
assert.deepEqual(wrong.meta.moov, made.meta.moov, "…by walking the boxes");
wrong.index?.drop();
const frag = new Uint8Array(fs.readFileSync(videoFixture("h264-fragmented.mp4")));
const fragFound = (await indexVideo(local(frag), frag.length, null, engine))!;
assert.equal(fragFound.meta.layout, "fragmented");
assert.equal(fragFound.index, null, "a fragmented file is described, not indexed (the media worker plays it)");
// What the browser test plays (VP9 + Opus): the codecs as MSE names them —
// "opus", not the sample entry's "Opus", which Chromium refuses (39p).
const vp9 = new Uint8Array(fs.readFileSync(videoFixture("vp9-opus.mp4", { seconds: 6 })));
const vp9Found = (await indexVideo(local(vp9), vp9.length, null, engine))!;
assert.match(vp9Found.meta.codecs ?? "", /^vp09\.\d\d\.\d\d\.\d\d,opus$/, `VP9 + Opus as MSE names them (${vp9Found.meta.codecs})`);
vp9Found.index?.drop();
const noise = crypto.getRandomValues(new Uint8Array(4096));
assert.equal(await indexVideo(local(noise), noise.length, null, engine).catch(() => null), null, "not an MP4: nothing");

// ── 4. Through GC01 frames ─────────────────────────────────────────
{
	const chunk = 64 * 1024; // small: a segment spans several frames
	const ck = newContentKey();
	const key = await importContentKey(ck);
	const sealed = await sealChunked(key, endFile, chunk);
	let fetches = 0;
	const reader = new FrameReader({
		size: endFile.length,
		chunk,
		fetchCipher: async (a, b) => {
			fetches++;
			return sealed.slice(a, b + 1);
		},
		open: (frame, i, final) => openChunk(key, frame, i, final),
	});
	const some = await reader.read(100_000, 200_000);
	assert.deepEqual(some, endFile.subarray(100_000, 300_000), "the plaintext range, byte for byte, across frames");
	const before = fetches;
	await reader.read(150_000, 1000);
	assert.equal(fetches, before, "a frame just opened is kept, not fetched again");
	assert.deepEqual(await reader.read(endFile.length - 10, 100), endFile.subarray(endFile.length - 10), "the last frame (final flag), cut at the end");
	const viaFrames = (await indexVideo((o, l) => reader.read(o, l), endFile.length, null, engine))!;
	const plain = (await indexVideo(local(endFile), endFile.length, null, engine))!;
	assert.deepEqual(viaFrames.meta, plain.meta, "the same sidecar through the frames");
	for (const n of [0, viaFrames.index!.segments.length - 1]) {
		const blocks = viaFrames.index!.plan(n);
		const parts = await Promise.all(blocks.map(([o, l]) => reader.read(o, l)));
		const joined = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
		let at = 0;
		for (const p of parts) {
			joined.set(p, at);
			at += p.length;
		}
		const pj = new Uint8Array(joined.length);
		let pat = 0;
		for (const [o, l] of plain.index!.plan(n)) {
			pj.set(endFile.subarray(o, o + l), pat);
			pat += l;
		}
		assert.deepEqual(viaFrames.index!.segment(n, joined), plain.index!.segment(n, pj), `segment ${n}: the same bytes through the frames`);
	}
	viaFrames.index!.drop();
	plain.index!.drop();
}

// ── 6. Music in MP4 (39w): the same engine, no picture ─────────────
// An M4A plays through the in-page player as a film does — indexed, cut
// into segments, appended as fMP4 — with an audio/mp4 MediaSource type.
for (const name of ["aac.m4a", "opus.m4a"] as const) {
	const path = videoFixture(name, { seconds: 20 });
	const file = new Uint8Array(fs.readFileSync(path));
	const found = await indexVideo(local(file), file.length, null, engine);
	assert.ok(found?.index, `${name}: indexed`);
	const { index, meta } = found;
	assert.deepEqual(meta.tracks.map((t) => t.type), ["audio"], `${name}: one track, audio`);
	assert.match(index.summary.codecs, name === "aac.m4a" ? /^mp4a\.40\.2$/ : /^opus$/, `${name}: the codec MSE is asked for (${index.summary.codecs})`);
	assert.equal(mseType(index.summary.codecs, false), `audio/mp4; codecs="${index.summary.codecs}"`);
	const seconds = probeDuration(path);
	assert.ok(Math.abs(index.summary.durationMs / 1000 - seconds) < 0.25, `${name}: duration ${index.summary.durationMs} ms ≈ ffprobe's ${seconds} s`);
	const segs = index.segments;
	assert.ok(segs.length >= 2, `${name}: a track is cut into segments too (${segs.length}), so a seek fetches only its own`);
	const end = segs[segs.length - 1]![0] + segs[segs.length - 1]![1];
	assert.ok(Math.abs(end - seconds) < 0.25, `${name}: the segments cover the track (${end} s)`);
	for (let n = 0; n < segs.length; n++) {
		const blocks = index.plan(n);
		const joined = new Uint8Array(blocks.reduce((a, [, l]) => a + l, 0));
		let at = 0;
		for (const [o, l] of blocks) {
			joined.set(file.subarray(o, o + l), at);
			at += l;
		}
		const seg = index.segment(n, joined);
		assert.equal(String.fromCharCode(...seg.subarray(4, 8)), "moof", `${name}: segment ${n} is a moof`);
	}
	index.drop();
}
// An MP3 is not the engine's: the viewer never asks it (isMp4), and the
// box walk would refuse it anyway — the media worker plays it.
{
	const mp3 = new Uint8Array(fs.readFileSync(videoFixture("tone.mp3", { seconds: 5 })));
	assert.equal(isMp4("tone.mp3", "audio/mpeg"), false, "an MP3 goes to the media worker");
	assert.equal(isMp4("track.m4a", null) && isMp4("book.m4b", null) && isMp4("x", "audio/x-m4a"), true, "an M4A (and an M4B) goes to the engine");
	await assert.rejects(indexVideo(local(mp3), mp3.length, null, engine), /does not fit the file/, "…which would refuse an MP3's bytes, not misread them");
}

// ── 5. A file the engine cannot read is a refusal, not a crash ─────
{
	const module = await WebAssembly.compile(wasm);
	const lone = await MediaEngine.instantiate(module);
	const junk = new Uint8Array(64);
	new DataView(junk.buffer).setUint32(0, 64);
	junk.set([0x6d, 0x6f, 0x6f, 0x76], 4); // "moov" with nothing sensible inside
	assert.throws(() => lone.index(junk, 0, 64), /unsupported|parse|box/i, "the engine says what it could not read");
	assert.ok(lone.alive, "a refusal leaves the engine working (only a trap retires an instance)");
	const again = (await indexVideo(local(fastFile), fastFile.length, null, lone))!;
	assert.ok(again.index, "…and it indexes the next video");
	again.index!.drop();
}

console.log("ok  unit:video — the walk (moov at either end, boxes that do not fit refused), the engine (ffprobe's duration, the MSE codecs, every segment moof+mdat, a short input refused), the sidecar (round trip, malformed refused, a wrong place corrected, fragmented described, non-MP4 nothing), the same bytes and segments through GC01 frames, music in MP4 (AAC and Opus M4As indexed and cut like films, an audio/mp4 type; an MP3 left to the media worker), an unreadable moov refused without breaking the engine");
