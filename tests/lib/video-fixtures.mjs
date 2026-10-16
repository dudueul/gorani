// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Real MP4s for the video tests (commit 39p), made by ffmpeg once and kept
 * in tests/output/video/ (which git ignores). A real encoder's output, not
 * hand-built boxes: the engine is checked against what cameras and phones
 * actually write — edit lists, B-frames, interleaved audio, `moov` at the
 * end or (faststart) at the front.
 *
 * Which codecs: H.264 + AAC is what most files are, and what every real
 * browser decodes; the Chromium that Playwright drives has no H.264 or AAC
 * decoder (they are licensed codecs), so the browser test plays VP9 + Opus
 * in MP4 — the same container, the same engine path.
 *
 * ffmpeg is a test prerequisite (docs/TESTS.md › Prerequisites); without it
 * these helpers throw with that said, rather than skipping quietly.
 */

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const DIR = path.join(ROOT, "tests/output/video");

/** What each fixture is: ffmpeg's arguments after the inputs. */
const RECIPES = {
	// The common case: H.264 High with B-frames, AAC, moov at the END
	// (ffmpeg's default — a phone's recording looks like this).
	"h264-aac-moov-end.mp4": ["-c:v", "libx264", "-preset", "ultrafast", "-g", "30", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "64k"],
	// The same, faststart: moov at the front (what a web export writes).
	"h264-aac-faststart.mp4": ["-c:v", "libx264", "-preset", "ultrafast", "-g", "30", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "64k", "-movflags", "+faststart"],
	// Fragmented (moof/mdat pairs): described, not indexed.
	"h264-fragmented.mp4": ["-c:v", "libx264", "-preset", "ultrafast", "-g", "30", "-pix_fmt", "yuv420p", "-c:a", "aac", "-movflags", "frag_keyframe+empty_moov"],
	// What Playwright's Chromium can decode: VP9 + Opus, in MP4.
	"vp9-opus.mp4": ["-c:v", "libvpx-vp9", "-deadline", "realtime", "-cpu-used", "8", "-b:v", "400k", "-g", "30", "-c:a", "libopus", "-b:a", "48k"],
	// The same, noisy and at a high constant rate: big enough (≈ 8 MB for
	// 12 s) that its GC01 frames, at the 5 MiB minimum part, are two — so a
	// segment's blocks can sit across a frame boundary.
	"vp9-opus-noisy.mp4": ["-vf", "noise=alls=80:allf=t+u", "-c:v", "libvpx-vp9", "-deadline", "realtime", "-cpu-used", "8", "-b:v", "6M", "-minrate", "6M", "-maxrate", "6M", "-g", "30", "-c:a", "libopus", "-b:a", "48k"],

	// For the protected copies (commit 40a, unit:drm-pack): every slice
	// header shape the parser must step over exactly. Each is a different
	// path through crate::nal.
	// Baseline: CAVLC (a header that ends mid-byte), no B-frames.
	"h264-baseline.mp4": ["-c:v", "libx264", "-profile:v", "baseline", "-preset", "ultrafast", "-g", "30", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "64k"],
	// High: CABAC, B-pyramid, weighted P prediction (pred_weight_table),
	// four slices a frame, several references (list modifications, memory
	// management), 8x8 transforms and a custom quantiser matrix in the PPS.
	"h264-high.mp4": ["-c:v", "libx264", "-preset", "medium", "-profile:v", "high", "-bf", "3", "-b_strategy", "2", "-refs", "4", "-weightp", "2", "-g", "30", "-x264-params", "slices=4:b-pyramid=normal:cqm=jvt", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "64k"],
	// Interlaced (MBAFF): frame_mbs_only = 0, so field flags in every header.
	"h264-interlaced.mp4": ["-c:v", "libx264", "-preset", "fast", "-flags", "+ildct+ilme", "-x264-params", "interlaced=1", "-g", "30", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "64k"],
	// Parameter sets sent in band at every keyframe as well (avc3-style).
	"h264-inband.mp4": ["-c:v", "libx264", "-preset", "fast", "-g", "30", "-x264-params", "repeat-headers=1", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "64k"],
	// HEVC as a phone writes it: WPP (entry points in every header), SAO,
	// temporal MVP, B-pyramid, weighted prediction, inter-predicted RPSs.
	"hevc-main.mp4": ["-c:v", "libx265", "-preset", "fast", "-tag:v", "hvc1", "-x265-params", "log-level=error:keyint=30:bframes=4:b-pyramid=1:weightp=1:weightb=1:ref=4", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "64k"],
	// HEVC Main 10, three slices a frame (slice segment addresses), the
	// parameter sets repeated in band at every keyframe.
	"hevc-main10.mp4": ["-c:v", "libx265", "-preset", "medium", "-tag:v", "hvc1", "-x265-params", "log-level=error:keyint=30:slices=3:repeat-headers=1:bframes=3", "-pix_fmt", "yuv420p10le", "-c:a", "aac", "-b:a", "64k"],
	// HEVC without WPP: no entry points, and deblocking/SAO left at the
	// PPS's word (no override in the slice header).
	"hevc-nowpp.mp4": ["-c:v", "libx265", "-preset", "fast", "-tag:v", "hvc1", "-x265-params", "log-level=error:keyint=30:wpp=0:sao=0:bframes=2", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "64k"],

	// Music (39w): the tone alone (`-vn` drops the picture). AAC in MP4 is
	// what an M4A is; Opus in MP4 is what Playwright's Chromium decodes;
	// an MP3 is what the MP4 engine does not cut — the media worker plays it.
	"aac.m4a": ["-vn", "-c:a", "aac", "-b:a", "128k"],
	"opus.m4a": ["-vn", "-c:a", "libopus", "-b:a", "64k"],
	"tone.mp3": ["-vn", "-c:a", "libmp3lame", "-b:a", "128k"],
};

/** A fixture's path, made on first use: `seconds` of test picture and tone. */
export function videoFixture(name, { seconds = 6, size = "320x180" } = {}) {
	const recipe = RECIPES[name];
	if (!recipe) throw new Error(`no video fixture ${name}`);
	const out = path.join(DIR, `${seconds}s-${size}-${name}`);
	if (fs.existsSync(out) && fs.statSync(out).size > 0) return out;
	fs.mkdirSync(DIR, { recursive: true });
	// (The container follows the extension ffmpeg sees: MP4 for the MP4
	// family, M4A included — its own muxer refuses Opus — MP3 for an MP3.)
	const part = `${out}.part${name.endsWith(".mp3") ? ".mp3" : ".mp4"}`;
	const probe = spawnSync("ffmpeg", ["-version"], { encoding: "utf8" });
	if (probe.status !== 0) throw new Error("the video tests need ffmpeg (docs/TESTS.md › Prerequisites) — it was not found on PATH");
	const r = spawnSync(
		"ffmpeg",
		["-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", `testsrc2=size=${size}:rate=30:duration=${seconds}`, "-f", "lavfi", "-i", `sine=frequency=440:sample_rate=48000:duration=${seconds}`, "-shortest", ...recipe, part],
		{ encoding: "utf8" },
	);
	if (r.status !== 0) throw new Error(`ffmpeg could not make ${name}: ${r.stderr}`);
	fs.renameSync(part, out);
	return out;
}

/** The engine's WebAssembly, built if missing or stale (scripts/build-media-wasm.mjs). */
export function mediaWasm() {
	const r = spawnSync(process.execPath, [path.join(ROOT, "scripts/build-media-wasm.mjs")], { cwd: ROOT, encoding: "utf8" });
	if (r.status !== 0) throw new Error(`building the media engine failed:\n${r.stdout}\n${r.stderr}`);
	return fs.readFileSync(path.join(ROOT, "web/public/gorani-media.wasm"));
}

/** ffprobe's duration of a file, in seconds. */
export function probeDuration(file) {
	const r = spawnSync("ffprobe", ["-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", file], { encoding: "utf8" });
	return Number(r.stdout.trim());
}
