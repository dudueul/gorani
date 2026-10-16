// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * From a video's plaintext to an index the player can build segments from
 * (commit 39p, docs/VIDEO.md) — the same steps for a sealed file being
 * played (the reader decrypts frames) and a local file being uploaded (the
 * reader slices the File), so the sidecar written at upload and the one
 * written on first play are made by one piece of code.
 *
 * 1. A sidecar says where the moov is: read exactly that — trusted only as
 *    far as the box found there IS a moov of that size (a sidecar is a
 *    client's word, and a stale one must not feed the engine garbage).
 * 2. No sidecar, or a wrong one: walk the top-level boxes to find it.
 * 3. A fragmented file (moofs, or an `mvex` in the moov) is described but
 *    not indexed: the browser's own player streams those well through the
 *    media service worker, and the engine's fragmented path is for the
 *    server-side assembly it was written for.
 */

import type { MediaEngine, MediaIndex } from "./media-engine.ts";
import { MOOV_CAP, layoutOf, parseBoxHeader, topBoxes, videoMetaFrom, type ReadAt, type VideoMeta } from "../vault/video-meta.ts";

export interface IndexedVideo {
	/** The sidecar to keep (fresh when `changed`). */
	meta: VideoMeta;
	/** The engine's index — null for a fragmented file. The caller drops it. */
	index: MediaIndex | null;
	/** The sidecar was made (or corrected) here: worth writing back. */
	changed: boolean;
}

/** Segments aim at four seconds: short enough for a quick seek, long
 * enough that a film is not thousands of appends (they are cut on
 * keyframes, so a camera's long GOP makes them longer anyway). */
const TARGET_MS = 4000;

export async function indexVideo(read: ReadAt, size: number, sidecar: VideoMeta | null, engine: MediaEngine): Promise<IndexedVideo | null> {
	if (sidecar?.layout === "regular" && sidecar.moov) {
		const [at, len] = sidecar.moov;
		if (len <= MOOV_CAP && at + len <= size) {
			const moov = await read(at, len);
			const head = moov.length >= 8 ? parseBoxHeader(moov.subarray(0, Math.min(16, moov.length)), at, size) : null;
			if (head?.type === "moov" && head.size === len) {
				const index = engine.index(moov, at, size, TARGET_MS);
				// (A sidecar written before the engine ran has no summary yet;
				// one written by an older engine may name the codecs otherwise —
				// 39p's "Opus" for "opus". The engine's own word wins, and the
				// sidecar is written again.)
				const changed = sidecar.durationMs === null || sidecar.codecs !== index.summary.codecs;
				return { meta: changed ? videoMetaFrom({ layout: "regular", moov: [at, len] }, index.summary) : sidecar, index, changed };
			}
		}
	}
	if (sidecar?.layout === "fragmented") return { meta: sidecar, index: null, changed: false };
	const boxes = await topBoxes(read, size);
	const where = layoutOf(boxes);
	if (!where) return null; // not an MP4
	if (where.layout === "fragmented") return { meta: videoMetaFrom(where, null), index: null, changed: true };
	const [at, len] = where.moov;
	if (len > MOOV_CAP) return null;
	const moov = await read(at, len);
	const exact = layoutOf(boxes, moov);
	// (An mvex inside the moov: fragmented after all, its tables empty.)
	if (!exact || exact.layout === "fragmented") return { meta: videoMetaFrom({ layout: "fragmented", moov: where.moov }, null), index: null, changed: true };
	const index = engine.index(moov, at, size, TARGET_MS);
	return { meta: videoMetaFrom(exact, index.summary), index, changed: true };
}
