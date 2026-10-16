// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The video sidecar — `.hlsmeta` in docs/VIDEO.md (commit 39p).
 *
 * Like the music tags (docs/MUSIC.md), it exists only because a client that
 * already held the plaintext chose to seal a summary of it: the server
 * stores an opaque blob per file version and can never learn a duration,
 * a resolution or a codec. What the blob holds:
 *
 * ```text
 * {
 *   v: 1, container: "mp4",
 *   layout: "regular" | "fragmented",   regular = sample tables in one moov
 *   moov: [offset, size] | null,        where the moov box is, in PLAINTEXT bytes
 *   durationMs, codecs,                 "avc1.64001f,mp4a.40.2" — what MSE is asked
 *   width, height,
 *   tracks: [{ type, codec }]
 * }
 * ```
 *
 * Why the moov's PLACE and not the whole index: the index of a two-hour
 * film (every sample's size and timing) is megabytes, and a store row is
 * not the place for megabytes. The moov itself is in the file; knowing
 * where it is turns "walk the boxes, frame by frame, to find it" into one
 * read. The player indexes it in WebAssembly in milliseconds (media-engine.ts).
 *
 * Pure TypeScript, no DOM: the box walk and the shape checks run in Node
 * for tests/unit/video.test.ts exactly as in the browser.
 */

export interface VideoTrack {
	type: "video" | "audio";
	codec: string;
}

export interface VideoMeta {
	v: 1;
	container: "mp4";
	layout: "regular" | "fragmented";
	moov: [number, number] | null;
	durationMs: number | null;
	codecs: string | null;
	width: number;
	height: number;
	tracks: VideoTrack[];
}

/** What the engine's index says (media-engine.ts › summary). */
export interface EngineSummary {
	durationMs: number;
	codecs: string;
	tracks: { id: number; type: "video" | "audio"; codec: string; width: number; height: number }[];
	/** Every segment's [start, duration] in seconds — cut on keyframes. */
	segments: [number, number][];
	warnings: string[];
}

/** A plaintext reader: `length` bytes at `offset` (fewer only at the end). */
export type ReadAt = (offset: number, length: number) => Promise<Uint8Array>;

/** One top-level box. `size` covers the header too. */
export interface TopBox {
	type: string;
	offset: number;
	size: number;
	headerLen: number;
}

/**
 * The largest moov the player will read. A real two-hour film's is a few
 * MB; a box claiming more is a damaged or hostile file, and reading it
 * would decrypt (and hold) that much before showing a frame.
 */
export const MOOV_CAP = 64 * 1024 * 1024;

/** How many top-level boxes the walk looks at. A regular file has a handful
 * (ftyp, free, mdat, moov); a fragmented one has thousands of moof/mdat
 * pairs, and the walk stops at the first moof — it has learned enough. */
const WALK_LIMIT = 64;

/**
 * One box header at `offset` of a file of `fileSize` (ISO/IEC 14496-12 §4.2):
 * a 32-bit size and a four-character type; size 1 means a 64-bit size
 * follows, size 0 means "to the end of the file". A size that does not fit
 * the file is refused — the walk would otherwise jump past the end, or
 * loop on a zero-length box.
 */
export function parseBoxHeader(b: Uint8Array, offset: number, fileSize: number): TopBox {
	if (b.length < 8) throw new Error(`a box header at ${offset} is cut short`);
	const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
	const small = dv.getUint32(0);
	const type = fourcc(b, 4);
	let size: number;
	let headerLen = 8;
	if (small === 1) {
		if (b.length < 16) throw new Error(`a large box header at ${offset} is cut short`);
		const big = dv.getBigUint64(8);
		if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`the ${type} box at ${offset} claims more bytes than any file holds`);
		size = Number(big);
		headerLen = 16;
	} else if (small === 0) {
		size = fileSize - offset;
	} else {
		size = small;
	}
	if (size < headerLen || offset + size > fileSize) throw new Error(`the ${type} box at ${offset} does not fit the file (${size} bytes)`);
	return { type, offset, size, headerLen };
}

/** A box type: four bytes read as characters. */
function fourcc(b: Uint8Array, at: number): string {
	return String.fromCharCode(b[at] ?? 0, b[at + 1] ?? 0, b[at + 2] ?? 0, b[at + 3] ?? 0);
}

/** The top-level boxes, in order — stopping after a moof (see WALK_LIMIT). */
export async function topBoxes(read: ReadAt, fileSize: number): Promise<TopBox[]> {
	const boxes: TopBox[] = [];
	let at = 0;
	while (at + 8 <= fileSize && boxes.length < WALK_LIMIT) {
		const box = parseBoxHeader(await read(at, Math.min(16, fileSize - at)), at, fileSize);
		boxes.push(box);
		if (box.type === "moof") break;
		at += box.size;
	}
	return boxes;
}

/**
 * Where the moov is, and whether the file is fragmented: a moof at the top
 * level, or an `mvex` inside the moov (the sample tables are then empty
 * and the moofs carry everything). Not an MP4 at all → null.
 */
export function layoutOf(boxes: TopBox[], moovBytes?: Uint8Array): { layout: "regular" | "fragmented"; moov: [number, number] } | null {
	if (boxes[0]?.type !== "ftyp") return null;
	const moov = boxes.find((b) => b.type === "moov");
	if (!moov) return null;
	const fragmented = boxes.some((b) => b.type === "moof") || (moovBytes !== undefined && hasChild(moovBytes, "mvex"));
	return { layout: fragmented ? "fragmented" : "regular", moov: [moov.offset, moov.size] };
}

/** A direct child box of a whole box (header included) by type. */
function hasChild(box: Uint8Array, type: string): boolean {
	let at = box.length >= 16 && new DataView(box.buffer, box.byteOffset).getUint32(0) === 1 ? 16 : 8;
	while (at + 8 <= box.length) {
		const dv = new DataView(box.buffer, box.byteOffset + at);
		const size = dv.getUint32(0);
		if (fourcc(box, at + 4) === type) return true;
		if (size < 8) return false;
		at += size;
	}
	return false;
}

/** The sidecar for a file — from the engine's summary when it indexed the
 * moov (a regular file), from the walk alone otherwise. */
export function videoMetaFrom(where: { layout: "regular" | "fragmented"; moov: [number, number] }, summary: EngineSummary | null): VideoMeta {
	const video = summary?.tracks.find((t) => t.type === "video");
	return {
		v: 1,
		container: "mp4",
		layout: where.layout,
		moov: where.moov,
		durationMs: summary ? summary.durationMs : null,
		codecs: summary ? summary.codecs : null,
		width: video?.width ?? 0,
		height: video?.height ?? 0,
		tracks: summary ? summary.tracks.map((t) => ({ type: t.type, codec: t.codec })) : [],
	};
}

/**
 * A sidecar opened from the store — checked field by field. It is sealed in
 * its file's place (no other file's blob opens here), but it was written by
 * whichever client made it, and the player trusts the moov place it names
 * only as far as the box at that place says "moov".
 */
export function parseVideoMeta(text: string): VideoMeta | null {
	let v: unknown;
	try {
		v = JSON.parse(text);
	} catch {
		return null;
	}
	if (typeof v !== "object" || v === null) return null;
	const m = v as Record<string, unknown>;
	const nat = (x: unknown) => typeof x === "number" && Number.isSafeInteger(x) && x >= 0;
	if (m.v !== 1 || m.container !== "mp4" || (m.layout !== "regular" && m.layout !== "fragmented")) return null;
	const moov = m.moov === null ? null : Array.isArray(m.moov) && m.moov.length === 2 && m.moov.every(nat) ? ([m.moov[0], m.moov[1]] as [number, number]) : undefined;
	if (moov === undefined) return null;
	if (!(m.durationMs === null || nat(m.durationMs)) || !(m.codecs === null || (typeof m.codecs === "string" && m.codecs.length <= 200))) return null;
	if (!nat(m.width) || !nat(m.height) || !Array.isArray(m.tracks) || m.tracks.length > 32) return null;
	const tracks: VideoTrack[] = [];
	for (const t of m.tracks as unknown[]) {
		const tr = t as Record<string, unknown>;
		if ((tr?.type !== "video" && tr?.type !== "audio") || typeof tr.codec !== "string" || tr.codec.length > 100) return null;
		tracks.push({ type: tr.type, codec: tr.codec });
	}
	return { v: 1, container: "mp4", layout: m.layout, moov, durationMs: m.durationMs as number | null, codecs: m.codecs as string | null, width: m.width as number, height: m.height as number, tracks };
}

/** The MSE type for a sidecar or summary: `video/mp4; codecs="…"`. */
export function mseType(codecs: string, hasVideo: boolean): string {
	return `${hasVideo ? "video" : "audio"}/mp4; codecs="${codecs}"`;
}

/** The segment holding time `t` (seconds): the last whose start ≤ t. */
export function segmentAt(segments: readonly (readonly [number, number])[], t: number): number {
	let lo = 0;
	let hi = segments.length - 1;
	if (hi < 0) return -1;
	while (lo < hi) {
		const mid = (lo + hi + 1) >> 1;
		if (segments[mid]![0] <= t) lo = mid;
		else hi = mid - 1;
	}
	return lo;
}

/**
 * What the player appends next (MsePlayer › pump): the first segment from
 * the one playing that the buffer does not hold — or -1 when everything up
 * to `ahead` seconds past `t` is there. "Holds" is judged by the segment's
 * MIDDLE: buffered ranges start and end a few milliseconds off a segment's
 * nominal edges (audio priming, B-frame offsets), and a check on the edges
 * would fetch the same segment forever.
 */
export function nextSegment(segments: readonly (readonly [number, number])[], buffered: readonly (readonly [number, number])[], t: number, ahead: number): number {
	const from = Math.max(0, segmentAt(segments, t));
	for (let i = from; i < segments.length; i++) {
		const [start, dur] = segments[i]!;
		if (start > t + ahead) return -1;
		const mid = start + dur / 2;
		if (!buffered.some(([a, b]) => a <= mid && mid <= b)) return i;
	}
	return -1;
}
