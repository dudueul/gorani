// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Plaintext ranges of a sealed file, for the in-page video player
 * (commit 39p, docs/VIDEO.md).
 *
 * A GC01 file is frames that each open on their own:
 *
 * ```text
 * object  = frame 0 ‖ frame 1 ‖ …     every frame but the last: chunk + 28 bytes
 * frame i = nonce ‖ ciphertext ‖ tag  AAD = "GC01" ‖ i ‖ final
 * ```
 *
 * so plaintext bytes [a, b) need only the frames that cover them. The
 * reader asks for each run of missing frames with ONE ciphertext range,
 * opens them, and keeps the last few — the player reads a segment's
 * blocks one after another, and neighbouring blocks share frames. Two
 * reads that want the same frame at once share one fetch.
 *
 * The media service worker (web/public/sw-media.js) does the same for the
 * browser's own player; this one serves the page, where the WebAssembly
 * engine needs bytes in hand, not a URL. The key never leaves the caller:
 * `open` is a closure over it.
 */

/** 12-byte nonce + 16-byte tag, as chunked-file.ts › FRAME_OVERHEAD. */
const OVERHEAD = 28;

export interface FrameReaderOptions {
	/** Plaintext size of the file. */
	size: number;
	/** Plaintext bytes per frame. */
	chunk: number;
	/** Ciphertext bytes [start, end] (inclusive) of the stored object. */
	fetchCipher: (start: number, end: number) => Promise<Uint8Array>;
	/** Open frame `i` (`final` for the last) — chunked-file.ts › openChunk. */
	open: (frame: Uint8Array, i: number, final: boolean) => Promise<Uint8Array>;
	/** How many opened frames to keep (default: 96 MiB worth, at least 3). */
	keep?: number;
}

export class FrameReader {
	readonly size: number;
	private readonly chunk: number;
	private readonly frames: number;
	private readonly keep: number;
	/** Opened frames, oldest first (a Map keeps insertion order). */
	private readonly cache = new Map<number, Uint8Array>();
	private readonly pending = new Map<number, Promise<Uint8Array>>();
	/** Ciphertext bytes fetched so far — the tests check the cache with it. */
	fetched = 0;

	private readonly o: FrameReaderOptions;

	constructor(o: FrameReaderOptions) {
		this.o = o;
		if (!Number.isSafeInteger(o.chunk) || o.chunk <= 0) throw new Error("a frame reader needs the file's chunk size");
		this.size = o.size;
		this.chunk = o.chunk;
		this.frames = Math.max(1, Math.ceil(o.size / o.chunk));
		this.keep = o.keep ?? Math.max(3, Math.floor((96 * 1024 * 1024) / o.chunk));
	}

	/** `length` plaintext bytes at `offset` — fewer only past the end. */
	async read(offset: number, length: number): Promise<Uint8Array> {
		if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0) throw new Error("a read is whole bytes from a place in the file");
		const end = Math.min(offset + length, this.size);
		if (end <= offset) return new Uint8Array(0);
		const first = Math.floor(offset / this.chunk);
		const last = Math.floor((end - 1) / this.chunk);
		const opened = await this.framesIn(first, last);
		const out = new Uint8Array(end - offset);
		let at = 0;
		for (let i = first; i <= last; i++) {
			const frame = opened[i - first]!;
			const from = i === first ? offset - i * this.chunk : 0;
			const to = Math.min(frame.length, end - i * this.chunk);
			out.set(frame.subarray(from, to), at);
			at += to - from;
		}
		return out;
	}

	/** Frames first..last, opened: from the cache, from a fetch already on
	 * its way, or fetched now — each run of missing frames in one range. */
	private async framesIn(first: number, last: number): Promise<Uint8Array[]> {
		const wanted: Promise<Uint8Array>[] = [];
		let runStart = -1;
		const flush = (upTo: number) => {
			if (runStart < 0) return;
			const run = this.fetchRun(runStart, upTo);
			for (let i = runStart; i <= upTo; i++) wanted[i - first] = run[i - runStart]!;
			runStart = -1;
		};
		for (let i = first; i <= last; i++) {
			const hit = this.cache.get(i);
			if (hit) {
				// Touch it: most recently used goes to the back.
				this.cache.delete(i);
				this.cache.set(i, hit);
			}
			const known = hit ? Promise.resolve(hit) : this.pending.get(i);
			if (known) {
				flush(i - 1);
				wanted[i - first] = known;
			} else if (runStart < 0) {
				runStart = i;
			}
		}
		flush(last);
		return Promise.all(wanted);
	}

	/** One ciphertext range for frames a..b; one promise per frame. */
	private fetchRun(a: number, b: number): Promise<Uint8Array>[] {
		const frame = this.chunk + OVERHEAD;
		const cipherSize = this.size + this.frames * OVERHEAD;
		const start = a * frame;
		const end = Math.min((b + 1) * frame, cipherSize) - 1;
		const body = this.o.fetchCipher(start, end).then((bytes) => {
			if (bytes.length !== end - start + 1) throw new Error(`the store returned ${bytes.length} bytes for frames ${a}–${b} (${end - start + 1} expected)`);
			this.fetched += bytes.length;
			return bytes;
		});
		const out: Promise<Uint8Array>[] = [];
		for (let i = a; i <= b; i++) {
			const p = body
				.then((bytes) => {
					const from = (i - a) * frame;
					return this.o.open(bytes.subarray(from, Math.min(from + frame, bytes.length)), i, i === this.frames - 1);
				})
				.then((plain) => {
					this.remember(i, plain);
					return plain;
				})
				.finally(() => this.pending.delete(i));
			this.pending.set(i, p);
			out.push(p);
		}
		return out;
	}

	private remember(i: number, plain: Uint8Array): void {
		this.cache.set(i, plain);
		while (this.cache.size > this.keep) {
			const oldest = this.cache.keys().next().value as number;
			this.cache.delete(oldest);
		}
	}

	/** Let go of every opened frame (the viewer closed, or Lock). */
	clear(): void {
		this.cache.clear();
	}
}

/** The same reader over a file sealed whole (GV02, under 48 MB): it is
 * opened once, on the first read, and sliced after that. */
export class WholeReader {
	private plain: Promise<Uint8Array> | null = null;
	readonly size: number;
	private readonly openAll: () => Promise<Uint8Array>;
	constructor(size: number, openAll: () => Promise<Uint8Array>) {
		this.size = size;
		this.openAll = openAll;
	}

	async read(offset: number, length: number): Promise<Uint8Array> {
		this.plain ??= this.openAll();
		const all = await this.plain;
		return all.slice(offset, Math.min(offset + length, all.length));
	}

	clear(): void {
		this.plain = null;
	}
}
