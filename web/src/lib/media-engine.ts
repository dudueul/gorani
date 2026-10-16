// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The page's side of gorani-media in WebAssembly (commit 39p,
 * crates/media-wasm, docs/VIDEO.md).
 *
 * The module is built from the repository's own Rust (scripts/
 * build-media-wasm.mjs → /gorani-media.wasm) and imports NOTHING: no
 * filesystem, no clock, no network, no JavaScript callbacks. It is handed
 * bytes and hands bytes back — a `moov` becomes an index, and the index
 * plus a segment's sample bytes become fMP4 for Media Source Extensions.
 * It never sees a file's key: the page decrypts (frame-reader.ts) and
 * passes plaintext in. The one key it does see is a protected copy's
 * (commit 40a, docs/DRM.md): the Worker hands it to a lead's browser to
 * package that copy, and `protect()` passes it in for exactly that.
 *
 * The boundary (no wasm-bindgen, so no generated glue to audit):
 *
 *   - inputs go into memory from `gm_alloc`; every call returns an i32,
 *     ≥ 0 for success (or an index's handle), < 0 for an error whose
 *     `{"error"}` waits in the result slot;
 *   - the result slot (`gm_out_ptr`/`gm_out_len`) is COPIED out at once and
 *     freed — memory can grow on the next call, and a view of the old
 *     buffer would then read nothing;
 *   - u64 arguments travel as BigInt, so a 200 GB file's offsets stay exact.
 *
 * A panic aborts the instance (the release profile is panic = "abort"),
 * which surfaces here as a WebAssembly.RuntimeError. Nothing in that
 * instance is trusted after it: the engine marks itself broken and the
 * next `mediaEngine()` starts a fresh one from the compiled module.
 *
 * CSP: compiling WebAssembly needs 'wasm-unsafe-eval' in script-src, which
 * the app's policy has carried since the Argon2id vault (web/public/
 * _headers). It allows compiling wasm and nothing else — not eval, not
 * inline scripts.
 */

import type { EngineSummary } from "../vault/video-meta.ts";

interface Exports {
	memory: WebAssembly.Memory;
	gm_alloc(len: number): number;
	gm_free(ptr: number, len: number): void;
	gm_out_ptr(): number;
	gm_out_len(): number;
	gm_out_free(): void;
	gm_index_moov(ptr: number, len: number, moovAbs: bigint, fileSize: bigint, targetMs: number): number;
	gm_drop(handle: number): void;
	gm_init(handle: number): number;
	gm_plan(handle: number, n: number): number;
	gm_segment(handle: number, n: number, ptr: number, len: number): number;
	gm_protect(handle: number, ptr: number, len: number): number;
	gm_protect_init(packager: number): number;
	gm_protect_segment(packager: number, n: number, ptr: number, len: number): number;
	gm_protect_drop(packager: number): void;
}

const EXPORTS = ["memory", "gm_alloc", "gm_free", "gm_out_ptr", "gm_out_len", "gm_out_free", "gm_index_moov", "gm_drop", "gm_init", "gm_plan", "gm_segment", "gm_protect", "gm_protect_init", "gm_protect_segment", "gm_protect_drop"] as const;

export class MediaEngine {
	private broken = false;
	// (Plain fields, not constructor parameter properties: Node runs these
	// modules by stripping types, and a parameter property is not a type.)
	private readonly x: Exports;
	private constructor(x: Exports) {
		this.x = x;
	}

	/** An engine from a compiled module (one instance each: an index lives
	 * inside the instance that made it). */
	static async instantiate(module: WebAssembly.Module): Promise<MediaEngine> {
		const instance = await WebAssembly.instantiate(module, {});
		const x = instance.exports as unknown as Exports;
		for (const name of EXPORTS) if (!(name in x)) throw new Error(`the media engine lacks ${name} — rebuild it (scripts/build-media-wasm.mjs)`);
		return new MediaEngine(x);
	}

	get alive(): boolean {
		return !this.broken;
	}

	/**
	 * Index a regular MP4 from its whole moov box, which sits at plaintext
	 * offset `moovAbs` of a file of `fileSize`. Segments are cut on
	 * keyframes, aiming at `targetMs`.
	 */
	index(moov: Uint8Array, moovAbs: number, fileSize: number, targetMs = 4000): MediaIndex {
		// The moov moves in: gm_index_moov takes ownership of this memory.
		const p = this.put(moov);
		const h = this.call(() => this.x.gm_index_moov(p, moov.length, BigInt(moovAbs), BigInt(fileSize), targetMs));
		const summary = JSON.parse(this.text()) as EngineSummary;
		return new MediaIndex(this, h, summary);
	}

	/** @internal — the calls MediaIndex makes. */
	initOf(h: number): Uint8Array {
		this.call(() => this.x.gm_init(h));
		return this.bytes();
	}

	/** @internal */
	planOf(h: number, n: number): [number, number][] {
		this.call(() => this.x.gm_plan(h, n));
		return JSON.parse(this.text()) as [number, number][];
	}

	/** @internal */
	segmentOf(h: number, n: number, joined: Uint8Array): Uint8Array {
		const p = this.put(joined);
		try {
			this.call(() => this.x.gm_segment(h, n, p, joined.length));
		} finally {
			// (After a trap the instance is gone, and freeing in it would only trap again.)
			if (!this.broken) this.x.gm_free(p, joined.length);
		}
		return this.bytes();
	}

	/** @internal */
	drop(h: number): void {
		if (!this.broken) this.x.gm_drop(h);
	}

	/** @internal — the key material is copied in, then its buffer zeroed. */
	protectOf(h: number, material: Uint8Array): number {
		const p = this.put(material);
		try {
			return this.call(() => this.x.gm_protect(h, p, material.length));
		} finally {
			if (!this.broken) {
				new Uint8Array(this.x.memory.buffer, p, material.length).fill(0);
				this.x.gm_free(p, material.length);
			}
		}
	}

	/** @internal */
	protectInitOf(ph: number): Uint8Array {
		this.call(() => this.x.gm_protect_init(ph));
		return this.bytes();
	}

	/** @internal */
	protectSegmentOf(ph: number, n: number, joined: Uint8Array): Uint8Array {
		const p = this.put(joined);
		try {
			this.call(() => this.x.gm_protect_segment(ph, n, p, joined.length));
		} finally {
			if (!this.broken) this.x.gm_free(p, joined.length);
		}
		return this.bytes();
	}

	/** @internal */
	protectDrop(ph: number): void {
		if (!this.broken) this.x.gm_protect_drop(ph);
	}

	/** Copy bytes into the instance. */
	private put(bytes: Uint8Array): number {
		if (!this.alive) this.dead();
		const p = this.x.gm_alloc(bytes.length) >>> 0;
		new Uint8Array(this.x.memory.buffer, p, bytes.length).set(bytes);
		return p;
	}

	/** Run one export: a trap breaks the engine, a negative answer is the
	 * engine's own error message. */
	private call(f: () => number): number {
		if (!this.alive) this.dead();
		let rc: number;
		try {
			rc = f();
		} catch (e) {
			this.broken = true;
			throw new Error(`the media engine stopped on this file (${e instanceof Error ? e.message : String(e)})`);
		}
		if (rc < 0) {
			let message = "the media engine refused this file";
			try {
				message = (JSON.parse(this.text()) as { error?: string }).error ?? message;
			} catch {
				// keep the generic message
			}
			throw new Error(message);
		}
		return rc;
	}

	/** The result slot, copied out and freed. */
	private bytes(): Uint8Array {
		const p = this.x.gm_out_ptr() >>> 0;
		const n = this.x.gm_out_len() >>> 0;
		const out = new Uint8Array(this.x.memory.buffer, p, n).slice();
		this.x.gm_out_free();
		return out;
	}

	private text(): string {
		return new TextDecoder().decode(this.bytes());
	}

	private dead(): never {
		throw new Error("the media engine stopped earlier — reopen the video");
	}
}

/** One indexed file. `drop()` frees its tables inside the engine. */
export class MediaIndex {
	private dropped = false;
	private readonly engine: MediaEngine;
	private readonly handle: number;
	readonly summary: EngineSummary;
	constructor(engine: MediaEngine, handle: number, summary: EngineSummary) {
		this.engine = engine;
		this.handle = handle;
		this.summary = summary;
	}

	get segments(): [number, number][] {
		return this.summary.segments;
	}

	/** The fMP4 init segment: ftyp + moov with empty tables and mvex. */
	init(): Uint8Array {
		return this.engine.initOf(this.live());
	}

	/** The plaintext blocks segment `n` needs: [[offset, length], …]. */
	plan(n: number): [number, number][] {
		return this.engine.planOf(this.live(), n);
	}

	/** Segment `n` (moof + mdat) from its planned blocks, joined in order. */
	segment(n: number, joined: Uint8Array): Uint8Array {
		return this.engine.segmentOf(this.live(), n, joined);
	}

	/**
	 * A packager for this video's protected copy (commit 40a): `material` is
	 * the 48 bytes the Worker handed out — key, key id, constant IV. Throws,
	 * with the reason, for a video FairPlay cannot play.
	 */
	protect(material: Uint8Array): Protector {
		return new Protector(this.engine, this.engine.protectOf(this.live(), material), this);
	}

	drop(): void {
		if (this.dropped) return;
		this.dropped = true;
		this.engine.drop(this.handle);
	}

	private live(): number {
		if (this.dropped) throw new Error("this video's index was already let go");
		return this.handle;
	}
}

/**
 * Packages one protected copy: `init()`, then `segment(n, …)` for every
 * segment IN ORDER (parameter sets a stream sends in band carry over),
 * each from the same planned blocks as MediaIndex.segment.
 */
export class Protector {
	private dropped = false;
	private readonly engine: MediaEngine;
	private readonly handle: number;
	private readonly index: MediaIndex;
	constructor(engine: MediaEngine, handle: number, index: MediaIndex) {
		this.engine = engine;
		this.handle = handle;
		this.index = index;
	}

	init(): Uint8Array {
		return this.engine.protectInitOf(this.live());
	}

	segment(n: number, joined: Uint8Array): Uint8Array {
		return this.engine.protectSegmentOf(this.live(), n, joined);
	}

	/** The plan is the index's: the same plaintext blocks. */
	plan(n: number): [number, number][] {
		return this.index.plan(n);
	}

	drop(): void {
		if (this.dropped) return;
		this.dropped = true;
		this.engine.protectDrop(this.handle);
	}

	private live(): number {
		if (this.dropped) throw new Error("this protected copy's packager was already let go");
		return this.handle;
	}
}

let compiled: Promise<WebAssembly.Module> | null = null;
let current: MediaEngine | null = null;

/**
 * The page's engine: compiled once from /gorani-media.wasm, instantiated
 * again only after a trap. `source` lets Node tests hand the bytes in.
 */
export async function mediaEngine(source?: BufferSource): Promise<MediaEngine> {
	if (current?.alive) return current;
	compiled ??= (async () => {
		if (source) return WebAssembly.compile(source);
		const r = await fetch("/gorani-media.wasm");
		if (!r.ok) throw new Error(`the media engine is missing from this deployment (${r.status})`);
		return WebAssembly.compile(await r.arrayBuffer());
	})();
	try {
		current = await MediaEngine.instantiate(await compiled);
	} catch (e) {
		compiled = null;
		throw e;
	}
	return current;
}
