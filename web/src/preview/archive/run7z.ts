// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Driving 7-Zip (7z-wasm: 7-Zip 24.09 as WebAssembly, LGPL with the unRAR
 * restriction) — commit 42e, docs/PREVIEWS.md › Archives. It runs in the
 * archive reader's worker, in the preview frame; its file system is in
 * memory and holds only the archive it was given.
 *
 * Every entry is written to stdout (-so) and counted as it comes: past its
 * cap the run is stopped — so an entry that inflates past what it claims
 * (a bomb, a liar) is never held whole. Names are taken literally (-spd).
 * A password is always given (-p…), so 7-Zip never waits for one.
 *
 * The module is the worker's; this file needs only its call surface, so
 * unit:preview-facts drives the same code with 7z-wasm in Node.
 */

import { memName, parseListing, STREAMS, troubleOf } from "./sevenzip.ts";
import type { Listing } from "./types.ts";
import { Refusal } from "./zip.ts";

export interface SevenZipModule {
	FS: { writeFile(path: string, data: Uint8Array): void; unlink(path: string): void; mkdir(path: string): void; analyzePath(path: string): { exists: boolean } };
	callMain(args: string[]): number | undefined;
}

class Cap extends Error {}

/** Streams the module writes to: set by each run. */
export interface Sink {
	out(byte: number): void;
	err(byte: number): void;
}

export class SevenZip {
	private n = 0;
	private cap = Number.POSITIVE_INFINITY;
	private text = "";
	private buf: Uint8Array = new Uint8Array(0);
	/** The archive's path in 7-Zip's file system. */
	private path = "";
	/** A single compressed stream: its one entry is "everything". */
	private single = false;

	private module: SevenZipModule;

	constructor(module: SevenZipModule) {
		this.module = module;
	}

	/** Hand these to the module's factory as stdout and stderr. */
	static sink(get: () => SevenZip | null): Sink {
		return {
			out: (c) => get()?.onOut(c),
			err: (c) => get()?.onErr(c),
		};
	}

	private onOut(c: number): void {
		if (this.n >= this.cap) throw new Cap("cap");
		if (this.n >= this.buf.length) {
			const next = new Uint8Array(Math.max(4096, this.buf.length * 2));
			next.set(this.buf);
			this.buf = next;
		}
		this.buf[this.n++] = c;
	}

	private onErr(c: number): void {
		if (this.text.length < 64 * 1024) this.text += String.fromCharCode(c);
	}

	/** Run 7-Zip; its stdout (up to `cap` bytes), its words, its code. */
	private run(args: string[], cap = 4 * 1024 * 1024): { out: Uint8Array; text: string; code: number | "capped" } {
		this.buf = new Uint8Array(0);
		this.n = 0;
		this.cap = cap;
		this.text = "";
		let code: number | "capped";
		try {
			code = this.module.callMain(args) ?? 0;
		} catch (e) {
			if (!(e instanceof Cap)) throw e;
			code = "capped";
		}
		return { out: this.buf.subarray(0, this.n), text: this.text, code };
	}

	/** Put the archive in place (under its own name: a single stream inside
	 * is named after it). */
	load(bytes: Uint8Array, name: string): void {
		if (!this.module.FS.analyzePath("/in").exists) this.module.FS.mkdir("/in");
		if (this.path) this.module.FS.unlink(this.path);
		this.path = `/in/${memName(name)}`;
		this.module.FS.writeFile(this.path, bytes);
	}

	list(password: string | null, physicalSize: number): Listing {
		const r = this.run(["l", "-slt", `-p${password ?? ""}`, this.path], 64 * 1024 * 1024);
		const words = `${new TextDecoder().decode(r.out)}\n${r.text}`;
		const trouble = troubleOf(words);
		if (trouble === "password") {
			const l = parseListing("", this.path, physicalSize);
			return { ...l, headersEncrypted: true, encryption: "AES-256", format: "7z", warnings: [] };
		}
		if (trouble === "not-archive" && !/Type = /.test(words)) throw new Refusal("unsupported", "7-Zip cannot read it as an archive");
		const l = parseListing(new TextDecoder().decode(r.out), this.path, physicalSize);
		this.single = STREAMS.has(Object.entries({ gzip: "gzip", bzip2: "bzip2", xz: "xz", Zstandard: "zstd", LZMA: "lzma", "compress (.Z)": "Z", LZ4: "lz4", lzip: "lzip" }).find(([k]) => k === l.format)?.[1] ?? "");
		return l;
	}

	/** One entry, by its path exactly as listed. */
	extract(path: string, password: string | null, cap: number): Uint8Array {
		const r = this.run(["x", "-so", "-spd", "-y", `-p${password ?? ""}`, this.path, ...(this.single ? [] : ["--", path])], cap + 1);
		if (r.code === "capped") throw new Refusal("liar", "it unpacks past the viewer's limit — or past what it claims");
		const trouble = troubleOf(r.text);
		if (trouble === "password") throw new Refusal("password", password === null ? "it is encrypted" : "the password is wrong");
		if (r.code !== 0 && trouble) throw new Refusal(trouble === "unsupported" ? "unsupported" : "damaged", trouble === "unsupported" ? "7-Zip has no decoder for its method" : "it is damaged (7-Zip reports an error in its data)");
		return r.out.slice();
	}

	/** A compressed stream (a bzip2 or LZMA block of an ALZ or EGG), unpacked. */
	stream(kind: "bz2" | "lzma", data: Uint8Array, cap: number): Uint8Array {
		if (!this.module.FS.analyzePath("/in").exists) this.module.FS.mkdir("/in");
		const path = `/in/stream.${kind}`;
		this.module.FS.writeFile(path, data);
		try {
			const r = this.run(["x", "-so", "-y", path], cap + 1);
			if (r.code === "capped") throw new Refusal("liar", "it unpacks past what it claims");
			if (r.code !== 0 && troubleOf(r.text)) throw new Refusal("damaged", "its compressed data is damaged");
			return r.out.slice();
		} finally {
			this.module.FS.unlink(path);
		}
	}

	/** LZMA as EGG and ZIP store it (5 property bytes, then data), made a .lzma file. */
	lzma(props: Uint8Array, data: Uint8Array, size: number, cap: number): Uint8Array {
		const file = new Uint8Array(13 + data.length);
		file.set(props.subarray(0, 5), 0);
		const v = new DataView(file.buffer);
		v.setUint32(5, size >>> 0, true);
		v.setUint32(9, Math.floor(size / 2 ** 32), true);
		file.set(data, 13);
		return this.stream("lzma", file, cap);
	}

	/**
	 * A compressed stream holding one TAR (".tar.gz", ".tgz", ".tar.xz"…):
	 * the TAR, unpacked (capped), to list in its place — or null.
	 */
	innerTar(l: Listing, cap: number): { name: string; bytes: Uint8Array } | null {
		const type = Object.entries({ gzip: 1, bzip2: 1, xz: 1, Zstandard: 1, LZMA: 1, "compress (.Z)": 1, LZ4: 1, lzip: 1 }).some(([k]) => l.format === k);
		const only = l.entries.length === 1 ? l.entries[0]! : null;
		if (!type || !only || !/\.tar$|^[^.]*$/i.test(only.path)) return null;
		const bytes = this.extract(only.path, null, cap);
		const isTar = bytes.length > 262 && new TextDecoder("latin1").decode(bytes.subarray(257, 262)) === "ustar";
		return isTar ? { name: only.path.endsWith(".tar") ? only.path : `${only.path}.tar`, bytes } : null;
	}
}

export { STREAMS };
