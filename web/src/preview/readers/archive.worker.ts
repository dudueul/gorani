// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The archive reader's worker (commit 42e, docs/PREVIEWS.md › Archives):
 * every archive is read here, off the frame's main thread, by one of
 *
 *   our own readers   ZIP (archive/zip.ts), ALZ (alz.ts), EGG (egg.ts)
 *   7-Zip 24.09       everything else, as WebAssembly (archive/run7z.ts):
 *                     its two files are asked of the app by the frame only
 *                     when an archive needs them, and kept as files of their
 *                     own (LGPL with the unRAR restriction, NOTICE)
 *
 * The protocol (with the reader, archive.ts):
 *   ← open {bytes, name}            → listing | need-7z | error
 *   ← seven {glue, wasm}            (7-Zip, when asked for)
 *   ← unlock {password}             → listing (names now visible) | wrong
 *   ← extract {index, password}     → entry {bytes} | refused {kind, why}
 * Every entry is capped at the viewer's whole-read limit and at what it
 * claims; a symbolic link's target is read from its body (a few bytes).
 */

import { isAlz, listAlz, extractAlz, type AlzListing } from "../archive/alz.ts";
import { isEgg, listEgg, extractEgg, type EggListing } from "../archive/egg.ts";
import { SevenZip, type SevenZipModule } from "../archive/run7z.ts";
import type { Listing } from "../archive/types.ts";
import { extractZip, isZip, listZip, Refusal, type ZipItem, type ZipListing } from "../archive/zip.ts";

/** The viewer's whole-read cap (ui/viewer/mode.ts › MAX_INLINE). */
const LIMIT = 256 * 1024 * 1024;

interface TT {
	createPolicy(n: string, r: { createScriptURL(u: string): string }): { createScriptURL(u: string): unknown };
}
const tt = (self as unknown as { trustedTypes?: TT }).trustedTypes;
// The worker inherits the frame's CSP and Trusted Types: the one script it
// loads (7-Zip's, from a blob: URL of what the app sent) passes a policy
// that accepts blob: URLs and nothing else.
const policy = tt?.createPolicy("gorani-preview", {
	createScriptURL: (u) => {
		if (!u.startsWith("blob:")) throw new TypeError("the archive worker runs only code it was handed");
		return u;
	},
});

const post = (m: unknown, transfer: Transferable[] = []) => (self as unknown as Worker).postMessage(m, transfer);

let bytes = new Uint8Array(0);
let name = "";
let engine: "zip" | "alz" | "egg" | "7z" = "7z";
let listing: Listing | null = null;
let seven: SevenZip | null = null;
let sevenWaiting: ((s: SevenZip) => void) | null = null;
/** What 7-Zip currently holds: the archive, or a TAR it held. */
let sevenHas: "archive" | "inner" | null = null;
let password: string | null = null;

async function sevenZip(): Promise<SevenZip> {
	if (seven) return seven;
	post({ t: "need-7z" });
	return new Promise((ok) => (sevenWaiting = ok));
}

async function load7z(glue: string, wasm: ArrayBuffer): Promise<void> {
	const url = URL.createObjectURL(new Blob([glue], { type: "text/javascript" }));
	(self as unknown as { importScripts(u: unknown): void }).importScripts(policy ? policy.createScriptURL(url) : url);
	URL.revokeObjectURL(url);
	const factory = (self as unknown as { SevenZip?: (o: object) => Promise<SevenZipModule> }).SevenZip;
	if (!factory) throw new Error("7-Zip did not load");
	let me: SevenZip | null = null;
	const sink = SevenZip.sink(() => me);
	const module = await factory({ wasmBinary: new Uint8Array(wasm), stdin: () => null, stdout: sink.out, stderr: sink.err, print: () => {}, printErr: () => {} });
	me = new SevenZip(module);
	seven = me;
	sevenWaiting?.(me);
	sevenWaiting = null;
}

/** The links' targets: a link's body is its target (tiny), read to be named. */
async function linkTargets(l: Listing): Promise<Record<number, string>> {
	const out: Record<number, string> = {};
	for (const e of l.entries.filter((x) => x.link !== null && (x.size ?? 0) <= 4096 && !x.encrypted).slice(0, 20)) {
		try {
			const body = await extract(e.index, null);
			out[e.index] = new TextDecoder().decode(body).slice(0, 300);
		} catch {
			// unreadable: named without its target
		}
	}
	return out;
}

async function list(): Promise<Listing> {
	if (isZip(bytes)) {
		const z = listZip(bytes);
		if (z) return (engine = "zip"), z;
	}
	if (isAlz(bytes)) {
		const a = listAlz(bytes);
		if (a) return (engine = "alz"), a;
	}
	if (isEgg(bytes)) {
		const g = listEgg(bytes);
		if (g) return (engine = "egg"), g;
	}
	engine = "7z";
	const s = await sevenZip();
	s.load(bytes, name);
	sevenHas = "archive";
	let l = s.list(password, bytes.length);
	// A compressed stream of one TAR (.tar.gz): the TAR is what is listed.
	const inner = l.headersEncrypted ? null : s.innerTar(l, LIMIT);
	if (inner) {
		s.load(inner.bytes, inner.name);
		sevenHas = "inner";
		const il = s.list(null, inner.bytes.length);
		l = { ...il, format: `${l.format} › ${il.format}`, inner: inner.name, physicalSize: bytes.length };
	}
	return l;
}

async function extract(index: number, pw: string | null): Promise<Uint8Array> {
	const l = listing!;
	const e = l.entries[index];
	if (!e) throw new Refusal("damaged", "no such entry");
	if (e.undecodable) throw new Refusal("unsupported", "its name could not be decoded, so it cannot be asked for");
	const s7 = () => sevenZip();
	if (engine === "zip") {
		return extractZip(bytes, e as ZipItem, pw, LIMIT, async (item, p) => {
			// A method our code does not have: 7-Zip, by its (decodable) name.
			const s = await s7();
			if (sevenHas !== "archive") (s.load(bytes, name), (sevenHas = "archive"));
			if ((item as ZipItem).encoding !== "utf-8") throw new Refusal("unsupported", "its method needs 7-Zip, which cannot find it by its Korean name");
			return s.extract(item.path, p, Math.min(LIMIT, (item.size ?? LIMIT) + 65536));
		});
	}
	if (engine === "alz") return extractAlz(bytes, (l as AlzListing).items[index]!, pw, LIMIT, async (stream, cap) => (await s7()).stream("bz2", stream, cap));
	if (engine === "egg") {
		const g = l as EggListing;
		return extractEgg(bytes, g, g.items[index]!, pw, LIMIT, { bzip2: async (stream, cap) => (await s7()).stream("bz2", stream, cap), lzma: async (props, data, size, cap) => (await s7()).lzma(props, data, size, cap) });
	}
	const s = await s7();
	if (e.size !== null && e.size > LIMIT) throw new Refusal("too-big", "it is larger than the viewer opens");
	return s.extract(e.path, pw, Math.min(LIMIT, e.size === null ? LIMIT : e.size + 65536));
}

const clean = (l: Listing): Listing => ({ ...l, entries: l.entries.map(({ index, path, dir, size, packed, modified, method, encrypted, link, crc, attributes, comment, undecodable }) => ({ index, path, dir, size, packed, modified, method, encrypted, link, crc, attributes, comment, undecodable })) });

function refusal(e: unknown): { t: "refused"; kind: string; why: string } {
	if (e instanceof Refusal) return { t: "refused", kind: e.kind, why: e.message };
	return { t: "refused", kind: "damaged", why: e instanceof Error ? e.message.slice(0, 200) : "it could not be read" };
}

self.onmessage = async (ev: MessageEvent<{ t: string; bytes?: ArrayBuffer; name?: string; glue?: string; wasm?: ArrayBuffer; password?: string; index?: number }>) => {
	const m = ev.data;
	try {
		if (m.t === "seven" && m.glue && m.wasm) {
			await load7z(m.glue, m.wasm);
		} else if (m.t === "open" && m.bytes) {
			bytes = new Uint8Array(m.bytes);
			name = m.name ?? "archive";
			listing = await list();
			const twoNames = engine === "zip" ? (listing as ZipListing).items.filter((i) => i.localName !== null).map((i) => ({ central: i.path, local: i.localName! })) : [];
			post({ t: "listing", listing: clean(listing), twoNames, links: await linkTargets(listing), password });
		} else if (m.t === "unlock" && typeof m.password === "string") {
			const before = listing;
			password = m.password;
			if (engine === "7z" && before?.headersEncrypted) {
				const s = await sevenZip();
				s.load(bytes, name);
				sevenHas = "archive";
				const l = s.list(password, bytes.length);
				if (l.headersEncrypted) {
					password = null;
					return post({ t: "wrong" });
				}
				listing = { ...l, encryption: l.encryption ?? "AES-256" };
				return post({ t: "listing", listing: clean(listing), twoNames: [], links: {}, password });
			}
			// Otherwise it is tried on the encrypted entries (the smallest first):
			// right if it opens one — an archive may hold entries under
			// different passwords, and each refuses a wrong one when opened.
			const tries = (listing?.entries ?? []).filter((e) => e.encrypted && !e.dir).sort((a, b) => (a.size ?? 0) - (b.size ?? 0)).slice(0, 8);
			let opened = !tries.length;
			for (const e of tries) {
				try {
					await extract(e.index, password);
					opened = true;
					break;
				} catch (err) {
					if (!(err instanceof Refusal && err.kind === "password")) {
						opened = true; // it decrypted, but something else is wrong with it
						break;
					}
				}
			}
			if (!opened) {
				password = null;
				return post({ t: "wrong" });
			}
			post({ t: "listing", listing: clean(listing!), twoNames: [], links: {}, password });
		} else if (m.t === "extract" && typeof m.index === "number") {
			const out = await extract(m.index, password);
			const copy = out.byteOffset === 0 && out.byteLength === out.buffer.byteLength ? (out.buffer as ArrayBuffer) : out.slice().buffer;
			post({ t: "entry", index: m.index, bytes: copy }, [copy]);
		}
	} catch (e) {
		post(m.t === "open" ? { t: "error", message: e instanceof Error ? e.message : String(e) } : refusal(e));
	}
};
