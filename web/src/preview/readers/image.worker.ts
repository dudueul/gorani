// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The image reader's worker (commit 42d, docs/PREVIEWS.md › Images): the
 * parsing that is heavy, or that a crafted file could send into a long
 * loop, off the frame's main thread — as pdf.js and SheetJS do theirs.
 *
 *   metadata   exifr: EXIF, GPS, XMP, IPTC, ICC (image/meta.ts)
 *   TIFF       UTIF (Photopea, MIT): every page, decoded to pixels
 *   HEIF       libheif (LGPL-3.0, as WebAssembly): the frame asks the app
 *              for it (two files of its own, replaceable as the licence
 *              asks) and hands them here only for a HEIC
 *   RAW        the camera's own JPEG preview (image/raw.ts), cut out
 *   thumbnail  an EXIF thumbnail compared with the picture: 32×32 grey
 *              copies of each, the best of the eight orientations
 *
 * Pictures come back as ImageBitmaps (transferred, not copied). Sizes are
 * checked before anything is decoded: a declared size past the limits is
 * refused, never allocated. Bundled as a classic script (see
 * scripts/build-readers.mjs).
 */

import UTIF from "utif2";
import { MAX_DECODED_PIXELS, MAX_PIXELS, sniffImage, structureOf, type Sniffed, type Structure } from "../image/structure.ts";
import { rawPreviews, cr3Metadata, type Preview } from "../image/raw.ts";
import { readMeta, readThumbnail, type Meta } from "../image/meta.ts";
import type { ThumbCheck } from "../facts/image.ts";

export interface Job {
	bytes: ArrayBuffer;
	name: string;
	/** libheif's script and WebAssembly, for a HEIF. */
	heif?: { glue: string; wasm: ArrayBuffer };
}

export interface Page {
	bitmap: ImageBitmap;
	width: number;
	height: number;
}

export interface Done {
	t: "done";
	sniff: Sniffed;
	structure: Structure;
	meta: Meta | null;
	previews: Preview[];
	/** The decoded pages or pictures (TIFF, HEIF), at most MAX_PAGES. */
	pages: Page[];
	/** How many there are in all. */
	pageCount: number;
	/** A RAW file's largest preview: a JPEG, for the frame's <img>. */
	preview: ArrayBuffer | null;
	thumb: ThumbCheck | null;
	thumbBytes: ArrayBuffer | null;
	refused: "too-large" | "no-decoder" | "failed" | "no-preview" | null;
	error: string | null;
}

const MAX_PAGES = 20;

interface HeifImage {
	get_width(): number;
	get_height(): number;
	display(target: { data: Uint8ClampedArray; width: number; height: number }, done: (d: unknown) => void): void;
	free?(): void;
}
interface HeifModule {
	HeifDecoder: new () => { decode(b: Uint8Array): HeifImage[] };
}
let heif: HeifModule | null = null;

interface TT {
	createPolicy(n: string, r: { createScriptURL(u: string): string }): { createScriptURL(u: string): unknown };
}
const tt = (self as unknown as { trustedTypes?: TT }).trustedTypes;
// The worker inherits the frame's CSP — Trusted Types included: the one
// script it loads (libheif's, from a blob: URL the frame made of what the
// app sent) goes through a policy that allows blob: URLs and nothing else.
const policy = tt?.createPolicy("gorani-preview", {
	createScriptURL: (u) => {
		if (!u.startsWith("blob:")) throw new TypeError("the image worker runs only code it was handed");
		return u;
	},
});

function loadHeif(glue: string, wasm: ArrayBuffer): HeifModule {
	if (heif) return heif;
	const url = URL.createObjectURL(new Blob([glue], { type: "text/javascript" }));
	(self as unknown as { importScripts(u: unknown): void }).importScripts(policy ? policy.createScriptURL(url) : url);
	URL.revokeObjectURL(url);
	const make = (self as unknown as { libheif?: (o: { wasmBinary: Uint8Array }) => HeifModule }).libheif;
	if (!make) throw new Error("libheif did not load");
	// Given the WebAssembly's bytes, libheif compiles it at once (no fetch).
	heif = make({ wasmBinary: new Uint8Array(wasm) });
	return heif;
}

const bitmapOf = (rgba: Uint8ClampedArray, w: number, h: number) => createImageBitmap(new ImageData(rgba as Uint8ClampedArray<ArrayBuffer>, w, h));

async function decodeTiff(buf: ArrayBuffer): Promise<{ pages: Page[]; count: number; refused: Done["refused"] }> {
	const ifds = UTIF.decode(buf).filter((i) => !(((i as Record<string, number[]>).t254?.[0] ?? 0) & 1));
	const pages: Page[] = [];
	let refused: Done["refused"] = null;
	for (const ifd of ifds.slice(0, MAX_PAGES)) {
		const t = ifd as Record<string, number[]>;
		const w = t.t256?.[0] ?? 0;
		const h = t.t257?.[0] ?? 0;
		if (!w || !h) continue;
		if (w * h > MAX_DECODED_PIXELS) {
			refused = "too-large";
			continue;
		}
		UTIF.decodeImage(buf, ifd);
		const rgba = UTIF.toRGBA8(ifd);
		if (rgba.length < w * h * 4) continue;
		pages.push({ bitmap: await bitmapOf(new Uint8ClampedArray(rgba.buffer, rgba.byteOffset, w * h * 4), w, h), width: w, height: h });
	}
	return { pages, count: ifds.length, refused: pages.length ? null : (refused ?? "failed") };
}

async function decodeHeif(bytes: Uint8Array, lib: HeifModule): Promise<{ pages: Page[]; count: number; refused: Done["refused"] }> {
	const images = new lib.HeifDecoder().decode(bytes);
	const pages: Page[] = [];
	let refused: Done["refused"] = null;
	for (const im of images.slice(0, MAX_PAGES)) {
		const w = im.get_width();
		const h = im.get_height();
		if (!w || !h || w * h > MAX_DECODED_PIXELS) {
			refused = "too-large";
			im.free?.();
			continue;
		}
		const data = new Uint8ClampedArray(w * h * 4);
		const ok = await new Promise<boolean>((done) => im.display({ data, width: w, height: h }, (d) => done(!!d)));
		im.free?.();
		if (ok) pages.push({ bitmap: await bitmapOf(data, w, h), width: w, height: h });
	}
	for (const im of images.slice(MAX_PAGES)) im.free?.();
	return { pages, count: images.length, refused: pages.length ? null : (refused ?? "failed") };
}

/** 32×32 grey values of a bitmap (or a part of it), stretched. */
function grey(bmp: ImageBitmap, crop?: { x: number; y: number; w: number; h: number }): Float32Array {
	const c = new OffscreenCanvas(32, 32);
	const g = c.getContext("2d")!;
	const r = crop ?? { x: 0, y: 0, w: bmp.width, h: bmp.height };
	g.drawImage(bmp, r.x, r.y, r.w, r.h, 0, 0, 32, 32);
	const px = g.getImageData(0, 0, 32, 32).data;
	const out = new Float32Array(32 * 32);
	for (let i = 0; i < out.length; i++) out[i] = 0.299 * px[i * 4]! + 0.587 * px[i * 4 + 1]! + 0.114 * px[i * 4 + 2]!;
	return out;
}

/** The thumbnail without the black bars a camera pads it with. */
function trimmed(bmp: ImageBitmap): { x: number; y: number; w: number; h: number } {
	const c = new OffscreenCanvas(bmp.width, bmp.height);
	const g = c.getContext("2d")!;
	g.drawImage(bmp, 0, 0);
	const px = g.getImageData(0, 0, bmp.width, bmp.height).data;
	const dark = (x: number, y: number) => {
		const i = (y * bmp.width + x) * 4;
		return px[i]! < 24 && px[i + 1]! < 24 && px[i + 2]! < 24;
	};
	const row = (y: number) => Array.from({ length: bmp.width }, (_, x) => x).every((x) => dark(x, y));
	const col = (x: number) => Array.from({ length: bmp.height }, (_, y) => y).every((y) => dark(x, y));
	let top = 0;
	let bottom = bmp.height - 1;
	let left = 0;
	let right = bmp.width - 1;
	while (top < bottom && row(top)) top++;
	while (bottom > top && row(bottom)) bottom--;
	while (left < right && col(left)) left++;
	while (right > left && col(right)) right--;
	return { x: left, y: top, w: right - left + 1, h: bottom - top + 1 };
}

/** The eight ways a grid can be turned or mirrored. */
function variants(a: Float32Array): Float32Array[] {
	const at = (f: (x: number, y: number) => number) => {
		const o = new Float32Array(1024);
		for (let y = 0; y < 32; y++) for (let x = 0; x < 32; x++) o[y * 32 + x] = a[f(x, y)]!;
		return o;
	};
	const n = 31;
	return [
		a,
		at((x, y) => y * 32 + (n - x)),
		at((x, y) => (n - y) * 32 + (n - x)),
		at((x, y) => (n - y) * 32 + x),
		at((x, y) => x * 32 + y),
		at((x, y) => (n - x) * 32 + y),
		at((x, y) => (n - x) * 32 + (n - y)),
		at((x, y) => x * 32 + (n - y)),
	];
}

async function compareThumb(thumb: Uint8Array, picture: Uint8Array, mime: string, s: Structure): Promise<ThumbCheck | null> {
	if (!s.width || !s.height) return null;
	const tb = await createImageBitmap(new Blob([thumb as BlobPart], { type: "image/jpeg" }));
	const pb = await createImageBitmap(new Blob([picture as BlobPart], { type: mime }), { resizeWidth: 256, resizeHeight: Math.max(1, Math.round((256 * s.height) / s.width)), resizeQuality: "medium" });
	try {
		const whole = { x: 0, y: 0, w: tb.width, h: tb.height };
		const cut = trimmed(tb);
		// The picture's shape as stored, and turned (a thumbnail may be either).
		const pa = s.width / s.height;
		const near = (a: number) => Math.min(Math.abs(Math.log(a / pa)), Math.abs(Math.log(a * pa)));
		const area = near(cut.w / cut.h) < near(tb.width / tb.height) ? cut : whole;
		const ta = area.w / area.h;
		const shape = near(ta) > 0.06;
		const t = grey(tb, area);
		let best = { mean: Infinity, far: 1 };
		for (const p of variants(grey(pb))) {
			let sum = 0;
			let far = 0;
			for (let i = 0; i < 1024; i++) {
				const d = Math.abs(t[i]! - p[i]!);
				sum += d;
				if (d > 64) far++;
			}
			if (sum / 1024 < best.mean) best = { mean: sum / 1024, far: far / 1024 };
		}
		return { width: tb.width, height: tb.height, shape, thumbAspect: ta, pictureAspect: pa, mean: Math.round(best.mean * 10) / 10, far: Math.round(best.far * 1000) / 1000 };
	} finally {
		tb.close();
		pb.close();
	}
}

async function run(job: Job): Promise<Done> {
	const bytes = new Uint8Array(job.bytes);
	const sniff = sniffImage(bytes, job.name);
	const structure = structureOf(bytes, sniff.format);
	const done: Done = { t: "done", sniff, structure, meta: null, previews: [], pages: [], pageCount: 0, preview: null, thumb: null, thumbBytes: null, refused: null, error: null };
	const fmt = sniff.format;
	if (!fmt) return done;

	// The metadata: from the file; for a RAW format exifr cannot read, from
	// its own records (CR3's CMT1) or its preview (RAF).
	done.meta = await readMeta(bytes);
	const raw = /^(dng|cr2|nef|arw|orf|rw2|pef|raw|cr3|raf)$/.test(fmt);
	if (raw) {
		done.previews = rawPreviews(bytes, fmt);
		const best = done.previews[0];
		if (best) done.preview = bytes.slice(best.offset, best.offset + best.length).buffer;
		else done.refused = "no-preview";
		if (!done.meta && fmt === "cr3") for (const block of cr3Metadata(bytes)) done.meta ??= await readMeta(block);
		if (!done.meta && best) done.meta = await readMeta(bytes.subarray(best.offset, best.offset + best.length));
		return done;
	}

	const declared = structure.width && structure.height ? structure.width * structure.height : 0;
	if (declared > MAX_PIXELS) {
		done.refused = "too-large";
		return done;
	}
	try {
		if (fmt === "tiff") {
			const r = await decodeTiff(job.bytes);
			Object.assign(done, { pages: r.pages, pageCount: r.count, refused: r.refused });
		} else if (fmt === "heic") {
			if (!job.heif) done.refused = "no-decoder";
			else {
				const r = await decodeHeif(bytes, loadHeif(job.heif.glue, job.heif.wasm));
				Object.assign(done, { pages: r.pages, pageCount: r.count, refused: r.refused });
			}
		} else if (fmt === "jxl" || fmt === "psd" || fmt === "jp2") {
			done.refused = "no-decoder";
		} else if (fmt === "jpeg") {
			const thumb = await readThumbnail(bytes);
			if (thumb) {
				done.thumbBytes = thumb.slice().buffer;
				done.thumb = await compareThumb(thumb, bytes, "image/jpeg", structure).catch(() => null);
			}
		}
	} catch (e) {
		done.refused = "failed";
		done.error = e instanceof Error ? e.message.slice(0, 200) : String(e).slice(0, 200);
	}
	return done;
}

self.onmessage = async (e: MessageEvent<Job>) => {
	try {
		const done = await run(e.data);
		const transfer: Transferable[] = [...done.pages.map((p) => p.bitmap)];
		if (done.preview) transfer.push(done.preview);
		if (done.thumbBytes) transfer.push(done.thumbBytes);
		(self as unknown as Worker).postMessage(done, transfer);
	} catch (err) {
		(self as unknown as Worker).postMessage({ t: "error", message: err instanceof Error ? err.message : String(err) });
	}
};
