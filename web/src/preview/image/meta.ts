// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A picture's metadata (commit 42d, docs/PREVIEWS.md › Images): EXIF (the
 * camera, the time, GPS), XMP (the editing history, the AI-source mark),
 * IPTC (the author, the caption), the ICC profile's name, PNG's header.
 * Read by exifr (Mike Kovařík, MIT) from the bytes — never from a URL, so
 * its loaders that fetch are never reached (and the frame's CSP would
 * stop them). Values stay as the file wrote them: dates are the file's
 * text, not parsed into this computer's time zone.
 *
 * Pure: unit:preview-facts runs it on the fixtures in Node.
 */

import exifr from "exifr";

import type { Meta } from "./tags.ts";
export type { Meta } from "./tags.ts";

const OPTIONS = {
	tiff: true,
	ifd0: true,
	exif: true,
	gps: true,
	ifd1: true,
	interop: false,
	makerNote: false,
	userComment: true,
	xmp: true,
	iptc: true,
	icc: true,
	jfif: false,
	ihdr: true,
	mergeOutput: false,
	sanitize: true,
	reviveValues: false,
	translateKeys: true,
	translateValues: true,
	multiSegment: true,
	silentErrors: true,
} as const;

/** The metadata, or null when there is none (or exifr does not read the format). */
export async function readMeta(bytes: Uint8Array): Promise<Meta | null> {
	try {
		const m = (await exifr.parse(bytes, OPTIONS as never)) as Meta | undefined;
		if (!m || typeof m !== "object") return null;
		// Drop what does not survive a postMessage or would only bloat it
		// (the thumbnail's bytes are read on their own, below).
		const out: Meta = {};
		for (const [group, tags] of Object.entries(m)) {
			if (!tags || typeof tags !== "object") continue;
			const kept: Record<string, unknown> = {};
			for (const [k, v] of Object.entries(tags)) {
				if (typeof v === "function") continue;
				if (typeof v === "string" && v.length > 64 * 1024) kept[k] = `${v.slice(0, 64 * 1024)}…`;
				else if (v instanceof Uint8Array && v.length > 4096) kept[k] = `(${v.length} bytes)`;
				else kept[k] = v;
			}
			out[group] = kept;
		}
		return Object.keys(out).length ? out : null;
	} catch {
		return null;
	}
}

/** The EXIF thumbnail (IFD1), when it is a JPEG. */
export async function readThumbnail(bytes: Uint8Array): Promise<Uint8Array | null> {
	try {
		const t = (await exifr.thumbnail(bytes)) as Uint8Array | undefined;
		return t && t.length > 4 && t[0] === 0xff && t[1] === 0xd8 ? new Uint8Array(t) : null;
	} catch {
		return null;
	}
}
