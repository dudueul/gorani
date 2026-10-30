// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a picture says about itself that looking at it would not (commit
 * 42d, docs/PREVIEWS.md › Images) — what an investigation asks of a
 * photo, and what a lure hides in one:
 *
 *   Where and when   GPS (a phone writes it to the metre), the time taken
 *                    and its zone, the camera, its serial number, its owner
 *   What was done    the editor and its recorded history; a thumbnail that
 *                    no longer matches the picture (cropped, or something
 *                    painted over AFTER the camera made the thumbnail — the
 *                    thumbnail may still show it); modified long after taken
 *   Where it came    an AI model's mark (IPTC DigitalSourceType), an image
 *     from           generator's settings, Content Credentials
 *   What it hides    data after the picture's end (a ZIP: a polyglot; a
 *                    program; text that is code), code in a comment (a web
 *                    shell), a name that is not what the bytes are
 *   What it would    SVG: script, handlers, HTML inside, things it would
 *     do             load from outside, links — none of it run or loaded
 *   What it costs    a declared size no viewer should decode (60000×60000
 *                    pixels in 70 bytes)
 *
 * Pure: the reader's findings go in (structure.ts, meta.ts, raw.ts, and
 * what only a browser can measure — the thumbnail's likeness, an SVG's
 * parsed elements); sentences and the Info panel's rows come out.
 * unit:preview-facts runs it on the fixtures in Node.
 */

import type { Fact } from "../host.ts";
import { formatPosition, gpsOf, type Gps, type Meta } from "../image/tags.ts";
import type { Preview } from "../image/raw.ts";
import type { Sniffed, Structure } from "../image/structure.ts";
export { MAX_DECODED_PIXELS, MAX_PIXELS } from "../image/structure.ts";
import { linkFact, plural, shortUrl, some } from "../office.ts";

/** How an embedded thumbnail compares with the picture (the reader measures). */
export interface ThumbCheck {
	width: number;
	height: number;
	/** Its shape is not the picture's (beyond black bars). */
	shape: boolean;
	thumbAspect: number;
	pictureAspect: number;
	/** Mean difference of a 32×32 grey copy of each, 0–255 (the best of 8 orientations). */
	mean: number;
	/** Share of those cells that differ by more than a quarter of the range. */
	far: number;
}

export interface SvgFindings {
	scripts: number;
	handlers: number;
	/** foreignObject elements (HTML inside an SVG). */
	foreign: number;
	password: boolean;
	remote: string[];
	links: string[];
	jsLinks: number;
	/** A DOCTYPE declaring entities: not parsed, not drawn. */
	entities: boolean;
	/** Pictures carried inside it (data: URLs). */
	embedded: number;
}

export interface ImageFindings {
	name: string;
	sniff: Sniffed;
	structure: Structure;
	meta: Meta | null;
	/** A RAW file's previews, the largest first. */
	previews: Preview[];
	/** Pages or pictures our decoder found (TIFF pages, HEIF images). */
	pages: number;
	/** What is shown, and its size. */
	shown: { width: number; height: number; what: "picture" | "preview" | "page" } | null;
	/** Why nothing (or less) is shown, when that is the case. */
	refused: "too-large" | "no-decoder" | "not-a-picture" | "entities" | "failed" | "no-preview" | null;
	thumb: ThumbCheck | null;
	svg: SvgFindings | null;
}

const EXPECTED: Record<string, RegExp> = {
	jpg: /^jpeg$/, jpeg: /^jpeg$/, jpe: /^jpeg$/, jfif: /^jpeg$/, png: /^png$/, apng: /^png$/, gif: /^gif$/, webp: /^webp$/, avif: /^avif$/,
	heic: /^heic$/, heif: /^heic$/, hif: /^heic$/, tif: /^tiff$/, tiff: /^tiff$/, svg: /^svg$/, svgz: /^svgz?$/, bmp: /^bmp$/, dib: /^bmp$/, ico: /^ico$/, cur: /^ico$/,
	jxl: /^jxl$/, psd: /^psd$/, jp2: /^jp2$/, j2k: /^jp2$/,
	dng: /^(dng|tiff|raw)$/, cr2: /^(cr2|tiff|raw)$/, cr3: /^cr3$/, nef: /^(nef|tiff|raw)$/, nrw: /^(nef|tiff|raw)$/, arw: /^(arw|tiff|raw)$/, orf: /^orf$/, rw2: /^rw2$/, raf: /^raf$/, pef: /^(pef|tiff|raw)$/,
};
const RAW = /^(dng|cr2|nef|arw|orf|rw2|pef|raw|cr3|raf)$/;
const EDITORS = /photoshop|lightroom|gimp|affinity|pixelmator|snapseed|paint\.net|canva|picsart|meitu|faceapp|facetune|capture one|luminar|darktable|rawtherapee|krita|photopea|picasa|fotor|befunky|vsco|remini|lensa|midjourney|stable diffusion|dall-e|firefly/i;

const first = (m: Meta | null, ...paths: string[]): string | null => {
	for (const p of paths) {
		const [g, k] = p.split(".") as [string, string];
		const v = m?.[g]?.[k];
		if (typeof v === "string" && v.trim()) return v.trim();
		if (typeof v === "number") return String(v);
		if (Array.isArray(v) && v.length && v.every((x) => typeof x === "string")) return v.join(", ");
		if (v && typeof v === "object" && !(v instanceof Uint8Array)) {
			const lang = (v as Record<string, unknown>)["x-default"] ?? (v as Record<string, unknown>).value;
			if (typeof lang === "string" && lang.trim()) return lang.trim();
		}
	}
	return null;
};

/** "2026:01:02 03:04:05" → a Date in UTC (as written: no zone). */
const exifTime = (s: string | null): number | null => {
	const m = s ? /^(\d{4})[:-](\d\d)[:-](\d\d)[ T](\d\d):(\d\d):(\d\d)/.exec(s) : null;
	return m ? Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!) : null;
};
const span = (ms: number) => {
	const min = Math.round(ms / 60000);
	if (min < 120) return plural(min, "minute");
	const h = Math.round(min / 60);
	if (h < 48) return plural(h, "hour");
	const d = Math.round(h / 24);
	return d < 730 ? plural(d, "day") : plural(Math.round(d / 365), "year");
};
const size = (n: number) => (n < 1024 ? `${n} bytes` : n < 1048576 ? `${(n / 1024).toFixed(1)} kB` : `${(n / 1048576).toFixed(1)} MB`);
const quote = (s: string, n = 80) => `“${shortUrl(s).slice(0, n)}${s.length > n ? "…" : ""}”`;
const CODE = /<\?php|<script|eval\s*\(|base64_decode|system\s*\(|passthru|shell_exec|powershell|cmd\.exe|\/bin\/sh|wscript/i;

/** The camera, as people say it: "Apple iPhone 15 Pro" (not "Apple Apple iPhone…"). */
export function cameraOf(m: Meta | null): string | null {
	const make = first(m, "ifd0.Make");
	const model = first(m, "ifd0.Model");
	if (!make && !model) return null;
	if (make && model && model.toLowerCase().startsWith(make.toLowerCase().split(/\s/)[0]!)) return model;
	return [make, model].filter(Boolean).join(" ");
}

/** When it was taken, as written, with its zone when the file says. */
export function takenOf(m: Meta | null): string | null {
	const t = first(m, "exif.DateTimeOriginal", "exif.CreateDate", "xmp.CreateDate", "ifd0.ModifyDate");
	if (!t) return null;
	const zone = first(m, "exif.OffsetTimeOriginal", "exif.OffsetTime");
	return `${t.replace(/^(\d{4}):(\d\d):(\d\d)/, "$1-$2-$3")}${zone ? ` ${zone}` : ""}`;
}

function gpsFact(g: Gps): Fact {
	if (g.zeroed) return { level: "info", text: "Its GPS fields are there but zeroed (0, 0) — the location was removed, or never fixed" };
	const where = formatPosition(g);
	const parts = [where];
	if (g.alt !== undefined) parts.push(`${Math.round(g.alt)} m ${g.alt < 0 ? "below sea level" : "up"}`);
	if (g.direction !== undefined) parts.push(`facing ${Math.round(g.direction)}°${g.directionRef === "magnetic" ? " (magnetic)" : ""}`);
	if (g.accuracy !== undefined) parts.push(`±${Math.round(g.accuracy)} m`);
	if (g.when) parts.push(`GPS time ${g.when}`);
	return { level: "warn", text: `Carries where it was taken: ${parts.join(" · ")}`, copy: where };
}

export function imageFacts(f: ImageFindings): Fact[] {
	const facts: Fact[] = [];
	const m = f.meta;
	const s = f.structure;
	const ext = f.name.includes(".") ? f.name.split(".").pop()!.toLowerCase() : "";
	const fmt = f.sniff.format;

	// ── the summary ──
	const camera = cameraOf(m);
	const taken = takenOf(m);
	const dims = f.shown ? `${f.shown.width}×${f.shown.height}` : s.width && s.height ? `${s.width}×${s.height}` : "";
	const label = f.sniff.label.replace(/^an? /, "");
	facts.push({
		level: "info",
		text: [
			label.charAt(0).toUpperCase() + label.slice(1),
			dims,
			f.pages > 1 ? plural(f.pages, fmt === "tiff" ? "page" : "picture") : s.frames > 1 ? plural(s.frames, "frame") : "",
			camera ?? "",
			taken ? `taken ${taken}` : "",
		].filter(Boolean).join(" · "),
	});

	// ── is it what it says ──
	if (!fmt) {
		facts.push({ level: "warn", text: `Named .${ext || "(nothing)"}, but it is ${f.sniff.other ?? "not a picture"} — not drawn` });
	} else if (ext && EXPECTED[ext] && !EXPECTED[ext]!.test(fmt)) {
		const svg = fmt === "svg" || fmt === "svgz";
		facts.push({ level: svg ? "warn" : "info", text: svg ? `Named .${ext}, but it is an SVG drawing — SVG can carry script (drawn here as a picture: nothing in it runs)` : `Named .${ext}, but it is ${f.sniff.label}` });
	}

	// ── what it costs ──
	if (f.refused === "too-large" && s.width && s.height) {
		const mp = (s.width * s.height) / 1e6;
		facts.push({ level: "warn", text: `Declares ${s.width}×${s.height} pixels (${mp >= 1000 ? `${(mp / 1000).toFixed(1)} gigapixels` : `${Math.round(mp)} megapixels`}) — not drawn: a decompression bomb, or larger than this viewer draws` });
	}
	if (f.refused === "no-decoder") facts.push({ level: "info", text: `No decoder here for ${f.sniff.label} — its metadata is below` });
	if (f.refused === "failed") facts.push({ level: "warn", text: `It could not be decoded — damaged, or made to break decoders` });

	// ── RAW ──
	if (fmt && RAW.test(fmt)) {
		const best = f.previews[0];
		facts.push(best
			? { level: "info", text: `A camera RAW file: showing the camera's own ${best.width}×${best.height} preview${f.previews.length > 1 ? ` (of ${f.previews.length})` : ""} — the sensor data${s.width && s.height ? ` (${s.width}×${s.height})` : ""} is not decoded` }
			: { level: "info", text: "A camera RAW file with no preview found in it — the sensor data is not decoded here" });
	}

	// ── where and when ──
	const g = gpsOf(m);
	if (g) facts.push(gpsFact(g));
	const people: string[] = [];
	const add = (label: string, v: string | null) => v && people.push(`${label} ${quote(v, 40)}`);
	add("artist", first(m, "ifd0.Artist", "dc.creator", "iptc.Byline", "ifd0.XPAuthor"));
	add("owner", first(m, "exif.OwnerName", "exif.CameraOwnerName"));
	add("copyright", first(m, "ifd0.Copyright", "dc.rights", "iptc.CopyrightNotice"));
	if (people.length) facts.push({ level: "info", text: `Names people: ${people.join(", ")}` });
	const serials = [first(m, "exif.SerialNumber", "exif.BodySerialNumber"), first(m, "exif.LensSerialNumber")].filter(Boolean) as string[];
	if (serials.length) facts.push({ level: "info", text: `Names its camera: serial number ${serials.map((x) => quote(x, 30)).join(", lens ")} — the same camera's other photos carry it too` });

	// ── what was done to it ──
	if (f.thumb?.shape) {
		const r = (a: number) => (a >= 1 ? `${a.toFixed(2)}:1` : `1:${(1 / a).toFixed(2)}`);
		facts.push({ level: "warn", text: `Its embedded thumbnail has another shape (${r(f.thumb.thumbAspect)} against ${r(f.thumb.pictureAspect)}): the picture was cropped after it was taken — the thumbnail may show what was cut away` });
	} else if (f.thumb && (f.thumb.mean > 22 || f.thumb.far > 0.03)) {
		facts.push({ level: "warn", text: `Its embedded thumbnail shows a different picture: it was changed after the thumbnail was made — the thumbnail may show what was painted over or removed` });
	}
	const software = first(m, "xmp.CreatorTool", "ifd0.Software", "ihdr.Software");
	const history = Array.isArray(m?.xmpMM?.History) ? (m!.xmpMM!.History as Record<string, unknown>[]) : [];
	if (software && EDITORS.test(software)) {
		const last = history.at(-1);
		facts.push({ level: "info", text: `Edited with ${quote(software, 50)}${history.length ? ` — its XMP history records ${plural(history.length, "step")}${last?.action ? `, the last “${String(last.action)}”${last.when ? ` ${String(last.when)}` : ""}` : ""}` : ""}` });
	} else if (history.length > 1) facts.push({ level: "info", text: `Its XMP history records ${plural(history.length, "step")} of editing` });
	const takenAt = exifTime(first(m, "exif.DateTimeOriginal", "exif.CreateDate"));
	const modified = first(m, "ifd0.ModifyDate");
	const modifiedAt = exifTime(modified);
	if (takenAt !== null && modifiedAt !== null && modifiedAt - takenAt > 5 * 60_000) facts.push({ level: "info", text: `Modified ${span(modifiedAt - takenAt)} after it was taken (${modified})` });

	// ── where it came from ──
	const source = first(m, "Iptc4xmpExt.DigitalSourceType", "xmp.DigitalSourceType");
	if (source && /trainedAlgorithmicMedia|algorithmicMedia|compositeSynthetic|compositeWithTrainedAlgorithmicMedia/i.test(source)) {
		facts.push({ level: "info", text: `Its metadata says it was made${/composite/i.test(source) ? " in part" : ""} by an AI model (IPTC DigitalSourceType: ${source.split("/").pop()})` });
	}
	const generator = s.texts.find((t) => /^(parameters|prompt|workflow|Dream|sd-metadata|invokeai_metadata)$/i.test(t.key));
	if (generator) facts.push({ level: "info", text: `Carries an image generator's settings (${generator.key}): ${quote(generator.value, 90)}` });
	if (s.c2pa) facts.push({ level: "info", text: "Carries Content Credentials (C2PA) — a signed record of how it was made; not verified here" });

	// ── what it hides ──
	if (s.trailing) {
		const t = s.trailing;
		facts.push(t.benign
			? { level: "info", text: `After the picture: ${t.kind} — ${size(t.length)}` }
			: { level: "warn", text: `${size(t.length)} after the end of the picture: ${t.kind} — something carried inside a picture (a polyglot file)` });
	}
	for (const c of s.comments.slice(0, 3)) {
		facts.push(CODE.test(c) ? { level: "warn", text: `Its comment holds code: ${quote(c, 70)} — a web shell or a script hidden in a picture` } : { level: "info", text: `Comment: ${quote(c, 90)}` });
	}
	for (const t of s.texts.filter((x) => x !== generator && x.key !== "XML:com.adobe.xmp" && CODE.test(x.value)).slice(0, 3)) {
		facts.push({ level: "warn", text: `Its text chunk “${t.key}” holds code: ${quote(t.value, 70)}` });
	}

	// ── SVG ──
	const v = f.svg;
	if (v) {
		if (v.entities) facts.push({ level: "warn", text: "Declares XML entities (the “billion laughs” shape: each expanding into more) — not drawn; its source is shown" });
		if (v.scripts || v.handlers) facts.push({ level: "warn", text: `Contains script (${[v.scripts ? plural(v.scripts, "<script>", "<script>s") : "", v.handlers ? plural(v.handlers, "event handler") : ""].filter(Boolean).join(", ")}) — not run: an SVG drawn as a picture runs nothing` });
		if (v.foreign) facts.push({ level: "warn", text: `Contains HTML (${plural(v.foreign, "foreignObject")})${v.password ? " with a form asking for a password" : ""} — not drawn as a page` });
		if (v.remote.length) facts.push({ level: "warn", text: `Would load ${plural(v.remote.length, "thing")} from outside (not loaded): ${some(v.remote.map(shortUrl), 3)}` });
		if (v.jsLinks) facts.push({ level: "warn", text: `${plural(v.jsLinks, "javascript: link")} — inert here` });
		const links = linkFact(v.links);
		if (links) facts.push(links);
		if (v.embedded) facts.push({ level: "info", text: `Carries ${plural(v.embedded, "picture")} inside it (data: URLs)` });
	}

	if (f.sniff.native && s.frames > 1 && !f.pages) facts.push({ level: "info", text: `Animated: ${plural(s.frames, "frame")}` });
	return facts;
}

// ── the Info panel ────────────────────────────────────────────────────

export interface Group {
	title: string;
	rows: [string, string][];
}

/** A tag's value, as a line of text. */
export function show(v: unknown): string {
	if (v === null || v === undefined) return "";
	if (typeof v === "string") return v.length > 300 ? `${v.slice(0, 300)}…` : v;
	if (typeof v === "number") return Number.isInteger(v) ? String(v) : String(Number(v.toPrecision(6)));
	if (typeof v === "boolean") return v ? "yes" : "no";
	if (v instanceof Uint8Array) return v.length <= 8 ? [...v].join(" ") : `(${v.length} bytes)`;
	if (Array.isArray(v)) return v.length > 16 ? `${v.slice(0, 16).map(show).join(", ")}, … (${v.length})` : v.map(show).join(", ");
	if (typeof v === "object") {
		const o = v as Record<string, unknown>;
		if (typeof o["x-default"] === "string") return show(o["x-default"]);
		const values = Object.values(o);
		if (values.length && values.every((x) => typeof x === "number")) return show(values);
		return Object.entries(o).slice(0, 8).map(([k, x]) => `${k}: ${show(x)}`).join("; ");
	}
	return String(v);
}

/** Bulky technical tags the panel leaves to "All metadata" (or out). */
const NOISE = /^(StripOffsets|StripByteCounts|TileOffsets|TileByteCounts|ThumbnailOffset|ThumbnailLength|JPEGInterchangeFormat\w*|ExifVersion|FlashpixVersion|GPSVersionID|ComponentsConfiguration|ExifIFD|GPSIFD|SubIFD|InteropIFD|PrintIM|MakerNote|ApplicationNotes)$/;

export function metaGroups(f: ImageFindings): Group[] {
	const m = f.meta;
	const s = f.structure;
	const get = (p: string) => first(m, p);
	const groups: Group[] = [];
	const group = (title: string, rows: [string, string | null | undefined][]) => {
		const kept = rows.filter((r): r is [string, string] => !!r[1]);
		if (kept.length) groups.push({ title, rows: kept });
	};

	group("Picture", [
		["Format", f.sniff.label],
		["Size", s.width && s.height ? `${s.width} × ${s.height} (${((s.width * s.height) / 1e6).toFixed(1)} MP)` : null],
		["Shown", f.shown && (f.shown.width !== s.width || f.shown.height !== s.height) ? `${f.shown.width} × ${f.shown.height} (${f.shown.what})` : null],
		[f.sniff.format === "tiff" ? "Pages" : "Pictures", f.pages > 1 ? String(f.pages) : null],
		["Frames", s.frames > 1 ? String(s.frames) : null],
		["Orientation", get("ifd0.Orientation")],
		["Colour profile", get("icc.ProfileDescription") ?? get("icc.DeviceModelDesc")],
		["Previews", f.previews.length ? f.previews.map((p) => `${p.width}×${p.height}`).join(", ") : null],
	]);
	const g = gpsOf(m);
	group("Taken", [
		["Taken", takenOf(m)],
		["Digitised", get("exif.CreateDate")],
		["Modified", get("ifd0.ModifyDate") ?? get("xmp.ModifyDate")],
		["GPS time", g?.when],
	]);
	const exposure = [
		typeof m?.exif?.ExposureTime === "number" ? (m.exif.ExposureTime < 1 ? `1/${Math.round(1 / m.exif.ExposureTime)} s` : `${m.exif.ExposureTime} s`) : "",
		typeof m?.exif?.FNumber === "number" ? `f/${m.exif.FNumber}` : "",
		m?.exif?.ISO ? `ISO ${show(m.exif.ISO)}` : "",
		typeof m?.exif?.FocalLength === "number" ? `${m.exif.FocalLength} mm` : "",
	].filter(Boolean).join(" · ");
	group("Camera", [
		["Camera", cameraOf(m)],
		["Lens", get("exif.LensModel") ?? get("exif.LensMake")],
		["Exposure", exposure || null],
		["Serial number", get("exif.SerialNumber") ?? get("exif.BodySerialNumber")],
		["Lens serial", get("exif.LensSerialNumber")],
		["Owner", get("exif.OwnerName") ?? get("exif.CameraOwnerName")],
		["Software", get("ifd0.Software")],
	]);
	if (g && !g.zeroed) {
		group("Location", [
			["Position", formatPosition(g)],
			["Decimal", `${g.lat.toFixed(6)}, ${g.lon.toFixed(6)}`],
			["Altitude", g.alt !== undefined ? `${g.alt.toFixed(1)} m` : null],
			["Facing", g.direction !== undefined ? `${g.direction.toFixed(1)}° (${g.directionRef} north)` : null],
			["Accuracy", g.accuracy !== undefined ? `±${g.accuracy} m` : null],
		]);
	}
	const history = Array.isArray(m?.xmpMM?.History) ? (m!.xmpMM!.History as Record<string, unknown>[]) : [];
	group("Editing", [
		["Made with", get("xmp.CreatorTool")],
		...history.slice(0, 12).map((h, i): [string, string] => [`Step ${i + 1}`, [h.action, h.when, h.softwareAgent].filter(Boolean).map(String).join(" · ")]),
		["Document", get("xmpMM.DocumentID")],
		["Original", get("xmpMM.OriginalDocumentID")],
	]);
	group("People and rights", [
		["Artist", get("ifd0.Artist") ?? get("ifd0.XPAuthor")],
		["Creator", get("dc.creator") ?? get("iptc.Byline")],
		["Copyright", get("ifd0.Copyright") ?? get("dc.rights") ?? get("iptc.CopyrightNotice")],
		["Title", get("dc.title") ?? get("iptc.ObjectName") ?? get("ifd0.XPTitle")],
		["Description", get("ifd0.ImageDescription") ?? get("dc.description") ?? get("iptc.Caption")],
		["Keywords", get("dc.subject") ?? get("iptc.Keywords") ?? get("ifd0.XPKeywords")],
		["Comment", get("exif.UserComment") ?? get("ifd0.XPComment")],
		["Place", [get("iptc.City"), get("iptc.State"), get("iptc.Country")].filter(Boolean).join(", ") || null],
	]);
	group("Hidden in the file", [
		...s.comments.slice(0, 5).map((c, i): [string, string] => [`Comment ${i + 1}`, show(c)]),
		...s.texts.filter((t) => t.key !== "XML:com.adobe.xmp").slice(0, 10).map((t): [string, string] => [`Text “${t.key}”`, show(t.value)]),
		["After the end", s.trailing ? `${size(s.trailing.length)} at byte ${s.trailing.offset}: ${s.trailing.kind}` : null],
		["Thumbnail", f.thumb ? `${f.thumb.width} × ${f.thumb.height}${f.thumb.shape ? " — another shape" : f.thumb.mean > 22 || f.thumb.far > 0.03 ? " — a different picture" : " — matches"}` : null],
		["AI source", get("Iptc4xmpExt.DigitalSourceType")?.split("/").pop()],
		["Content Credentials", s.c2pa ? "present (not verified)" : null],
	]);
	const all: [string, string][] = [];
	for (const [name, tags] of Object.entries(m ?? {})) {
		for (const [k, v] of Object.entries(tags)) {
			if (NOISE.test(k) || all.length >= 400) continue;
			const text = show(v);
			if (text) all.push([`${name} · ${k}`, text]);
		}
	}
	if (all.length) groups.push({ title: "All metadata", rows: all });
	return groups;
}
