// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Type→icon mapping, drawn as inline SVG (no external assets — the CSP
 * allows nothing but self, so every icon is ours). One `kindOf(name)` decides
 * the glyph from the *decrypted* extension; the sealed type (the version's
 * stored mime, opened with the store key) is the fallback for extensionless
 * files.
 */

export type FileKind = "folder" | "image" | "video" | "audio" | "pdf" | "doc" | "sheet" | "slides" | "code" | "archive" | "text" | "file";

export function kindOf(name: string, mime?: string | null): FileKind {
	const ext = name.includes(".") ? name.split(".").pop()!.toLowerCase() : "";
	const table: Record<string, FileKind> = {
		png: "image", jpg: "image", jpeg: "image", gif: "image", webp: "image", heic: "image", avif: "image", svg: "image", bmp: "image", tiff: "image",
		mp4: "video", mov: "video", mkv: "video", webm: "video", avi: "video", m4v: "video",
		mp3: "audio", m4a: "audio", flac: "audio", ogg: "audio", opus: "audio", wav: "audio", aac: "audio",
		pdf: "pdf",
		docx: "doc", doc: "doc", hwp: "doc", hwpx: "doc", rtf: "doc", odt: "doc", md: "text", txt: "text",
		xlsx: "sheet", xls: "sheet", csv: "sheet", ods: "sheet",
		pptx: "slides", ppt: "slides", odp: "slides",
		ts: "code", js: "code", rs: "code", py: "code", go: "code", json: "code", toml: "code", yaml: "code", yml: "code", sh: "code", c: "code", cpp: "code", java: "code", kt: "code", swift: "code", html: "code", css: "code",
		zip: "archive", "7z": "archive", tar: "archive", gz: "archive", xz: "archive", rar: "archive",
	};
	if (table[ext]) return table[ext];
	if (mime?.startsWith("image/")) return "image";
	if (mime?.startsWith("video/")) return "video";
	if (mime?.startsWith("audio/")) return "audio";
	if (ext) return "file";
	return mime === "text/plain" ? "text" : "file";
}

const STROKE = 'fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"';

/** A 24×24 glyph, coloured by the caller's text classes. */
export function icon(kind: FileKind, cls = "h-5 w-5"): string {
	const body: Record<FileKind, string> = {
		folder: `<path ${STROKE} d="M3 7.5A1.5 1.5 0 0 1 4.5 6h4l2 2.5h7A1.5 1.5 0 0 1 19 10v7a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 3 17Z"/>`,
		image: `<rect ${STROKE} x="3.5" y="5" width="17" height="14" rx="2"/><circle ${STROKE} cx="9" cy="10" r="1.6"/><path ${STROKE} d="m5 17 4.5-4.5 3 3L15 13l4 4"/>`,
		video: `<rect ${STROKE} x="3.5" y="5.5" width="17" height="13" rx="2"/><path ${STROKE} d="m10.5 9.5 4 2.5-4 2.5Z"/>`,
		audio: `<path ${STROKE} d="M9 17V6.5l10-2V15"/><circle ${STROKE} cx="7" cy="17" r="2"/><circle ${STROKE} cx="17" cy="15" r="2"/>`,
		pdf: `<path ${STROKE} d="M6 3.5h8l4 4V20a.5.5 0 0 1-.5.5h-11A.5.5 0 0 1 6 20V3.5Z"/><path ${STROKE} d="M14 3.5V8h4"/><text x="8" y="16" font-size="6" fill="currentColor" stroke="none" font-family="sans-serif">PDF</text>`,
		doc: `<path ${STROKE} d="M6 3.5h8l4 4V20a.5.5 0 0 1-.5.5h-11A.5.5 0 0 1 6 20V3.5Z"/><path ${STROKE} d="M14 3.5V8h4M9 12h6M9 15.5h6"/>`,
		sheet: `<path ${STROKE} d="M6 3.5h8l4 4V20a.5.5 0 0 1-.5.5h-11A.5.5 0 0 1 6 20V3.5Z"/><path ${STROKE} d="M14 3.5V8h4M9 12h6M9 15h6M9 12v6.5M12 12v6.5M9 18.5h6"/>`,
		slides: `<rect ${STROKE} x="4" y="5" width="16" height="11" rx="1.5"/><path ${STROKE} d="M12 16v3M9 19h6"/>`,
		code: `<path ${STROKE} d="m9 8-4 4 4 4M15 8l4 4-4 4"/>`,
		archive: `<rect ${STROKE} x="5" y="3.5" width="14" height="17" rx="1.5"/><path ${STROKE} d="M12 4v4M10 8h4M10 10.5h4M12 13.5v3"/>`,
		text: `<path ${STROKE} d="M6 3.5h8l4 4V20a.5.5 0 0 1-.5.5h-11A.5.5 0 0 1 6 20V3.5Z"/><path ${STROKE} d="M14 3.5V8h4M9 12h6M9 15.5h4"/>`,
		file: `<path ${STROKE} d="M6 3.5h8l4 4V20a.5.5 0 0 1-.5.5h-11A.5.5 0 0 1 6 20V3.5Z"/><path ${STROKE} d="M14 3.5V8h4"/>`,
	};
	return `<svg viewBox="0 0 24 24" class="${cls}" aria-hidden="true">${body[kind]}</svg>`;
}