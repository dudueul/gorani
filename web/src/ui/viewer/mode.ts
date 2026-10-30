// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What the viewer can show, decided from the decrypted name/mime and the
 * size — pure and Node-testable. The rules are security rules as much as
 * UX: nothing here fetches anything, nothing evals, and oversized content
 * falls back to Download rather than being read whole into a tab.
 */

import type { ReaderId } from "./sandbox.ts";

// (`refused`: a malware sample, or a file whose type does not verify —
// commit 29e. Decided before anything else, and nothing is decrypted.
// `too-large`: something only shown by reading it whole, above MAX_INLINE.
// `document`: a format that needs a parser — shown by a reader in the
// sandboxed preview frame, never in the app's own page (42a, sandbox.ts).
// Pictures are among them since 42d: the browser's own decoders are a
// parser a crafted picture attacks too.)
export type ViewerMode = "video" | "audio" | "text" | "document" | "unsupported" | "too-large" | "refused";

/** The extensions each sandboxed reader takes (42a PDF; 42b Office, 한글; 42c email; 42d pictures). */
const BY_EXT: Record<string, ReaderId> = {
	pdf: "pdf",
	docx: "docx", docm: "docx", dotx: "docx", dotm: "docx",
	xlsx: "sheet", xlsm: "sheet", xlsb: "sheet", xltx: "sheet", xltm: "sheet", xls: "sheet", xlt: "sheet", ods: "sheet", csv: "sheet", tsv: "sheet",
	pptx: "pptx", pptm: "pptx", ppsx: "pptx", ppsm: "pptx", potx: "pptx", potm: "pptx",
	hwp: "hwp", hwpx: "hwp", hwt: "hwp",
	doc: "legacy", dot: "legacy", ppt: "legacy", pps: "legacy", pot: "legacy", rtf: "legacy", odt: "legacy", ott: "legacy", odp: "legacy", otp: "legacy",
	eml: "email", msg: "email",
	jpg: "image", jpeg: "image", jpe: "image", jfif: "image", png: "image", apng: "image", gif: "image", webp: "image", avif: "image", bmp: "image", dib: "image", ico: "image", cur: "image",
	heic: "image", heif: "image", hif: "image", tif: "image", tiff: "image", svg: "image", svgz: "image", jxl: "image", psd: "image", jp2: "image",
	dng: "image", cr2: "image", cr3: "image", nef: "image", nrw: "image", arw: "image", srf: "image", sr2: "image", orf: "image", rw2: "image", raw: "image", rwl: "image",
	pef: "image", srw: "image", raf: "image", "3fr": "image", erf: "image", kdc: "image", dcr: "image", mos: "image", iiq: "image", mef: "image", x3f: "image",
};

/** …and the types, for a file whose name says nothing. */
const BY_MIME: Record<string, ReaderId> = {
	"application/pdf": "pdf",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
	"application/vnd.ms-word.document.macroenabled.12": "docx",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "sheet",
	"application/vnd.ms-excel": "sheet",
	"application/vnd.ms-excel.sheet.macroenabled.12": "sheet",
	"application/vnd.ms-excel.sheet.binary.macroenabled.12": "sheet",
	"application/vnd.oasis.opendocument.spreadsheet": "sheet",
	"text/csv": "sheet",
	"text/tab-separated-values": "sheet",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
	"application/vnd.ms-powerpoint.presentation.macroenabled.12": "pptx",
	"application/x-hwp": "hwp",
	"application/haansofthwp": "hwp",
	"application/vnd.hancom.hwp": "hwp",
	"application/vnd.hancom.hwpx": "hwp",
	"application/hwp+zip": "hwp",
	"application/msword": "legacy",
	"application/vnd.ms-powerpoint": "legacy",
	"application/rtf": "legacy",
	"text/rtf": "legacy",
	"application/vnd.oasis.opendocument.text": "legacy",
	"application/vnd.oasis.opendocument.presentation": "legacy",
	"message/rfc822": "email",
	"application/vnd.ms-outlook": "email",
};

/** Which sandboxed reader shows a file, if one does: by its name first
 * (what the person sees), then its stored type. */
export function readerFor(kind: string, mime: string | null, name: string): ReaderId | null {
	const ext = name.includes(".") ? name.split(".").pop()!.toLowerCase() : "";
	if (kind === "pdf") return "pdf";
	const type = (mime ?? "").split(";")[0]!.trim().toLowerCase();
	return BY_EXT[ext] ?? BY_MIME[type] ?? (kind === "image" || type.startsWith("image/") ? "image" : null);
}

/**
 * The reader for what the bytes ARE, when the name says something else
 * (42b). Disguise is the point of a lure: "invoice.doc" is very often RTF
 * (the Equation Editor exploits), a web archive, or a .docx renamed; a
 * ".docx" may be a Word 97 file carrying macros. The name picked a reader;
 * the first bytes correct it, within the family the name promised (a
 * ".doc" that is a PDF is shown as the PDF it is). The reader then names
 * the mismatch among its facts. Pure: unit:viewer-modes.
 */
export function sniffReader(head: Uint8Array, guess: ReaderId, name: string): ReaderId {
	const ascii = String.fromCharCode(...head.subarray(0, 16));
	const ext = name.includes(".") ? name.split(".").pop()!.toLowerCase() : "";
	if (ascii.startsWith("%PDF-")) return "pdf";
	if (ascii.startsWith("{\\rtf")) return "legacy";
	const zip = head[0] === 0x50 && head[1] === 0x4b && head[2] === 0x03 && head[3] === 0x04;
	const ole = head[0] === 0xd0 && head[1] === 0xcf && head[2] === 0x11 && head[3] === 0xe0;
	if (guess === "sheet" || guess === "hwp" || guess === "email" || guess === "image") return guess; // each reads every form of its family (a .msg is an OLE file; the picture reader names a disguise itself)
	if (zip && guess === "legacy") {
		// A ".doc" or ".ppt" that is really the 2007+ format, renamed.
		if (/^(doc|dot)$/.test(ext)) return "docx";
		if (/^(ppt|pps|pot)$/.test(ext)) return "pptx";
	}
	// A ".docx"/".pptx" that is an OLE container: a 97–2003 file renamed
	// (or a password-protected one — the legacy reader says which).
	if (ole && (guess === "docx" || guess === "pptx")) return "legacy";
	return guess;
}

/** Above this, what is shown by reading it WHOLE into the tab — an image,
 * or media when neither streaming path is there — is offered as a
 * Download instead (a tab holding 1 GB of bytes is not an experience). */
export const MAX_INLINE = 256 * 1024 * 1024;
/** Text is rendered up to this many bytes, then truncated with a note. */
export const TEXT_CAP = 2 * 1024 * 1024;

export function pickViewerMode(kind: string, mime: string | null, size: number, policy: "normal" | "sample" | "unverified" = "normal", name = ""): ViewerMode {
	if (policy !== "normal" || kind === "sample") return "refused";
	// A reader in the frame takes the file whole, so it meets the same cap.
	if (readerFor(kind, mime, name)) return size > MAX_INLINE ? "too-large" : "document";
	// Video and audio stream: the in-page player (39p) and the media worker
	// fetch just the frames being played, from a file of any size — the
	// viewer caps their whole-blob FALLBACK (viewer.ts › readWhole). Text
	// opens only its first TEXT_CAP bytes. (Until 39w the cap came first,
	// for every kind: a film over 256 MB — what the streamer exists for —
	// said "no inline preview yet". Pictures, read whole, met the cap here
	// until 42d; now they meet it above, as every reader does.)
	return modeOf(kind, mime);
}

function modeOf(kind: string, mime: string | null): ViewerMode {
	switch (kind) {
		case "video":
			return "video";
		case "audio":
			return "audio";
		case "text":
		case "code":
			return "text";
		case "doc":
		case "sheet":
		case "slides":
		case "archive":
			// The formats with a reader in the frame never get here
			// (readerFor, above); archives get theirs next (42e).
			return mime === "text/plain" ? "text" : "unsupported";
		default: {
			if (mime?.startsWith("video/")) return "video";
			if (mime?.startsWith("audio/")) return "audio";
			if (mime?.startsWith("text/")) return "text";
			return "unsupported";
		}
	}
}

/** The blob mime for media the page plays (never application/octet-stream,
 * and never a type the browser would run as a document). Pictures had a
 * raster allow-list here (security review, commit 23: a stored
 * `image/svg+xml` must not become a blob: URL on the APP's origin, where
 * "open image in new tab" would run its script beside the vault); since
 * 42d no picture becomes a blob: URL in the app's page at all — each is
 * drawn in the preview frame. */
export function renderMime(kind: string, mime: string | null, _name: string): string {
	if (kind === "video") return mime?.startsWith("video/") ? mime : "video/mp4";
	if (kind === "audio") return mime?.startsWith("audio/") ? mime : "audio/mpeg";
	return "text/plain";
}
