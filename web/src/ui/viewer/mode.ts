// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What the viewer can show, decided from the decrypted name/mime and the
 * size — pure and Node-testable. The rules are security rules as much as
 * UX: nothing here fetches anything, nothing evals, and oversized content
 * falls back to Download rather than being read whole into a tab.
 */

export type ViewerMode = "image" | "video" | "audio" | "text" | "unsupported";

/** Above this, offer Download instead of reading whole (chunked files stream, but a tab holding 1 GB of bytes is not an experience). */
export const MAX_INLINE = 256 * 1024 * 1024;
/** Text is rendered up to this many bytes, then truncated with a note. */
export const TEXT_CAP = 2 * 1024 * 1024;

export function pickViewerMode(kind: string, mime: string | null, size: number): ViewerMode {
	if (size > MAX_INLINE) return "unsupported";
	switch (kind) {
		case "image":
			return "image";
		case "video":
			return "video";
		case "audio":
			return "audio";
		case "text":
		case "code":
			return "text";
		case "pdf":
		case "doc":
		case "sheet":
		case "slides":
		case "archive":
			// The styled document readers and the archive browser land with the
			// streaming commit (⑩b): mp4-hls-core for video, pdf.js for PDFs.
			return mime === "text/plain" ? "text" : "unsupported";
		default: {
			if (mime?.startsWith("image/")) return "image";
			if (mime?.startsWith("video/")) return "video";
			if (mime?.startsWith("audio/")) return "audio";
			if (mime?.startsWith("text/")) return "text";
			return "unsupported";
		}
	}
}

/** The blob mime for rendering (never application/octet-stream — a stored
 * HTML/SVG must not run as the app). */
export function renderMime(kind: string, mime: string | null, name: string): string {
	const ext = name.includes(".") ? name.split(".").pop()!.toLowerCase() : "";
	if (kind === "image") {
		const known = ["png", "jpg", "jpeg", "gif", "webp", "avif", "bmp"];
		if (known.includes(ext)) return `image/${ext === "jpg" ? "jpeg" : ext}`;
		return mime?.startsWith("image/") ? mime : "image/png";
	}
	if (kind === "video") return mime?.startsWith("video/") ? mime : "video/mp4";
	if (kind === "audio") return mime?.startsWith("audio/") ? mime : "audio/mpeg";
	return "text/plain";
}