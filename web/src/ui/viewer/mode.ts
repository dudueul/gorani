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
// sandboxed preview frame, never in the app's own page (42a, sandbox.ts).)
export type ViewerMode = "image" | "video" | "audio" | "text" | "document" | "unsupported" | "too-large" | "refused";

/** Which sandboxed reader shows a file, if one does (42a: PDF). */
export function readerFor(kind: string, mime: string | null, name: string): ReaderId | null {
	const ext = name.includes(".") ? name.split(".").pop()!.toLowerCase() : "";
	if (kind === "pdf" || mime === "application/pdf" || ext === "pdf") return "pdf";
	return null;
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
	const mode = modeOf(kind, mime);
	// Only an image is read whole to be shown, so only an image meets the
	// cap here. Video and audio stream: the in-page player (39p) and the
	// media worker fetch just the frames being played, from a file of any
	// size — the viewer caps their whole-blob FALLBACK (viewer.ts ›
	// readWhole). Text opens only its first TEXT_CAP bytes. (Until 39w the
	// cap came first, for every kind: a film over 256 MB — what the
	// streamer exists for — said "no inline preview yet".)
	return mode === "image" && size > MAX_INLINE ? "too-large" : mode;
}

function modeOf(kind: string, mime: string | null): ViewerMode {
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
		case "doc":
		case "sheet":
		case "slides":
		case "archive":
			// Office, HWP and archives get their readers in the frame next
			// (42b, 42e); PDF already has one (readerFor, above).
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
		// A RASTER allow-list — for the stored mime too, not only the
		// extension (security review, commit 23). The stored mime is chosen by
		// whoever uploaded (and, sealed or not, a hostile server can swap it):
		// `image/svg+xml` passed `startsWith("image/")`, and a blob URL lives
		// on the APP's origin — "open image in new tab" would run the SVG's
		// script next to the vault.
		const raster = ["png", "jpeg", "gif", "webp", "avif", "bmp"];
		const fromExt = ext === "jpg" ? "jpeg" : ext;
		if (raster.includes(fromExt)) return `image/${fromExt}`;
		const sub = mime?.startsWith("image/") ? (mime.slice("image/".length).split(";")[0] ?? "").trim().toLowerCase() : "";
		return raster.includes(sub) ? `image/${sub}` : "image/png";
	}
	if (kind === "video") return mime?.startsWith("video/") ? mime : "video/mp4";
	if (kind === "audio") return mime?.startsWith("audio/") ? mime : "audio/mpeg";
	return "text/plain";
}