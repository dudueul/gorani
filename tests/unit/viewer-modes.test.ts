// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The viewer's mode picker: which renderer a file gets, decided from the
 * decrypted name/mime and size. Pure, Node-testable — and a security rule
 * set as much as a UX table (see the module docs in viewer.ts).
 */

import { pickViewerMode, readerFor, renderMime, MAX_INLINE } from "../../web/src/ui/viewer/mode.ts";
import assert from "node:assert/strict";

// (The signature is (kind, mime, size[, policy]). Until commit 29e half of
// these calls passed a file NAME as the mime and the size as a fourth
// argument the function did not have — they passed because the kind
// decided alone. A fourth parameter now exists, and would have read "100"
// as a policy: the calls say what they mean again.)

// Images by kind and by mime.
assert.equal(pickViewerMode("image", null, 100), "image");
assert.equal(pickViewerMode("file", "image/webp", 100), "image");

// Media plays inline under the size cap.
assert.equal(pickViewerMode("video", null, 1024), "video");
assert.equal(pickViewerMode("audio", "audio/flac", 1024), "audio");

// Text/code render escaped; markdown is text too.
assert.equal(pickViewerMode("text", null, 10), "text");
assert.equal(pickViewerMode("code", null, 10), "text");
assert.equal(pickViewerMode("file", "text/markdown", 10), "text");

// The size cap is for what is read WHOLE to be shown: an image. Video and
// audio stream at any size, and text opens only its head (39w — the cap
// used to come first, so a film over 256 MB had "no preview" at all).
assert.equal(pickViewerMode("image", "image/png", MAX_INLINE + 1), "too-large");
assert.equal(pickViewerMode("image", "image/png", MAX_INLINE), "image", "at the cap, still shown");
assert.equal(pickViewerMode("video", null, 20 * 1024 ** 3), "video", "a 20 GB film streams");
assert.equal(pickViewerMode("audio", "audio/flac", MAX_INLINE + 1), "audio", "so does a long recording");
assert.equal(pickViewerMode("text", "text/plain", MAX_INLINE + 1), "text", "a big log opens its first part");
// PDFs open in the sandboxed preview frame (42a, sandbox.ts) — by kind, by
// mime or by name — read whole into it, so they meet the same cap.
assert.equal(pickViewerMode("pdf", "application/pdf", 10), "document");
assert.equal(pickViewerMode("file", "application/pdf", 10), "document", "by its mime");
assert.equal(pickViewerMode("file", null, 10, "normal", "report.PDF"), "document", "by its name");
assert.equal(pickViewerMode("pdf", "application/pdf", MAX_INLINE + 1), "too-large", "read whole, so capped");
assert.equal(pickViewerMode("pdf", "application/pdf", 10, "sample"), "refused", "a PDF that is a sample is never parsed, sandbox or not");
assert.equal(readerFor("pdf", null, "a.pdf"), "pdf");
assert.equal(readerFor("text", "text/plain", "a.txt"), null, "plain text needs no parser: it stays in the page, escaped");

// Formats whose readers are still to come are honest about it — except a
// text/plain mime, which still shows.
assert.equal(pickViewerMode("archive", null, 10), "unsupported");
assert.equal(pickViewerMode("doc", "text/plain", 10), "text");

// Malware samples (commit 29e): refused before anything else — whatever
// the kind or mime says, and a type that does not verify is refused too.
assert.equal(pickViewerMode("image", "image/png", 10, "sample"), "refused");
assert.equal(pickViewerMode("text", "text/plain", 10, "unverified"), "refused");
assert.equal(pickViewerMode("sample", null, 10), "refused", "the sample kind alone refuses");
assert.equal(pickViewerMode("image", "image/png", 10, "normal"), "image");

// Render mimes never let stored content run as the app.
assert.equal(renderMime("image", null, "pic.svg"), "image/png", "SVG never runs");
assert.equal(renderMime("image", "image/svg+xml", "pic"), "image/png", "a stored SVG mime never reaches a blob URL either (commit 23)");
assert.equal(renderMime("image", "text/html", "x.png"), "image/png", "the extension wins only inside the raster list");
assert.equal(renderMime("image", "image/webp", "noext"), "image/webp", "a raster stored mime is kept");
assert.equal(renderMime("image", null, "pic.jpg"), "image/jpeg");
assert.equal(renderMime("video", null, "v.mkv"), "video/mp4");
assert.equal(renderMime("text", "text/plain", "n"), "text/plain");

console.log("ok  viewer modes: the cap only where a file is read whole (media streams at any size), mimes, escape-by-construction, samples refused");