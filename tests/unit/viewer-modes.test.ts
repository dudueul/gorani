// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The viewer's mode picker: which renderer a file gets, decided from the
 * decrypted name/mime and size. Pure, Node-testable — and a security rule
 * set as much as a UX table (see the module docs in viewer.ts).
 */

import { pickViewerMode, renderMime, MAX_INLINE } from "../../web/src/ui/viewer/mode.ts";
import assert from "node:assert/strict";

// Images by extension and by mime.
assert.equal(pickViewerMode("image", "photo.png", null, 100), "image");
assert.equal(pickViewerMode("file", "image/webp", 100), "image");

// Media plays inline under the size cap.
assert.equal(pickViewerMode("video", "movie.mp4", null, 1024), "video");
assert.equal(pickViewerMode("audio", "song.flac", null, 1024), "audio");

// Text/code render escaped; markdown is text too.
assert.equal(pickViewerMode("text", "notes.txt", null, 10), "text");
assert.equal(pickViewerMode("code", "main.rs", null, 10), "text");
assert.equal(pickViewerMode("file", "text/markdown", 10), "text");

// The size cap: oversized anything falls back to Download.
assert.equal(pickViewerMode("video", null, MAX_INLINE + 1), "unsupported");

// Structured formats are honest about not being ready (the styled readers
// and pdf.js land with ⑩b) — except a text/plain mime, which still shows.
assert.equal(pickViewerMode("pdf", "doc.pdf", null, 10), "unsupported");
assert.equal(pickViewerMode("archive", "backup.7z", null, 10), "unsupported");
assert.equal(pickViewerMode("doc", "text/plain", 10), "text");

// Render mimes never let stored content run as the app.
assert.equal(renderMime("image", null, "pic.svg"), "image/png", "SVG never runs");
assert.equal(renderMime("image", "image/svg+xml", "pic"), "image/png", "a stored SVG mime never reaches a blob URL either (commit 23)");
assert.equal(renderMime("image", "text/html", "x.png"), "image/png", "the extension wins only inside the raster list");
assert.equal(renderMime("image", "image/webp", "noext"), "image/webp", "a raster stored mime is kept");
assert.equal(renderMime("image", null, "pic.jpg"), "image/jpeg");
assert.equal(renderMime("video", null, "v.mkv"), "video/mp4");
assert.equal(renderMime("text", "text/plain", "n"), "text/plain");

console.log("ok  viewer modes: caps, mimes, escape-by-construction");