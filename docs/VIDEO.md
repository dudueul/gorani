# Video: streaming sealed files, and the `.hlsmeta` sidecar

> Copyright 2026- Seongwoo Hong. All rights reserved.

The family NAS holds big videos; a player should seek into the middle of a
20 GB movie without downloading it. The trick gorani uses is the one the
whole vault already rests on: **every GC01 frame opens on its own** — so a
player can fetch only the frames a scene needs. What is missing between
"frames exist" and "the `<video>` element seeks" is *media structure*:
which box holds which sample, where the keyframes are, what the track
durations are. That structure is what the `.hlsmeta` sidecar carries, and
it is produced by the same engine that powers the stream-worker project.

## The sidecar (one sealed summary per video version, commit 39p)

```text
video_meta (file_id, version) — sealed under the files key into place
file.video(area, file, version), like the music tags (docs/MUSIC.md)
  {
    v: 1, container: "mp4",
    layout: "regular" | "fragmented",
    moov: [offset, size],          where the moov box is, in plaintext bytes
    durationMs, codecs,            "avc1.64001f,mp4a.40.2" — what MSE is asked
    width, height,
    tracks: [{ type, codec }]
  }
```

It holds where the `moov` is, not the whole index. A two-hour film's
sample tables are megabytes, and a store row is not the place for
megabytes. The moov is in the file already: knowing its place turns "walk
the boxes, frame by frame, to find it" into one read, and the engine
indexes it in WebAssembly in milliseconds. The duration, picture size and
codecs are there so the Movie tab (39o) can list videos without opening any.

- **Written at upload** from the local file (its moov is a slice away), or
  **on first play** by the first member who may write there.
  `PUT members/<id>/files/<file>/video { version, meta }`. The server checks
  only what it can see: a live version, sealed text, sane sizes, not a
  malware sample (nothing ever decodes one).
- **Read** by the player, which trusts the moov place only as far as the box
  found there is a moov of that size (`lib/video-index.ts`). A stale or
  wrong sidecar is corrected by walking the boxes, and written back.
- **Resealed** with every store rotation (kind `video`), purged with its
  version, and in no backup: any client holding the plaintext can make it
  again.

## Playing it in the page (39p)

```text
the <video> wants time T
  → the index's segment table: T is in segment n (cut on keyframes, ~4 s)
  → its planned plaintext blocks, read through lib/frame-reader.ts —
    one ciphertext range per run of missing GC01 frames, opened here,
    the last few kept
  → gorani-media (WebAssembly) builds segment n as fMP4 (moof + mdat)
  → SourceBuffer.appendBuffer (ui/viewer/mse-player.ts)
```

- **The engine** is the stream-worker's MP4 core, vendored as
  `crates/media` (gorani-media) and built to WebAssembly by
  `crates/media-wasm` (`scripts/build-media-wasm.mjs`, run before every web
  build). The C ABI has no wasm-bindgen and imports nothing (`gm_*` exports,
  a result slot, indexes behind handles). It never sees a key: the page
  decrypts and hands it plaintext.
- **It buffers ahead, not everything.** 30 s past the playhead, 20 s behind.
  A full buffer lets go more and tries once again. A seek is just a new
  playhead: the next segment is always the first one from the playhead
  that the buffer does not hold.
- **Safari**: ManagedMediaSource (iOS 17.1+) where plain MediaSource is
  missing.
- **Which files**:
  - A regular MP4 (moov at either end) whose codecs this browser's MSE
    plays.
  - Everything else plays the older way: through the media service worker
    below. That covers fragmented MP4s, other containers, codecs MSE
    refuses, and any failure of the engine or the decoder.
- **CSP**: compiling WebAssembly needs `'wasm-unsafe-eval'`, which the app
  has carried since the Argon2id vault. It allows compiling wasm and
  nothing else.

## Status

- ⑩a: the viewer plays images, text/code, and audio/video from the
  decrypted blob — seeking inside the downloaded blob works because GC1
  frames open independently; ≤256 MB inline.
- ⑩b (landed in ⑩ on paper; **working since commit 25** — see below):
  **streaming playback through a service worker** — the browser's own
  `<video>` player drives; the worker (scope "/", claiming ONLY `/media/`
  paths and never answering anything else — Mailflare's iOS pass-through
  lesson) answers Range requests with decrypted plaintext:
  `gorani-media-lib.js` maps a plaintext range to whole GC01 frames, one
  ciphertext range fetch, frame-by-frame decrypt (the content key rides
  from the page as a cloned, still non-extractable CryptoKey), honest 206
  headers. Multi-GB files seek without downloading; no MSE, no box
  surgery, no DRM. The frame math is imported by the worker AND tested in
  Node from the same file.

  **Why "landed" was not true until commit 25** (docs/SECURITY-REVIEW.md ›
  O11) — four bugs, each enough on its own, none visible to a test that
  never played a video: the worker was registered at scope "/media/", but
  a service worker serves the pages it *controls* and the app page is "/",
  so `<video>` requests never reached it; it began with an `import` but was
  registered as a classic worker, so it never even installed; its
  whole-file path authenticated the magic alone (4 bytes) instead of
  GV02's 16-byte header, so no whole file could decrypt; and its fetches
  carried no dev identity, so even a working worker was refused by the dev
  server. Plus two wrong answers: whole frames instead of the asked range,
  and always `video/mp4`. `e2e:app` now plays the path: a 9 MiB video, a
  Range fetched through the worker, exact bytes and headers, and a 404
  once the viewer closes.
- **39p**: the sidecar and the in-page player above. A regular MP4 now plays
  through MSE, with keyframe-accurate seeks and no service worker in the
  way. The streaming path above remains for everything else.