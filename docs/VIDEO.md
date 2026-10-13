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

## The sidecar (one small sealed file per video version)

```text
<object>.hlsmeta   (sealed with the version's content key, like .thumb and text)
  {
    v: 1,
    kind: "mp4",
    duration: seconds,
    tracks: [{ id, type: "video"|"audio", codec, timescale, duration }],
    keyframes: [{ time, chunk, offset }],   // time → GC01 frame + inner offset
    fragments: [{ time, chunk, offset, duration, sampleCount }],
    size: plaintext bytes
  }
```

The `keyframes`/`fragments` tables are exactly what `mp4-hls-core`'s index
builder produces for stream-worker (Case B assembly: regular MP4 assembled
into fMP4 fragments on the fly). In stream-worker that index lives next to
the file in the bucket and the *server* assembles segments; in gorani the
server must never decrypt — so the same index is sealed and shipped to the
client, and the assembly runs **in the browser**:

```text
player wants time T
  → keyframe table: T lands in fragment F (chunk i, inner offset o)
  → fetch Range [i*frame, …] over the GC01 object (the server relays verbatim)
  → decrypt those frames (WebCrypto, the session's content key)
  → mp4-hls-core (WASM) builds the fMP4 init + media segment in memory
  → MSE SourceBuffer.appendBuffer
```

No DRM, per the family's decision: the bytes were decrypted by the family's
own device; MSE plays them the same as any local file. The sealed storage is
the protection.

## Why WASM, and why it is safe here

`mp4-hls-core` parses boxes and builds segments — it never touches a key.
Rust-in-WASM for key *handling* would give up WebCrypto's non-extractable
keys (docs/COURSE.md, Lesson 2); for key-free media parsing it buys speed
and one shared implementation with the native clients, which also build
`.hlsmeta` at upload. The vendored crate is `crates/media/` with a
wasm-pack build (scripts/build-media-wasm.mjs) and the license/notices as
in NOTICE.

## What each part does at upload

1. The browser (or desktop client) reads the MP4's *metadata boxes only*
   (never `mdat`) while sealing — mp4-hls-core's indexer was built for
   exactly this (any file size, O(box index)).
2. The resulting tables are sealed with the version's content key and
   uploaded as the `.hlsmeta` sidecar (`PUT …/files/:id/versions/:n/extras`
   — the sidecar route arrives with the streaming commit).
3. Devices without the indexer backfill on first open, the way text
   sidecars backfill.

## Status

- ⑩a (this commit): the viewer plays images, text/code, and audio/video
  from the decrypted blob — seeking inside the downloaded blob works
  because GC1 frames open independently; ≤256 MB inline.
- ⑩b (next): vendor `crates/media` → WASM; build `.hlsmeta` at upload; the
  MSE player reads the sidecar and streams ranges; the sidecar routes.
  The design above is the contract; the wire formats are shared with
  stream-worker's `index.json` shape where they agree.