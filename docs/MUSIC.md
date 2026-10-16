# Music: the metadata feed

> Copyright 2026- Seongwoo Hong. All rights reserved.
> The library view's design — and why the server can never know a title.

## The constraint that shapes everything

A zero-trust NAS sees sealed bytes. An MP3's ID3 tag is as invisible to the
server as the file's name — so there is no server-side tag reading, no
"scan the library" job, no metadata extractor. Every piece of metadata
exists because **a client that already held the plaintext** chose to seal a
summary of it.

## The flow

```text
upload (audio/*) ──▶ browser parses the tags from the plaintext it holds
                 ──▶ sealText(storePublic, JSON { title, artist, album, track, durationSec })
                 ──▶ sent as the `mmeta` field; the server stores the OPAQUE blob
                     in music_meta (file_id, version) — refused if unsealed
library view     ──▶ GET /api/v1/members/<id>/files/music  (ONE feed of sealed blobs)
                 ──▶ opens each blob with the store key — no audio decrypted
play             ──▶ the viewer streams the file (the only moment audio plaintext exists)
```

**How a track plays (39w).** It always streams, and decrypts only what is
being played:

- **An M4A or M4B** (AAC or ALAC in MP4) goes through the in-page player
  that plays films (docs/VIDEO.md). Its moov is indexed in WebAssembly and
  the track is cut into ~4-second fMP4 segments. Each segment is fetched,
  decrypted and appended to an `<audio>` element through MediaSource when
  the playhead needs it. Its sidecar is written at upload, as a video's is.
- **MP3, FLAC, Ogg and WAV** are not MP4, and the engine does not cut them.
  They stream through the media worker: the browser's own player asks for
  byte ranges, and the worker answers with decrypted bytes. This happens
  from the first byte at any size. Until 39w a track under 8 MiB was
  decrypted whole before it started.

- **One blob per version** (`PRIMARY KEY (file_id, version)`): a remaster
  carries new tags; the feed joins on the file's LIVING version, so old
  blobs stop appearing the moment the pointer moves. The trigger-fed
  `music_seq` counter bounds the change feed.
- **The feed is ciphertext with sizes** (`blobSealed`, `id`, `version`,
  `size`) — a leaked feed reveals that someone's family has music, and
  nothing else.
- **Blobs we can no longer open** (a rotated key's leftovers) are skipped
  by the library honestly rather than failing the whole feed.

## The parser (`web/src/vault/music-meta.ts`)

Pure TypeScript, one module for browser and Node tests. Scope: **ID3v2.3/2.4**
text frames (`TIT2`/`TPE1`/`TALB`/`TRCK`, encodings latin-1, UTF-16 with
BOM, UTF-8) and **FLAC** (STREAMINFO duration + Vorbis comments). MP4/M4A
metadata rides its own container grammar — the library treats it as
"unknown metadata", not an error. The subtleties the tests pin down: the
UTF-16 terminator is two NULs aligned to the character boundary (byte-level
scanning would cut a last character's high byte), v2.3 frame sizes are
plain 32-bit where v2.4's are synchsafe, and FLAC's total-samples field is
36 bits straddling byte three's low nibble.

## What the server may ask for

Only the shape: the blob must be sealed text. It cannot require fields,
validate a schema, or reject a title — every one of those would be a
way for the server to learn something. `tests/api/music.test.mjs` walks
the contract; `tests/unit/music.test.ts` owns the parser byte by byte.