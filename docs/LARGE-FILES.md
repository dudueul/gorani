# Large files — up to 255 GB (D12)

> Copyright 2026- Seongwoo Hong. All rights reserved.
> The design for docs/DECISIONS.md › D12, written before the code (as
> docs/CUSTODY.md was for D5–D8). Disk images, memory captures and packet
> captures are the files a security team stores most and can least afford
> to lose to a size limit.

## What changes, in one paragraph

A GC01 file (docs/ENCRYPTION.md) is frames of `chunk` bytes, one frame per
multipart part, and the backends allow at most 10 000 parts. At the fixed
8 MiB chunk that is 78 GiB — and the browser read the whole file into
memory first, so the real limit was the tab's RAM, and the Worker copied
each part three times, so a larger part would have overrun its 128 MB
isolate. D12 makes the chunk grow with the file, the browser read and seal
one slice at a time, the Worker stream parts through untouched, uploads
survive a dropped connection or a closed tab, and the export package
stream to disk instead of being built in memory.

## The numbers

```text
chunk(size) = max(8 MiB, the smallest power of two ≥ ⌈size / 10 000⌉)
  ≤ 78 GiB   →  8 MiB        (every file today: nothing changes)
  ≤ 156 GiB  →  16 MiB
  ≤ 255 GiB  →  32 MiB       (D12's ceiling: 255 GiB / 10 000 = 26.1 MiB)
MAX_FILE   = 255 GiB          refused above, by the client and the Worker
MAX_CHUNK  = 64 MiB           the Worker's cap on a part (a request body
                              far under every plan's limit, never buffered)
```

A power of two keeps frame arithmetic exact, and one formula — in
`web/src/vault/chunked-file.ts` and its Rust twin `crates/formats/src/
chunked.rs`, pinned by shared vectors — means the browser, the CLI and the
desktop shells agree on every file's frames.

## Build order (each stage green on its own)

| Stage | What |
|---|---|
| 31a *(landed)* | **Adaptive chunks, streamed parts, streamed browser uploads.** `chunkFor` in both languages; the Worker refuses sizes over 255 GiB and chunks over 64 MiB, and pipes each part's body to the backend (S3: `UNSIGNED-PAYLOAD` with the length fixed; R2: the binding's stream) — no copy in the isolate. The browser hashes the file in one streamed pass (the hash is signed before any byte leaves), then seals and uploads slice by slice, retrying a failed part (three tries, backoff). |
| 31b *(landed)* | **Resumable uploads.** The in-flight upload — its id, object key, chunk, the sealed fields (name, type, key, signed hash, intake), the parts done — is kept in the browser (IndexedDB; every field already sealed). After a dropped connection or a closed tab, choosing the same file again (name, size, modified time, and the same SHA-256) continues from the first missing part. The server keeps an unfinished upload for the housekeeping window, then aborts it. |
| 31c *(landed: downloads in 31c, the export in 31d)* | **Streaming downloads and export.** A download larger than the tab can hold streams through the media service worker (`/media/<id>?download`), decrypting frame by frame to the browser's own download. The export package streams too (File System Access where the browser has it, the service worker otherwise), with ZIP64 for entries and archives over 4 GiB; `tools/verify-export.mjs` reads ZIP64 and hashes entries from disk, never holding one whole. |

Not in D12 (recorded here so nobody assumes otherwise):

- **The CLI into cases.** The CLI (`clients/core`) authenticates as a
  personal DEVICE, and a case has no devices (CASES.md stage 3). Uploading
  a 255 GB image into an evidence case from a command line needs the
  member's identity key and case grants on that machine — the desktop
  shells' work (D16, docs/DESKTOP.md). The browser path above is the one
  that reaches cases now.
- **Backups of stores too large to copy.** The streaming backup job copies
  objects into one .gbak (at most 10 000 × 8 MiB); a store holding 255 GB
  files gets manifest backups (DECISIONS.md › D12), a later commit.

## 31a as built

- `chunkFor` (web/src/vault/chunked-file.ts) and `chunked::chunk_for`
  (crates/formats), with `MAX_FILE`, `MAX_PARTS` and (Rust) `MAX_CHUNK`;
  eight boundary sizes in tests/vectors.json › chunked › chunkFor, read
  by both languages' vector tests.
- The Worker (`routes.rs › upload_start`): 413 above 255 GiB, 400 for a
  chunk above 64 MiB or a plan over 10 000 parts. Parts (file uploads and
  share copies alike) go through `s3.rs › multipart_part_stream`: the
  request's body wrapped in a `FixedLengthStream` of its declared
  `Content-Length` and handed to the R2 binding or to the signed S3 PUT
  (`UNSIGNED-PAYLOAD`, as every request already was). No length → 411; a
  length over one 64 MiB frame → 413. The Worker's own uploads (backup
  containers) keep the buffered `multipart_part`.
- The browser (`model.ts`): one streamed SHA-256 pass (`digestOf`,
  hash-wasm over 8 MiB slices; WebCrypto's one-shot digest for files that
  go up whole), then — above 48 MiB — a `FrameSource` that reads, seals
  and returns frame *i* only when the bridge asks for it. The bridge sends
  each part with up to three tries (1 s, then 4 s) for a dropped
  connection, a 5xx or a 429, never for a refusal, and says how far a
  long upload has come at each quarter. Audio tags are parsed only for
  files up to 512 MiB (the parser needs the whole file).
- Not yet: "copy" (duplicate) and a share link still read the file whole
  — both go through the plaintext in one buffer; they stay bounded by the
  tab's memory until 31c streams them.

## 31b as built

- The bridge's one `putMultipart` became three steps the MODEL drives —
  `multipartStart`, `multipartPart` (the retrying `sendPart`),
  `multipartComplete` — so `FilesModel › sendFrames` can journal every
  part that lands (and so the unit test drives the real resume logic, not
  a mock of it).
- `web/src/lib/upload-journal.ts`: the record per unfinished upload in
  IndexedDB (`gorani-uploads`), keyed by the model's keyed fingerprint of
  "name ‖ size ‖ modified ‖ SHA-256" — no plaintext name at rest; every
  stored field is already sealed or public. A memory journal where
  IndexedDB is missing (and in tests).
- Resume: the same file chosen again → the hash pass runs (as always) →
  the key matches → the content key is unwrapped from the record's own
  sealed field and the frames from the first missing part on are sealed
  and sent under the SAME upload, id and signed record. A server that
  forgot the upload ("no such upload": the housekeeping window passed, or
  it was discarded) → the record is dropped and the file starts over.
- The explorer says, when it opens, which uploads stopped part-way and how
  far they got; `discardUpload` aborts one on the server and forgets it.
- Not yet: no button for discarding (the window — `uploadDays`, 2 by
  default — does it), and a resume needs the same browser profile.

## 31c as built (downloads)

- `web/public/gorani-media-lib.js › downloadStream`: a whole GC01 file
  as a pull-based stream (highWaterMark 0): a window of frames (about
  32 MiB of ciphertext, at least one frame) fetched by Range, each opened
  in its place, hashed as it passes; the stream errors at the first frame
  that does not open, and never pads a short answer. With it, a plain-JS
  `sha256Stream` (the worker imports nothing from the app bundle) — both
  checked in Node by `unit:media-frames`.
- `sw-media.js`: one-use download registrations (`/media/dl/<random>`,
  forgotten as they are served, and on Lock) answered with the stream, an
  exact `Content-Length` and `Content-Disposition: attachment`; the
  plaintext's SHA-256 goes back to the page over a MessagePort.
- `model.ts › streamDownload`: above 256 MiB, a chunked file downloads
  this way, and the page checks the returned hash against the uploader's
  signed record when it finishes (the in-tab path checks it the same way).
  The page **navigates** to the worker's URL — a link without the
  `download` attribute: Chromium sends a download-attribute request
  straight to the network, past the service worker (found by the e2e
  test, which caught the app's own page arriving as the "file").
- Samples still download zipped in the tab (up to 2 GiB; larger ones go
  through the export), and a file too large for the tab with no worker is
  refused with the reason rather than tried.

## 31d as built (the export)

- `web/src/vault/zip.ts › ZipStream`: entries streamed in, each followed
  by a data descriptor (bit 3: CRC and sizes after the data); ZIP64 extras
  and end records wherever a size, an offset or the count needs them —
  or everywhere, with `forceZip64`, which is how the tests prove the
  ZIP64 paths without writing 4 GiB. A ZipCrypto entry under bit 3 checks
  its password against the DOS time's high byte (the CRC is not known
  yet), the convention Info-ZIP and Python read. A zip inside a zip is a
  ZipStream whose sink is the outer entry's `write`.
- `export.ts`: the walk streams each version ONCE through a pump — into
  its entry (a sample's into its own "infected" zip, inside) or nowhere
  (re-verification) — hashing it on the way; the source's `objectStream`
  hands it the response body, decrypted frame by frame. The manifest,
  which needs every hash, is written last. With a `sink` nothing is
  collected; without one (the tests, a browser with no service worker)
  the parts come back as before.
- The browser: `pipeToDownload` (media-worker.ts) registers a pipe with
  the media worker, the page navigates to it, and the worker asks the
  page for one chunk each time the browser's download wants more —
  the export runs exactly as fast as the disk takes it.
- `tools/verify-export.mjs` reads the package from disk with positional
  reads — ZIP64 end records and extras, sizes from the central directory
  (data descriptors), a sample's zip opened in place through a window
  onto the outer file — hashing every entry a slice at a time and
  checking its CRC. Nothing is held whole but the manifest.

## Why these choices

- **Hash first, then upload.** The uploader's signature covers SHA-256 of
  the plaintext (CUSTODY.md stage 4) and the duplicate check needs it
  before anything is stored. One extra read of the file is cheap next to
  uploading it; holding it in memory is impossible.
- **Stream through the Worker, don't presign.** A presigned PUT straight
  to the bucket would spare the Worker the bytes — and hand the browser a
  URL that writes to storage without the Worker's checks (who may upload
  where, the object key, the frame arithmetic at completion). The Worker
  staying in the path costs nothing once it no longer buffers.
- **Resume from the client's own record.** The parts done are the
  client's to know (it has their ETags); asking the backend to list them
  would trust a second source for the same fact. A record that no longer
  matches (the server aborted the upload) fails at completion and starts
  over — the honest failure.
