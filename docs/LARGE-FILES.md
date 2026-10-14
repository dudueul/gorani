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
| 31a | **Adaptive chunks, streamed parts, streamed browser uploads.** `chunkFor` in both languages; the Worker refuses sizes over 255 GiB and chunks over 64 MiB, and pipes each part's body to the backend (S3: `UNSIGNED-PAYLOAD` with the length fixed; R2: the binding's stream) — no copy in the isolate. The browser hashes the file in one streamed pass (the hash is signed before any byte leaves), then seals and uploads slice by slice, retrying a failed part (three tries, backoff). |
| 31b | **Resumable uploads.** The in-flight upload — its id, object key, chunk, the sealed fields (name, type, key, signed hash, intake), the parts done — is kept in the browser (IndexedDB; every field already sealed). After a dropped connection or a closed tab, choosing the same file again (name, size, modified time, and the same SHA-256) continues from the first missing part. The server keeps an unfinished upload for the housekeeping window, then aborts it. |
| 31c | **Streaming downloads and export.** A download larger than the tab can hold streams through the media service worker (`/media/<id>?download`), decrypting frame by frame to the browser's own download. The export package streams too (File System Access where the browser has it, the service worker otherwise), with ZIP64 for entries and archives over 4 GiB; `tools/verify-export.mjs` reads ZIP64 and hashes entries from disk, never holding one whole. |

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
