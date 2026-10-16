# DRM: protected copies of videos (FairPlay first)

> Copyright 2026- Seongwoo Hong. All rights reserved.
> The design for commit 40 — written before the code, as every design here
> is. It answers one question: how can someone watch a video without being
> handed a file they can keep? It also says plainly what that costs in a
> store built so the server can read nothing.

## What it is for

gorani encrypts every file in the browser: the server stores bytes it
cannot read, and anyone who can watch a video holds the key that opens it.
That is the right default, but it means a viewer who can watch can also
keep. Once a key has been handed out, a "view only" switch on the server
can only stop the next download. It cannot take back the key or the bytes.

A **protected copy** is a second rendition of one video. Viewers get that
copy instead of the original, and its key never reaches the page:

- **Who gets it.** The people asked for: a view-only share link, an
  external with a view-only grant on a case, and members.
- **Who keeps the original.** Leads. They still download the original
  file, as today.
- **How it is locked.** The copy is encrypted the way the film studios
  require (`cbcs`, ISO/IEC 23001-7). Its key goes from our license server
  straight into the device's DRM module (Apple's FairPlay in Safari). The
  page's JavaScript never holds the key, so devtools, a download manager
  or a browser extension sees only ciphertext.

## The trade-off, stated once

> **A protected copy is not end-to-end encrypted.** The server holds its
> key.

There is no way around this. To hand the key to Apple's DRM module and
nobody else, the license server has to have it. In this store that server
is our Worker. You accepted this ("sacrificing partial key saves at
DB-level"), and the design keeps it as small as it can:

| | Original | Protected copy |
|---|---|---|
| Encrypted by | the uploader's browser (GC01 frames) | the lead's browser (`cbcs`) |
| Key held by | the people the area is sealed to | the Worker: a per-video key, sealed in the database under a Worker secret |
| Server can decrypt | **never** | **yes**: whoever has the database AND the Worker secret |
| Server can see | sizes, times | also the copy's segment layout (a video's rough bitrate over time) |
| Who reads it | leads (and an own area's owner) | everyone else with read access, and the links |

The sealing means one leak is not enough. Someone holding a database dump
or the S3 bucket also needs `DRM_KEY_SECRET`, which lives only in
Cloudflare's secret store. Each video has its own key, so a leaked key
opens one copy. Deleting a video deletes its key row; the copy can then
never be opened again, even from a backup of the bucket.

Only videos someone protects are affected. Every other file is exactly as
before.

## What it protects against, and what it does not

**It stops:**

- a share-link recipient, an external, or a member saving the video. They
  receive `cbcs` ciphertext and a license only Apple's DRM module can
  open;
- "Save video as…", download managers, devtools, extensions, and copying
  the bytes out of the browser cache;
- forwarding a link past what the link policy allows (expiry and the
  plays count, as the server already enforces for links).

On Apple devices, FairPlay also blacks out the video in screenshots and
screen recordings. That is Apple's behaviour, not ours, and it can change.

**It does not stop:**

- **the operator.** The server holds the key: see above;
- **leads.** They keep the original by design;
- **anything already handed out.** Protecting a video does not take back
  a copy someone already has: a member's earlier download, the desktop
  sync, or an existing ordinary share link (the app offers to revoke
  those when you protect);
- **a camera pointed at the screen,** or a broken DRM module (jailbroken
  devices and the like). No DRM stops these.

## Who sees which copy

The rule the Worker enforces, in one place (`drm.rs › who_gets_original`):

- **In a member's own area:** only the owner reads it at all. Protecting
  matters there only for the links the owner makes.
- **In a case:** a lead on the case gets the original. Everyone else on
  the case gets the protected copy only: analysts, auditors and externals.
  That includes the person who uploaded it, who had the plaintext anyway.
- **A view-only share link** carries no file key at all, only a token. It
  plays the protected copy.

For a protected video, "only the protected copy" means the Worker refuses
the original's bytes to everyone else. That covers every route that serves
them: download, range reads for the in-page player, zip, export, versions,
and the desktop sync. Refusing on the server is the whole barrier, and it
is enough, because nobody can decrypt GC01 bytes they never receive.

## How a video gets protected

1. **A lead chooses Protect** in the viewer (🔒 Protect…, after a plain
   confirmation of what it means). Their browser holds the plaintext.
2. **The Worker makes a key.** It generates a random content key K, a key
   id and a constant IV, and stores K sealed under `DRM_KEY_SECRET`. The
   seal names the area, the file and the version, so a sealed key cannot
   be moved to another video. The Worker returns K to this lead's browser,
   once.
3. **The lead's browser packages the copy** with the engine from commit
   39p (gorani-media, in WebAssembly). It reads the original in GC01
   frames, re-cuts it into fMP4 segments of about 4 seconds, and encrypts
   each sample:
   - **video** (H.264, HEVC): one 16-byte block in every ten (the 1:9
     pattern) after each slice header. The headers stay clear, as the
     standard requires, so hardware decoders can read them. The parser for
     those headers is the largest piece of new code;
   - **audio** (AAC): every whole 16-byte block, from the constant IV.

   The init segment says so in its boxes: `encv`/`enca`, `sinf`, `frma`,
   `schm` = `cbcs`, and `tenc` with the key id, the pattern and the IV.
   Each video fragment carries its subsample map in `senc`/`saiz`/`saio`.
   This is the same layout Shaka Packager and Bento4 write. Apple's
   players, ffmpeg, and later Widevine all read it.
4. **The copy is uploaded as one object**,
   `drm/<area's prefix>/<file>/<version>-<key id>`, in parts of at least
   8 MiB, through the same streamed multipart path as any upload. It goes
   up as it is, not in GC01 frames, because Safari's own player must read
   it. With the last part goes its layout: the init's byte range, and each
   segment's offset, length and duration. The Worker checks that layout
   against the object storage actually holds: it must tile it exactly, or
   the copy is deleted and the lead told why.
5. **The Worker writes the playlist** on request from that layout:
   - `EXT-X-MAP` and `EXT-X-BYTERANGE` into the one object;
   - `EXT-X-KEY:METHOD=SAMPLE-AES,URI="skd://<key id>"`.

   A member's player fetches it under Access, as every request already
   goes. A view-only link's player cannot add a header, so the URLs it is
   given carry a signed viewing session instead (below).

A new version of a protected video needs a new copy. Until a lead makes
one (the viewer offers "Make protected copy" when the current version has
none), viewers are told the copy is being prepared. They never see the
stale copy, and never the original.

## How it plays

Only in Safari: macOS, iPhone and iPad.

1. The viewer sets the playlist as the `<video>`'s source. Safari's own
   HLS player reads it and meets the `skd://` key.
2. Standard EME (`com.apple.fps`):
   - the page loads Apple's certificate from `GET drm/fairplay/certificate`;
   - FairPlay builds an SPC, a request sealed to that certificate;
   - the page posts it to `POST drm/fairplay/license` with the viewer's
     token;
   - the Worker checks the token, opens K, and answers with a CKC: K
     sealed to that device's session;
   - FairPlay decrypts inside Apple's DRM module, and the page never sees
     K.
3. The license server is the user's own `fairplay.rs`, vendored into the
   Worker. It turns an SPC into a CKC with RSA-OAEP-SHA1 and AES, and was
   checked against Apple's SDK test vectors in stream-worker. It needs
   three Worker secrets, from Apple's FairPlay Streaming Deployment
   Package:
   - `FAIRPLAY_CERT`, the certificate. It is public, but kept with the
     others;
   - `FAIRPLAY_PRIVATE_KEY`;
   - `FAIRPLAY_ASK`, the Application Secret Key.

   Without all three, Protect is not offered and the license route answers
   503.
4. **The license is checked against who is asking.** The token names the
   rendition. The asset id inside the SPC must match it, so a token for one
   video cannot unlock another. Every license is audited (`drm.license`)
   with the viewer, the video and the link. Revoking a link or a grant
   stops the next license; one already playing ends with its session.

**Other browsers:** Chrome, Firefox, and Edge on Windows or Android show
"This video is protected. Open it in Safari on a Mac, iPhone or iPad."
They get no fallback. A Clear Key fallback would hand the key to the page,
which is exactly what protection exists to prevent.

**Widevine later:** the same `cbcs` copy plays in Widevine (Chrome,
Android) unchanged. That needs one more `pssh` box and a second license
route. Google does not give out a free Widevine license server:

- Widevine's own needs a licence agreement with Google, plus a service
  certificate;
- the hosted multi-DRM services (EZDRM, Axinom, PallyCon, BuyDRM) charge
  per license. Some have a small free tier.

The copy is laid out so either can be added without packaging anything
again.

## View-only links

An ordinary share link hands over a sealed copy, which is useless without
the secret after `#` and the password. A view-only link hands over nothing
to open, so the claim itself must prove both:

- **The page derives a claim proof** from the link's secret and the
  stretched password: HKDF, beside the link's other keys, in
  web/src/vault/share-crypto.ts and its twin web/public/gorani-share-lib.js.
- **The server keeps only the proof's SHA-256.** A claim without the
  right proof is refused and audited. The link's path alone, which does
  reach servers, starts nothing.
- **A claim is a viewing session** of 8 hours: one of the link's viewings
  spent, a token for the license, and a playlist URL signed by the Worker
  (HMAC under a key derived from `DRM_KEY_SECRET`). The URL names the
  session by its hash, so finding it in a log later unlocks nothing: the
  license still needs the token itself, sent in a header only the page's
  script sends.
- **The usual link rules hold:** a password always, at most 7 days, a
  count of viewings, and revoking ends the next license. A view-only link
  has nothing at `/data`.

## Before it can play anywhere: Apple

- **Apple must approve the deployment package.** FairPlay Streaming
  credentials come from developer.apple.com/streaming/fps. The Account
  Holder of a paid Apple Developer account requests them, and Apple
  reviews each request, which has taken weeks. The program is meant for
  services that stream content; a request for family videos and case
  evidence may be asked for more detail or refused. Nothing here works in
  production until Apple says yes.
- **Apple's test credentials do not play.** The SDK ships test
  credentials, but they only check a license server against Apple's
  sample requests. Real Safari will not accept them. Our tests make
  throwaway keys at run time, never committed, and check the license
  server end to end with fairplay.rs's own client side. The packaging is
  checked by decrypting each copy with ffmpeg and comparing every frame
  with the original's.
- **No FairPlay in CI.** No browser in our CI has FairPlay: Playwright's
  WebKit on Linux has none. So the first real play happens on your Mac or
  iPhone, after Apple approves. Everything up to that point is tested
  here.

## Storage and cost

- **Space.** A copy is about the size of the original: it is the same
  samples, re-boxed. Protecting a video roughly doubles its space, and the
  copy counts toward the area like any file.
- **Packaging speed.** It runs at about the speed the browser can read
  and decrypt the original, which for a phone video is seconds. Most of
  the time is the upload.
- **Server work.** The Worker does one RSA operation per license, a
  millisecond. Segments are range reads proxied from S3, like every other
  read.

## Decisions (asked before the code)

1. **Protect is a lead's explicit choice, per video.** Making a view-only
   link or a view-only grant for an unprotected video offers Protect first.
   Only the videos chosen pay the double space.
2. **HDCP Type 0 is required.** The CKC carries the HDCP-enforcement TLLV
   set to Type 0. A TV, projector or adapter without HDCP shows black, and
   so does an HDMI capture box. The viewer says so before playing, so a
   black screen on a projector is not a surprise.
3. **Apple's package is requested and pending.** The commits build and test
   everything short of a real play. The three secrets are added when Apple
   answers (docs/PRODUCTION.md › FairPlay).

## As built (commit 40)

| Piece | Where |
|---|---|
| `cbcs` packager: samples, `sinf`/`tenc`, `senc`/`saiz`/`saio` | crates/media/src/cbcs.rs |
| The slice headers (H.264, HEVC) and parameter sets | crates/media/src/nal.rs |
| The browser's door: `gm_protect`, `gm_protect_init`, `gm_protect_segment` | crates/media-wasm, web/src/lib/media-engine.ts › Protector |
| The license server (SPC → CKC), blinded RSA | crates/fairplay (gorani-fairplay) |
| Custody, copy routes, playlist, media, license, view-only sessions | worker/src/drm.rs |
| The rows (migration v21: `drm_files`, `drm_copies`, `shares.drm`, `shares.claim_hash`) | worker/src/drm_store.rs, member.rs |
| The original refused to everyone else | routes.rs › file_download, drm.rs › original_allowed |
| Packaging in the lead's browser | web/src/ui/files/model.ts › protectVideo |
| Playing: Safari + EME | web/src/ui/viewer/fairplay.ts, viewer.ts; web/public/s.js |
| View-only links | share-dialog.ts, share-crypto.ts › claim, files_store.rs › share_claim |
| Readiness at a glance | Team › Status › Protected videos |

Tests:

| Suite | What it checks |
|---|---|
| `unit:drm-pack` | Seven real H.264 and HEVC encodings (CAVLC, CABAC with B-pyramid and weighted prediction and four slices, interlaced, in-band parameter sets, WPP, Main 10, no WPP) packaged as the page packages them. With the key, ffmpeg decrypts every packet to the original's and decodes every frame to the original's. Without it, every packet differs. ffmpeg's `trace_headers` of the locked copy equals the original's, so every slice header stayed clear. VP9/Opus is refused with the reason. |
| `rust` | The pattern (one block in ten, IV restarting per subsample, short tails clear), the sample-entry rewrite, the bit reader (emulation prevention, a partly read byte), the KSM round trip with HDCP Type 0, wrong credentials named, malformed SPCs never panicking, the layout and playlist rules, the original rule |
| `api:drm` | Covers the whole server side with throwaway FairPlay credentials and a second, JavaScript implementation of the player: <ul><li>only a lead protects, and a lying layout is refused</li><li>the original goes to the lead, and the case plays the copy by playlist and byte range</li><li>a license opens to the very key the copy was packaged with</li><li>an SPC for another key gets nothing</li><li>every license is audited</li><li>a view-only link needs its proof, plays by signed URLs (a forged one does not), licenses with its token, downloads nothing, and stops when revoked</li><li>Remove protection gives the original back</li></ul> |
| `unit:share-lib` | The claim proof agrees between the app and the share page, and differs for another password or link |
| `e2e:app` | A lead protects a case's video in the viewer (her browser packages and uploads) and keeps the original; a view-only link's page, signed out in Chromium, unlocks with the password and says it plays in Safari; no CSP violations |

## Limits, known and chosen

- **No real Safari play yet.** That waits on Apple's package. Two details
  are for that first play to confirm:
  - audio's `tenc` pattern is written 0:0 (whole-block, as Bento4
    writes it). If Safari wants 1:0, it is a one-byte change and no copy
    needs encrypting again;
  - the SPC's asset id is accepted as `skd://<key id>` or the bare key id,
    whichever Safari sends.
- **Refused, with the reason said:**
  - codecs other than H.264/HEVC video and AAC/AC-3/E-AC-3 audio;
  - MV-HEVC (iPhone spatial video);
  - H.264 data partitioning, SVC, MVC and 3D;
  - HEVC multilayer, 3D and screen-content extensions;
  - more than 42 slices in one frame (the `saiz` byte's limit).
- **A new key needs every video protected again.** Replacing
  `DRM_KEY_SECRET` means a lead protects each video again; there is no
  re-seal walk yet.
- **The desktop sync gets the server's refusal** for a protected video
  it may not have the original of, said in those words. It does not play
  copies.
- **Re-verification and the export read originals.** Run by an analyst or
  an auditor, they report protected videos as refused. A lead's run reads
  them as before.
- **The poster** (a 320-px frame, 39o) stays visible to everyone who can
  list the video.
- **What was handed out stays out.** Existing ordinary links, earlier
  downloads and synced copies are not taken back. Revoke the links when
  protecting.
