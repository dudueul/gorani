# Previews: hostile files, opened safely

> Copyright 2026- Seongwoo Hong. All rights reserved.
> How the viewer shows formats that need a parser (commit 42a onward). The
> viewer's own modes (raster images, text, video, music) are in
> web/src/ui/viewer/mode.ts. Why malware samples are never shown at all is
> in CUSTODY.md, stage 5.

## The problem

A security team's files are the ones attackers make: a PDF that exploits
its reader, an Office document with a macro, a phishing email that reports
back when it is opened. Showing them needs parsers (pdf.js, Office
readers, MIME parsers), and a parser is exactly what a crafted file
attacks.

In this app a successful attack in the page would be the worst kind. The
page holds the unlocked vault: its keys, the session, the API, and every
other file.

So every format that needs a parser is opened somewhere else, in a frame
that has none of that.

## The preview frame

`web/public/preview.html`, shown by `web/src/ui/viewer/sandbox.ts`:

```
the app (gorani origin)                     the frame (opaque origin)
──────────────────────                      ─────────────────────────
decrypts the file
fetches /readers/pdf.js        ──open──▶    imports the reader from a blob:
transfers the bytes + a port                draws the file
                               ◀─asset──    "cmaps/UniKS-UCS2-H.bcmap"?
checks the name, fetches it    ──bytes─▶
                               ◀─shown──    facts: "contains JavaScript"
shows the facts, outside
                               ◀─key/step─  Escape, ←/→, a swipe
closes the frame               ✕            (gone, with the file)
```

**What the frame cannot do, and what stops it:**

| It cannot… | Because |
|---|---|
| read the app's cookies, storage, IndexedDB or keys | `sandbox="allow-scripts"` with no `allow-same-origin`: its origin is opaque (`null`) |
| reach into the app's page | cross-origin: `parent.document` throws |
| call the API, or reach the network at all | its CSP allows only `blob:` and `data:` for every kind of request: connect, image, font, media |
| carry the file out by navigating itself | the app's CSP has `frame-src 'self'`, which also governs where a frame may navigate; a frame that navigates anyway (to a page of this site) is closed |
| open windows, submit forms, download, or navigate the top page | none of those sandbox flags is given |
| run code it was not handed | its CSP allows the bootstrap by hash, the readers by `blob:`, and Trusted Types on top |
| keep anything between files | every file gets a new frame, thrown away when the viewer closes |

**What it holds:** the one file it was asked to show, decrypted. A file
that exploits a reader therefore holds, at most, itself, in a frame that
cannot tell anyone.

**It fetches nothing.** In production the site sits behind Cloudflare
Access, and an opaque-origin frame's own requests would carry no cookie.
So the frame is designed to need none:

1. The app fetches the reader's code (`/readers/<id>.js`, its worker) and
   hands it over as text.
2. The frame's one inline script, pinned by hash in its CSP, imports the
   code from a `blob:` URL.
3. The few files a reader needs at run time are asked of the app by name.
   For pdf.js these are CMaps for CJK text, standard fonts and image
   decoders. The app answers only names on that reader's list (`ASSETS`
   in sandbox.ts).

**Its headers** (`web/public/_headers`, `/preview.html`) replace the app's
rather than adding to it, using the `! Header` lines. Two policies would
both be enforced, and the app's forbids `blob:` scripts.

**Facts** about the file, such as "contains JavaScript — not run" or
"links to …", are sent by the reader and shown by the viewer above the
frame, as text. A file can draw anything inside the frame, but it cannot
draw over these.

## The readers

Each reader is one self-contained bundle, built by
`scripts/build-readers.mjs` from `web/src/preview/readers/<id>.ts` into
`web/public/readers/` (a build output, git-ignored). `web/src/preview/host.ts`
is the reader's side of the port.

### PDF (pdf.js, `readers/pdf.ts`)

- **Pages:** drawn as they come into view, sharp on high-density screens,
  with a text layer for selecting and finding text.
- **Toolbar:** a page list, previous and next page, zoom (fit to width, up
  to 150 %), and Find (Enter for the next page with a match, Shift+Enter
  for the one before, Ctrl/⌘+F to jump there).
- **Passwords:** a password-protected PDF asks for its password in the frame.
- **Facts:**
  - page count and PDF version;
  - title, author, creator, producer, made and changed dates;
  - **JavaScript or automatic actions** (never run);
  - **embedded files** (named, never opened);
  - **links** (listed, never followed);
  - form fields.
- **Not done:** no PDF scripting (pdf.js's separate scripting sandbox is
  never loaded); no annotation layer, so links are not clickable; no XFA
  forms; images over 50 megapixels are not decoded.
- **The legacy build.** pdf.js 6's modern build calls built-ins too new for
  many browsers in use (`Map.prototype.getOrInsertComputed`); the legacy
  build polyfills them.
- **A classic worker.** The worker is re-bundled as a classic script,
  because an opaque-origin frame cannot start a module worker from a
  `blob:` URL.

## Tests

- **`unit:preview-frame`:**
  - the bootstrap's hash is the one pinned in the frame's CSP;
  - the frame's policy replaces the app's and allows nothing off the
    computer;
  - the app keeps `frame-src 'self'`;
  - the sandbox flags are `allow-scripts` only;
  - asset names cannot climb out of a reader's folder.
- **`unit:viewer-modes`:** PDFs route to the frame by kind, mime or name,
  are capped like any whole read, and samples are refused first.
- **`e2e:preview`** (Chromium):
  - the frame's headers;
  - a PDF's pages, text, Korean through a CMap, Find, and facts;
  - a hostile PDF: no dialog, no request, its link and attachment named;
  - an attack from inside the frame: no cookie, storage, parent, API,
    network, popup or top navigation, and a beacon stopped by the CSP. A
    navigation away is refused and the frame is closed;
  - the frame's only request is its own page;
  - on a phone the PDF fits the screen, and a swipe inside the frame opens
    the next file.
- **Fixtures** are made by `tests/fixtures/preview/make.py` (reportlab,
  pypdf), the same bytes on every run.
