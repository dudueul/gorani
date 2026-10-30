# Previews: hostile files, opened safely

> Copyright 2026- Seongwoo Hong. All rights reserved.
> How the viewer shows formats that need a parser (commit 42a onward: PDF;
> 42b: Word, Excel, PowerPoint, 한글 and the older Office formats; 42c:
> email, .eml and Outlook's .msg; 42d: every picture; 42e: archives; 42f:
> Markdown, JSON, XML, web pages and code; 42g: programs and any file as
> bytes — the one view a malware sample may have; 42h: Office macros'
> source; 42i: shortcuts and Prefetch files). The
> viewer's own modes (raster images, text, video, music) are in
> web/src/ui/viewer/mode.ts. Why malware samples are never shown at all is
> in CUSTODY.md, stage 5.

## The problem

A security team's files are the ones attackers make: a PDF that exploits
its reader, an Office document with a macro, a phishing email that reports
back when it is opened. Showing them needs parsers (pdf.js, Office
readers, MIME parsers), and a parser is exactly what a crafted file
attacks. So is a picture: the browser's own image decoders are parsers
too, and CVE-2023-4863 (a heap overflow in libwebp) was exploited in the
wild through ordinary `<img>` tags.

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
| run code it was not handed | its CSP allows the bootstrap by hash, the readers by `blob:`, and Trusted Types on top (below) |
| turn a file's text into markup | the frame's default Trusted Types policy sends every HTML string through DOMPurify (below) |
| follow a link in a file | a click on a link does nothing (`host.ts`); links are listed among the facts |
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

## Inside the frame

### The default Trusted Types policy (42b)

The frame's CSP requires Trusted Types, and names three policies; no other
can be made (`unit:preview-frame`):

| policy | what it allows |
|---|---|
| `gorani-preview` | blob: URLs as script URLs — the reader's worker — and nothing else |
| `dompurify` | DOMPurify's own, for what it hands back |
| `default` | what the browser calls when code writes a plain **string** into an HTML sink |

The default policy is there for the libraries. pptx-preview sets each run
of slide text with `innerHTML`. Without the policy, a slide whose text is
`<img src=x onerror=…>` would be markup; with it, every such string goes
through DOMPurify first: no handlers, no `<style>`, no forms, no frames.
One sink is let through untouched: `DOMParser`. docx-preview reads the
file's XML with it, a parsed document is inert (nothing in it loads or
runs), and DOMPurify would strip XML it does not know. Strings as code
(`eval`, `setTimeout("…")`, `javascript:` URLs) are refused outright.

`e2e:preview` attacks this from inside a Word frame, as page script: the
handler and the `<style>` are gone, the picture the cleaned HTML kept is
stopped by the CSP, and eval, string timers, `new Function` and a new
policy are all refused.

### ZIP bombs (42b)

Word, Excel, PowerPoint, HWPX and OpenDocument files are ZIP archives. A
ZIP says in its directory how big each part is once inflated, and nothing
makes it tell the truth: 42 kB can inflate to petabytes. The rendering
libraries would hold the inflated parts in memory and take the tab down.

So before any library sees a ZIP, `preview/zip.ts` inflates every part as
a stream (16 kB in at a time, each piece counted and dropped) and refuses
the file if:

- the directory's own claims add up past 1 GiB;
- a part grows past what the directory said;
- a part uses a compression this reader does not have.

### Names that lie (42b)

Disguise is the point of a lure. An "invoice.doc" is often RTF (the
Equation Editor exploits) or a web archive. A ".docx" may be a Word 97
file carrying macros. So the name picks a reader, and the file's first
bytes correct it, within the family the name promised
(`mode.ts › sniffReader`). The reader then says so: "Named .doc, but it is
an RTF document — a disguise lures use: Word opens it all the same".

### Facts are pure code (42b)

What each reader says about a file is computed by code with no DOM and no
renderer: `preview/facts/` (Word, PowerPoint, 한글), `preview/legacy/` (the
older formats), `sheet.worker.ts › analyse`, `office.ts`, `ole.ts`.
`unit:preview-facts` runs all of it on the fixtures in Node, so every
planted trick is checked in milliseconds. The readers only draw.

## The readers

Each reader is one self-contained bundle, built by
`scripts/build-readers.mjs` from `web/src/preview/readers/<id>.ts` into
`web/public/readers/` (a build output, git-ignored). `web/src/preview/host.ts`
is the reader's side of the port; `kit.ts` holds the zoom buttons and Find
for readers that draw HTML.

| reader | formats | library |
|---|---|---|
| `pdf` | PDF | pdf.js, its worker |
| `docx` | .docx .docm .dotx .dotm | docx-preview |
| `sheet` | .xlsx .xlsm .xlsb .xls .ods .csv .tsv | SheetJS, in a worker |
| `pptx` | .pptx .pptm .ppsx .potx | pptx-preview (with ECharts for charts) |
| `hwp` | .hwp (HWP 5 and 3) .hwpx | rhwp, as WebAssembly (12 MB, asked of the app) |
| `legacy` | .doc .ppt .rtf .odt .odp, and web pages or MHT archives named .doc | our own parsers (`preview/legacy/`) |
| `email` | .eml (and message/rfc822), .msg | postal-mime; msgreader for .msg; DOMPurify |
| `image` | every picture: JPEG, PNG, GIF, WebP, AVIF, BMP, ICO, SVG; TIFF; HEIF (.heic); camera RAW (DNG, CR2, CR3, NEF, ARW, ORF, RW2, RAF, PEF…) | the browser's decoders (in the frame); UTIF and libheif in a worker; exifr; our own structure and RAW readers (`preview/image/`) |
| `archive` | ZIP (and JAR, APK, IPA…), ALZ, EGG; 7z, RAR, TAR and its compressions, gzip, bzip2, xz, zstd, CAB, ISO, UDF, WIM, DMG, VHD(X), ARJ, LZH, CPIO, RPM, DEB, XAR, MSI, CHM, squashfs… | our own ZIP, ALZ and EGG readers (`preview/archive/`); 7-Zip 24.09 as WebAssembly, in a worker |
| `hex` | any file as bytes; programs (PE: .exe .dll .sys…; ELF; Mach-O, universal too) taken apart; the only reader a malware sample reaches | our own parsers (`preview/binary/`); @noble/hashes for SHA-256, SHA-1, MD5 and the imphash |
| `text` | Markdown; JSON, JSON Lines, notebooks; XML (plists, project files, .wsf, .sct); web pages (.html, .hta); code and scripts (PowerShell, batch, VBScript, JScript, shell, Python, JavaScript, PHP, C-family, Go, Rust, SQL, YAML, INI, .reg, .env, YARA, …) | marked (Markdown), highlight.js (core, about 40 languages), DOMPurify; our own trees, limits and triage (`preview/text/`) |

### PDF (pdf.js, `readers/pdf.ts`)

- **Pages:** drawn as they come into view, sharp on high-density screens,
  with a text layer for selecting and finding text.
- **Toolbar:** a page list, previous and next page, zoom (fit to width, up
  to 150 %), and Find (Enter for the next page with a match, Shift+Enter
  for the one before, Ctrl/⌘+F to jump there).
- **Passwords:** a password-protected PDF asks for its password in the
  frame. (Not with a `<form>`: in a frame sandboxed without `allow-forms`,
  the browser stops a form's submission before its submit event fires.
  Enter and the Open button do it instead — found when 42b first tested
  the prompt.)
- **Facts:**
  - page count, PDF version, whether it is encrypted;
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

### Word (docx-preview, `readers/docx.ts`)

- **Pages:** docx-preview turns the XML into HTML elements, built one by
  one; pages split at the document's page breaks. Zoom fits the width, up
  to 125 %. Find marks matches with the CSS Custom Highlight API, so the
  document's own DOM is never changed.
- **Options chosen for a hostile file:** an altChunk (raw HTML or MHT
  carried inside) is not rendered; fonts embedded in the file are not
  loaded (a font is a program the font engine runs); tracked changes show
  accepted; pictures become blob: URLs.
- **Facts:**
  - pages (as Word last counted), title, author, last saved by, dates,
    the program, company, template;
  - **macros** (vbaProject.bin, even under a .docx name);
  - **a template fetched on opening** (attachedTemplate, External — the
    "template injection" trick);
  - **pictures or objects fetched from outside**, and a `\\server` path,
    which makes Windows offer the reader's sign-in hash;
  - **fields that run or fetch**: DDE and DDEAUTO (the command quoted),
    INCLUDEPICTURE, INCLUDETEXT, LINK, MACROBUTTON;
  - embedded objects, ActiveX controls, an altChunk;
  - **hidden text** (quoted), **tracked changes** (the deleted text
    quoted — a swapped bank account shows here), comments;
  - links; embedded fonts; a digital signature (not checked).

### Excel (SheetJS, `readers/sheet.ts`, `sheet.worker.ts`)

- **Why a worker:** a workbook is the one format whose parse can take
  seconds, and some browsers keep a sandboxed frame in the page's own
  process (Limits, below). The workbook stays in the worker; the frame
  asks for the rows it is about to show, 200 at a time, and for search
  hits.
- **The grid:** column letters and row numbers held in place, merged cells
  across, hidden rows and columns drawn striped, a formula bar (the cell's
  formula as text), sheet tabs along the bottom, Find across every sheet.
  Values are the ones the file saved: **formulas are never recalculated**,
  so nothing in one can run. A formula saved without its value shows the
  formula, dimmed.
- **Hidden sheets are shown**, marked: a very hidden sheet is where a lure
  keeps what the reader should not see, and only a macro or a file editor
  can unhide one in Excel.
- **CSV:** by its byte-order mark, else UTF-8 if it is valid UTF-8, else
  CP949 (what Korean Excel saves). Cells are kept as text — "1-2" is not a
  date, "=…" is not a formula.
- **Facts:**
  - sheets, the text's code page, who and when;
  - **macros**, **Excel 4.0 (XLM) macro sheets** (their formulas quoted:
    `=EXEC("calc.exe")`), **Auto_Open/Auto_Close** names;
  - **hidden and very hidden sheets**;
  - **DDE formulas** (`=cmd|' /C calc'!A0`) and formulas that fetch or
    run (WEBSERVICE, FILTERXML, CALL, REGISTER, EXEC, RTD, IMAGE,
    IMPORT…);
  - **data connections** (web queries, Power Query) and **outside
    workbooks**;
  - **CSV injection**: cells that start with =, +, − or @;
  - links; how many formulas, and how many read other workbooks;
  - a sheet longer than 200,000 rows: only the first are read.

### PowerPoint (pptx-preview, `readers/pptx.ts`)

- **Slides:** drawn 960 px wide, then zoomed to the window; previous and
  next slide; Find. Speaker notes as a card under their slide; hidden
  slides striped and labelled.
- **Slide text is HTML to this library:** it writes each run with
  `innerHTML`. In this frame that string meets the default Trusted Types
  policy and DOMPurify (above). (A slide's literal "<b>" may show bold for
  the same reason: a cosmetic cost, paid inside the frame.)
- **Pictures linked from outside are taken out first.** An `<a:blip>`
  with `r:link` and nothing embedded is the beacon trick. pptx-preview
  fails the whole deck on one, and none could be shown here anyway, so
  they are removed before the library sees the deck. If the library still
  draws nothing, each slide's text is shown instead, and a fact says so.
- **Facts:**
  - slides, who and when;
  - **"Run program" actions** (`ppaction://program` — the program named),
    macro and object actions, **actions on a mere mouse-over**;
  - **hidden slides**; speaker notes; comments;
  - macros, embedded objects, pictures and media from outside, links.

### 한글 (rhwp, `readers/hwp.ts`)

HWP is the format Korean public offices and companies exchange, and so
the one attackers in Korea send. rhwp (Rust, MIT) parses and lays out
HWP 5, HWP 3 and HWPX, and paints pages on a canvas.

- **Pages:** drawn as they come into view, at the screen's density; a text
  layer of transparent runs laid exactly over each canvas (from rhwp's
  own layout), so text can be selected and found; Find by page.
- **Passwords:** an encrypted file asks for its password (HWP 5 and HWPX).
- **The WebAssembly** (12 MB) is an asset: the frame asks the app, which
  fetches it once per page load. rhwp asks the page how wide a run of
  text is in a font; a 2D canvas answers.
- **Facts**, read from the structure (`facts/hwp.ts`):
  - pages, HWP version, who and when (`\x05HwpSummaryInformation`, or
    HWPX's `content.hpf`);
  - **a script that runs on opening** (`Scripts/DefaultJScript`): every
    한글 file has one, nearly always empty — only one with code in it is
    a warning, and the code is quoted;
  - **PostScript** in BinData (`.eps`) — how most 한글 malware got in, a
    Ghostscript exploit; never drawn;
  - OLE objects, program files in BinData;
  - links (HWP 5 keeps a hyperlink's address with its colon escaped,
    `https\://…`); pictures linked from outside;
  - a distribution document (배포용), DRM, a signature;
  - **the path from the computer that saved it** (`DocOptions/_LinkDoc`),
    often with a Windows user name in it.

### The older formats (`readers/legacy.ts`, `preview/legacy/`)

No library draws these faithfully in a browser any more, and they are the
formats old exploits ride in. This reader shows their **text** — every
piece of it, hidden text and deleted revisions included, which the bar
says — and their **facts**, read by small parsers of our own:

| format | how its text is read | what its facts look at |
|---|---|---|
| Word 97–2003 (.doc) | the FIB → the piece table → 8-bit or UTF-16 pieces; fields' codes kept, results shown | Macros/VBA; ObjectPool (each object's class from its CompObj); `\x01Ole10Native` (the packaged file's name and path); Equation Native; SummaryInformation (a template that is an address); field codes |
| PowerPoint 97–2003 (.ppt) | the record tree: text atoms in each slide and in the slides' outline; notes (the notes master skipped) | InteractiveInfo actions (run a program, a macro); ExHyperlink addresses; VBAInfo (`fHasMacros`, not merely the record, which LibreOffice always writes); embedded and linked objects; hidden slides |
| RTF | a tokenizer: groups, control words, `\'hh` bytes in the document's code page, `\uN`; destinations without text skipped | `\object` with its `\objclass` and `\objupdate` (updates itself on opening); `\*\template`; `\fldinst` codes; unclosed groups and absurd nesting (scanner evasion) |
| OpenDocument text and slides | `content.xml` parsed as inert XML, text:p and text:h | Basic/ and Scripts/ macros; macros bound to events; embedded objects; outside pictures; links; a password (manifest) |
| a web page or MHT named .doc | parsed as inert HTML, its text read out, the parsed page thrown away | scripts, what it would load from outside, links |

Every parser stops at a size or depth no document reaches: four million
characters of text, 64 nested record containers, 5000 nested RTF groups.

### Email (`readers/email.ts`, `mail/parse.ts`, `facts/mail.ts`) (42c)

A security team's commonest hostile file is an email someone reported. It
arrives as an `.eml` (the message as it travelled, MIME) or as Outlook's
`.msg` (an OLE container of MAPI properties). `mail/parse.ts` reads both
into one shape: postal-mime for MIME, msgreader for .msg, whose headers as
received are a single property (PR_TRANSPORT_MESSAGE_HEADERS). msgreader
was written for Node and asks for iconv-lite; the bundle gets a small shim
in its place (`preview/shims/iconv-lite.ts`) that decodes with the
browser's own `TextDecoder`.

The message is shown in four tabs:

| tab | what it shows |
|---|---|
| Message | the HTML body, cleaned (below), in a shadow root |
| Text | the text body, or the HTML's text when there is none |
| Headers | the Received chain as a table, oldest hop first, then every header as written |
| Source | the raw message, up to 2 MB (.eml only; a .msg has no source) |

Above them: the subject, From, Reply-To, To, Cc, the Date line exactly as
it is written (evidence, not a parsed date), and every attachment with its
type, size and SHA-256 (to look up), and Open and Save buttons.

**The HTML is cleaned in an inert parse first.** The body is parsed with
`DOMParser`, so nothing in it loads or runs. In that parsed copy:

1. what it would do is collected for the facts: links, forms, scripts and
   event handlers, frames, a meta refresh;
2. every picture from outside becomes a grey placeholder ("picture from
   outside, not loaded"); every outside `url()` and `@import` in its CSS is
   removed. A tracker therefore never learns the message was opened, and
   would not even if the frame's CSP failed;
3. `cid:` pictures are drawn from the message's own parts, as `blob:` URLs.

Only then does DOMPurify turn it into nodes, removing scripts, forms and
inputs, frames, objects, `<base>`, `<link>`, `<meta>` and media, and the
attributes that fetch (`srcset`, `ping`, `background`, `poster`). Only
`http(s):`, `mailto:`, `tel:`, `blob:` and pictures as `data:` survive as
URLs. The result goes into a **shadow root**, so the message's CSS styles
only itself and cannot draw over the reader. Each link's title is replaced
by where it really goes (the sender's own title is the sender's words); a
bar at the bottom shows it on hover; a click goes nowhere.

**The facts** (`facts/mail.ts`, pure), the questions a phishing triage
starts with:

- **Did the receiving server believe it?** SPF, DKIM and DMARC from the
  **topmost** Authentication-Results only. That one is added by the last
  server, the receiving organisation's own; anything below it was already
  in the message when it arrived, and a sender can write it. The fixture
  carries a forged "all pass" below the real "fail", and the reader says
  fail.
- **Where did it come from?** The Received chain, oldest first. The hop
  that counts is the one written by the server named in that
  Authentication-Results (its authserv-id): its "from" is the computer
  that connected, which the sender could not choose. The hops before it
  are the sender's own claims, and the fact says how many there are. A
  Date far from the first hop is named.
- **Is it who it says?** A display name that is another address
  (`"service@paypal.com" <…@secure-login.example>`); a domain dressed as
  another (`paypal.com.secure-login.example`); punycode; a Reply-To or an
  envelope sender (Return-Path) at another organisation.
- **Where do its links go?** Text that reads one address over a link to
  another; punycode, IP and `user@host` links; shorteners; Windows
  protocol handlers (`search-ms:`, `ms-msdt:`, `ms-officecmd:` …) and file
  shares (`\\host\share`), the routes of several exploits; `javascript:`
  and `data:` links.
- **What would it load?** Pictures and CSS from outside (trackers), forms,
  and forms asking for a password, scripts and handlers, frames, a refresh
  to another page.
- **What does it carry?** Each attachment judged by its name **and** its
  bytes (`partRisk`): a double extension (`invoice.pdf.exe`), a
  right-to-left mark hiding the real one, a kind that runs (programs,
  scripts, shortcuts, disk images, OneNote, macro-enabled Office), a
  "PDF" whose first bytes are a Windows program, an encrypted ZIP (no
  scanner could look inside), and HTML that builds a file in the browser
  (HTML smuggling). Also: S/MIME or PGP signatures, a calendar invitation,
  a forwarded message.

There can be many facts in a lure, so the viewer shows 40 at most:
the summary line first, then the warnings, then the rest, in a panel that
scrolls.

**Attachments: the frame asks, the app decides.** The frame cannot open a
file or write to the vault, and it should not be able to. Open and Save
send the attachment's bytes to the app (`host.handOver`). `sandbox.ts`
accepts only a known action, bytes under the whole-read cap, at most one
request every half second, and cleans the name: no path, no control or
bidirectional characters, at most 200 characters.

- **Open** shows the attachment in a **new** frame with its own reader, as
  any file is shown: a forwarded `.eml` in an email reader, a `.docx` in
  Word's, a picture as a picture. They stack: the header reads
  "phish.eml › statement.docx", and Back, or Escape, returns. A
  program is not shown; it can be saved.
- **Save** asks first, in the app, outside any frame. The app judges the
  bytes itself with the same `partRisk` (the reader in the frame is only
  believed about what the app can see too), and offers a risky attachment
  as a **malware sample** by default: uploaded beside the message,
  flagged, never previewed, downloaded only inside an "infected" zip
  (CUSTODY.md, stage 5). It is signed and recorded like any upload.

### Pictures (`readers/image.ts`, `preview/image/`, `facts/image.ts`) (42d)

Every picture the vault shows is drawn in the frame, never in the app's
page: the viewer, the explorer's Quick Look and details pane, and the Movie
tab's posters (a poster is a picture whoever can write the area made). The
small ones use the frame's **compact** mode (`ui/viewer/picture.ts`): the
picture alone, fitted, in a frame that takes no clicks and no keyboard.

| format | drawn by |
|---|---|
| JPEG, PNG (APNG), GIF, WebP, AVIF, BMP, ICO | the browser, as an `<img>` of a `blob:` URL, inside the frame |
| SVG (and .svgz, inflated as a stream to at most 32 MB) | the browser, as an `<img>` too: an SVG drawn as a picture runs no script and loads nothing. Its source in a tab, as text |
| TIFF | UTIF, in the reader's worker: every page (up to 20), turned by its Orientation |
| HEIF (.heic, .heif) | libheif as WebAssembly, in the worker. Its two files (1.5 MB) are asked of the app only when a HEIF is opened, and kept as files of their own (LGPL-3.0, NOTICE) |
| camera RAW | the camera's own JPEG preview, found by our own reader (`image/raw.ts`): JPEGs in a TIFF's directories and SubIFDs (DNG, CR2, NEF, ARW, ORF, RW2, PEF), CR3's PRVW and THMB boxes, the JPEG RAF's header points at; else a scan for JPEGs. The largest is shown. The sensor data is not decoded |
| JPEG XL, Photoshop, JPEG 2000 | nothing (no decoder here); the metadata is still read |

**Before anything decodes a picture**, `image/structure.ts` walks its
structure: JPEG segments, PNG chunks, GIF blocks, WebP's RIFF, the ISO
boxes of HEIF/AVIF/CR3, TIFF directories (`image/tiff.ts`: every offset
checked, a directory read once, at most 64). From these it learns:

- the size the file **declares**. Above 220 megapixels nothing is drawn;
  above 100 for what our decoders draw (4 bytes a pixel). A 69-byte PNG
  that declares 60000×60000 is named as a decompression bomb;
- where the picture **ends**, so what comes after it can be named;
- its comments, text chunks, and the blocks that carry metadata.

**The metadata** is read by exifr in the worker: EXIF, GPS, XMP, IPTC, ICC,
PNG's header and text. It is shown in an **Info panel** in the frame
(beside the picture; a sheet over it on a phone): the picture, when it was
taken (as written, with its time zone), the camera and lens, the location,
the editing history, people and rights, what is hidden in the file, and
every tag under "All metadata".

**The facts** (`facts/image.ts`, pure):

- **Where and when.** GPS to the metre ("Carries where it was taken:
  37.56630° N, 126.97790° E · 38 m up · facing 128° · ±5 m"). The viewer
  offers to **copy** the coordinates. The frame has no clipboard, so the
  app does it, and only for words the fact shows (`sandbox.ts ›
  cleanFact`). Nothing is sent anywhere: no map is drawn, no service asked.
  Also the time taken, the camera's serial number, its owner, the artist
  and copyright.
- **What was done to it.** The editor and its XMP history; modified long
  after it was taken. Also an embedded **thumbnail that no longer
  matches**. A camera writes a 160×120 copy of the photo into its EXIF,
  and many editors leave it as it was. The worker draws both at 32×32 in
  grey, in all eight orientations (a phone stores both on their side),
  trims the black bars a camera pads a thumbnail with, and compares:
  - another shape means the picture was **cropped**, and the thumbnail may
    show what was cut away;
  - another picture means something was **painted over or removed**, and
    the thumbnail may still show it.

  The thumbnail is in the Info panel, to look at.
- **Where it came from.** An AI model's mark (IPTC DigitalSourceType:
  trainedAlgorithmicMedia); an image generator's settings in a PNG
  (Stable Diffusion's "parameters", ComfyUI's "prompt"); Content
  Credentials (C2PA), present but not verified.
- **What it hides.** Data after the picture's end: a ZIP (a polyglot), a
  program, text that is code, or a JPEG nothing declares. Things expected
  there are named as harmless: a motion photo's video, the extra pictures
  Multi-Picture Format declares, Samsung's trailer. Code in a comment or a
  text chunk (a web shell: `<?php system(…)`). A name that is not what the
  bytes are: a JPEG named .png is information; an SVG named .png is a
  warning (SVG can carry script); a web page named .png is not drawn at
  all.
- **What an SVG would do,** from an inert parse: scripts and event
  handlers, HTML inside (foreignObject, a password form), what it would
  load from outside, its links, `javascript:` links. None of it is run or
  loaded. An SVG that declares XML entities (the "billion laughs" shape)
  is not parsed or drawn; its source is shown.
- **Animation** (GIF, APNG, WebP frames), TIFF pages, HEIF pictures.

**Zoom, pan and pinch** (`image/stage.ts`, Pointer Events, so mouse, pen
and fingers alike):

- the wheel zooms around the pointer (a trackpad's pinch arrives as a
  wheel with Ctrl);
- a drag pans; two fingers pinch;
- a double click or tap fits, or goes to 100 %;
- keys: `+` `−` `0` (fit) `1` (actual pixels) `R` (turn) `I` (Info).

The picture is sized rather than scaled, so an SVG stays sharp. Past 300 %
pixels are drawn as squares. Zoomed in, a swipe pans the picture instead of
opening the next file (`host.setSwipeGuard`).

### Archives (`readers/archive.ts`, `preview/archive/`, `facts/archive.ts`) (42e)

An archive is listed in the frame; nothing in it is unpacked to a disk or
run. Its worker (`readers/archive.worker.ts`) reads it with one of:

| engine | formats | why |
|---|---|---|
| our ZIP reader (`archive/zip.ts`) | ZIP and its kin (JAR, APK, IPA, XPI…) | the details decide what a tool shows, and 7-Zip's WebAssembly build turns a Korean (CP949) name into question marks |
| our ALZ reader (`archive/alz.ts`) | ALZ, ALZip's own (common in Korea) | no library reads it |
| our EGG reader (`archive/egg.ts`) | EGG, ALZip's newer format | no library reads it; written from ESTsoft's published specification |
| 7-Zip 24.09 (`archive/run7z.ts`) | 7z, RAR 4/5, TAR, gzip, bzip2, xz, zstd, LZMA, LZ4, CAB, ISO, UDF, WIM, DMG, VHD/VHDX/VMDK, ARJ, LZH, CPIO, RPM, ar/DEB, XAR, MSI, CHM, NSIS, squashfs, cramfs, … | the widest reader there is. Its two files (1.7 MB) are asked of the app only when an archive needs them, and kept as files of their own (NOTICE) |

7-Zip is driven as its command line is: `l -slt` for a technical listing
(`archive/sevenzip.ts` reads it), and `x -so -spd` for one entry. The
entry is written to stdout and counted as it comes; at its cap the run is
stopped. A password is always given, so 7-Zip never waits for one. A
compressed stream holding one TAR (`.tar.gz`, `.tgz`, `.tar.xz`…) is
listed as that TAR.

**What the reader shows:** the folders and files, a breadcrumb, and a
filter over every path. Each name is shown as written: `..` stays `..`, a
leading `/` is a folder of its own, and a right-to-left mark is shown as
`[RLO]` rather than obeyed (in the app's facts too, for every reader:
`sandbox.ts › cleanFact`).

**An entry** opens the way an email's attachment does (42c). **Open**
hands it to the app, which shows it in a new frame with its own reader,
stacked: "lure.zip › nested.zip › inner.txt", with Back. **Save** hands it
to the app, which asks before it writes.

**Sizes.** Every entry is capped at the viewer's whole-read limit and at
what it claims, plus a little:

- deflate is inflated as a stream and stopped past the cap;
- 7-Zip is stopped mid-run past the cap;
- every CRC is checked.

An entry that inflates past its claim (a liar) is refused, never held.

**Passwords.** ZipCrypto and WinZip AES (`archive/crypto.ts`, with
@noble's AES and SHA-1) for ZIP, ALZ and EGG; 7-Zip's own for the rest
(7z AES with encrypted names included). The reader asks for a password
when entries, or their names, are encrypted, and refuses a wrong one.
**"infected"**, the password malware samples are swapped with, is one
click away. Everything it opens is a **malware sample**:

- the frame offers only Save as sample;
- the hand-over says so, and the app refuses to open it and saves it only
  as a sample, the box ticked and locked (`viewer.ts › openInner,
  confirmSave`).

A reader can make a file more restricted this way, never less.

**The facts** (`facts/archive.ts`, pure):

- **Can anyone see in?** Entries encrypted, so no scanner looked inside;
  names encrypted; the password "infected".
- **Where would it write?** A path that climbs out of the folder it is
  unpacked into (`../../`, "Zip Slip"); an absolute path; a symbolic link
  and where it points (its body is its target, read for this).
- **What is inside?** Programs, scripts, shortcuts, and names that
  pretend (`invoice.pdf.exe`, a right-to-left mark), judged by the email
  reader's own rules; archives inside the archive; a disk image, whose
  files lose Windows' internet mark (a way past SmartScreen).
- **Is it honest?**
  - the same path twice, or twice but for case;
  - a ZIP entry whose local header names it differently from the
    directory (two tools would show two different files);
  - data after the end, or bytes in front of it;
  - a ZIP bomb's ratio, or a total past 4 GB;
  - a name that is not the format (a RAR named .zip).
- What the reader could not do: AZO and LEA entries, names that could not
  be decoded, a split archive's other parts.

### Text (`readers/text.ts`, `preview/text/`, `facts/text.ts`) (42f)

Plain text and logs are not here: they stay in the app's page, escaped
(no parser reads them, so there is nothing to attack). What comes here is
text a program would parse, render or run.

| kind | shown as | the parser's limit |
|---|---|---|
| Markdown | rendered by marked, cleaned (below), in a shadow root; its source in a tab | — |
| JSON | a tree built as it is opened, 500 items at a time; each value's path on a click (`$.sites[1].name`) | its nesting is counted first: past 512 levels it is not parsed (a stack exhausted is the attack) |
| JSON Lines | a record a line, up to 100,000 | each line as JSON |
| XML | a tree from an inert parse, its path on a click (`/settings/site[2]`) | not parsed at all when it declares entities or points outside (below) |
| web pages | their source, never the page | an inert parse, for the facts |
| code | highlighted, with line numbers; Wrap hides them (they would lie) | highlighted up to 1 MB, plain beyond |

Every kind has its Source tab and Find. The first 8 MB are shown. A bigger
JSON is shown as source, not parsed, and the facts say why.

**Markdown is cleaned as an email is (42c).** marked turns it into HTML,
raw HTML included. That HTML is first parsed inert, for the facts: its
scripts, forms, frames and outside pictures are counted. Every picture
that is not a picture inside the file itself becomes a placeholder; a
relative one too, since the frame could not fetch it anyway. DOMPurify
then removes every script, style, form, frame and media element. What
remains goes into a shadow root, so its CSS cannot reach the bar. A link
shows where it goes on hover, and a click goes nowhere (host.ts).

**XML that reaches out is never parsed.** A DOCTYPE that declares
entities is the "billion laughs" (entities that nest, a few kilobytes
that expand to gigabytes). One that names an outside DTD or entity is
XXE, the classic way an XML parser is made to read a file or call out.
The browser's parser does neither of the dangerous things, but a tree
built from such a file would show what the browser chose. So the file is
shown as source, and the facts name the entity and the address.

**A binary file with a text name** (a binary plist, a database named
.json) holds NUL bytes, which text never does. It is shown as characters,
never parsed, and the facts say it is binary. A *program* with a text
name (`invoice.js` that starts with MZ) goes to the hex reader (42g).

**Encoding.** A BOM decides; otherwise UTF-8 if the bytes are UTF-8, then
Korean (CP949, as Korean Windows writes it), then Western (Windows-1252).
The facts name the encoding used.

**The facts** (`facts/text.ts`, pure). These are what an analyst looks for
first in a leaked file or a lure's script:

- **Secrets** (`text/secrets.ts`): private keys; AWS, GitHub, GitLab,
  Slack, Google, Stripe, OpenAI and Anthropic keys; JSON Web Tokens; Azure
  storage keys; passwords in connection strings, settings and URLs. Each
  is named by kind and line and **masked** (its first and last four
  characters), so the facts never spread a key further. Placeholders
  (`changeme`, `${VAR}`, `<your key>`) are skipped.
- **What a script would do** (`text/script.ts`), one finding a line, in
  line order:
  - downloading and running code (PowerShell, `curl … | sh`, certutil,
    bitsadmin, mshta, regsvr32, rundll32, WMIC);
  - hidden code: PowerShell hidden and unrestricted, base64 decoded and
    run, assemblies loaded from memory, Windows APIs from PowerShell;
  - VBScript and JScript writing files, running commands, fetching;
    JavaScript building code to eval; Node.js and Python running commands;
  - staying: Run keys, scheduled tasks, services, crontab,
    authorized_keys, new users;
  - damage and cover: shadow copies deleted, recovery disabled, logs
    cleared, Defender off, AMSI bypassed;
  - shells: a reverse shell, a web shell.

  A PowerShell `-EncodedCommand` is **decoded** (base64 of UTF-16LE) and
  quoted, and the addresses it hid are listed with the rest. Windows
  Script Encoder (`#@~^`), obfuscators' names and strings built a
  character at a time are named. So are long base64 runs, every URL, and
  every public IP address.
- **Pages** (Markdown, HTML): the scripts, forms and frames they hold
  (none drawn), and what they would load from outside (nothing loaded).
- **XML**: entities, an outside DTD or entity, XInclude, code inside an
  XSLT stylesheet (`msxsl:script`).
- **JSON**: why it is not valid, or how many records and bad lines.

### Macros (`preview/vba/`, `facts/vba.ts`) (42h)

Every Office reader shows a file's macros, not just that it has them: a
**Macros** button in its bar opens the modules — flagged where they hide
something — with each one's source as text. **Open as text** hands a
module to the text reader (42f: VBA highlighted, its own facts), and
**Save** puts it into the vault as a `.bas` or `.cls`, after asking.
Nothing is run.

| file | where the macros are |
|---|---|
| .docm .xlsm .pptm (and templates, add-ins) | `word/`, `xl/` or `ppt/vbaProject.bin` — an OLE file of its own |
| .doc | the `Macros/` storage |
| .xls | `_VBA_PROJECT_CUR/` |
| .ppt | an ExOleObjStg record in the PowerPoint stream: zlib, then an OLE file (inflated up to its declared size) |
| .odt .ods .odp | `Basic/<library>/<module>.xml` — StarBasic, as text |

**Reading a VBA project** follows Microsoft's specification [MS-OVBA]:
`VBA/dir` (compressed) lists the modules, their streams and the code page;
each module's stream is its **compiled code** (p-code) followed by its
**compressed source**; `PROJECT` is what the VBA editor reads. The
decompressor reproduces the specification's own examples; the PROJECT
values decrypt as Excel's own do.

**Is the source what runs?** Office runs the compiled code when its
version matches, and never looks at the source. So:

- **VBA stomping** — a tool replaces the source with something harmless
  and leaves the compiled code. In p-code a string literal is its length
  and its text, so the reader lists the literals the compiled code holds:
  any the source never says ("certutil -urlcache …" behind an empty Sub)
  is named; a source that is gone beside real compiled code is named too;
- **hidden modules** — in the project's directory but not in the list the
  editor shows: their code runs all the same;
- a **form's controls** keep text in its `o` stream, a usual hiding place
  for a payload: listed, and read by the script triage;
- a project **locked for viewing** (its DPB decrypts to a password hash)
  is locked in the editor only: the source is read here.

**The facts** (`facts/vba.ts`, replacing the bare "Contains macros"):

- **When:** what runs by itself — on open (AutoOpen, Document_Open,
  Workbook_Open, Auto_Open…), when a document is made from a template, on
  close, or when an ActiveX control is drawn (InkPicture1_Painted,
  Frame1_Layout…: an automatic start not called AutoOpen);
- **What:** running programs (Shell, WScript.Shell, ShellExecute,
  MacScript), downloading, writing and deleting files, COM objects,
  Excel 4 macros, calls by name, rewriting VBA, the environment, the
  registry, keystrokes, sandbox checks, payloads read from the document's
  own properties, shapes, cells or forms, hiding what it does — each with
  its module and line;
- **Declares** of Windows functions, and the shellcode loader's set by
  name (VirtualAlloc, RtlMoveMemory, CreateThread,
  EnumSystemLanguageGroupsW, CallWindowProc…);
- **How it hides:** characters built with Chr(), reversed strings, long
  hex or base64 runs, strings cut and joined, very long lines;
- the 42f triage over the source, the compiled code's unseen strings and
  the forms' text: command lines, encoded PowerShell (decoded), addresses.

### Forensic formats (`preview/forensic/`, `facts/forensic.ts`) (42i)

The hex reader takes apart the files an incident responder collects, each
in a tab of its own beside Hex and Strings:

**Windows shortcuts (.lnk)**, from [MS-SHLLINK]. Since Office blocked
macros from the internet, a shortcut in a ZIP or an ISO is how much
malware starts. And every shortcut Windows makes is evidence.

- **What it runs:** the target from LinkInfo (a local path, or a share),
  from the shell items (long names included) and from the
  environment-variable block; the arguments, quoted and read by the 42f
  triage (an encoded PowerShell command decoded).
- **How it hides:** arguments padded with blanks past the 260 characters
  the Properties box shows; a minimized window; an icon borrowed from a
  browser or a PDF reader while the target is an interpreter; "run as
  administrator"; a working folder in TEMP; a network share it reaches for
  (and offers the user's sign-in hash to); bytes appended after its end.
- **Where it was made:** the tracker block's machine name, and in its
  version-1 object IDs the network card's MAC address (VMware's, VirtualBox's
  or Hyper-V's: made in a virtual machine) and a time; the target's
  volume (type, serial, label), times and size — or none at all, the mark
  of a builder tool.

**Prefetch files (.pf)**: Windows keeps one per program it has run.

- Windows 10 and 11 compress them: "MAM\x04", the size, then Xpress
  Huffman ([MS-XCA]), decompressed here (`forensic/xpress.ts`, written from
  the specification).
- Read from SCCA versions 17 (XP) to 31 (11), as dissect.target and
  libscca document the layout: the program, its path hash, the run count,
  the last eight run times, every file it touched in its first seconds,
  and the volumes (device, serial, creation time, folders).
- **The facts:** how often and when it ran; where it ran from (a folder
  any user can write to is a warning); the files it touched in such
  folders; a dual-use or offensive tool by name (rclone, PsExec, procdump,
  Mimikatz, netcat, remote-access and tunnelling tools, AdFind,
  wevtutil…); a file name whose program or hash no longer matches its
  header (renamed, or brought from another machine).

Both parsers were checked against independent readers on the same bytes:
LnkParse3 for shortcuts, dissect.target for Prefetch and dissect.util for
Xpress Huffman (both used only as test oracles, never shipped).

### Programs (`readers/hex.ts`, `preview/binary/`, `facts/binary.ts`) (42g)

Any file can be shown as bytes, and a program is taken apart; nothing is
run, mapped, disassembled or decoded as what it claims to be. Every byte
reaches the page as a number, through `textContent`.

| tab | what it shows |
|---|---|
| Program | PE, ELF or Mach-O: the header, the sections (offsets, sizes, rights, entropy; a click goes to them in Hex), the imports grouped by library with the dangerous ones marked, exports, libraries, the signature, the version strings, the hashes |
| Hex | offset, hex and ASCII, sixteen bytes a row, drawn only where you look (a 256 MB file is 16 million rows); Go to an offset; Find text, UTF-16 text or hex bytes, forward and (Shift+Enter) back, wrapping; an entropy strip of the whole file — dark where it repeats, bright where it is compressed or encrypted — that goes where you click; the status line reads the byte as u8, u16 and u32 and names its section |
| Strings | ASCII and UTF-16LE runs of 5 or more, by offset (what `strings` and `strings -el` print), filtered as you type; a click goes to the string in Hex |

**Which files.** Programs by name (.exe .dll .sys .scr .cpl .ocx .efi
.so .dylib .ko .elf .o .bin .node .pyd …), by type, and *by their first
bytes under any name but an archive's*: an "invoice.pdf" that starts with
MZ is the lure, and it is shown as the program it is (a self-extracting
archive stays with the archive reader, which lists it). Other binaries
(.wasm, .dex, .class, .lnk, .dmp, .pcap, .evtx, .db) come here too, and
any file with no reader offers **Inspect as hex**.

**The parsers** (pure, `unit:preview-facts`), written from the formats'
own specifications — the PE/COFF specification, the System V ELF ABI,
Apple's `<mach-o/loader.h>` and `<mach-o/fat.h>`:

- every offset a file gives is bounds-checked before it is followed (a
  read past the end ends the walk with "cut short", it never throws);
- every loop a file controls is capped (96 sections — the Windows loader's
  own limit —, 1000 import descriptors, 4096 load commands…);
- an RVA is mapped through the section table, and one that points at
  nothing is skipped;
- checked against the tools analysts trust, on real compiler output:
  pefile (imphash, sections, entropy, version strings, exports) for
  mingw's .exe and .dll, readelf for gcc's ELF, llvm-otool and llvm-nm
  for clang's universal Mach-O.

**The facts** (`facts/binary.ts`), the first minute of triage:

- **What** it is (and a name that says otherwise), SHA-256 (copyable),
  the imphash — pefile's own method, Winsock's ordinals named as pefile
  names them; for an oleaut32 ordinal no imphash at all rather than a
  wrong one.
- **Who:** the compile time (in the future, zeroed, or before 1995: forged
  or a reproducible build's hash); the Authenticode signature's names, or
  a Mach-O's identifier, Team ID and ad hoc flag — **never verified here**,
  and said so; who the version resource says made it, and an unsigned file
  that claims to be Microsoft's; its own name for itself; the PDB path,
  and a user folder in it; a manifest asking for administrator.
- **How:** packers by their section names (UPX, ASPack, MPRESS, Themida,
  VMProtect…), sections of near-random bytes, sections both writable and
  executable, an entry point in the last section or outside any, TLS
  callbacks, an overlay after the last section, few imports that look the
  rest up at run time, none at all; for ELF a stripped or missing section
  table, UPX, an odd loader, a writable-and-executable segment, an RPATH
  anyone can write, a kernel module; for Mach-O no signature on Apple
  silicon, libraries loaded from /tmp.
- **What for:** the imports grouped by capability — injection, keylogging,
  downloading, credential theft, services, anti-debugging, privileges, the
  reverse shell's socket + dup2 + exec — strong ones as warnings, common
  ones as one line. In the strings: what a script would do (the 42f
  triage, at the offset), URLs, public IPs, .onion and Bitcoin addresses,
  registry Run keys, user folders, and the marks installers, packers and
  known tools leave (NSIS, Inno Setup, PyInstaller, AutoIt, Go, Rust,
  Mimikatz, Cobalt Strike, Meterpreter, a ransom note's words).

**Malware samples** are inspected here and nowhere else — the hex reader
has no Open, Save or hand-over. The inspection goes into the audit trail
first (docs/CUSTODY.md › Inspection), and the frame shows a banner.

## Limits

- **A reader that hangs can freeze the tab on some browsers.** Desktop
  Chrome and Edge run a sandboxed frame in a process of its own: a file
  that sends a reader into an endless loop freezes only the frame, and
  closing the viewer ends it. Chromium's headless test shell, and browsers
  without site isolation for sandboxed frames (Chrome on Android, Safari
  today), keep the frame on the page's own thread, so the whole tab
  stalls. Measured in 42b: a 2-second loop in the frame stalled the page
  2 s in the headless shell, and 12 ms in full Chromium. Nothing is read
  or sent either way. The heaviest parsers run in workers (pdf.js, SheetJS)
  for this reason. docx-preview and pptx-preview need the DOM, so they
  cannot.
- **Fidelity.** docx-preview and pptx-preview approximate Word's and
  PowerPoint's layout; rhwp approximates 한글's; fonts are this computer's.
  The facts do not depend on any of it.
- **Formulas are never recalculated**; spreadsheets show saved values.
- **The older formats are text only.**
- **An email's HTML is shown as cleaned, not as sent.** Forms, scripts and
  outside pictures are gone, by design; the Source tab has the original.
- **A .msg has no source**: Outlook keeps properties, not the message.
  Its headers are there only when it came from outside the organisation.
- **RAW files show the camera's preview**, not the sensor data: an edit
  made to the RAW in a darkroom program is not seen. JPEG XL, Photoshop
  and JPEG 2000 files show their metadata only. A HEIF's thumbnails and
  depth maps are not shown; a TIFF shows its first 20 pages.
- **The thumbnail check is a likeness at 32×32**, for JPEG's EXIF
  thumbnail only: a small change (a word retouched) can pass it. When it
  speaks it is evidence; when it is silent it proves nothing.
- **Every small picture is a frame of its own** (Quick Look, the details
  pane, each poster on screen): safe, and heavier than an `<img>`.
- **EGG's AZO method is not decoded.** It is ESTsoft's own; the one open
  decoder known (in EggDotNet) carries no licence of its own, so it is not
  taken. Nor are LEA-encrypted entries opened (no library here has the
  cipher). AZO and LEA entries are listed.
- **The EGG format is ESTsoft's.** Its specification's licence permits
  non-commercial use and asks for ESTsoft's approval for commercial use
  (NOTICE).
- **7-Zip's WebAssembly build has only UTF-8.** In formats other than ZIP,
  ALZ and EGG, a name in another encoding (a Korean LZH, say) is listed
  with question marks and cannot be asked for by name; the facts say so.
- **A split archive** (`.001`, `.z01`, a split EGG) is listed one part at
  a time: the vault holds each part as a file of its own.
- **Script triage is pattern matching.** It names what is written
  plainly; a script obfuscated past its patterns (built from pieces,
  encrypted, run from a second stage) passes it. It is a reading aid, not
  a verdict: a clean report proves nothing, and the 42g hex reader and a
  sandbox are the next steps for anything suspected.
- **Secret patterns are the providers' published formats**, plus
  assignments that look like passwords. A key in another shape is missed;
  a test key in the right shape is reported.
- **Highlighting stops at 1 MB** and showing at 8 MB.
- **Shortcuts: property stores are listed, not decoded**, and shell
  items are read for their names only. A Prefetch file's trace chains
  (which blocks were read) are not shown.
- **Macros: the compiled code is not disassembled.** Stomping is found
  by the literals the compiled code holds and the source does not; code
  that builds its strings at run time (Chr(), arithmetic) and has a
  plausible source can pass that check. olevba's pcodedmp-style
  disassembly would go further; it is not here. Excel 4.0 macro sheets
  are quoted (42b), not evaluated.
- **Signatures are not verified.** The hex reader names what an
  Authenticode or Mach-O signature carries; checking it needs the
  certificate chain and its revocation status, which a sandbox with no
  network cannot have. "Signed" is never shown as "trusted".
- **No disassembly, no .NET metadata beyond its runtime, no resources but
  the version and manifest read.** Imports are what the file declares: a
  packed program declares little, and the facts say so.
- **A file is shown up to the viewer's whole-read cap** (256 MB); a bigger
  sample is downloaded zipped into an analysis environment.

## Tests

- **`unit:preview-frame`:**
  - the bootstrap's hash is the one pinned in the frame's CSP;
  - the frame's policy replaces the app's and allows nothing off the
    computer;
  - three Trusted Types policies, and no duplicates;
  - the app keeps `frame-src 'self'`;
  - the sandbox flags are `allow-scripts` only;
  - asset names cannot climb out of a reader's folder; 한글's reader may
    ask for its WebAssembly and nothing else; the others for nothing;
  - an attachment's name cleaned before the app uses it (42c): no path, no
    control or right-to-left characters, a length cap;
  - the image reader may ask for libheif's two files and nothing else; a
    fact's Copy is kept only when it is words the fact shows (42d);
  - the archive reader may ask for 7-Zip's two files and nothing else; a
    direction-changing character in any fact is shown, not obeyed (42e).
- **`unit:preview-frame`** (42g): the text and hex readers ask for no
  asset; `openPreview` refuses a sample for any reader but hex; the viewer
  writes the audit line before it opens the bytes.
- **`unit:viewer-modes`:** each format to its reader, by name or type,
  capped like any whole read, samples refused first; the first bytes
  correcting a disguised name (a .msg is OLE, and stays email); (42f)
  Markdown, JSON, XML, web pages and code to the text reader, plain text
  and logs kept in the page, a sample script never parsed; (42g) programs
  to the hex reader by name, type, and their first bytes under any name
  but an archive's.
- **`unit:preview-facts`** (Node, milliseconds): ZIP bombs refused (a part
  that lies, a directory that over-claims); every planted trick in the
  hostile Word, Excel, PowerPoint, 한글, .doc and RTF fixtures named, the
  honest ones warning of nothing; .xls and .ods read; CP949 CSV detected;
  .doc, .ppt and RTF text read right (Korean included); (42c) the email
  fixtures' facts: the forged Authentication-Results not believed, the
  entry hop, the sender's disguises, every planted link and attachment,
  the .msg read like the .eml, and the honest message warning of nothing;
  (42d) every picture fixture sniffed by its bytes, its declared size, its
  end and what follows it, a RAW file's own previews, GPS and the camera,
  the editing history, the AI mark, the bomb, and the facts each makes;
  (42e) every archive fixture through our ZIP, ALZ and EGG readers and
  7-Zip in Node: names (CP949), ZipCrypto and AES, wrong passwords, liars,
  bombs, links, solid EGG, AZO, ESTsoft's own EGG sample, and the facts;
  (42f) a leaked config's every key found and masked, placeholders not; a
  dropper's every line named in order and its `-EncodedCommand` decoded;
  a reverse shell, a web shell, Script Encoder, an obfuscator; JSON
  nesting refused before parsing; XML entities and outside DTDs; Korean
  and UTF-16 text decoded; (42g) mingw's .exe and .dll, gcc's ELF and
  clang's universal Mach-O read as pefile, readelf and llvm-otool read
  them; the hostile PE's every trick named; files cut short anywhere said,
  never thrown; strings, Find, capabilities; (42h) MS-OVBA's example
  vectors decompressed, Excel's own PROJECT values decrypted, a project
  built at test time read alike from .docm, .xlsm, .pptm, .doc, .xls and
  .ppt, and OpenDocument Basic: auto-run, Shell, Declares, stomping (the
  source wiped, or literals it never says), hidden modules, a lock, a
  form's text; an honest macro warning of nothing more than its presence;
  (42i) a lure shortcut and a Prefetch file built at test time, every fact;
  a share, a renamed Prefetch file, cut-short files; Xpress Huffman across
  blocks and long matches.
- **`e2e:preview`** (Chromium):
  - the frame's headers;
  - a PDF's pages, text, Korean through a CMap, Find, and facts; a
    password-protected PDF opened with its password;
  - a hostile PDF: no dialog, no request, its link and attachment named;
  - an attack from inside the frame: no cookie, storage, parent, API,
    network, popup or top navigation, and a beacon stopped by the CSP. A
    navigation away is refused and the frame is closed;
  - Word, Excel (and a CP949 CSV), PowerPoint, HWP, HWPX (and a
    password), Word and PowerPoint 97, RTF, OpenDocument: each drawn, or
    its text shown, with Find and facts; the hostile files' tricks named,
    their markup shown as text; an RTF and a web archive named .doc named
    as disguises;
  - the default Trusted Types policy attacked from inside;
  - forensic formats (42i): the lure shortcut's facts, its Shortcut tab
    and arguments; the Prefetch file's facts and its flagged files;
  - macros (42h): a .docm's project named fact by fact, the Macros pane's
    flagged modules, a module opened in the text reader and back; the
    same project in an .xlsm, a .doc and a .ppt; OpenDocument Basic;
  - programs (42g): the four real builds taken apart; the hostile PE's
    facts, its sections, Go to, Find in text and hex, a string followed
    into Hex; a program named .pdf; a file of no format inspected as hex;
    a sample, out of the archive and saved, inspected as bytes only — the
    hex reader and no other — and both inspections in the audit trail;
  - text (42f): Markdown rendered with no script, form, frame or outside
    picture, a link that hovers true and clicks nowhere, Find; JSON and
    XML trees and their paths; the deep JSON and the XXE refused; a
    phishing page shown as source; code highlighted and wrapped; the
    dropper's, the installer's and the leaked config's facts; a program
    named .js said to be binary; a log kept in the page;
  - archives (42e): ZIP, ALZ, EGG, 7z, RAR, TAR.GZ, ISO listed, folders
    walked, entries opened in previews of their own (a nested archive in
    turn); the lure's every trick named; a wrong password refused,
    "infected" a sample saved only as one; names hidden by AES unlocked; a
    liar stopped; AZO named;
  - pictures (42d): every format drawn in the frame and none in the page;
    zoom by wheel, keys and double click, a drag that pans; GPS copied;
    the redacted photo's thumbnail and the cropped one's shape caught; the
    polyglot, the AI mark, the bomb, the disguises; TIFF pages, HEIF
    through libheif, the RAW previews; the hostile SVG's script never run
    and its beacons never asked for; the details pane's compact frame; on
    a phone, a pinch, a pan instead of the next file, a double tap;
  - email (42c): an .eml drawn with its own picture, Find, the headers,
    text and source tabs, its PDF opened in its own preview and back; a
    phishing message's facts, its link shown on hover and dead on click,
    no script, form or outside picture drawn; its .docx opened, its
    "invoice.pdf.exe" saved as a sample and then refused; a forwarded
    message opened from the report; Outlook's .msg;
  - no dialog, no CSP or Trusted Types violation, no request off the
    computer, and the frames' only requests their own page;
  - on a phone the PDF and a Word page fit the screen, and a swipe inside
    the frame opens the next file.
- **Fixtures** are made, not downloaded:
  - `tests/fixtures/preview/make.py` (reportlab, pypdf): the PDFs;
  - `office.py` (python-docx, openpyxl, python-pptx; LibreOffice for the
    older formats): the Office files and the hostile variants;
  - `ole.mjs` (rhwp, cfb): the 한글 files, the OLE surgery Python
    cannot do, and Outlook's .msg;
  - `mail.py` (no libraries: MIME written out by hand, so every header is
    exactly what a test expects): the .eml messages;
  - `images.py` (Pillow draws; EXIF, XMP, TIFF directories, the DNG, CR3
    and RAF layouts and the HEIF boxes written by hand; ffmpeg's x265
    encodes the HEIF's picture): the pictures;
  - `archives.py` (each format's own tool — zip, 7z, rar, gcab, xorriso,
    arj, zstd; LHA, the hostile ZIPs, ALZ and EGG written by hand, ALZ
    checked with unalz, EGG from ESTsoft's specification): the archives.
  - `tests/lib/forensic.mjs` builds shortcuts ([MS-SHLLINK]) and Prefetch
    files (with an Xpress Huffman writer) at test time; LnkParse3 and
    dissect read them as written;
  - `tests/lib/vba.mjs` builds VBA projects at test time (an [MS-OVBA]
    compressor, the dir and PROJECT streams, DPB "encryption") and puts
    them into copies of the Office fixtures; olevba reads what it writes
    as it reads Office's own. No macro is kept as a file;
  - `programs.sh` (mingw-w64, gcc, clang with ld64.lld and llvm-lipo): the
    honest programs, each printing one line. The hostile PE is built when
    the tests run (`tests/lib/programs.mjs`): structurally valid, a RET
    for code, and nothing a scanner would take for malware on disk;
  - `texts.py` (no libraries): the Markdown, JSON, XML, page and code
    files. The hostile scripts and the leaked config are built when the
    tests run (`tests/lib/hostile-text.mjs`), from pieces, so the
    repository holds no file a virus or secret scanner would flag.

  Everything except what LibreOffice writes is the same bytes on every run.
  Nothing in them is a working exploit: the scripts are text, the
  PostScript draws nothing, the "program" is a sentence.
