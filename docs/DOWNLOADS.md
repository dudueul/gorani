# Downloads: one file, or a zip of many

> Copyright 2026- Seongwoo Hong. All rights reserved.
> How the web explorers hand files out (commit 41a). How the bytes are
> opened is in ENCRYPTION.md and LARGE-FILES.md; what a signed content hash
> proves is in CUSTODY.md, stage 4; why samples are treated differently is
> in CUSTODY.md, stage 5.

## Ways out

| How | What you get |
|---|---|
| **Download** (an item's menu; Finder's Quick Look) | each selected file on its own, checked against its signature |
| **Download as zip** (an item's menu, with files, folders or both selected) | one zip: the files, the folders with everything in them, and `gorani-check.txt` |
| **Download this folder as zip** (right-click empty space) | the folder on screen, whole |
| **Download as zip** on a folder in the tree / the Finder sidebar | that folder, whole, even while the Trash is open |
| **Download all as zip** on Home | everything in the area |

A single file that is a malware sample comes as a zip encrypted with the
password `infected` (commit 29e). A zip of many files leaves samples out
(see below).

## What happens, step by step

`FilesModel.downloadZip` and `downloadFolderZip` (web/src/ui/files/model.ts)
both end in `zipDownload`:

1. **The plan.** Each selected folder is walked through the area's tree
   (`state.tree`, which every listing brings whole). Each folder's files are
   listed page by page (`GET files/list?folder=…&offset=…&limit=1000`), with
   their names decrypted here. Each file and folder gets its path in the
   zip from `ZipNames` (see "Names" below).
2. **Who may go in.** The files' keys entries are fetched in batches
   (`POST files/keys`, 200 ids per call; the server answers up to 500).
   Each file's render policy comes from its own sealed type, as the viewer
   decides it (`policyOf`). Anything but `normal` is left out.
3. **Where the zip goes.** Up to 256 MiB in total, the zip is built in this
   tab and saved as one Blob. Above that, it streams to disk through the
   media worker as it is made (`pipeToDownload`, the same pipe as a case
   export, 31d), so the tab never holds it. With no worker, anything over
   2 GiB is refused with a reason rather than tried.
4. **The zip.** `ZipStream` (web/src/vault/zip.ts) writes stored entries,
   with a data descriptor after each and ZIP64 fields where the sizes need
   them. Each file is fetched at the version whose type was checked, and is
   decrypted frame by frame. Every frame passes through SHA-256 on its way
   into the entry. After the last byte, the hash is checked against the
   uploader's signed record (`checkContentHash`), just as a single download
   checks it.
5. **The report** is written last, once every verdict is known, as
   `gorani-check.txt` at the top of the zip.
6. **The closing message** says how many files, how many were flagged
   (naming the first three), and how many were left out.

## Malware samples are left out

A sample leaves the vault only inside a zip with the password `infected`.
That convention exists so that no tool and no person handles it by
accident: antivirus does not quarantine it, a double-click does not run it,
and the unzip step asks first. A plain zip containing one would undo all
of that. The sample would be on disk, unencrypted, the moment the zip is
unpacked.

So a zip of many files skips them, and says so. The report lists each
sample under **Left out**, and the closing message counts them. A file
whose sealed type does not verify is treated as a sample too: its type
is the only thing that says it is not one.

To get a sample, download it on its own. It comes as `name.zip`, password
`infected`, with its SHA-256 in the message.

## The check report

`gorani-check.txt` is plain text. Each file gets a block:

```
OK         Case 41a/photos/a.jpg
  SHA-256  48abdb6467282f258ec56984d387defd1ea38497c1b7df46076766d2daa2ffa8
  Size     9 bytes
  Check    content verified — exactly the bytes bo signed
```

| Verdict | Means |
|---|---|
| `OK` | exactly the bytes the uploader signed |
| `UNSIGNED` | the uploader signed no hash (an upload from before 29d): nothing to check against |
| `MISMATCH` | **not** the bytes the uploader signed: do not rely on this copy |
| `UNTRUSTED` | signed, but by a key this team does not trust (or no identity was open) |
| `INVALID` | the signature or record does not verify, e.g. one the server moved here from another file |
| `FAILED` | the download broke part-way: the copy in the zip is incomplete, and says how many bytes arrived |

A file that is flagged still goes in. Someone investigating a mismatch
needs the bytes to examine. The report and the closing message make sure
nobody takes the copy for a verified one.

Why hashes in a text file, when a zip already has CRC-32s: a CRC catches
accidents, not changes. Anyone can rewrite an entry and its CRC. The
SHA-256 in the report is the one the uploader's signature covers. After
unzipping, anyone can re-check a file with the tool they already have:
`sha256sum` (Linux), `shasum -a 256` (macOS), or `Get-FileHash` (Windows
PowerShell).

A file whose name did not open in its place (the explorer shows
"⚠ unverified — not sealed here") goes in under `unverified-name-<id>`,
with a note in its block. Nothing a server wrote ever names a file on
someone's disk.

## Names

The names are the uploaders' own, and a name can be any text someone
typed. `zip-download.ts` turns each one into **one safe path segment**:

- `/` and `\` become `_`, so a name cannot become a path (`../../.bashrc`
  stays one file, `.._.._.bashrc`);
- control characters and `< > : " | ? *`, which Windows refuses, become `_`;
- a trailing dot or space becomes `_`, because Windows strips them and two
  names would merge;
- `.` and `..` become `_`, and Windows device names (`CON`, `nul.txt`, …)
  get a leading `_`;
- an empty name becomes `unnamed`, and a very long one is cut to 120
  characters, keeping its extension.

Then `ZipNames` makes each path **unique within its folder, ignoring case**.
Windows and macOS folders ignore case, so `A.JPG` and `a.jpg` would
overwrite each other when the zip is unpacked there. The second becomes
`A (2).JPG`. A file and a folder may not share a name either, and
`gorani-check.txt` at the top is reserved for the report.

Folders are entries of their own (`name/`, with the directory attribute), so
an empty folder is still there after unzipping.

## What a server could try

- **A tree with a loop** (a folder listed as its own ancestor): each folder
  is walked once.
- **A listing that never ends** (the same page sent again and again): a page
  that brings no new file ends that folder's walk.
- **Rows that claim another folder:** ignored. A folder's files are the rows
  that name that folder.
- **Clearing a sample's flag:** the sealed type still marks it, so it is
  still left out.
- **Swapping a version** between the type check and the fetch: the fetch
  names the version that was checked, and the bridge refuses any other.
- **Swapping a record or a name:** the file shows as `INVALID`, or goes in
  under its id. It is never passed off as verified.

## Tests

- `unit:zip-download`: the naming rules and the report.
- `unit:zipstream`: folder entries read back by Python's zipfile, and an
  empty folder surviving extraction.
- `unit:explorer` (Download as zip): a real tree with the sealed crypto,
  checked by Python's zipfile. It covers paths kept, names made safe and
  unique, the sample left out, a moved record flagged `INVALID`, the
  report's hashes equal to the entries' hashes, a dropped connection marked
  `FAILED`, and the Trash refused.
- `e2e:app`: Download as zip from the Windows menu in Chromium, the file
  byte for byte, and the report naming it.
