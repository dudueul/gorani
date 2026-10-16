# Uploads: files, folders, and where a drop goes

> Copyright 2026- Seongwoo Hong. All rights reserved.
> How the web explorers take files in (commit 39r). How each file is sealed
> is in ENCRYPTION.md and LARGE-FILES.md; the duplicate check is in
> DUPLICATES.md.

## Ways in

| How | Where it goes |
|---|---|
| **Upload files…** (New menu, right-click on empty space) | the folder on screen |
| **Upload folder…** (same menus) | the folder on screen, as a folder with its subfolders |
| drag files or folders **onto the list** | the folder on screen — an outline says which while they hover |
| drag them **onto a folder** (a row, the tree, the Finder sidebar) | **into that folder** |
| drag them **onto a breadcrumb** | into that crumb's folder |
| drag them **anywhere else** | nowhere: refused, with a note on where files go |

Until 39r: a dropped folder arrived as one empty "file" named after it; a
drop onto a folder went to the folder on screen; the list itself took no
drop at all; and a drop the app did not take was opened by the browser —
in this tab, in place of the app, so the unlocked session went with the
page. The shell now refuses every file drop that no target took
(`shell.ts › onStrayDrop`).

## Folders

`web/src/ui/files/dropped.ts` turns what the browser hands over into one
tree — the folders, parents first, and each file with the folders above it:

- **A drop** gives entries (`item.webkitGetAsEntry()`). They must be taken
  during the drop event — the DataTransfer is emptied once the handler
  returns — and a directory is read with `readEntries` again and again
  until it answers with nothing (Chrome answers 100 at a time: a folder of
  250 photos read once would upload 100).
- **The folder picker** (`<input webkitdirectory>`) gives every file with its
  `webkitRelativePath`.

Then `FilesModel.uploadTree` makes the folders under the target. A folder
of the same name already there is used, not doubled — dropping the same
folder twice adds to it, as copying onto a folder does on a desktop. Each
file goes into its own folder, through the same upload as any file (sealed
here, fingerprinted, the duplicate prompt, an evidence case's intake
record asked once, before any folder is made).

Left out, and counted in the summary: the systems' own litter —
`.DS_Store`, `Thumbs.db`, `ehthumbs.db`, `desktop.ini`, and macOS's `._`
files. A drop holds at most 10,000 files and 32 levels; bigger trees are
refused whole (upload them in parts, or with `gorani-sync`), never cut off
part-way.

## While it runs

Uploads run one batch at a time — a second drop waits for the first, so
there is one duplicate prompt and one progress line. The status bar shows
"Uploading 12 of 340 · IMG_0012.jpg" and **Stop**: the file being sent
finishes, the rest are not sent, and the toast says how many went.

## Tests

| Suite | What it checks |
|---|---|
| `unit:explorer` | The walk past readEntries' first 100, the litter left out, empty folders kept, the picker's paths, an oversized folder refused whole; a tree uploaded into its folders, a second drop merged into the folder already there, a drop onto a folder landing in it, Stop after the file being sent, a drop of nothing but litter said so |
| `e2e:app` | In the browser: a folder picked whole (subfolder, files, litter left out), files dropped onto a folder row, onto the list (with the outline), onto a breadcrumb, and a stray drop refused |
