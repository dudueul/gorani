# Movies: the area's videos as a shelf

> Copyright 2026- Seongwoo Hong. All rights reserved.
> The Movie tab (commit 39o) — family videos as much as films. How each
> part is made without the server learning a title, a length or a frame.

## What it shows

- **Collections are folders.** Every folder that holds videos is a section,
  by its path ("Holidays / 2025"), and the top folder's videos come first.
  No series, seasons or catalogue: the folders a person made are the
  collections.
- **A card per video**:
  - its poster;
  - its length, "1:02:03";
  - its picture size, "1080p" or "4K";
  - its size on disk;
  - how far the person watching got, as a bar and "40% watched".
- **Playing** opens the same viewer the explorers use. MP4s play in the page
  through the engine (docs/VIDEO.md); everything else plays the older way.

Every video kind is listed. Length, picture size and poster need the MP4
sidecar, so other containers show the name, the size and an icon.

## Where each piece comes from

| What | Made by | Stored |
|---|---|---|
| name | the uploader's browser | the file's sealed name, as always |
| length, picture size, codecs | the engine reading the moov (39p) | `video_meta`, sealed into `file.video(area, file, version)` |
| poster | a frame this browser drew: at upload from the local file, or a moment into the first play | beside the sidecar, sealed into `file.poster(area, file, version)` — a ~20 KB WebP |
| where you left off | the viewer, every 10 s while playing and on pause or close | `watch_positions`, sealed into `file.position(area, file, member)` |
| subtitles | files beside the video, decrypted when it opens | they are ordinary files |

Nothing in the tab decrypts a video:

- names open with the store key;
- lengths come from one feed of sealed sidecars (`GET files/videos`);
- a poster is fetched only for a card that scrolls into view.

The server can see that a file has a sidecar, a poster or a saved position,
and when. It cannot see what any of them says.

## Resume

- Each member has their own position per video. In a case, a read-only
  grantee saves theirs too: where someone paused is theirs, not the file's.
  The Worker puts the caller's own id in; a client never names the member.
- A position near the start or the end is not offered: within 5% of the
  length, at most 5 seconds (a film's credits; the last third of a second of
  a 6-second clip). Otherwise the viewer says "Resumed at 12:34", with Start
  over beside it.
- Positions follow a store rotation like every other sealed value (kind
  `position`), and go when their file is purged.

## Subtitles

The viewer looks in the video's folder for `.vtt` and `.srt` files whose
name starts with the video's own base name:

- `Holiday.mp4` takes `Holiday.vtt`, `Holiday.en.vtt`, `Holiday.ko.srt`;
- the part between the base name and the extension is the language.

Each file is decrypted, converted to WebVTT if it is SRT (a header, and a
dot before the milliseconds), and attached as a `<track>` from a blob: URL
revoked when the viewer closes. The browser's own controls switch them.

## Posters, when there are none

- A video uploaded before 39o, or by a client that makes no poster (the
  desktop sync, the CLI), gets one the first time someone plays it in the
  page: the frame on screen two seconds in.
- A browser that cannot decode a file's codec makes none: H.264 in a
  Chromium build without it, for instance. The card keeps its icon until a
  browser that can plays it.

## Playing a film from any folder (39z)

The tab lists videos from every folder, and the explorer may be showing
any one of them, or none. So the viewer decides what it may play from the
film's own keys entry, which holds the server's sample flag and the
sealed type. It opens that type in its place, as for every file
(`model.ts › renderInfo`). It never looks at the open folder's rows.

Until 39z it did look at them. A film in a folder the explorer was not
showing found no row. The viewer, failing closed, then showed it as a
malware sample ("this file's type does not verify in its place", under
the sample's icon), though nothing was wrong with it. Failing closed is
still the rule:

- no keys entry at all, so nothing can be opened: refused;
- a type that does not open in its place: refused;
- a sample's mark, either one: refused, wherever the explorer is.

The same slip was in four more places, each fixed the same way:

- **Streaming:** a track or film the media worker plays, sized from the
  row (`mediaHandle`);
- **Previews:** the first bytes a preview opens (`preview`);
- **Downloads:** the streamed download of a big file (`streamDownload`);
- **Paste:** Paste in another folder, which lost the copy's date and type
  (`paste`). The date is now taken at Copy.

## Tests

| Suite | What it checks |
|---|---|
| `unit:explorer` | Subtitles found by the video's base name, with and without a language, not another video's; SRT converted to WebVTT, VTT passed through |
| `api:files` 8d | The sidecar routes the tab reads |
| `api:rotation` | Sidecars, posters and positions resealed with every other value |
| `e2e:app` | The card's length from the sidecar and its poster made at upload; opening it, with the explorer in another folder, plays it (39z: no refusal) and resumes where the previous play stopped; an `.en.srt` beside it becomes an English track with its cue |
| `unit:explorer` 5e, 13 | (39z) A film in a folder the explorer is not showing opens as itself and previews; Get Info alone still needs its row; Paste elsewhere keeps the date and type; a sample there, with the server's flag cleared, is still refused |
