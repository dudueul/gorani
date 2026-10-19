# The web app on a phone

> Copyright 2026- Seongwoo Hong. All rights reserved.
> How the browser app works on a phone (commit 41b). The model under it is
> the same one the desktop looks use (web/src/ui/files/model.ts). The
> downloads it offers are in DOWNLOADS.md.

## When the phone layout is used

The rule is the **width**, not the device. A window narrower than 640 CSS
pixels gets the phone layout (`web/src/lib/phone.ts`). Anything wider gets
the Windows or Finder look:

- a phone held upright: phone layout;
- the same phone turned sideways, or any tablet: the desktop look, which
  works with a finger at that size;
- a desktop browser made narrow: phone layout, and wide again restores the
  desktop look, with no reload.

640 is also Tailwind's `sm:` breakpoint. The stylesheet's responsive
classes and the switch in the shell therefore agree on what "narrow" means.

## What changes

| Screen | On a phone |
|---|---|
| Header | One row: **Files · Music · Movies · Team**, plus **☰** (who is signed in, the areas to switch to, Lock). The desktop header's area list, Windows/Finder switch and Lock button are not drawn. |
| Files | The touch explorer (`files/phone.ts`), described below. |
| Viewer | Full screen. One short header row (name, position, Download, ✕); the details line moves under the picture. Swipe for the next file. |
| Movies | One poster per row, full width. |
| Music | One column: artist and album fold under the title. |
| Team | The tabs become a row that scrolls sideways; fixed-width fields shrink to the screen. |
| Unlock, setup | Cards fit the width. Every field is 16 px (below). The recovery code field turns off autocorrect and capitals. |
| Toasts | Above the bottom bar, wrapped to the screen's width. |

### The touch explorer

| Do | What happens |
|---|---|
| Tap a row | A folder opens; a file opens in the viewer. |
| **‹** (top left) | Up one folder. The phone's own Back gesture works too, because the address holds the folder (39l). |
| Long-press a row, or its **⋯** | The item's actions, as a sheet: Open, Download, Download as zip, Share…, Rename…, Move to ›, Copy, Cut, Request files…, Verify signature, Custody…, Mark as malware sample…, Select, Delete, Delete forever…. These are the desktop menus' actions; the model and the server still decide which are allowed. |
| **⋯** (top right) | The folder's own menu: Sort by ›, Paste here, Upload malware samples…, Request files…, Inbox, Download this folder as zip, Find duplicates…, Trash, Refresh. |
| 🔍 | Search the whole area. This uses the local index, so names never leave the browser. |
| Bottom bar | **Upload · New folder · Select**. While selecting: **Download · Zip · Move · Delete · More**. In the Trash: **Restore all · Empty · Select**. |
| After Copy or Cut | A bar offers **Paste** into the folder on screen; ✕ forgets what was copied. |

Rows are 56 px tall, and the bars' buttons are at least 44 px: the sizes
both phone platforms recommend for a fingertip.

### The sheet

`files/sheet.ts` shows a bottom sheet instead of a menu at the pointer.
On a touch screen there is no pointer, and a thumb reaches the bottom of
the screen, not the middle. A sheet takes the same `MenuItem` lists as the
desktop menus. A submenu (Move to ›, Sort by ›) opens in place with a
Back row, because a 390-pixel screen has no room for a flyout. Items are
`role="menuitem"`, as in the desktop menu.

### Long-press, and the browser's own menu

A finger held still for 500 ms is a long-press: the platforms' own timing.
Moving more than 10 px first makes it a scroll instead. On Android the
browser also fires `contextmenu` for a long-press. The explorer cancels
that event, so the browser's own menu never appears over a decrypted name
(it would offer to copy it, search for it, or share it with other apps).
The rows are also marked `-webkit-touch-callout: none` and
`user-select: none` for the same reason on iOS.

### Swiping in the viewer

The explorer hands the viewer the folder's files in the order on screen
(`ViewerTarget.siblings`). On a phone, a horizontal swipe opens the next
or previous file. On a keyboard, **←** and **→** do the same, and the
desktop looks pass their files too. The shell mounts a fresh viewer for
each file (`keyed` by id), so the previous file's blob URL, player and
media-worker key are released as it leaves.

A gesture is not treated as a swipe when:

- two fingers are down (a pinch);
- it started on a video or audio player (scrubbing);
- the page is zoomed in (panning).

### 16-pixel fields

iOS Safari zooms the page into any field whose text is smaller than 16 px,
and does not zoom back out. On a phone every `input`, `select` and
`textarea` is 16 px (`styles/global.css`). The rule is unlayered, so it
wins over the `text-sm` utilities.

## Add to Home Screen

The app installs as a home-screen app that opens without the browser's
bar:

- **iPhone (Safari):** Share → Add to Home Screen.
- **Android (Chrome):** ⋮ → Add to Home screen (or Install app).

What makes it work:

- **`web/public/manifest.webmanifest`**: `display: standalone`, a start URL
  of `/`, and three icons (192 and 512 tiles, and a maskable 512 whose deer
  stays inside the circle Android may crop to);
- **`index.html`**: the manifest link, `theme-color`, an
  `apple-touch-icon` (180 px), and `viewport-fit=cover`. With that set,
  the header, the bottom bar and the viewer pad themselves with
  `env(safe-area-inset-*)` around a notch and the home indicator;
- **the icons** are made by `tools/icons/render.mjs` from the same drawing
  as every other icon. Edit `docs/assets/gorani.svg`, not the PNGs;
- **the CSP** has always allowed `manifest-src 'self'` (web/public/_headers).

**Behind Cloudflare Access.** A browser fetches a manifest without cookies
unless the link says otherwise. Access would then answer the request with
its sign-in page, and the phone would find no manifest. The link carries
`crossorigin="use-credentials"`, so the Access cookie goes with it.

If a phone still shows a blank icon after installing, add an Access
**Bypass** policy for `/manifest.webmanifest` and `/icons/*`. These hold
nothing private: the app's name and the deer.

**Locking still applies.** An installed app is the same page at the same
origin, so it locks the same way: after 15 minutes idle, or 5 minutes
hidden (D15). A phone hides apps often. Opening the app after a while
asks to unlock, as the browser tab does.

## Not on a phone

- **Folder upload, and drag and drop.** Phone browsers cannot pick a
  folder, and have nothing to drag from. Upload takes files; New folder
  makes the folders.
- **The preview pane, columns and keyboard shortcuts.** Tap opens the
  viewer instead.
- **Choosing Windows or Finder.** The phone has its own layout. The choice
  is kept for the next wide window (`loadSkin`).

## Tests

`e2e:phone` runs Chromium as a Pixel 7: a 412-pixel touch screen, with real
touches sent through the browser's input pipeline. It checks, in order:

1. The unlock field is 16 px, with no capitalisation.
2. The touch explorer is shown, and no desktop look.
3. Rows are at least 56 px tall.
4. Upload works, and New folder through its prompt.
5. Tap opens a file, and a swipe moves to the next file and back.
6. A long-press opens one sheet, and does not open the file.
7. Rename… starts from the old name.
8. Move to › opens its submenu in place.
9. ‹ goes up a folder.
10. Select two files, then Zip: Python's zipfile finds both files and the report.
11. Delete moves a file to the Trash, and you can get back out of the Trash.
12. Music, Movies, Team › Status and Team › People each fit the screen width.
13. A wide window shows the desktop look, and narrow again shows the phone layout.
14. ☰ ticks the open area, and Lock locks.
15. The manifest and its icons are served, and the browser's own parser
    reports no errors.

Throughout, no screen scrolls sideways and the CSP reports no violation.
