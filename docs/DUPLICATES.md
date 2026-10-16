# Duplicates: the same bytes, found without the server reading them

> Copyright 2026- Seongwoo Hong. All rights reserved.
> How gorani notices a file that is already stored (commit 39n), and what
> each place does about it.

## The tag

Every version a client uploads carries a **duplicate tag**:

```text
tag = HMAC-SHA256(fp, SHA-256(plaintext))      hex, 64 characters
fp  = the area's fingerprint secret            (files secrets, sealed into
                                                the area's `store.secrets`
                                                place; made by the first
                                                browser that uploads there)
```

- The **browser** makes it in `web/src/ui/files/model.ts › fingerprint`.
- The **native clients** make it in `clients/core/src/area.rs ›
  duplicate_tag` (since 39n; until then they sent none, so nothing they
  uploaded was ever found). Both implementations use the same 32 raw digest
  bytes; `area::tests` pins a vector computed outside both.

What the server learns, honestly:

- It stores the tags, so it can see that two are **equal**. That has always
  been true, and Find duplicates does not tell it anything new.
- It cannot learn **what** the bytes are. A tag is keyed, so the server
  cannot match it against a hash it already knows (a known file, a
  leaked document); only someone holding `fp` could.
- Names stay sealed everywhere below; the server returns them sealed and
  the client opens them.

An area whose secrets do not exist yet (no browser has uploaded there)
makes no tags. A file uploaded before that is never matched, but it still
uploads normally.

## At upload — the browser

`model.ts › upload` hashes each file once; the same digest feeds both the
signed content hash and the tag. It then asks the server for
`GET files/match?size=…`: every live file of exactly that size, with its
tag, folder and **sealed** name. It compares the tags itself. When one
matches, the prompt (`duplicate-dialog.ts`) shows:

- which file already has the bytes, and the folder it is in;
- **Skip this file** (the default) or **Keep both**;
- in a batch, "Do the same for every other duplicate in this upload";
- Esc or "Stop the upload" ends the batch there.

Until 39n this was the browser's own OK/Cancel box with a count. It never
said which file was the twin, or where, and it asked once per twin.

## Find duplicates

To open it:

- Windows skin: right-click empty space › Find duplicates…
- Finder skin: right-click empty space › Find Duplicates…

What it does:

- `GET files/duplicates` (`files_store.rs › files_duplicates`) returns every
  live file whose living version shares its size and tag with another. It
  is capped at 5 000 rows, largest files first.
- The view (`duplicates-dialog.ts`) groups the copies. In each set, every
  copy except the oldest starts ticked, and the ticked copies go to the
  Trash.
- Nothing is deleted outright: the Trash keeps a file for 30 days (a lead,
  or the owner, may delete it for good from there — docs/TRASH.md). An
  evidence case refuses the move, and says so.
- "Show" goes to a copy's folder and selects it.

## The desktop clients

- **`gorani-sync push`** checks before uploading. `--duplicates
  skip|keep|ask` decides; the default asks on a terminal and skips
  otherwise. A skipped push prints `{"skipped": …, "duplicateOf": [...]}`
  and exits 0, so a script that pushes the same file twice gets one copy
  and a line saying where the other is.
- **The sync engines** (gorani-mount, the Windows and macOS shells via
  `replica.rs`) upload anyway, tagged, and log which file the new one
  duplicates. A folder the system manages cannot refuse a copy put into
  it: the file must exist, or it would vanish after the write. The copy is
  reported, and Find duplicates lists it.

## Tests

| Suite | What it checks |
|---|---|
| `unit:explorer` | The prompt is told the twin's name and folder. |
| `api:files` 8c | Match returns the sealed name and folder. The duplicates listing returns the pair and not a same-size different file. Another member is refused, and a copy in the Trash is no longer a duplicate. |
| `api:client-live` | The CLI's tag. A duplicate push is skipped and names the twin; `--duplicates keep` stores a copy; a CLI copy is listed like a browser one. |
| `e2e:app` | In the browser: the prompt and Skip, "for the rest" with Keep both, and Find duplicates trashing two of three copies. |
