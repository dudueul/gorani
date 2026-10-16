# Orphans: records that point at nothing

> Copyright 2026- Seongwoo Hong. All rights reserved.
> What happens when a record and what it names come apart (commit 39t) —
> asked for after the first production upload failed (39s): "if it is
> orphaned, remove the record after checking S3 again".

The rule throughout: **nothing is removed on one answer**, and nothing is
removed at all where removing would lose something real.

## A folder that is gone

A folder goes away while a view still shows it — deleted or moved to the
Trash on another device, or during a long upload into it.

- **Refused at the server.** A new file, a move or a new folder into a folder
  that is not live answers `404 no such folder: it was deleted or moved to
  the Trash (on another device?) — refresh, and choose another`
  (`files_store.rs › folder_refusal`, and folder_put/folder_patch for a
  parent). Until 39t a FILE was stored there anyway — and no listing ever
  showed it again, since the explorer lists a folder's files only inside it.
  A refused whole-file or multipart upload deletes its object, so no bytes
  are left behind either.
- **Followed in the browser.** The explorer re-lists, goes to the top when
  the folder on screen is the one that went, and says what happened once:
  an upload batch stops there, a multi-item move stops at the first refusal
  (`model.ts › ifFolderGone`).
- **Repaired by housekeeping.** Files and folders that were stranded before
  39t (their folder purged, or in the Trash while they are not) are moved to
  the top folder, each move on the trail (`file.rehome`, `folder.rehome`).
  They are never deleted — the bytes are fine; only the place was lost.
- **Restoring from the Trash** puts an item at the top when its folder is not
  live — in the Trash, or (since 39t) purged altogether: until then only the
  Trash was checked, so a file whose folder had been purged came back
  inside a folder that no longer existed.

## Bytes the storage does not have

A read finds no object (`404`) where a record says there is one — the
object was deleted behind the Worker's back, or lost by the storage.
`routes.rs › lost_object` makes sure before anything changes:

1. **Ask again.** A read right after a write can miss on a store that is
   only eventually consistent; if the object is there now, the reader is
   told to try again.
2. **Ask about other files of the same area** (up to three). A storage that
   has NONE of them is not this deployment's bucket — a wrong `S3_BUCKET` or
   endpoint would make every file look lost, and trashing them all is the
   one answer that turns a configuration mistake into data loss. So
   nothing is changed, and the reader is pointed at Team › Status › Test
   connection. An area with no other file cannot tell the two apart either,
   and nothing is changed there.
3. Only then does the store act (`files_store.rs › file_lost`):
   - a **working** file whose living version is gone goes to the **Trash** —
     out of the listings, restorable for 30 days should the bytes come back
     (a restored backup, a storage recovered from an outage) — with
     `file.lost` and the reason on its trail;
   - **evidence**, a case under a **legal hold**, or an **older version**:
     nothing moves. The loss is recorded; for evidence it is an incident for
     a lead, not housekeeping.

The reader hears `410 Gone` with which of these happened.

A storage that **refuses** a read (a 403, say) is not a missing file: it
answers `502 the storage refused this read (HTTP 403 AccessDenied) …`. Until
39t every non-2xx read said "Not Found" — with the production 403s, every
file would have looked lost.

## Uploads that never finished

- A multipart upload the storage **refused to start** leaves no bookkeeping:
  the row made before asking the storage is deleted at once (it used to wait
  for the two-day housekeeping sweep).
- A part for a multipart upload the storage **no longer knows** (aborted,
  expired by a lifecycle rule) answers `404 no such upload`, and its
  bookkeeping goes. The browser's resume record is dropped on that answer
  and the file starts over (`model.ts › uploadOne`, since 31b).
- Uploads abandoned for any other reason are swept after two days, as before.

## Tests

| Suite | What it checks |
|---|---|
| `api:orphans` | A gone folder takes no file, move or subfolder, and leaves no bytes; lost bytes checked twice, then a working file to the Trash with `file.lost` on its trail; none of the area's files in the storage → nothing changed; a refused read is a refusal, not Not Found; lost evidence stays, recorded; a refused upload start leaves no bookkeeping; a part for an upload the storage forgot answers no such upload |
