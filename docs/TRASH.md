# The Trash, and Delete forever

A deleted file goes to the Trash first. It waits there 30 days, then the
nightly housekeeping purges it. Delete forever (commit 39v) skips the wait,
for whoever the team allows. This page covers both, and the rules they
share.

## Who may

| | Move to Trash | Delete forever, Empty Trash |
|---|---|---|
| A member, in their own area | yes | yes |
| A lead, on a case they write on | yes | yes |
| An analyst, auditor or external with a write grant | yes | **no**: the Trash, where a lead can restore it |
| Anyone, in an evidence case | no | no |
| Anyone, under a legal hold | no | no |

**Why not everyone who can trash.** The Trash is a deletion's one safety
net: for 30 days a lead can restore whatever an analyst deleted, whether
it was a mistake or an insider covering tracks. A deletion that skips it
belongs to the people who answer for the case, so the team decided "leads,
and owners in their own area" (docs/DECISIONS.md › D7). The rule is
`routes.rs › purge_allowed`, the same shape as DRM's `original_allowed`.

**Evidence and holds** refuse in the files store itself
(`files_store.rs › evidence_refusal`), in the same words the Trash uses:
an evidence case's files are never deleted, and a legal hold deletes
nothing until two leads lift it.

## What Delete forever takes

`POST …/files/purge` (`files_store.rs › files_purge`) takes:

- **Named files**, live or already in the Trash.
- **Named folders, with everything beneath them.** That means subfolders,
  their files, and a file someone trashed on its own from inside: a folder
  takes what is inside it, as Shift+Delete does.
- **For Empty Trash (`{ trash: true }`), exactly what the Trash holds.**
  Nothing living goes, not even a stray left in a trashed folder;
  housekeeping moves strays back to the top (docs/ORPHANS.md).

With each file go:

- **Every version's sealed bytes**, from the bucket.
- **Its share links.** They are revoked at once, and each link's sealed
  copy is deleted. A link still being uploaded has its multipart upload
  aborted. Before this, a link outlived a deleted file until its expiry.
- **A new version still uploading into the file**: the upload is aborted.
- **The rows that hang off it** (`member.rs › purge_dependents`, the same
  list the Trash's purge uses): its wrapped content keys, music and video
  metadata, watch positions, contributors, and protected copies with
  their sealed keys.

## The order

Each step leaves storage in a state that can be finished later:

1. **Mark.** The items get one mark (`trashed_with = purge:<uuid>`) and
   go to the Trash if they were not there already. Every later step reads
   that one predicate, so a folder of 100 000 files never meets the SQL
   bound-parameter ceiling. Ids are named 50 to a statement.
2. **Queue every object for deletion** in the deletion outbox, before the
   rows that point to them go. The row is the last pointer to an object:
   delete it first, and a failed S3 delete leaves an object nothing will
   ever find. This is the Trash purge's order (commit 25, O10).
3. **Delete the rows.** Shares are revoked; housekeeping removes revoked
   share rows a day later.
4. **Write the trail.** One line per item named (`file.purge`,
   `folder.purge`), then the total (`files.purge` or `trash.empty`,
   `files:N,folders:M,sharesRevoked:K`). The change feed's triggers write
   `file.purge` and `folder.purge`, so a synced device removes its copies.
5. **Drain the outbox.** A delete the storage refuses stays queued, and
   housekeeping retries it (Team › Status shows any pending).

## Asked first

The same request with `preview: true` returns `{ files, folders, shares }`
and changes nothing. The browser can't see inside a folder that isn't
listed, so the server counts what would go. The prompt
(`shared.ts › deleteForever`, `emptyTrash`) then says it:

> Delete “notes.txt” forever?
>
> It skips the Trash and cannot be restored: every version goes, from
> storage too.
>
> 2 share links to it stop working now.

A folder adds "That is 12 files and 3 folders, with everything inside
the folders." Only links that work now are counted. One still being
uploaded works for nobody yet, though it is revoked all the same.

## In the explorers

Delete forever is offered only where the server would allow it
(`model.ts › canPurge`: a lead, or the member's own area, never evidence).
A legal hold the browser can't know about is refused in the server's
words.

| | Windows | Finder |
|---|---|---|
| A file's or folder's menu | Delete forever… (under Delete) | Delete Forever… (under Move to Trash) |
| A folder in the tree or the sidebar | Delete forever… | Delete Forever… |
| An item in the Trash | Delete forever… (under Restore) | Delete Forever… (under Put Back) |
| The Trash itself, or its empty space | Empty Trash… | Empty Trash… |
| Keys | Shift+Delete; Delete in the Trash | ⌥⌘⌫; ⌘⌫ in the Trash |
| The toolbar's 🗑 in the Trash | deletes forever (asked first) | deletes forever (asked first) |

Each key asks first. To someone who may not delete forever, the keys say
why ("Only a lead deletes forever here — Delete moves it to the Trash").

## Tests

- `api:purge`: who may and who may not; the preview; a file with two
  versions and two links leaving nothing in the bucket or the outbox; a
  folder tree; Empty Trash; evidence and a legal hold refusing.
- `rust` (`routes.rs › delete_forever_is_a_leads_act_or_the_owners`): the
  rule.
- `e2e:app`: the item in both explorers, the prompt's words, No keeping
  the file, Yes deleting it, and the same from the Trash.
