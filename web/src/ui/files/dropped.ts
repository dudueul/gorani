// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a drop or a folder picker hands the explorer, as a tree to upload
 * (commit 39r, docs/UPLOADS.md).
 *
 * `DataTransfer.files` lists only the TOP of a drop: a dropped folder
 * appears there as one empty "file" named after it, and its contents are
 * not there at all. The contents come through the entries API instead —
 * `item.webkitGetAsEntry()` (every current browser has it, under that
 * name), walked directory by directory. Two traps it sets:
 *
 *   - the entries must be taken DURING the drop event: once the handler
 *     returns, the DataTransfer is emptied and every item reads as nothing.
 *     `entriesOf` is synchronous for that reason; the walk comes after;
 *   - `readEntries` answers in batches (Chrome: 100 at a time) and must be
 *     called again until it answers with none — a folder of 250 photos
 *     read once would upload 100 of them, silently.
 *
 * The folder picker (`<input webkitdirectory>`) instead gives every file
 * with its `webkitRelativePath`, "Holiday/day 1/IMG_0001.jpg".
 *
 * No decorators here, so tests/unit/explorer.test.ts loads it in Node.
 */

/** One file and the folders above it, from the drop's top level down. */
export interface PickedFile {
	file: File;
	dir: string[];
}

export interface PickedTree {
	files: PickedFile[];
	/** Every folder met, parents before children — empty ones included,
	 * so a dropped folder arrives with its whole shape. */
	dirs: string[][];
	/** Names left out, and why: the operating systems' own litter. */
	skipped: string[];
}

/**
 * Files the operating systems write into folders on their own — Finder's
 * view settings, Windows' thumbnail caches and folder settings, and the
 * "._" AppleDouble halves macOS leaves on non-Mac disks. Nobody means to
 * keep them, and every one would be sealed, stored and listed. (The same
 * list the sync clients' engines skip.)
 */
export function isLitter(name: string): boolean {
	return name === ".DS_Store" || name === "Thumbs.db" || name === "ehthumbs.db" || name === "desktop.ini" || name.startsWith("._");
}

/** How many files one drop may hold — beyond it, the drop is refused whole
 * rather than uploaded part-way (the person meant the whole folder). */
export const MAX_DROPPED_FILES = 10_000;
/** How deep a dropped tree may go (a link loop on some systems is endless). */
export const MAX_DEPTH = 32;

/** The minimal entry shapes the walk needs (FileSystemEntry and friends). */
export interface EntryLike {
	name: string;
	isFile: boolean;
	isDirectory: boolean;
}
export interface FileEntryLike extends EntryLike {
	file(ok: (f: File) => void, fail?: (e: unknown) => void): void;
}
export interface DirEntryLike extends EntryLike {
	createReader(): { readEntries(ok: (entries: EntryLike[]) => void, fail?: (e: unknown) => void): void };
}

/**
 * The drop's entries, taken NOW (see above). `entries` is null where the
 * browser has no entries API, or the drop came from a page rather than the
 * system (a synthetic DataTransfer) — then `files` is all there is, and a
 * folder in it cannot be told from a file.
 */
export function entriesOf(dt: DataTransfer): { entries: EntryLike[] | null; files: File[] } {
	const files = [...(dt.files ?? [])];
	const items = [...(dt.items ?? [])].filter((i) => i.kind === "file");
	const get = (i: DataTransferItem) => (typeof i.webkitGetAsEntry === "function" ? (i.webkitGetAsEntry() as EntryLike | null) : null);
	const entries = items.map(get);
	if (!items.length || entries.some((e) => e === null)) return { entries: null, files };
	return { entries: entries as EntryLike[], files };
}

/** Did the drag carry files from outside the page (not our own items)? */
export function carriesFiles(dt: DataTransfer | null): boolean {
	return Boolean(dt && [...(dt.types ?? [])].includes("Files"));
}

/** Walk the entries into a tree. */
export async function walkEntries(entries: EntryLike[]): Promise<PickedTree> {
	const tree: PickedTree = { files: [], dirs: [], skipped: [] };
	const visit = async (entry: EntryLike, dir: string[]): Promise<void> => {
		if (isLitter(entry.name)) {
			tree.skipped.push([...dir, entry.name].join("/"));
			return;
		}
		if (entry.isFile) {
			if (tree.files.length >= MAX_DROPPED_FILES) throw new Error(`a drop holds at most ${MAX_DROPPED_FILES.toLocaleString("en")} files — upload this folder in parts, or with gorani-sync`);
			const file = await new Promise<File>((ok, fail) => (entry as FileEntryLike).file(ok, fail));
			tree.files.push({ file, dir });
		} else if (entry.isDirectory) {
			const here = [...dir, entry.name];
			if (here.length > MAX_DEPTH) throw new Error(`“${here.join("/")}” is more than ${MAX_DEPTH} folders deep`);
			tree.dirs.push(here);
			for (const child of await readAll(entry as DirEntryLike)) await visit(child, here);
		}
	};
	for (const e of entries) await visit(e, []);
	return tree;
}

/** Every entry of a directory: readEntries again until it answers empty. */
async function readAll(dir: DirEntryLike): Promise<EntryLike[]> {
	const reader = dir.createReader();
	const all: EntryLike[] = [];
	for (;;) {
		const batch = await new Promise<EntryLike[]>((ok, fail) => reader.readEntries(ok, fail));
		if (!batch.length) return all.sort((a, b) => a.name.localeCompare(b.name));
		all.push(...batch);
	}
}

/** A drop without entries: just its files (a folder among them is skipped —
 * an entry-less browser shows it as an empty, typeless "file"). */
export function plainFiles(files: File[]): PickedTree {
	const tree: PickedTree = { files: [], dirs: [], skipped: [] };
	for (const file of files) {
		if (isLitter(file.name)) tree.skipped.push(file.name);
		else tree.files.push({ file, dir: [] });
	}
	return tree;
}

/** The folder picker's files, by their `webkitRelativePath`. */
export function fromRelativePaths(files: File[]): PickedTree {
	const tree: PickedTree = { files: [], dirs: [], skipped: [] };
	const seen = new Set<string>();
	if (files.length > MAX_DROPPED_FILES) throw new Error(`a folder upload holds at most ${MAX_DROPPED_FILES.toLocaleString("en")} files — upload this folder in parts, or with gorani-sync`);
	for (const file of files) {
		const parts = (file.webkitRelativePath || file.name).split("/").filter(Boolean);
		const dir = parts.slice(0, -1);
		if (parts.some(isLitter)) {
			tree.skipped.push(parts.join("/"));
			continue;
		}
		if (dir.length > MAX_DEPTH) throw new Error(`“${dir.join("/")}” is more than ${MAX_DEPTH} folders deep`);
		for (let d = 1; d <= dir.length; d++) {
			const key = dir.slice(0, d).join("/");
			if (!seen.has(key)) {
				seen.add(key);
				tree.dirs.push(dir.slice(0, d));
			}
		}
		tree.files.push({ file, dir });
	}
	return tree;
}
