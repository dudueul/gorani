// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Folder paths, decorator-free (like place.ts): the model uses them — the
 * duplicate prompt says where the copy already is — and the model's unit
 * test runs in Node, which cannot load the Lit components in shared.ts.
 */

/** A folder as the menus and prompts need it: its id, its parent, its name. */
export interface TreeFolder {
	id: string;
	parent?: string | null;
	name: string;
}

/** "Holiday › 2026 › Beach": a folder's whole path, so a list with two
 * folders called "2026" says which is which. */
export function folderPath(tree: TreeFolder[], id: string): string {
	const names: string[] = [];
	for (let cur: string | null = id; cur && names.length < 64; cur = tree.find((f) => f.id === cur)?.parent ?? null) {
		names.unshift(tree.find((f) => f.id === cur)?.name ?? "…");
	}
	return names.join(" › ");
}
