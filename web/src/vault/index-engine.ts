// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The local search index engine — pure, testable in Node, no DOM, no Worker
 * APIs. The worker (index.worker.ts) runs it; the main thread talks to it
 * through index.ts.
 *
 * What it is: an in-memory map of everything the member's listings have
 * shown this device — ids, decrypted names, folders, timestamps — searchable
 * instantly, with no server round-trip. What it is NOT: a copy of the vault.
 * It holds *names and paths* (the only plaintext the browser ever has) and
 * lives in one worker's memory.
 *
 * Persistence, the "untrackable" part (docs/COURSE.md, Lesson 9):
 *
 * ```text
 * unlock (passkey / password / recovery) ──▶ root key ──▶ indexKey (deriveIndexKey)
 *                                                              │ AES-256-GCM
 * snapshot (JSON of the entries) ──encrypt──▶ IndexedDB ◀──────┘
 * ```
 *
 * The snapshot is ciphertext at rest in the browser; the key exists only
 * between unlock and lock, and is derived from the vault root — which only
 * an unlock ceremony (a passkey's PRF output, an Argon2id password, a
 * recovery code) can produce. A copied IndexedDB is a random blob. Nothing
 * is sent anywhere; the server never sees a query.
 */

export interface IndexEntry {
	id: string;
	kind: "file" | "folder";
	folderId: string | null;
	name: string;
	updatedAt: number; // epoch ms
	size?: number;
}

export interface SearchHit extends IndexEntry {
	rank: number;
}

export class IndexEngine {
	private entries = new Map<string, IndexEntry>();

	get size(): number {
		return this.entries.size;
	}

	upsert(list: IndexEntry[]): void {
		for (const e of list) this.entries.set(e.id, e);
	}

	remove(ids: string[]): void {
		for (const id of ids) this.entries.delete(id);
	}

	/** Search names: prefix beats word-start beats substring; recents break ties. */
	search(query: string, limit = 50): SearchHit[] {
		const q = query.trim().toLowerCase();
		if (!q) return [];
		const hits: SearchHit[] = [];
		for (const e of this.entries.values()) {
			const name = e.name.toLowerCase();
			let rank: number | null = null;
			if (name.startsWith(q)) rank = 0;
			else if (name.includes(q)) {
				// A word-start match reads better than a mid-word one.
				const at = name.indexOf(q);
				rank = at > 0 && /[\s._\-[(]/.test(name[at - 1] ?? "") ? 1 : 2;
			}
			if (rank === null) continue;
			hits.push({ ...e, rank });
		}
		hits.sort((a, b) => a.rank - b.rank || b.updatedAt - a.updatedAt || a.name.localeCompare(b.name));
		return hits.slice(0, limit);
	}

	/** The most recently touched entries (the Recents view, both OSes have one). */
	recents(limit = 30): IndexEntry[] {
		return [...this.entries.values()].filter((e) => e.kind === "file").sort((a, b) => b.updatedAt - a.updatedAt).slice(0, limit);
	}

	serialize(): Uint8Array {
		return new TextEncoder().encode(JSON.stringify({ v: 1, entries: [...this.entries.values()] }));
	}

	load(bytes: Uint8Array): void {
		const data = JSON.parse(new TextDecoder().decode(bytes)) as { v: number; entries: IndexEntry[] };
		if (data.v !== 1) throw new Error("unknown index snapshot version");
		this.entries = new Map(data.entries.map((e) => [e.id, e]));
	}

	clear(): void {
		this.entries.clear();
	}
}