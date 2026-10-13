// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The index client: owns the worker, the request/response correlation, and
 * the encrypted snapshot's IndexedDB slot. One per unlocked session; closed
 * on lock (the worker's memory — the decrypted names — dies with it).
 *
 * ```text
 * open(memberId, indexKey) ─▶ worker init (decrypt snapshot) ─▶ ready
 * upsert/remove  ◀── the model feeds it on every listing and change
 * search/recents ─▶ instant, no server
 * save (debounced) ─▶ worker encrypts ─▶ IndexedDB ─▶ done
 * ```
 */

import type { IndexEntry, SearchHit } from "./index-engine.ts";

export interface LocalIndexLike {
	upsert(entries: IndexEntry[]): void;
	remove(ids: string[]): void;
	search(q: string, limit?: number): Promise<SearchHit[]>;
	recents(limit?: number): Promise<IndexEntry[]>;
	close(): Promise<void>;
}

const DB = "gorani-index";

async function idbLoad(memberId: string): Promise<ArrayBuffer | null> {
	return new Promise((resolve, reject) => {
		const open = indexedDB.open(DB, 1);
		open.onupgradeneeded = () => open.result.createObjectStore("kv");
		open.onsuccess = () => {
			const tx = open.result.transaction("kv", "readonly");
			const r = tx.objectStore("kv").get(`index:${memberId}`);
			r.onsuccess = () => resolve((r.result as ArrayBuffer | undefined) ?? null);
			r.onerror = () => reject(r.error);
		};
		open.onerror = () => reject(open.error);
	});
}

async function idbStore(memberId: string, ciphertext: ArrayBuffer): Promise<void> {
	await new Promise<void>((resolve, reject) => {
		const open = indexedDB.open(DB, 1);
		open.onupgradeneeded = () => open.result.createObjectStore("kv");
		open.onsuccess = () => {
			const tx = open.result.transaction("kv", "readwrite");
			tx.objectStore("kv").put(ciphertext, `index:${memberId}`);
			tx.oncomplete = () => resolve();
			tx.onerror = () => reject(tx.error);
		};
		open.onerror = () => reject(open.error);
	});
}

export class LocalIndex implements LocalIndexLike {
	private worker: Worker;
	private seq = 0;
	private pending = new Map<number, { resolve: (v: never) => void; reject: (e: Error) => void }>();
	private saveTimer: ReturnType<typeof setTimeout> | undefined;
	private closed = false;

	private constructor(private readonly memberId: string, worker: Worker, count: number) {
		this.worker = worker;
		void count;
		this.worker.onmessage = (event: MessageEvent) => {
			const msg = event.data as { type: string; id?: number; message?: string; ciphertext?: ArrayBuffer };
			// The snapshot lands in IndexedDB here, then resolves the save call.
			if (msg.type === "snapshot" && msg.ciphertext) void idbStore(this.memberId, msg.ciphertext);
			if (msg.type === "error") {
				const p = msg.id !== undefined ? this.pending.get(msg.id) : undefined;
				if (p) {
					this.pending.delete(msg.id!);
					p.reject(new Error(msg.message ?? "index error"));
				}
				return;
			}
			if (msg.id !== undefined) {
				const p = this.pending.get(msg.id);
				if (p) {
					this.pending.delete(msg.id);
					p.resolve(msg as never);
				}
			}
		};
	}

	/** Open (or start fresh) for one unlocked member. */
	static async open(memberId: string, indexKey: CryptoKey): Promise<LocalIndex> {
		const worker = new Worker(new URL("./index.worker.ts", import.meta.url), { type: "module" });
		const snapshot = await idbLoad(memberId);
		const ready = new Promise<number>((resolve, reject) => {
			worker.onmessage = (event: MessageEvent) => {
				const msg = event.data as { type: string; count?: number; message?: string };
				if (msg.type === "ready") resolve(msg.count ?? 0);
				else if (msg.type === "error") reject(new Error(msg.message ?? "index init failed"));
			};
			worker.onerror = (e) => reject(new Error(e.message));
		});
		worker.postMessage({ type: "init", key: indexKey, snapshot });
		const count = await ready;
		const index = new LocalIndex(memberId, worker, count);
		return index;
	}

	/** Feed entries from a listing (the model calls this after decrypting). */
	upsert(entries: IndexEntry[]): void {
		if (this.closed || !entries.length) return;
		this.worker.postMessage({ type: "upsert", entries });
		this.scheduleSave();
	}

	remove(ids: string[]): void {
		if (this.closed || !ids.length) return;
		this.worker.postMessage({ type: "remove", ids });
		this.scheduleSave();
	}

	search(q: string, limit = 50): Promise<SearchHit[]> {
		return this.call<SearchHit[]>("results", { type: "search", q, limit });
	}

	recents(limit = 30): Promise<IndexEntry[]> {
		return this.call<IndexEntry[]>("recents", { type: "recents", limit });
	}

	/** Persistence is the worker's job (it holds the key); this just awaits
	 * the encrypted snapshot and drops it in IndexedDB. */

	/** Persist (debounced) and stop the worker. */
	async close(): Promise<void> {
		if (this.closed) return;
		this.closed = true;
		if (this.saveTimer) clearTimeout(this.saveTimer);
		await this.saveNow();
		this.worker.terminate();
	}

	private scheduleSave(): void {
		if (this.saveTimer) clearTimeout(this.saveTimer);
		this.saveTimer = setTimeout(() => void this.saveNow(), 1500);
	}

	private saveNow(): Promise<void> {
		return this.call<void>("snapshot", { type: "save" });
	}

	private call<R>(expect: string, msg: Record<string, unknown>): Promise<R> {
		const id = ++this.seq;
		return new Promise<R>((resolve, reject) => {
			this.pending.set(id, { resolve: (v: never) => resolve(v as R), reject });
			this.worker.postMessage({ ...msg, id });
			setTimeout(() => {
				if (this.pending.has(id)) {
					this.pending.delete(id);
					reject(new Error(`index ${expect} timed out`));
				}
			}, 5000);
		});
	}
}