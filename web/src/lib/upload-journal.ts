// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The upload journal (D12, docs/LARGE-FILES.md › 31b): what an unfinished
 * multipart upload needs to continue after a dropped connection or a
 * closed tab — kept in this browser, never on the server.
 *
 * ```text
 * key     = fingerprint(name ‖ size ‖ modified ‖ SHA-256)   (the model's keyed tag: no plaintext at rest)
 * record  = { area, fileId, uploadId, objectKey, chunk, size, fields, parts: [{ partNumber, etag }], startedAt }
 * fields  = the upload's form fields — every one already sealed (name, type, content key,
 *           signed hash, intake) or public (ids, sizes, the duplicate tag)
 * ```
 *
 * Nothing here opens anything: the content key in `fields.ck` is sealed
 * to the store key, so resuming needs the vault unlocked, like uploading.
 * Choosing the same file again (same name, size, modified time AND the
 * same SHA-256 — the hash pass runs first anyway) finds the record, and
 * the upload continues from its first missing part with the SAME file id,
 * key and signed record: the frames already stored were sealed with them.
 *
 * The server forgets an unfinished upload after the housekeeping window
 * (`UPLOAD_DAYS`); a record older than that fails at completion and is
 * dropped — the upload then starts over, which is the honest outcome.
 */

export interface UploadRecord {
	area: string;
	fileId: string;
	uploadId: string;
	objectKey: string;
	chunk: number;
	size: number;
	fields: Record<string, string>;
	parts: { partNumber: number; etag: string }[];
	startedAt: string;
}

export interface UploadJournal {
	get(key: string): Promise<UploadRecord | null>;
	put(key: string, record: UploadRecord): Promise<void>;
	delete(key: string): Promise<void>;
	/** Every unfinished upload in an area (to say so, or to discard them). */
	list(area: string): Promise<{ key: string; record: UploadRecord }[]>;
}

/** A journal in memory (tests; a browser without IndexedDB). */
export function memoryJournal(): UploadJournal {
	const m = new Map<string, UploadRecord>();
	return {
		get: async (k) => structuredClone(m.get(k) ?? null),
		put: async (k, r) => void m.set(k, structuredClone(r)),
		delete: async (k) => void m.delete(k),
		list: async (area) => [...m].filter(([, r]) => r.area === area).map(([key, record]) => ({ key, record: structuredClone(record) })),
	};
}

const DB = "gorani-uploads";
const STORE = "journal";

function db(): Promise<IDBDatabase> {
	return new Promise((resolve, reject) => {
		const open = indexedDB.open(DB, 1);
		open.onupgradeneeded = () => open.result.createObjectStore(STORE);
		open.onsuccess = () => resolve(open.result);
		open.onerror = () => reject(open.error);
	});
}

async function tx<T>(mode: IDBTransactionMode, run: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
	const d = await db();
	return new Promise((resolve, reject) => {
		const t = d.transaction(STORE, mode);
		const r = run(t.objectStore(STORE));
		t.oncomplete = () => (d.close(), resolve(r.result));
		t.onerror = () => (d.close(), reject(t.error));
	});
}

/** The browser's journal: IndexedDB, falling back to memory where it is missing. */
export function browserJournal(): UploadJournal {
	if (typeof indexedDB === "undefined") return memoryJournal();
	return {
		get: async (k) => ((await tx("readonly", (s) => s.get(k))) as UploadRecord | undefined) ?? null,
		put: async (k, r) => void (await tx("readwrite", (s) => s.put(r, k))),
		delete: async (k) => void (await tx("readwrite", (s) => s.delete(k))),
		async list(area) {
			const keys = (await tx("readonly", (s) => s.getAllKeys())) as string[];
			const out: { key: string; record: UploadRecord }[] = [];
			for (const key of keys) {
				const record = (await tx("readonly", (s) => s.get(key))) as UploadRecord | undefined;
				if (record?.area === area) out.push({ key, record });
			}
			return out;
		},
	};
}
