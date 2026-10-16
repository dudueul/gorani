// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The production FilesBridge: the session's non-extractable store key does
 * every crypto operation; the API paths carry the member id the shell chose.
 * The model (model.ts) owns *what* to do; this owns *how bytes move*.
 *
 * Multipart uploads follow the same contract the tests exercise: start →
 * parts (one GC01 frame each) → complete; the Worker checks the object adds
 * up before recording it.
 */

import type { DuplicateAnswer, DuplicateQuestion, FilesBridge } from "./model.ts";
import { devIdentityHeaders } from "../../lib/api.ts";
import { areaPath } from "../../lib/area.ts";
import { browserJournal } from "../../lib/upload-journal.ts";
import { openWith, unwrapPlacedKey, type VaultPrivateKey } from "../../vault/vault-crypto.ts";
import { places } from "../../vault/places.ts";
import type { VaultSession } from "../../vault/session.ts";
import type { Signer, Trust } from "../../vault/identity.ts";
import type { IntakeFields } from "../../vault/intake.ts";
import { openChunkedStream } from "../../vault/chunked-file.ts";

export interface FilesHooks {
	confirmDuplicate(question: DuplicateQuestion): Promise<DuplicateAnswer>;
	toast(message: string): void;
	/** The member's signer and trust, once the team context is open (model.ts › FilesBridge.identity). */
	identity?(): { signer: Signer; trust: Trust } | null;
	/** The area's kind, and the intake form evidence uploads need (commit 29g). */
	areaKind?(): "evidence" | "working" | "own" | null;
	intake?(files: File[]): Promise<IntakeFields | null>;
}

/**
 * `openKey` is the area's key source: by default the member's own files
 * store; for a case (commit 27, the area switcher) the case key opened from
 * the member's grant — cases.ts › openCaseKey, signature checked. Either way
 * the key lives only as long as this bridge, and a locked session ends it.
 */
export function sessionBridge(session: VaultSession, hooks: FilesHooks, openKey: () => Promise<VaultPrivateKey> = async () => (await session.openStoreKey("files")).privateKey): FilesBridge {
	let cached: { privateKey: VaultPrivateKey } | null = null;
	const store = async () => {
		// A locked session hands out nothing — not even the store key this
		// bridge already opened (an upload still in flight when Lock is
		// pressed must not finish sealing with it).
		if (session.locked) {
			cached = null;
			throw new Error("the vault is locked");
		}
		if (!cached) {
			// The private key is all a store needs: it opens AND seals (GV04 —
			// a store seals to itself; commit 25). No public half is kept: a
			// public key in hand is exactly the path the server used to have.
			cached = { privateKey: await openKey() };
		}
		return cached;
	};

	return {
		apiGet: <T>(path: string) => fetchJson<T>("GET", path),
		apiSend: <T>(method: "POST" | "PUT" | "PATCH" | "DELETE", path: string, body?: unknown) => fetchJson<T>(method, path, body),
		storePrivate: () => store().then((s) => s.privateKey),
		identityHeaders: devIdentityHeaders,

		async fetchObject(memberId, id, version, range) {
			// `x-gorani-client`: the read log's "from what" (O14) — a label.
			const headers: Record<string, string> = { ...devIdentityHeaders(), "x-gorani-client": "web" };
			if (range) headers.Range = `bytes=${range[0]}-${range[1]}`;
			const res = await fetch(`${areaPath(memberId)}/files/${id}${version ? `?version=${version}` : ""}`, { headers });
			// (The server's own words — "moved to the Trash", "the storage
			// refused this read (HTTP 403 …)" — not just the status, 39t.)
			if (!res.ok && res.status !== 206) await throwIfError(res);
			return {
				body: new Uint8Array(await res.arrayBuffer()),
				ck: res.headers.get("x-gorani-ck") ?? "",
				chunk: Number(res.headers.get("x-gorani-chunk")) || null,
				version: servedVersion(res),
				hash: res.headers.get("x-gorani-hash"),
			};
		},

		async fetchObjectStream(memberId, id, version, sink) {
			const res = await fetch(`${areaPath(memberId)}/files/${id}${version ? `?version=${version}` : ""}`, { headers: { ...devIdentityHeaders(), "x-gorani-client": "web" } });
			// (The server's own words — "moved to the Trash", "the storage
			// refused this read (HTTP 403 …)" — not just the status, 39t.)
			if (!res.ok && res.status !== 206) await throwIfError(res);
			const ck = res.headers.get("x-gorani-ck") ?? "";
			const chunk = Number(res.headers.get("x-gorani-chunk")) || 0;
			const served = servedVersion(res);
			if (version !== undefined && served !== version) throw new Error("download failed: the server answered with another version");
			const hash = res.headers.get("x-gorani-hash");
			const storePriv = await store().then((s) => s.privateKey);
			// The key opens only from the place of THIS file's THIS version (O6).
			const key = await unwrapPlacedKey(storePriv, places.fileKey(memberId, id, served), ck);
			if (!chunk || !res.body) {
				await sink(await openWith(key, new Uint8Array(await res.arrayBuffer())));
				return { version: served, hash };
			}
			// Frames as they arrive: a multi-GB download never holds itself.
			// GC01 frames are NOT GV02 values — this loop used `openWith` (the
			// GV02 opener) on each frame, so every chunked file (> 48 MB) failed
			// to open, and nothing checked frame order or the final flag. The
			// format's streaming reader does both (commit 23).
			const total = Number(res.headers.get("content-length"));
			if (!total) throw new Error("download failed: the object's length is unknown");
			await openChunkedStream(key, res.body, chunk, total, (plain) => sink(plain));
			return { version: served, hash };
		},

		async putWhole(memberId, fields, sealed) {
			const form = formBody(fields, sealed);
			const res = await fetch(`${areaPath(memberId)}/files`, { method: "POST", headers: { ...devIdentityHeaders(), "content-type": form.contentType }, body: form.body });
			await throwIfError(res);
		},

		// A GC01 upload in the model's three steps (D12, FilesModel › sendFrames).
		multipartStart: (memberId, plan) => fetchJson<{ uploadId: string; key: string; parts: number }>("POST", `${areaPath(memberId)}/files/uploads`, plan),
		// One part; what the network lost is sent again, a refusal is not.
		multipartPart: (memberId, uploadId, key, n, frame) => sendPart(`${areaPath(memberId)}/files/uploads/${uploadId}/${n}?key=${encodeURIComponent(key)}`, frame, n),
		async multipartComplete(memberId, uploadId, fields) {
			const form = formBody(fields, null);
			const res = await fetch(`${areaPath(memberId)}/files/uploads/${uploadId}/complete`, {
				method: "POST",
				headers: { ...devIdentityHeaders(), "content-type": form.contentType },
				body: form.body,
			});
			await throwIfError(res);
		},
		// Unfinished uploads, remembered in this browser (31b, lib/upload-journal.ts).
		uploadJournal: browserJournal(),

		confirmDuplicate: hooks.confirmDuplicate,
		toast: hooks.toast,
		identity: () => hooks.identity?.() ?? null,
		areaKind: () => hooks.areaKind?.() ?? null,
		intake: (files) => hooks.intake?.(files) ?? Promise.resolve(null),
	};
}

/** The version a download IS (the Worker's `x-gorani-version`). Missing or
 * malformed is a refusal, not a guess — the key's place depends on it. */
function servedVersion(res: Response): number {
	const v = Number(res.headers.get("x-gorani-version"));
	if (!Number.isInteger(v) || v < 1) throw new Error("download failed: the server did not say which version this is");
	return v;
}

function formBody(fields: Record<string, string>, file: Uint8Array | null): { contentType: string; body: Blob } {
	const boundary = `gorani${[...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
	const parts: string[] = [];
	for (const [k, v] of Object.entries(fields)) {
		parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`);
	}
	let head = parts.join("");
	if (file) head += `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="sealed.bin"\r\nContent-Type: application/octet-stream\r\n\r\n`;
	const end = `\r\n--${boundary}--\r\n`;
	const blob = new Blob([head, file ? (file as unknown as BlobPart) : new Uint8Array(0), end]);
	return { contentType: `multipart/form-data; boundary=${boundary}`, body: blob };
}

async function fetchJson<T>(method: string, path: string, body?: unknown): Promise<T> {
	const res = await fetch(path, {
		method,
		headers: { ...devIdentityHeaders(), ...(body === undefined ? {} : { "content-type": "application/json" }) },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
	return throwIfError(res);
}

async function throwIfError<T>(res: Response): Promise<T> {
	const text = await res.text();
	let json: unknown = null;
	try {
		json = text ? JSON.parse(text) : null;
	} catch {}
	if (!res.ok) throw new Error((json as { error?: string } | null)?.error ?? `${res.status} ${res.statusText}`);
	return json as T;
}

/**
 * Send one part, retrying what the network lost (D12): up to three tries,
 * 1 s then 4 s apart, for a dropped connection, a 5xx or a 429. A refusal
 * (any other 4xx) is the server's answer, not a hiccup — thrown at once.
 */
async function sendPart(url: string, frame: Uint8Array, n: number): Promise<{ partNumber: number; etag: string }> {
	let lastError: unknown = null;
	for (let attempt = 0; attempt < 3; attempt++) {
		if (attempt) await new Promise((r) => setTimeout(r, 1000 * 4 ** (attempt - 1)));
		let res: Response;
		try {
			res = await fetch(url, {
				method: "PUT",
				headers: { ...devIdentityHeaders(), "content-type": "application/octet-stream" },
				body: frame as unknown as BodyInit, // (TS 5.9 ArrayBufferLike vs ArrayBuffer — the bytes are the same)
			});
		} catch (e) {
			lastError = e; // the network: try again
			continue;
		}
		if (res.ok) return (await res.json()) as { partNumber: number; etag: string };
		if (res.status < 500 && res.status !== 429) await throwIfError(res);
		// (The server's reason when it gave one — a storage refusal names its
		// code, 39s — so "failed three times" says why.)
		lastError = await throwIfError(res).catch((e: unknown) => e);
	}
	throw new Error(`part ${n} failed three times — ${lastError instanceof Error ? lastError.message : String(lastError)}`);
}
