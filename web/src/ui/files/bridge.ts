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

import type { FilesBridge } from "./model.ts";
import { devIdentityHeaders } from "../../lib/api.ts";
import { openWith, unwrapContentKey, type VaultPrivateKey, type SealTarget } from "../../vault/vault-crypto.ts";
import type { VaultSession } from "../../vault/session.ts";
import { openChunkedStream } from "../../vault/chunked-file.ts";

export interface FilesHooks {
	confirmDuplicate(count: number): Promise<"skip" | "keep" | "version" | null>;
	toast(message: string): void;
}

export function sessionBridge(session: VaultSession, hooks: FilesHooks): FilesBridge {
	let cached: { privateKey: VaultPrivateKey; publicKey: SealTarget } | null = null;
	const store = async () => {
		// A locked session hands out nothing — not even the store key this
		// bridge already opened (an upload still in flight when Lock is
		// pressed must not finish sealing with it).
		if (session.locked) {
			cached = null;
			throw new Error("the vault is locked");
		}
		if (!cached) {
			const opened = await session.openStoreKey("files");
			// The store key's public half is hybrid (GV03) — seal with both halves.
			cached = {
				privateKey: opened.privateKey,
				publicKey: opened.pqPublicKey ? { ec: opened.publicKey, kem: opened.pqPublicKey } : opened.publicKey,
			};
		}
		return cached;
	};

	return {
		apiGet: <T>(path: string) => fetchJson<T>("GET", path),
		apiSend: <T>(method: "POST" | "PUT" | "PATCH" | "DELETE", path: string, body?: unknown) => fetchJson<T>(method, path, body),
		storePrivate: () => store().then((s) => s.privateKey),
		storePublic: () => store().then((s) => s.publicKey),

		async fetchObject(memberId, id, version, range) {
			const headers: Record<string, string> = { ...devIdentityHeaders() };
			if (range) headers.Range = `bytes=${range[0]}-${range[1]}`;
			const res = await fetch(`/api/v1/members/${memberId}/files/${id}${version ? `?version=${version}` : ""}`, { headers });
			if (!res.ok && res.status !== 206) throw new Error(`download failed: ${res.status}`);
			return {
				body: new Uint8Array(await res.arrayBuffer()),
				ck: res.headers.get("x-gorani-ck") ?? "",
				chunk: Number(res.headers.get("x-gorani-chunk")) || null,
			};
		},

		async fetchObjectStream(memberId, id, version, sink) {
			const res = await fetch(`/api/v1/members/${memberId}/files/${id}${version ? `?version=${version}` : ""}`, { headers: devIdentityHeaders() });
			if (!res.ok && res.status !== 206) throw new Error(`download failed: ${res.status}`);
			const ck = res.headers.get("x-gorani-ck") ?? "";
			const chunk = Number(res.headers.get("x-gorani-chunk")) || 0;
			const storePriv = await store().then((s) => s.privateKey);
			const key = await unwrapContentKey(storePriv, ck);
			if (!chunk || !res.body) {
				await sink(await openWith(key, new Uint8Array(await res.arrayBuffer())));
				return;
			}
			// Frames as they arrive: a multi-GB download never holds itself.
			// GC01 frames are NOT GV02 values — this loop used `openWith` (the
			// GV02 opener) on each frame, so every chunked file (> 48 MB) failed
			// to open, and nothing checked frame order or the final flag. The
			// format's streaming reader does both (commit 23).
			const total = Number(res.headers.get("content-length"));
			if (!total) throw new Error("download failed: the object's length is unknown");
			await openChunkedStream(key, res.body, chunk, total, (plain) => sink(plain));
		},

		async putWhole(memberId, fields, sealed) {
			const form = formBody(fields, sealed);
			const res = await fetch(`/api/v1/members/${memberId}/files`, { method: "POST", headers: { ...devIdentityHeaders(), "content-type": form.contentType }, body: form.body });
			await throwIfError(res);
		},

		async putMultipart(memberId, fields, sealed, chunk) {
			const start = await fetchJson<{ uploadId: string; key: string; parts: number }>("POST", `/api/v1/members/${memberId}/files/uploads`, { size: Number(fields.size), chunk });
			const frames = Math.ceil(sealed.length / (chunk + 28));
			const parts: { partNumber: number; etag: string }[] = [];
			for (let p = 1; p <= frames; p++) {
				const frame = sealed.subarray((p - 1) * (chunk + 28), Math.min(sealed.length, p * (chunk + 28)));
				const res = await fetch(`/api/v1/members/${memberId}/files/uploads/${start.uploadId}/${p}?key=${encodeURIComponent(start.key)}`, {
					method: "PUT",
					headers: { ...devIdentityHeaders(), "content-type": "application/octet-stream" },
					body: frame as unknown as BodyInit, // (TS 5.9 ArrayBufferLike vs ArrayBuffer — the bytes are the same)
				});
				await throwIfError(res);
				parts.push((await res.json()) as { partNumber: number; etag: string });
			}
			const form = formBody({ ...fields, key: start.key, parts: JSON.stringify(parts) }, null);
			const res = await fetch(`/api/v1/members/${memberId}/files/uploads/${start.uploadId}/complete`, {
				method: "POST",
				headers: { ...devIdentityHeaders(), "content-type": form.contentType },
				body: form.body,
			});
			await throwIfError(res);
		},

		confirmDuplicate: hooks.confirmDuplicate,
		toast: hooks.toast,
	};
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