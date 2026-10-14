// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Backups, the browser side: the key file (the ONLY copy of the private
 * bundle) and the GB1 reader that verifies/opens a downloaded .gbak in the
 * tab — the Rust twin is crates/formats/src/backup.rs; the vectors keep
 * them byte-identical.
 *
 * Setup story: the browser generates a hybrid key pair, downloads the key
 * file (JSON with the GK1 bundle), and PUTs the public half to the server.
 * The backup job then writes containers the server can never open; restore
 * replays the decrypted rows/objects through the normal sealed-upload paths.
 */

import { generateHybridKey, importVaultKey, openText, importContentKey, type VaultPrivateKey } from "./vault-crypto.ts";
import { toBase64, fromBase64 } from "../lib/encoding.ts";
import { blobURL, revokeBlobURL } from "../lib/blob-urls.ts";

export interface BackupKeyFile {
	type: "gorani-backup-key";
	v: number;
	keyId: string;
	createdAt: string;
	/** base64 of the GK1 bundle — the private half, never on the server. */
	key: string;
}

/** Generate a backup key pair: download this key file, PUT the public half. */
export async function createBackupKey(): Promise<{ keyFile: BackupKeyFile; publicPut: { keyId: string; publicKey: JsonWebKey; pqPublicKey: string } }> {
	const root = await generateHybridKey();
	const keyFile: BackupKeyFile = { type: "gorani-backup-key", v: 1, keyId: root.keyId, createdAt: new Date().toISOString(), key: toBase64(root.bundle) };
	return { keyFile, publicPut: { keyId: root.keyId, publicKey: root.publicKey, pqPublicKey: root.pqPublicKey } };
}

/** Save the key file. Its blob URL is the most secret handle the app ever
 * mints (the backup's private bundle), so it goes through the tracker like
 * every decrypted byte — a lock in the next five seconds revokes it too. */
export function downloadKeyFile(keyFile: BackupKeyFile): void {
	const url = blobURL(new Blob([JSON.stringify(keyFile, null, "\t")], { type: "application/octet-stream" }));
	const a = document.createElement("a");
	a.href = url;
	a.download = `gorani-backup-key-${keyFile.keyId}.json`;
	a.click();
	setTimeout(() => revokeBlobURL(url), 5000);
}

// ── the GB1 reader (mirrors crates/formats/src/backup.rs) ───────────

const MAGIC = "GBAK1\n";
const SEG_SIZE = 1024 * 1024;
const TAG = 16;

export interface BackupEntry {
	json: Record<string, unknown>;
	object: Uint8Array;
}

export interface ParsedBackup {
	header: Record<string, unknown>;
	entries: BackupEntry[];
}

function aad(seg: number, finalSeg: boolean): Uint8Array {
	const a = new Uint8Array(16);
	a.set(new TextEncoder().encode("GBAK1"), 0);
	a[5] = "1".charCodeAt(0);
	a[6] = "A".charCodeAt(0);
	a[7] = finalSeg ? 1 : 0;
	new DataView(a.buffer).setBigUint64(8, BigInt(seg));
	return a;
}

function nonce(seg: number): Uint8Array {
	const n = new Uint8Array(12);
	new DataView(n.buffer).setBigUint64(4, BigInt(seg));
	return n;
}

/** Parse + decrypt a whole .gbak with the file key from the key file. */
export async function readBackup(bytes: Uint8Array, keyFile: BackupKeyFile): Promise<ParsedBackup> {
	const priv = await importVaultKey(fromBase64(keyFile.key));
	const header = parseHeader(bytes);
	const fileKey = await unwrapFileKey(priv, String(header.wrapped ?? ""));
	return { header, ...(await decryptEntries(bytes, 6 + 4 + (header.__headerLen as number), fileKey)) };
}

function parseHeader(bytes: Uint8Array): Record<string, unknown> {
	const magic = new TextDecoder().decode(bytes.subarray(0, 6));
	if (magic !== MAGIC) throw new Error("Not a gorani backup");
	const len = new DataView(bytes.buffer, bytes.byteOffset + 6, 4).getUint32(0);
	const header = JSON.parse(new TextDecoder().decode(bytes.subarray(10, 10 + len))) as Record<string, unknown> & { __headerLen?: number };
	header.__headerLen = len;
	return header;
}

async function unwrapFileKey(priv: VaultPrivateKey, wrapped: string): Promise<CryptoKey> {
	const raw = fromBase64(await openText(priv, wrapped));
	return importContentKey(raw);
}

async function decryptEntries(bytes: Uint8Array, at: number, fileKey: CryptoKey): Promise<{ entries: BackupEntry[] }> {
	const stream = new Uint8Array(bytes.length - at);
	let seg = 0;
	let written = 0;
	for (let pos = at; pos < bytes.length; ) {
		const remaining = bytes.length - pos;
		const [payloadLen, finalSeg] = remaining <= 12 + SEG_SIZE + TAG ? [remaining - 12 - TAG, true] : [SEG_SIZE, false];
		const claimed = new DataView(bytes.buffer, bytes.byteOffset + pos + 4, 8).getBigUint64(0);
		if (claimed !== BigInt(seg)) throw new Error("Backup segments are out of order");
		const plain = new Uint8Array(await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: bytes.subarray(pos, pos + 12) as BufferSource, additionalData: aad(seg, finalSeg) as BufferSource },
			fileKey,
			bytes.subarray(pos + 12, pos + 12 + payloadLen + TAG) as BufferSource,
		));
		stream.set(plain, written);
		written += plain.length;
		pos += 12 + payloadLen + TAG;
		seg++;
		if (finalSeg && pos !== bytes.length) throw new Error("Backup has bytes after the final segment");
	}
	// Walk the entry stream: jsonLen(4) + json + objectLen(8) + object.
	const entries: BackupEntry[] = [];
	let cursor = 0;
	const view = new DataView(stream.buffer, 0, written);
	while (cursor + 4 <= written) {
		const jsonLen = view.getUint32(cursor);
		cursor += 4;
		if (cursor + jsonLen > written) throw new Error("Backup entry JSON is cut short");
		const json = JSON.parse(new TextDecoder().decode(stream.subarray(cursor, cursor + jsonLen))) as Record<string, unknown>;
		cursor += jsonLen;
		if (cursor + 8 > written) throw new Error("Backup entry object length is cut short");
		const objLen = Number(view.getBigUint64(cursor));
		cursor += 8;
		if (cursor + objLen > written) throw new Error("Backup entry object is cut short");
		entries.push({ json, object: stream.subarray(cursor, cursor + objLen) });
		cursor += objLen;
	}
	if (cursor !== written) throw new Error("Backup stream has trailing bytes");
	return { entries };
}