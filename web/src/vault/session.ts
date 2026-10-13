// Copyright 2026- Seongwoo Hong. All rights reserved.
// The device-hold design follows Mailflare's vault session (Apache 2.0, ©
// Cloudflare, Inc.); see NOTICE.

/**
 * The unlocked session (docs/VAULT.md › In the browser). What "unlocked"
 * means, exactly:
 *
 * ```text
 * unlock secret ──▶ GW1-open ──▶ root bundle (bytes, for an instant)
 *                              ──▶ importKey NON-EXTRACTABLE ──▶ the session's root
 * store keys  ◀── opened on demand from the root, imported non-extractable, bytes wiped
 * ```
 *
 * A page script can *use* the root (open store keys, open content) but can
 * never *read* it — the P-256 half lives in WebCrypto's non-extractable key
 * object. Locking drops all of it; nothing persists unless you chose
 * "stay unlocked".
 *
 * **Device hold** ("stay unlocked within the auto-lock window", per browser):
 * a fresh non-extractable AES-GCM device key in IndexedDB, the root bundle
 * encrypted under it (`hold`), this tab's copy in sessionStorage for reloads.
 * A relaunch inside the window decrypts and re-imports — the bundle exists as
 * bytes only for the instant of import. Expiry slides while the app is
 * visible. "Ask on relaunch" (the default) stores nothing at all.
 *
 * | Threat | Answer |
 * |---|---|
 * | Script in the page while unlocked | can use keys, not read them; locking ends it |
 * | Stolen browser profile on "Ask" | nothing stored; nothing opens |
 * | Stolen profile on "Stay", inside the window | the device key is in the profile's IndexedDB — *this* is the limit; "Ask" is the answer |
 * | Another origin | IndexedDB is per-origin; the strict CSP keeps scripts out |
 */

import { importVaultKey, deriveIndexKey, type VaultPrivateKey } from "./vault-crypto.ts";
import { openStoreKey as openSealedStoreKey } from "./family.ts";
import { toBase64, fromBase64 } from "../lib/encoding.ts";
import type { VaultSettings } from "./methods.ts";

const subtle = () => globalThis.crypto.subtle;

export interface OpenedStoreKey {
	name: string;
	privateKey: VaultPrivateKey;
	publicKey: JsonWebKey;
	pqPublicKey?: string;
	keyId: string;
}

export interface VaultSession {
	readonly memberId: string;
	readonly settings: VaultSettings;
	readonly root: VaultPrivateKey;
	readonly rootKeyId: string;
	/** The local search index's key, derived without the root's bytes. */
	readonly indexKey: Promise<CryptoKey>;
	openStoreKey(name: string): Promise<OpenedStoreKey>;
	lock(): void;
}

/** Per-session store-key caches, kept out of the interface by a WeakMap. */
const caches = new WeakMap<VaultSession, Map<string, OpenedStoreKey>>();
const lockListeners = new Set<() => void>();

/** Called when the session locks (the UI switches to the lock screen). */
export function onLock(listener: () => void): () => void {
	lockListeners.add(listener);
	return () => lockListeners.delete(listener);
}

/** A session from an opened root bundle: import non-extractable, wire stores. */
export async function openSession(memberId: string, settings: VaultSettings, bundle: Uint8Array): Promise<VaultSession> {
	const root = await importVaultKey(bundle);
	bundle.fill(0); // the bytes are gone the instant the key exists
	const cache = new Map<string, OpenedStoreKey>();
	const session: VaultSession = {
		memberId,
		settings,
		root,
		rootKeyId: settings.keyId,
		indexKey: deriveIndexKey(root, settings.publicKey),
		async openStoreKey(name: string) {
			const cached = cache.get(name);
			if (cached) return cached;
			const key = settings.stores[name];
			if (!key) throw new Error(`no store key named ${name}`);
			const privateKey = await openSealedStoreKey(root, key);
			const opened: OpenedStoreKey = { name, privateKey, publicKey: key.publicKey, pqPublicKey: key.pqPublicKey, keyId: key.keyId };
			cache.set(name, opened);
			return opened;
		},
		lock() {
			void forgetOnDevice(memberId);
			cache.clear();
			for (const l of [...lockListeners]) l();
		},
	};
	caches.set(session, cache);
	return session;
}

// ── the device hold ─────────────────────────────────────────────────

const DB = "gorani-vault-device";
const HOLD_MS = 10 * 60 * 1000; // the auto-lock window

/** The hold record: the root bundle encrypted under a non-extractable device key. */
export interface DeviceHold {
	keyId: string; // the root key this hold belongs to
	iv: string; // base64
	ct: string; // base64 (the root bundle)
	exp: number; // epoch ms
}

async function db(): Promise<IDBDatabase> {
	return new Promise((resolve, reject) => {
		const open = indexedDB.open(DB, 1);
		open.onupgradeneeded = () => open.result.createObjectStore("kv");
		open.onsuccess = () => resolve(open.result);
		open.onerror = () => reject(open.error);
	});
}

async function idbPut(key: string, value: unknown): Promise<void> {
	const d = await db();
	await new Promise<void>((resolve, reject) => {
		const tx = d.transaction("kv", "readwrite");
		tx.objectStore("kv").put(value, key);
		tx.oncomplete = () => resolve();
		tx.onerror = () => reject(tx.error);
	});
	d.close();
}

async function idbGet<T>(key: string): Promise<T | undefined> {
	const d = await db();
	const v = await new Promise<T | undefined>((resolve, reject) => {
		const r = d.transaction("kv", "readonly").objectStore("kv").get(key);
		r.onsuccess = () => resolve(r.result as T | undefined);
		r.onerror = () => reject(r.error);
	});
	d.close();
	return v;
}

async function idbDel(key: string): Promise<void> {
	const d = await db();
	await new Promise<void>((resolve, reject) => {
		const tx = d.transaction("kv", "readwrite");
		tx.objectStore("kv").delete(key);
		tx.oncomplete = () => resolve();
		tx.onerror = () => reject(tx.error);
	});
	d.close();
}

/** Generate the non-extractable device key and hold the bundle for a window. */
export async function rememberOnDevice(memberId: string, bundle: Uint8Array, rootKeyId: string): Promise<void> {
	const deviceKey = await subtle().generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const ct = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv }, deviceKey, bundle as BufferSource));
	await idbPut(`key:${memberId}`, deviceKey);
	const hold: DeviceHold = { keyId: rootKeyId, iv: toBase64(iv), ct: toBase64(ct), exp: Date.now() + HOLD_MS };
	await idbPut(`hold:${memberId}`, hold);
	sessionStorage.setItem(`gorani-hold:${memberId}`, JSON.stringify(hold));
}

/** Read a still-valid hold back (a reload inside the window). */
export async function heldBundle(memberId: string): Promise<{ bundle: Uint8Array; keyId: string } | null> {
	const tab = sessionStorage.getItem(`gorani-hold:${memberId}`);
	const hold = (await idbGet<DeviceHold>(`hold:${memberId}`)) ?? (tab ? (JSON.parse(tab) as DeviceHold) : undefined);
	if (!hold || hold.exp < Date.now()) return null;
	const deviceKey = await idbGet<CryptoKey>(`key:${memberId}`);
	if (!deviceKey) return null;
	try {
		const bundle = new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: fromBase64(hold.iv) as BufferSource }, deviceKey, fromBase64(hold.ct) as BufferSource));
		return { bundle, keyId: hold.keyId };
	} catch {
		return null;
	}
}

/** Drop the hold AND the device key (lock, expiry, or switching to "Ask"). */
export async function forgetOnDevice(memberId: string): Promise<void> {
	sessionStorage.removeItem(`gorani-hold:${memberId}`);
	await idbDel(`key:${memberId}`);
	await idbDel(`hold:${memberId}`);
}

/** The auto-lock clock: lock N minutes after the app is hidden (0 = at once,
 * with a 1.5 s grace so reloads pass; negative = never). The UI owns the
 * setting; this module owns the clock. */
export function watchAutoLock(session: VaultSession, minutes: number): () => void {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const schedule = () => {
		clearTimeout(timer);
		if (minutes < 0) return;
		timer = setTimeout(() => session.lock(), minutes === 0 ? 1500 : minutes * 60_000);
	};
	const onVisibility = () => (document.visibilityState === "hidden" ? schedule() : clearTimeout(timer));
	document.addEventListener("visibilitychange", onVisibility);
	return () => {
		document.removeEventListener("visibilitychange", onVisibility);
		clearTimeout(timer);
	};
}