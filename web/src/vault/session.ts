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
 * bytes only for the instant of import. The window is fixed (HOLD_MS from
 * the unlock; it does not slide), and an expired hold is DELETED the moment
 * anything looks at it. "Ask on relaunch" (the default) stores nothing.
 *
 * **Locking** (commit 24, docs/SECURITY-REVIEW.md › O2) is a state, not a
 * cache flush: `lock()` marks the session locked (every later key use
 * throws), drops the opened store keys, deletes the device hold, and only
 * THEN tells its listeners — the shell, which unmounts everything that held
 * plaintext or keys. Before, "Lock" cleared a cache and nothing listened:
 * the explorer stayed on screen with every key still usable.
 *
 * | Threat | Answer |
 * |---|---|
 * | Script in the page while unlocked | can use keys, not read them; locking ends it |
 * | Stolen browser profile on "Ask" | nothing stored; nothing opens |
 * | Stolen profile on "Stay", inside the window | the device key is in the profile's IndexedDB — *this* is the limit; "Ask" is the answer |
 * | Another origin | IndexedDB is per-origin; the strict CSP keeps scripts out |
 */

import { importVaultKey, deriveIndexKey, type VaultPrivateKey } from "./vault-crypto.ts";
import { deriveRecordKey, macRecord, verifyRecord } from "./records.ts";
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
	/** True once locked — for good: a locked session never unlocks again. */
	readonly locked: boolean;
	/** Lock: resolves after the device hold is gone and listeners ran. */
	lock(): Promise<void>;
	/** Subscribe to this session's lock; returns the unsubscribe. */
	onLock(listener: () => void): () => void;
	/**
	 * Settings with newly pinned store records (trust on first use), or null
	 * if nothing was pinned since the last call. The shell persists them.
	 */
	takePinned(): VaultSettings | null;
}

/** A session from an opened root bundle: import non-extractable, wire stores. */
export async function openSession(memberId: string, settings: VaultSettings, bundle: Uint8Array): Promise<VaultSession> {
	const root = await importVaultKey(bundle);
	bundle.fill(0); // the bytes are gone the instant the key exists
	const cache = new Map<string, OpenedStoreKey>();
	const listeners = new Set<() => void>();
	const recordKey = deriveRecordKey(root);
	let pinned = false;
	let locked = false;
	let locking: Promise<void> | null = null;
	const session: VaultSession = {
		memberId,
		settings,
		root,
		rootKeyId: settings.keyId,
		indexKey: deriveIndexKey(root, settings.publicKey),
		get locked() {
			return locked;
		},
		async openStoreKey(name: string) {
			if (locked) throw new Error("the vault is locked");
			const cached = cache.get(name);
			if (cached) return cached;
			const key = settings.stores[name];
			if (!key) throw new Error(`no store key named ${name}`);
			// Authenticity first (docs/SECURITY-REVIEW.md › O3, records.ts):
			// a record carrying a MAC must verify under THIS root's record key,
			// or it was not made or pinned by us — refuse, loudly. A record
			// without one (sealed to us by someone else) is pinned now, after
			// the consistency check inside openSealedStoreKey passes.
			if (key.mac && !(await verifyRecord(await recordKey, name, key))) {
				throw new Error(`the "${name}" store key record failed authentication — it was changed by someone without this vault's root (the server?). Nothing was opened or sealed with it.`);
			}
			const privateKey = await openSealedStoreKey(root, key);
			if (!key.mac) {
				key.mac = await macRecord(await recordKey, name, key);
				pinned = true;
			}
			const opened: OpenedStoreKey = { name, privateKey, publicKey: key.publicKey, pqPublicKey: key.pqPublicKey, keyId: key.keyId };
			cache.set(name, opened);
			return opened;
		},
		lock() {
			// Idempotent: the Lock button, the idle clock and an unmount may all
			// ask; the work happens once and every caller awaits the same end.
			if (locking) return locking;
			locked = true;
			cache.clear();
			// The hold is deleted BEFORE the listeners run: the app's next
			// screen asks "is there a hold?" — answering yes would re-open the
			// vault the user just locked.
			locking = forgetOnDevice(memberId)
				.catch(() => {})
				.then(() => {
					for (const l of [...listeners]) l();
					listeners.clear();
				});
			return locking;
		},
		onLock(listener) {
			listeners.add(listener);
			return () => listeners.delete(listener);
		},
		takePinned() {
			if (!pinned) return null;
			pinned = false;
			return settings;
		},
	};
	return session;
}

// ── the device hold ─────────────────────────────────────────────────

const DB = "gorani-vault-device";
/** The device-hold window — equal to the hidden-tab lock (docs/DECISIONS.md
 * › D15): a reload or relaunch within it opens without the secret, never
 * longer. */
const HOLD_MS = 5 * 60 * 1000;

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
	if (!hold) return null;
	// An expired hold is not merely ignored — it is deleted, key and
	// ciphertext both. `exp` is just a number in a JSON record: a hold left
	// on disk past its window stays decryptable by anyone holding the
	// profile (docs/SECURITY-REVIEW.md › O4 — it used to be left).
	if (hold.exp < Date.now()) {
		await forgetOnDevice(memberId);
		return null;
	}
	const deviceKey = await idbGet<CryptoKey>(`key:${memberId}`);
	if (!deviceKey) {
		await forgetOnDevice(memberId);
		return null;
	}
	try {
		const bundle = new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: fromBase64(hold.iv) as BufferSource }, deviceKey, fromBase64(hold.ct) as BufferSource));
		return { bundle, keyId: hold.keyId };
	} catch {
		await forgetOnDevice(memberId);
		return null;
	}
}

/** Drop the hold AND the device key (lock, expiry, or switching to "Ask"). */
export async function forgetOnDevice(memberId: string): Promise<void> {
	sessionStorage.removeItem(`gorani-hold:${memberId}`);
	await idbDel(`key:${memberId}`);
	await idbDel(`hold:${memberId}`);
}

// ── the auto-lock clock ─────────────────────────────────────────────

/** docs/DECISIONS.md › D15: 15 idle minutes, or 5 minutes hidden. */
export const AUTO_LOCK = { idleMinutes: 15, hiddenMinutes: 5 } as const;

export interface AutoLockRules {
	idleMinutes: number;
	hiddenMinutes: number;
}

/**
 * The lock decision as a PURE function (unit:session tests it with plain
 * numbers — no browser, no timers): lock when the user has been idle too
 * long, or the tab has been hidden too long. `hiddenSince` is null while
 * the tab is visible.
 */
export function autoLockDue(now: number, lastActivity: number, hiddenSince: number | null, rules: AutoLockRules = AUTO_LOCK): boolean {
	if (now - lastActivity >= rules.idleMinutes * 60_000) return true;
	return hiddenSince !== null && now - hiddenSince >= rules.hiddenMinutes * 60_000;
}

/**
 * Drive `autoLockDue` from the page: activity (pointer, keys, wheel, touch)
 * resets the idle clock, `visibilitychange` starts/stops the hidden clock,
 * and a once-a-second check locks the session. Returns the cleanup — the
 * shell calls it on unmount (it used to be discarded, so every session
 * change stacked another listener).
 */
export function watchAutoLock(session: VaultSession, rules: AutoLockRules = AUTO_LOCK): () => void {
	let lastActivity = Date.now();
	let hiddenSince: number | null = document.visibilityState === "hidden" ? Date.now() : null;
	const activity = () => {
		lastActivity = Date.now();
	};
	const visibility = () => {
		hiddenSince = document.visibilityState === "hidden" ? Date.now() : null;
		if (hiddenSince === null) check();
	};
	const check = () => {
		if (!session.locked && autoLockDue(Date.now(), lastActivity, hiddenSince, rules)) void session.lock();
	};
	const events = ["pointerdown", "keydown", "wheel", "touchstart"] as const;
	for (const e of events) document.addEventListener(e, activity, { capture: true, passive: true });
	document.addEventListener("visibilitychange", visibility);
	const timer = setInterval(check, 1000);
	return () => {
		for (const e of events) document.removeEventListener(e, activity, { capture: true });
		document.removeEventListener("visibilitychange", visibility);
		clearInterval(timer);
	};
}
