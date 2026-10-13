// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The index worker: the engine lives here, its memory dies with it, and the
 * snapshot it persists is AES-256-GCM ciphertext under the session's
 * indexKey (derived from the vault root — passkey-gated by construction).
 * The main thread never sees decrypted names except through search results,
 * and the worker never talks to the network.
 */

import { IndexEngine, type IndexEntry, type SearchHit } from "./index-engine.ts";

const engine = new IndexEngine();
let key: CryptoKey | null = null;

const subtle = () => globalThis.crypto.subtle;

type In =
	| { type: "init"; key: CryptoKey; snapshot: ArrayBuffer | null }
	| { type: "upsert"; entries: IndexEntry[] }
	| { type: "remove"; ids: string[] }
	| { type: "search"; q: string; limit?: number; id: number }
	| { type: "recents"; limit?: number; id: number }
	| { type: "save"; id: number };

type Out =
	| { type: "ready"; count: number }
	| { type: "results"; id: number; hits: SearchHit[] }
	| { type: "recents"; id: number; entries: IndexEntry[] }
	| { type: "snapshot"; id: number; ciphertext: ArrayBuffer }
	| { type: "error"; id?: number; message: string };

self.onmessage = async (event: MessageEvent<In>) => {
	const msg = event.data;
	try {
		switch (msg.type) {
			case "init": {
				key = msg.key;
				if (msg.snapshot) {
					const iv = new Uint8Array(msg.snapshot, 0, 12);
					const ct = new Uint8Array(msg.snapshot, 12);
					const plain = await subtle().decrypt({ name: "AES-GCM", iv }, key, ct as BufferSource);
					engine.load(new Uint8Array(plain));
				}
				const out: Out = { type: "ready", count: engine.size };
				self.postMessage(out);
				return;
			}
			case "upsert":
				engine.upsert(msg.entries);
				return;
			case "remove":
				engine.remove(msg.ids);
				return;
			case "search": {
				const out: Out = { type: "results", id: msg.id, hits: engine.search(msg.q, msg.limit) };
				self.postMessage(out);
				return;
			}
			case "recents": {
				const out: Out = { type: "recents", id: msg.id, entries: engine.recents(msg.limit) };
				self.postMessage(out);
				return;
			}
			case "save": {
				if (!key) throw new Error("index not initialised");
				const iv = crypto.getRandomValues(new Uint8Array(12));
				const ct = await subtle().encrypt({ name: "AES-GCM", iv }, key, engine.serialize() as BufferSource);
				const ciphertext = new Uint8Array(12 + ct.byteLength);
				ciphertext.set(iv, 0);
				ciphertext.set(new Uint8Array(ct), 12);
				const out: Out = { type: "snapshot", id: msg.id, ciphertext: ciphertext.buffer };
				self.postMessage(out, { transfer: [out.ciphertext] });
				return;
			}
		}
	} catch (e) {
		const out: Out = { type: "error", id: (msg as { id?: number }).id, message: e instanceof Error ? e.message : String(e) };
		self.postMessage(out);
	}
};