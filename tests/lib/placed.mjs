// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A test's view of one files store, sealing the way the browser does since
 * commit 25 (GV04, web/src/vault/vault-crypto.ts › sealPlaced; places.ts).
 *
 * Every sealed value is sealed INTO its place — the store (member id), what
 * the value is, which item, which version — with the store's PRIVATE key
 * (a store seals to itself; the public key alone can no longer write here).
 * So a suite needs three things the old helpers did not: the store's
 * private key, the member id, and the item's id BEFORE sealing (ids are
 * client-chosen now, exactly because the place names them).
 *
 *   const s = await storeSealer(filesStore.bundle, "jinu");
 *   const id = s.newId();
 *   fields = { file_id: id, name: await s.fileName(id, "a.txt"),
 *              type: await s.fileType(id, 1, "text/plain"),
 *              ck: await s.fileKey(id, 1, rawKey) }
 */

import { importVaultKey, sealPlacedText, openPlacedText, wrapPlacedKey, unwrapPlacedKey } from "../../web/src/vault/vault-crypto.ts";
import { places, newItemId } from "../../web/src/vault/places.ts";

export async function storeSealer(bundle, member) {
	const priv = await importVaultKey(bundle.slice()); // importVaultKey wipes its input
	return {
		priv,
		member,
		newId: newItemId,
		fileName: (id, text) => sealPlacedText(priv, places.fileName(member, id), text),
		fileType: (id, version, text) => sealPlacedText(priv, places.fileType(member, id, version), text),
		fileKey: (id, version, raw) => wrapPlacedKey(priv, places.fileKey(member, id, version), raw),
		fileMusic: (id, version, json) => sealPlacedText(priv, places.fileMusic(member, id, version), typeof json === "string" ? json : JSON.stringify(json)),
		/** A version's content-hash record, sealed into its place (unsigned
		 * here — tests/lib/team.mjs › signedHash makes the real, signed one). */
		fileHash: (id, version, json) => sealPlacedText(priv, places.fileHash(member, id, version), typeof json === "string" ? json : JSON.stringify(json)),
		folderName: (id, text) => sealPlacedText(priv, places.folderName(member, id), text),
		shareName: (id, text) => sealPlacedText(priv, places.shareName(member, id), text),
		secrets: (text) => sealPlacedText(priv, places.storeSecrets(member), text),
		openFileName: (id, sealed) => openPlacedText(priv, places.fileName(member, id), sealed),
		openFolderName: (id, sealed) => openPlacedText(priv, places.folderName(member, id), sealed),
		openFileKey: (id, version, sealed) => unwrapPlacedKey(priv, places.fileKey(member, id, version), sealed),
		/** A whole new file's sealed fields (version 1), id chosen here. */
		async newFile(name, type, raw) {
			const id = newItemId();
			return { id, fields: { file_id: id, name: await this.fileName(id, name), type: await this.fileType(id, 1, type), ck: await this.fileKey(id, 1, raw) } };
		},
	};
}

/** A syntactically placed value for suites that test the server's SHAPE rules
 * only (the Worker checks the GV04 prefix; it cannot check the place). */
export const placedShape = (s) => "GV04:" + Buffer.from(`shape-only:${s}`).toString("base64");
