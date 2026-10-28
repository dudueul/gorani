// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A fresh deployment's first lead, with a recovery-code vault and a files
 * store sealed to it — what a browser test needs to unlock and upload
 * (e2e:phone, e2e:preview). Dev mode takes any bootstrap token.
 */

import assert from "node:assert/strict";
import { createCodeVault, createStoreKey, sealStoreKeyToMember } from "../../web/src/vault/keys.ts";

export async function seedLead(base, { id, name, email }) {
	const boot = await fetch(`${base}/api/v1/family/members`, {
		method: "POST",
		headers: { "content-type": "application/json", "x-gorani-dev-email": email, "x-gorani-bootstrap": "any-token-dev-mode-allows" },
		body: JSON.stringify({ id, name, role: "lead" }),
	});
	assert.ok(boot.ok, `the first lead: ${boot.status} ${await boot.text()}`);
	const vault = await createCodeVault();
	const own = await sealStoreKeyToMember(await createStoreKey(), { ec: vault.publicKey, kem: vault.pqPublicKey });
	const saved = await fetch(`${base}/api/v1/members/${id}/vault`, {
		method: "PUT",
		headers: { "content-type": "application/json", "x-gorani-dev-email": email },
		body: JSON.stringify({ settings: { enabled: true, keyId: vault.keyId, publicKey: vault.publicKey, pqPublicKey: vault.pqPublicKey, methods: vault.methods, stores: { files: own } } }),
	});
	assert.equal(saved.status, 200);
	return { recoveryCode: vault.recoveryCode };
}
