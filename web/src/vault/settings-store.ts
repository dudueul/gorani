// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Saving the vault settings: one field at a time (commit 39l).
 *
 * The settings are one JSON object (member.rs keeps it verbatim), and four
 * places in the app change parts of it: the identity record (team.ts ›
 * openTeam, and every pin in Team › People), the store records' MACs
 * (session.ts › takePinned, saved by the shell), and the unlock methods
 * (Team › Unlock). Each used to PUT the WHOLE object from its own copy —
 * and the copies drift: openTeam made one when it created an identity, so
 * a later pin saved from it would have put back the methods as they were
 * before a passkey was added in the same tab (or, the other way, a pinned
 * store saved from the session's object could drop a just-made identity).
 *
 * So a save reads the stored settings, changes ITS field on them, and
 * writes that back; a vault whose root changed meanwhile (a recovery
 * ceremony on another device) is refused rather than overwritten. Two
 * saves from two tabs in the same instant can still race — the window is
 * one request long instead of a whole session.
 */

import type { VaultSettings } from "./methods.ts";

/** A JSON call (team.ts › TeamCall, lib/api.ts) — only GET and PUT here. */
type Call = <T>(method: "GET" | "PUT", path: string, body?: unknown) => Promise<T>;

export async function updateSettings(call: Call, memberId: string, rootKeyId: string, change: (current: VaultSettings) => VaultSettings): Promise<VaultSettings> {
	const path = `/api/v1/members/${memberId}/vault`;
	const current = await call<VaultSettings | null>("GET", path);
	if (!current) throw new Error("This vault has no stored settings — set it up first");
	if (current.keyId !== rootKeyId) throw new Error("Your vault's key changed on another device — lock, unlock again, and retry");
	const next = change(current);
	await call("PUT", path, { settings: next });
	return next;
}
