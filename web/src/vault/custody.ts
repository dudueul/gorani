// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Custody transfers — docs/CUSTODY.md › Stage 6 › 29g (D5.6). The server
 * half is worker/src/custody.rs.
 *
 * Each evidence file has a custodian: the person answerable for it right
 * now. It starts as the uploader; it changes only by a transfer that BOTH
 * people sign:
 *
 * ```text
 * offer   (the custodian)  stmt("gorani-custody-offer-v1",  area, file, seq, from, to, SHA-256(reason))
 * accept  (the receiver)   stmt("gorani-custody-accept-v1", area, file, seq, from, to)
 * ```
 *
 * The reason is sealed into `custody.reason(area, file, seq)` (the case
 * key); its digest is in the offer, so the reason a reader opens is the one
 * the offerer signed. `seq` numbers the chain and is in both statements: a
 * server cannot reorder links or splice one file's chain into another's.
 *
 * Custody is a RECORD of responsibility, not an access control — everyone
 * granted on the case still reads the file (the read log records it).
 */

import { toHex } from "../lib/encoding.ts";
import { statements, type Signer, type Trust } from "./identity.ts";
import { places } from "./places.ts";
import { openPlacedText, sealPlacedText, type VaultPrivateKey } from "./vault-crypto.ts";

export interface CustodyEntry {
	seq: number;
	from: string;
	to: string;
	reasonSealed: string;
	offeredAt: string;
	offerSignature: string;
	acceptedAt: string | null;
	acceptSignature: string | null;
	cancelledAt: string | null;
}

/** The server's answer for one file: who uploaded it, and every link. */
export interface CustodyChain {
	owner: string;
	entries: CustodyEntry[];
}

export type CustodyCall = <T>(method: "GET" | "POST" | "DELETE", path: string, body?: unknown) => Promise<T>;

const enc = new TextEncoder();
const digest = async (text: string) => toHex(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", enc.encode(text))));

/** Hand a file over: the next link, offered and signed by the custodian. */
export async function offerCustody(call: CustodyCall, signer: Signer, store: VaultPrivateKey, base: string, area: string, file: string, chain: CustodyChain, to: string, reason: string): Promise<CustodyEntry> {
	const seq = chain.entries.length + 1;
	const reasonSealed = await sealPlacedText(store, places.custodyReason(area, file, seq), reason);
	const signature = await signer.sign(statements.custodyOffer(area, file, seq, signer.member, to, await digest(reason)));
	return call<CustodyEntry>("POST", `${base}/files/${file}/custody`, { seq, to, reasonSealed, signature });
}

/** Accept an offer made to you — after checking the offer's own signature. */
export async function acceptCustody(call: CustodyCall, signer: Signer, trust: Trust, store: VaultPrivateKey, base: string, area: string, file: string, entry: CustodyEntry): Promise<CustodyEntry> {
	if (entry.to !== signer.member) throw new Error("this offer is not made to you");
	const link = await checkLink(store, trust, area, file, entry);
	if (!link.offer) throw new Error(`the offer does not verify (${link.why}) — refusing to accept it`);
	const signature = await signer.sign(statements.custodyAccept(area, file, entry.seq, entry.from, entry.to));
	return call<CustodyEntry>("POST", `${base}/files/${file}/custody/${entry.seq}/accept`, { signature });
}

/** One link, checked: the offer (and its reason), and the acceptance if any. */
export async function checkLink(store: VaultPrivateKey, trust: Trust, area: string, file: string, e: CustodyEntry): Promise<{ offer: boolean; accept: boolean | null; reason: string | null; why: string }> {
	let reason: string | null = null;
	try {
		reason = await openPlacedText(store, places.custodyReason(area, file, e.seq), e.reasonSealed);
	} catch {
		return { offer: false, accept: null, reason: null, why: "the reason does not open in this link's place" };
	}
	const from = trust.of(e.from);
	const offer = !!from && (await from.verify(statements.custodyOffer(area, file, e.seq, e.from, e.to, await digest(reason)), e.offerSignature));
	if (!offer) return { offer, accept: null, reason, why: from ? `${e.from} did not sign this offer` : `${e.from} is not an identity you verified` };
	if (!e.acceptedAt || !e.acceptSignature) return { offer, accept: null, reason, why: "" };
	const to = trust.of(e.to);
	const accept = !!to && (await to.verify(statements.custodyAccept(area, file, e.seq, e.from, e.to), e.acceptSignature));
	return { offer, accept, reason, why: accept ? "" : to ? `${e.to} did not sign this acceptance` : `${e.to} is not an identity you verified` };
}

/** The whole chain, verified: every link signed by both, every `from` the previous `to`. */
export async function verifyChain(store: VaultPrivateKey, trust: Trust, area: string, file: string, chain: CustodyChain): Promise<{ ok: boolean; custodian: string; pending: CustodyEntry | null; links: { seq: number; from: string; to: string; reason: string | null; ok: boolean; why: string }[] }> {
	let custodian = chain.owner;
	let ok = true;
	let pending: CustodyEntry | null = null;
	const links = [];
	for (const e of [...chain.entries].sort((a, b) => a.seq - b.seq)) {
		if (e.cancelledAt) continue;
		const l = await checkLink(store, trust, area, file, e);
		let why = l.why;
		if (e.from !== custodian) why = `offered by ${e.from}, but ${custodian} held it`;
		const linkOk = l.offer && e.from === custodian && (e.acceptedAt ? l.accept === true : true);
		if (!linkOk) ok = false;
		links.push({ seq: e.seq, from: e.from, to: e.to, reason: l.reason, ok: linkOk, why });
		if (e.acceptedAt && linkOk) custodian = e.to;
		else if (!e.acceptedAt) pending = e;
	}
	return { ok, custodian, pending, links };
}
