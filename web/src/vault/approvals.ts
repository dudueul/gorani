// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The two-person rule — docs/CUSTODY.md › Stage 6 (D5.7, commit 29f). The
 * server half is worker/src/family/approvals.rs.
 *
 * ```text
 * request   stmt("gorani-approval-v1", id, action, case, requester)            signed by the requester
 * approve   stmt("gorani-approve-v1",  id, action, case, requester, approver)  signed by a second lead
 * ```
 *
 * The id is chosen HERE, before anything is signed (as file ids are since
 * commit 25): a statement can only name what already exists. The approval
 * statement repeats the request's fields, so a signature that agreed to
 * "close ir-7, asked by bo" can never be presented as agreement to
 * anything else.
 *
 * The server enforces the policy (who may ask, who may agree, once, within
 * a week) and stores the signatures; it verifies none of them. Clients do:
 * an approver checks the REQUEST's signature before signing their own, and
 * anyone reading the history checks both against their own trust.
 */

import { statements, type Signer, type Trust } from "./identity.ts";
import { newItemId } from "./places.ts";

export type TwoPersonAction = "case.close" | "hold.release" | "case.export";

export interface Approval {
	id: string;
	case: string;
	action: TwoPersonAction;
	status: "pending" | "approved" | "cancelled" | "expired";
	requestedBy: string;
	requestedAt: string;
	requestSignature: string;
	approvedBy: string | null;
	approvedAt: string | null;
	approveSignature: string | null;
	/** An approved case.export is spent by the export it allowed (commit 29h). */
	consumedAt?: string | null;
	consumedBy?: string | null;
}

/** A JSON call against the API (the shell's, or a test's). */
export type ApprovalCall = <T>(method: "GET" | "POST" | "DELETE", path: string, body?: unknown) => Promise<T>;

/** Ask for a two-person action: choose the id, sign, send. */
export async function requestApproval(call: ApprovalCall, signer: Signer, caseId: string, action: TwoPersonAction): Promise<Approval> {
	const id = newItemId();
	const signature = await signer.sign(statements.approval(id, action, caseId, signer.member));
	return call<Approval>("POST", `/api/v1/cases/${caseId}/approvals`, { id, action, signature });
}

/**
 * Agree, as the second lead. The request's own signature is checked FIRST,
 * against this lead's trust: agreeing to a request its named requester
 * never made would be agreeing to the server's word.
 */
export async function approveRequest(call: ApprovalCall, signer: Signer, trust: Trust, a: Approval): Promise<{ executed: TwoPersonAction; approval: Approval }> {
	if (a.requestedBy === signer.member) throw new Error("the second person must be a different lead — you asked for this");
	const asker = trust.of(a.requestedBy);
	if (!asker) throw new Error(`${a.requestedBy}'s identity is not one you verified — compare fingerprints before agreeing to their request`);
	if (!(await asker.verify(statements.approval(a.id, a.action, a.case, a.requestedBy), a.requestSignature))) {
		throw new Error(`the request's signature does not verify — ${a.requestedBy} did not ask for this; refusing to agree`);
	}
	const signature = await signer.sign(statements.approve(a.id, a.action, a.case, a.requestedBy, signer.member));
	return call("POST", `/api/v1/cases/${a.case}/approvals/${a.id}/approve`, { signature });
}

/** What a reader can say about a record: both signatures, by two people. */
export interface ApprovalCheck {
	/** The requester's signature verifies under an identity you trust. */
	request: boolean;
	/** The approver's does, and the approver is a different person — null while pending. */
	approve: boolean | null;
}

export async function verifyApproval(trust: Trust, a: Approval): Promise<ApprovalCheck> {
	const asker = trust.of(a.requestedBy);
	const request = !!asker && (await asker.verify(statements.approval(a.id, a.action, a.case, a.requestedBy), a.requestSignature));
	if (!a.approvedBy || !a.approveSignature) return { request, approve: null };
	const second = trust.of(a.approvedBy);
	const approve = a.approvedBy !== a.requestedBy && !!second && (await second.verify(statements.approve(a.id, a.action, a.case, a.requestedBy, a.approvedBy), a.approveSignature));
	return { request, approve };
}
