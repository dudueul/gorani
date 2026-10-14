// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The API helper: same-origin JSON with honest errors. Every gorani error
 * response is `{ "error": … }` with a real status (routes.rs's rule), so one
 * function serves the whole app: throw an `ApiError` carrying both, and the
 * UI decides what to show.
 */

/**
 * Dev identity: in `GORANI_DEV=1` deployments the Worker accepts this
 * header the way it accepts Access's JWT in production — and production
 * ignores it entirely (Access owns identity there), so attaching it when
 * the developer set it is always safe. Set once per browser profile:
 *   localStorage.setItem("gorani-dev-email", "you@family.test")
 * Shared by every fetch the app makes (the files transport included — a
 * missed one shows up as a mysterious 401 mid-session; the browser e2e
 * caught exactly that).
 */
export function devIdentityHeaders(): Record<string, string> {
	const email = localStorage.getItem("gorani-dev-email");
	return email ? { "x-gorani-dev-email": email } : {};
}

export class ApiError extends Error {
	constructor(
		readonly status: number,
		message: string,
	) {
		super(message);
	}
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
	const headers: Record<string, string> = { ...devIdentityHeaders(), ...(body === undefined ? {} : { "content-type": "application/json" }) };
	const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
	const text = await res.text();
	let json: unknown = null;
	try {
		json = text ? JSON.parse(text) : null;
	} catch {
		// A non-JSON answer (a proxy page, say) — the status still speaks.
	}
	if (!res.ok) {
		const message = (json as { error?: string } | null)?.error ?? `${res.status} ${res.statusText}`;
		throw new ApiError(res.status, message);
	}
	return json as T;
}

export const api = {
	get: <T>(path: string) => call<T>("GET", path),
	put: <T>(path: string, body: unknown) => call<T>("PUT", path, body),
	post: <T>(path: string, body?: unknown) => call<T>("POST", path, body),
	del: <T>(path: string) => call<T>("DELETE", path),
};

/** A team member as the registry reports it (readable structure by design). */
export interface Member {
	id: string;
	name: string;
	/** docs/CASES.md › Roles (the family's parent/child became lead/analyst). */
	role: TeamRole;
	emails: string[];
	active: boolean;
	createdAt: string;
	/** External members only: when their access ends. */
	expiresAt?: string | null;
}

export type TeamRole = "lead" | "analyst" | "auditor" | "external";

export interface FamilyState {
	members: Member[];
	audit: { id: number; at: string; actor: string; action: string; target: string; details?: string }[];
}