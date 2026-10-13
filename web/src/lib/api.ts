// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The API helper: same-origin JSON with honest errors. Every gorani error
 * response is `{ "error": … }` with a real status (routes.rs's rule), so one
 * function serves the whole app: throw an `ApiError` carrying both, and the
 * UI decides what to show.
 */

export class ApiError extends Error {
	constructor(
		readonly status: number,
		message: string,
	) {
		super(message);
	}
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
	const res = await fetch(path, {
		method,
		headers: body === undefined ? undefined : { "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
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

/** A family member as the registry reports it (readable structure by design). */
export interface Member {
	id: string;
	name: string;
	role: "parent" | "child";
	emails: string[];
	active: boolean;
	createdAt: string;
}

export interface FamilyState {
	members: Member[];
	master: { keyId: string; publicKey: { ec: JsonWebKey; kem: string } } | null;
	audit: { id: number; at: string; actor: string; action: string; target: string; details?: string }[];
}