// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Every blob: URL the app mints for DECRYPTED bytes, tracked so that locking
 * can revoke them all (docs/SECURITY-REVIEW.md › O2).
 *
 * A blob URL is a live handle to plaintext held by the browser: as long as
 * it is not revoked, any same-origin script can `fetch()` it back — after
 * the vault was "locked" too. Before commit 24 previews minted them and
 * forgot them. Rule: decrypted bytes become a URL only through `blobURL`,
 * and `revokeAllBlobURLs` runs on every lock.
 */

const live = new Set<string>();

export function blobURL(blob: Blob): string {
	const url = URL.createObjectURL(blob);
	live.add(url);
	return url;
}

export function revokeBlobURL(url: string | null | undefined): void {
	if (url && live.delete(url)) URL.revokeObjectURL(url);
}

/** Lock: every decrypted handle the app ever minted stops resolving. */
export function revokeAllBlobURLs(): void {
	for (const url of live) URL.revokeObjectURL(url);
	live.clear();
}

/** How many are live (the e2e asserts zero after a lock). */
export function liveBlobURLs(): number {
	return live.size;
}
