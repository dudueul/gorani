// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Malware samples — docs/CUSTODY.md › Stage 5 (D8, commit 29e).
 *
 * Two jobs live here, both small and both pure (Node-testable):
 *
 * 1. **The client's own mark.** A sample's sealed type (each version's
 *    `file.type` place, GV04) is `application/x-gorani-sample;
 *    original=<the real mime>`. The server also keeps a readable flag
 *    (it enforces "no share links"), but a server can clear its own flag —
 *    it cannot re-seal a type. So the client treats a file as a sample when
 *    EITHER mark says so: the only direction a lying server can push is
 *    "more careful".
 *
 * 2. **The zip.** Samples leave this app only as a ZIP encrypted with the
 *    password `infected` — the industry's convention (MalwareBazaar,
 *    VirusShare, vendor exchanges), so desktop antivirus does not
 *    quarantine the sample mid-investigation and a double-click does not
 *    run it. The encryption is "traditional PKWARE" (ZipCrypto, APPNOTE
 *    6.1), stored (no compression): the one format every unzip tool and
 *    Windows Explorer open. It is NOT confidentiality — ZipCrypto is broken
 *    and the password is public — it is a seatbelt for the last metre.
 *
 * The honest limits: one file per zip, at most 4 GiB − 13 bytes (no ZIP64;
 * refused above, with a message). Samples are rarely large.
 */

import { MAX_ZIP_ENTRY, zipEntries } from "./zip.ts";

export const SAMPLE_MIME = "application/x-gorani-sample";
export const SAMPLE_PASSWORD = "infected";

/** The sealed type of a sample's version, keeping the original for display. */
export function sampleType(original: string | null | undefined): string {
	return `${SAMPLE_MIME}; original=${encodeURIComponent(original || "application/octet-stream")}`;
}

/** Does an (opened) type mark a sample? */
export function isSampleType(type: string | null | undefined): boolean {
	return !!type && (type === SAMPLE_MIME || type.startsWith(`${SAMPLE_MIME};`));
}

/** The type the sample had before it was marked (display only — never used to render). */
export function originalType(type: string): string {
	const m = /;\s*original=([^;]*)/.exec(type);
	try {
		return m?.[1] ? decodeURIComponent(m[1]) : "application/octet-stream";
	} catch {
		return "application/octet-stream";
	}
}

// ── The zip (zip.ts holds the writer; one entry here, encrypted) ──────

export { crc32 } from "./zip.ts";
export { MAX_ZIP_ENTRY };

/**
 * One file in a ZipCrypto zip under `password` (default "infected"), stored.
 * `random` supplies the 11 random bytes of the encryption header (a test
 * passes a fixed one). Returns the zip's parts — a Blob of parts is not a
 * copy of the sample.
 */
export function zipEncrypted(name: string, plain: Uint8Array, { password = SAMPLE_PASSWORD, modified = new Date(), random }: { password?: string; modified?: Date; random?: (n: number) => Uint8Array } = {}): Uint8Array[] {
	if (plain.length > MAX_ZIP_ENTRY) throw new Error("this sample is larger than a zip without ZIP64 can hold (4 GiB) — not zipped");
	return zipEntries([{ name: name.replace(/[\\/]/g, "_") || "sample", data: plain, password, modified }], random ? { random } : {});
}
