// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * An archive, as the archive reader sees it (commit 42e, docs/PREVIEWS.md ›
 * Archives) — the same shape whichever engine read it: our own ZIP, ALZ and
 * EGG readers, or 7-Zip (WebAssembly) for the rest.
 *
 * Every field is what the archive SAYS. A size is a claim until an entry
 * is extracted (and capped while it is); a name is bytes someone chose.
 */

export interface Entry {
	/** Its index in the listing: how the reader asks for it. */
	index: number;
	/** The path as the archive writes it ("/" or "\" between parts, ".." and all). */
	path: string;
	dir: boolean;
	/** Bytes once unpacked, as claimed (null: not said). */
	size: number | null;
	packed: number | null;
	/** As written (no time zone is implied). */
	modified: string | null;
	method: string | null;
	encrypted: boolean;
	/** A symbolic link (its target, when known). */
	link: string | null;
	crc: string | null;
	/** Unix mode or DOS attributes, as text. */
	attributes: string | null;
	comment?: string;
	/** The name could not be decoded: listed, not opened. */
	undecodable?: boolean;
}

export interface Listing {
	/** The format, as people say it ("ZIP", "7z", "RAR 5", "ISO 9660"…). */
	format: string;
	/** The engine that read it. */
	engine: "zip" | "alz" | "egg" | "7-Zip";
	entries: Entry[];
	/** More entries than are listed. */
	truncated: boolean;
	/** Solid (one stream for many files: opening one unpacks those before it). */
	solid: boolean;
	/** Even its names are encrypted (7z -mhe): nothing is listed without the password. */
	headersEncrypted: boolean;
	/** "ZipCrypto", "AES-256"… */
	encryption: string | null;
	comment: string | null;
	/** What the engine warned of: data after the end, headers in error… */
	warnings: string[];
	/** A compressed stream holding one TAR, listed as that TAR (".tar.gz"). */
	inner: string | null;
	physicalSize: number;
}

/** Most entries listed: a listing past this is a trap or a disk image. */
export const MAX_ENTRIES = 50_000;
