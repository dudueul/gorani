// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * 7-Zip's words, read (commit 42e, docs/PREVIEWS.md › Archives). The
 * archive reader runs 7-Zip 24.09 compiled to WebAssembly (7z-wasm) in its
 * worker for every format our own readers do not take — 7z, RAR, TAR and
 * its compressions, CAB, ISO, ARJ, LZH, WIM, DMG, VHD, CPIO, RPM, XAR, CHM,
 * MSI, squashfs and the rest. It is driven as its command line is:
 *
 *   l -slt -ba -p…            a technical listing: blocks of "Key = value"
 *   x -so -spd -p… -- path    one entry, to stdout (counted, and stopped at
 *                             its cap), names taken literally (-spd: no
 *                             wildcards, so a file named "*" is one file)
 *
 * This file turns its listing text into a Listing, and its complaints into
 * kinds the reader can act on. Pure: unit:preview-facts.
 */

import { MAX_ENTRIES, type Entry, type Listing } from "./types.ts";

/** 7-Zip's Type, as people say it. */
const FORMATS: Record<string, string> = {
	"7z": "7z", Rar: "RAR", Rar5: "RAR 5", tar: "TAR", gzip: "gzip", bzip2: "bzip2", xz: "xz", zstd: "Zstandard", lzma: "LZMA", lzma86: "LZMA",
	Cab: "CAB (Windows cabinet)", Iso: "ISO 9660 disk image", Udf: "UDF disk image", Arj: "ARJ", Lzh: "LHA (LZH)", Z: "compress (.Z)", Cpio: "CPIO", Rpm: "RPM package", Ar: "ar (Debian package)",
	Xar: "XAR (macOS package)", Dmg: "Apple disk image", Wim: "Windows imaging (WIM)", Chm: "Compiled HTML Help (CHM)", Compound: "OLE compound file (MSI)", Nsis: "NSIS installer",
	SquashFS: "squashfs image", CramFS: "cramfs image", Ext: "ext file system image", FAT: "FAT disk image", NTFS: "NTFS disk image", VHD: "VHD disk image", VHDX: "VHDX disk image", VMDK: "VMDK disk image", VDI: "VDI disk image",
	QCOW: "QCOW disk image", HFS: "HFS disk image", APFS: "APFS disk image", MBR: "disk image (MBR)", GPT: "disk image (GPT)", zip: "ZIP", PE: "Windows program", ELF: "Linux program", "Mach-O": "macOS program",
	Base64: "Base64", IHex: "Intel HEX", UEFIc: "UEFI capsule", UEFIf: "UEFI firmware", lz4: "LZ4", lzip: "lzip", Swfc: "Flash (compressed)", Flv: "Flash video", Split: "split file",
};

export const formatName = (type: string) => FORMATS[type] ?? type;

/** Single-stream compressions: one file inside, named after the archive. */
export const STREAMS = new Set(["gzip", "bzip2", "xz", "zstd", "lzma", "lzma86", "Z", "lz4", "lzip"]);

/** "Key = value" blocks, split at blank lines (and at the "----------"
 * that ends the archive's own block). */
function blocks(text: string): Record<string, string>[] {
	const out: Record<string, string>[] = [];
	let cur: Record<string, string> | null = null;
	for (const line of text.split(/\r?\n/)) {
		if (!line.trim() || /^-{2,}$/.test(line.trim())) {
			if (cur) out.push(cur);
			cur = null;
			continue;
		}
		const at = line.indexOf(" = ");
		if (at < 0) {
			// "Path = …" ends with " =" when the value is empty.
			const bare = /^([A-Za-z][\w ]*?) =$/.exec(line);
			if (bare) (cur ??= {})[bare[1]!] = "";
			continue;
		}
		(cur ??= {})[line.slice(0, at)] = line.slice(at + 3);
	}
	if (cur) out.push(cur);
	return out;
}

const num = (s: string | undefined) => (s && /^\d+$/.test(s.trim()) ? Number(s) : null);

/**
 * The listing, from `l -slt` WITHOUT -ba (so the archive's own block
 * comes first: its Type, Solid, Method…). `archivePath` is the name the
 * archive was given in 7-Zip's file system, which its own block repeats.
 */
export function parseListing(text: string, archivePath: string, physicalSize: number): Listing {
	const all = blocks(text.slice(text.indexOf("\n--\n") >= 0 ? text.indexOf("\n--\n") + 4 : 0));
	const head = all.find((b) => b.Path === archivePath && b.Type) ?? all.find((b) => b.Type) ?? {};
	const type = head.Type ?? "";
	// A single compressed stream (gzip, zstd…) may list its one item with no
	// Path: it is named after the archive, without its extension.
	const single = STREAMS.has(type);
	const items = all.filter((b) => b !== head && ("Path" in b || (single && ("Size" in b || "Packed Size" in b))) && !("Type" in b && b.Path === archivePath));
	if (single) for (const b of items) if (!b.Path) b.Path = streamName(archivePath);
	const entries: Entry[] = [];
	for (const b of items.slice(0, MAX_ENTRIES)) {
		const attrs = b.Attributes ?? "";
		const unix = /([dl-])([r-][w-][xsStT-]){3}/.exec(attrs)?.[0] ?? "";
		const path = b.Path ?? "";
		entries.push({
			index: entries.length,
			path,
			dir: b.Folder === "+" || attrs.startsWith("D") || unix.startsWith("d"),
			size: num(b.Size),
			packed: num(b["Packed Size"]),
			modified: b.Modified || null,
			method: b.Method || null,
			encrypted: b.Encrypted === "+",
			link: b["Symbolic Link"] ? b["Symbolic Link"] : unix.startsWith("l") ? "" : null,
			crc: b.CRC || null,
			attributes: attrs.trim() || null,
			comment: b.Comment || undefined,
			undecodable: path.includes("�"),
		});
	}
	return {
		format: formatName(type),
		engine: "7-Zip",
		entries,
		truncated: items.length > MAX_ENTRIES,
		solid: head.Solid === "+",
		headersEncrypted: false,
		encryption: entries.some((e) => e.encrypted) ? (/AES/i.test(`${entries.find((e) => e.encrypted)?.method ?? ""} ${head.Method ?? ""}`) ? "AES-256" : "encrypted") : null,
		comment: head.Comment || null,
		warnings: warningsOf(text),
		inner: null,
		physicalSize: num(head["Physical Size"]) ?? physicalSize,
	};
}

/** The one file a compressed stream holds, named after it: "notes.txt.zst" → "notes.txt". */
export function streamName(archivePath: string): string {
	const base = archivePath.split("/").pop() ?? "data";
	const cut = base.replace(/\.(gz|tgz|bz2|tbz2?|xz|txz|zst|tzst|lzma|tlz|lz|lz4|z)$/i, (m) => (/^\.t/i.test(m) ? ".tar" : ""));
	return cut && cut !== base ? cut : `${base}.out`;
}

/** What 7-Zip complained of, as sentences (its own words, kept short). */
export function warningsOf(text: string): string[] {
	const out = new Set<string>();
	const known: [RegExp, string][] = [
		[/There are data after the end of archive/i, "there is data after the end of the archive"],
		[/There are some data after the end of the payload data/i, "there is data after the end of the archive's contents"],
		[/Headers Error/i, "its headers are in error"],
		[/Unexpected end of (archive|data)/i, "it ends early (cut off, or one part of a split archive)"],
		[/Unconfirmed start of archive/i, "its start could not be confirmed (something is in front of it)"],
		[/Is not archive/i, "it is not an archive"],
		[/CRC Failed/i, "a checksum does not match"],
		[/Unsupported Method/i, "it uses a method 7-Zip does not have"],
		[/Unavailable data/i, "part of it is missing"],
	];
	for (const [re, say] of known) if (re.test(text)) out.add(say);
	return [...out];
}

export type Trouble = "password" | "not-archive" | "damaged" | "unsupported" | null;

/** Why a run failed, from what 7-Zip wrote (stdout and stderr together). */
export function troubleOf(text: string): Trouble {
	if (/Wrong password|Cannot open encrypted archive|encrypted file\. Wrong password/i.test(text)) return "password";
	if (/Cannot open the file as archive|Can not open the file as archive|Is not archive/i.test(text)) return "not-archive";
	if (/Unsupported Method/i.test(text)) return "unsupported";
	if (/Data Error|CRC Failed|Headers Error|Unexpected end/i.test(text)) return "damaged";
	return null;
}

/** A name 7-Zip's file system can hold: the archive's own (its extension
 * tells 7-Zip what one stream inside is called), never a path. */
export function memName(name: string): string {
	const base = (name.split(/[\\/]/).pop() ?? "").replace(/[^\p{L}\p{N}._ -]/gu, "_").replace(/^\.+/, "").slice(-120);
	return base || "archive";
}
