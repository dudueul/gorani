// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a file is, by its first bytes (commit 42g): the magic numbers an
 * analyst knows by sight, so the hex reader can say "a Windows program"
 * or "a ZIP" whatever the name says. The table is small on purpose — the
 * formats that matter in an incident, each by its own published magic.
 *
 * Pure: unit:preview-facts.
 */

export type Family = "program" | "archive" | "document" | "picture" | "media" | "data" | "text";

export interface Identity {
	what: string;
	family: Family;
}

const at = (b: Uint8Array, off: number, sig: number[] | string): boolean => {
	const s = typeof sig === "string" ? [...sig].map((c) => c.charCodeAt(0)) : sig;
	if (off + s.length > b.length) return false;
	for (let i = 0; i < s.length; i++) if (b[off + i] !== s[i]) return false;
	return true;
};

/** [what, family, test] in order: the first that matches names it. */
const TABLE: [string, Family, (b: Uint8Array) => boolean][] = [
	["a Windows program (PE)", "program", (b) => at(b, 0, "MZ") && isPe(b)],
	["a DOS program (MZ)", "program", (b) => at(b, 0, "MZ")],
	["a Linux or Unix program (ELF)", "program", (b) => at(b, 0, [0x7f, 0x45, 0x4c, 0x46])],
	["a macOS or iOS program (Mach-O)", "program", (b) => at(b, 0, [0xcf, 0xfa, 0xed, 0xfe]) || at(b, 0, [0xce, 0xfa, 0xed, 0xfe]) || at(b, 0, [0xfe, 0xed, 0xfa, 0xcf]) || at(b, 0, [0xfe, 0xed, 0xfa, 0xce])],
	["a universal macOS program (Mach-O, several architectures)", "program", (b) => at(b, 0, [0xca, 0xfe, 0xba, 0xbe]) && b.length >= 8 && b[4] === 0 && b[5] === 0 && b[6] === 0 && b[7]! > 0 && b[7]! < 20],
	["a Java class", "program", (b) => at(b, 0, [0xca, 0xfe, 0xba, 0xbe])],
	["an Android DEX (Dalvik code)", "program", (b) => at(b, 0, "dex\n")],
	["WebAssembly", "program", (b) => at(b, 0, [0, 0x61, 0x73, 0x6d])],
	["a Windows shortcut (.lnk)", "program", (b) => at(b, 0, [0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0])],
	["a Windows Prefetch file", "data", (b) => at(b, 0, "MAM\x04") || at(b, 4, "SCCA")],
	["a ZIP", "archive", (b) => at(b, 0, [0x50, 0x4b, 3, 4]) || at(b, 0, [0x50, 0x4b, 5, 6])],
	["a RAR", "archive", (b) => at(b, 0, "Rar!\x1a\x07")],
	["a 7z archive", "archive", (b) => at(b, 0, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])],
	["gzip", "archive", (b) => at(b, 0, [0x1f, 0x8b])],
	["bzip2", "archive", (b) => at(b, 0, "BZh")],
	["xz", "archive", (b) => at(b, 0, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0])],
	["zstd", "archive", (b) => at(b, 0, [0x28, 0xb5, 0x2f, 0xfd])],
	["a Windows cabinet (CAB)", "archive", (b) => at(b, 0, "MSCF")],
	["an ALZ archive", "archive", (b) => at(b, 0, "ALZ\x01")],
	["an EGG archive", "archive", (b) => at(b, 0, [0x45, 0x47, 0x47, 0x41])],
	["an ar archive (or a .deb)", "archive", (b) => at(b, 0, "!<arch>\n")],
	["a disk image (ISO 9660)", "archive", (b) => at(b, 0x8001, "CD001")],
	["a PDF", "document", (b) => at(b, 0, "%PDF-")],
	["an Office 97–2003 or Outlook file (OLE)", "document", (b) => at(b, 0, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])],
	["RTF", "document", (b) => at(b, 0, "{\\rtf")],
	["a compiled help file (CHM)", "document", (b) => at(b, 0, "ITSF")],
	["a PNG picture", "picture", (b) => at(b, 0, [0x89, 0x50, 0x4e, 0x47])],
	["a JPEG picture", "picture", (b) => at(b, 0, [0xff, 0xd8, 0xff])],
	["a GIF picture", "picture", (b) => at(b, 0, "GIF8")],
	["a WebP picture", "picture", (b) => at(b, 0, "RIFF") && at(b, 8, "WEBP")],
	["a WAV sound", "media", (b) => at(b, 0, "RIFF") && at(b, 8, "WAVE")],
	["an AVI video", "media", (b) => at(b, 0, "RIFF") && at(b, 8, "AVI ")],
	["an MP4 / QuickTime / HEIF file", "media", (b) => at(b, 4, "ftyp")],
	["an Ogg file", "media", (b) => at(b, 0, "OggS")],
	["a FLAC sound", "media", (b) => at(b, 0, "fLaC")],
	["an MP3 (ID3)", "media", (b) => at(b, 0, "ID3")],
	["an SQLite database", "data", (b) => at(b, 0, "SQLite format 3\0")],
	["a Windows registry hive", "data", (b) => at(b, 0, "regf")],
	["a Windows event log (EVTX)", "data", (b) => at(b, 0, "ElfFile\0")],
	["a Windows minidump (a process's memory)", "data", (b) => at(b, 0, "MDMP")],
	["a Windows crash dump", "data", (b) => at(b, 0, "PAGEDU64") || at(b, 0, "PAGEDUMP")],
	["a packet capture (pcap)", "data", (b) => at(b, 0, [0xd4, 0xc3, 0xb2, 0xa1]) || at(b, 0, [0xa1, 0xb2, 0xc3, 0xd4])],
	["a packet capture (pcapng)", "data", (b) => at(b, 0, [0x0a, 0x0d, 0x0d, 0x0a])],
	["a script (#!)", "text", (b) => at(b, 0, "#!")],
];

function isPe(b: Uint8Array): boolean {
	if (b.length < 0x40) return false;
	const off = b[0x3c]! | (b[0x3d]! << 8) | (b[0x3e]! << 16) | (b[0x3f]! << 24);
	return off > 0 && off < b.length - 4 && at(b, off, "PE\0\0");
}

export function identify(b: Uint8Array): Identity | null {
	for (const [what, family, test] of TABLE) if (test(b)) return { what, family };
	return null;
}

/** A program's magic: MZ, ELF or Mach-O (the formats the hex reader takes apart). */
export const isProgram = (b: Uint8Array): boolean => {
	const id = identify(b);
	return !!id && id.family === "program" && /PE|MZ|ELF|Mach-O/.test(id.what);
};
