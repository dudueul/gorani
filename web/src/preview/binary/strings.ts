// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The strings in a binary (commit 42g): runs of printable ASCII, and of
 * UTF-16LE (Windows' own strings are wide), at least `min` characters
 * long — what `strings` and `strings -el` print, together, by offset.
 * A scanner, so the reader can feed a big file a slice at a time and
 * stay responsive; at most `cap` are kept (the total is still counted).
 *
 * Then what is in them (`stringFindings`): what a script in them would do
 * (text/script.ts reads the strings as it reads a script — a command
 * line inside a program is the same command), URLs, public IPs, Tor
 * addresses, Bitcoin addresses, registry paths, user folders in a build
 * path, and the marks installers and packers leave.
 *
 * Pure: unit:preview-facts.
 */

import { scanScript } from "../text/script.ts";
import { latin1 } from "./read.ts";

export interface Found {
	at: number;
	text: string;
	wide: boolean;
}

const printable = (c: number) => (c >= 0x20 && c <= 0x7e) || c === 9;
const MAX_LEN = 1000;

export class StringScanner {
	readonly items: Found[] = [];
	total = 0;
	private ascii = -1;
	private wide: [number, number] = [-1, -1];
	private readonly b: Uint8Array;
	private readonly min: number;
	private readonly cap: number;

	constructor(b: Uint8Array, min = 5, cap = 50_000) {
		this.b = b;
		this.min = min;
		this.cap = cap;
	}

	private keep(at: number, text: string, wide: boolean): void {
		this.total++;
		if (this.items.length < this.cap) this.items.push({ at, text: text.slice(0, MAX_LEN), wide });
	}

	/** Scan bytes [from, to); call again with the next slice. */
	scan(from: number, to: number): void {
		const b = this.b;
		for (let i = from; i < to; i++) {
			const c = b[i]!;
			if (printable(c)) {
				if (this.ascii < 0) this.ascii = i;
			} else if (this.ascii >= 0) {
				if (i - this.ascii >= this.min) this.keep(this.ascii, latin1(b.subarray(this.ascii, Math.min(i, this.ascii + MAX_LEN))), false);
				this.ascii = -1;
			}
			// UTF-16LE: a printable byte and a zero, checked at each parity.
			// (Each parity keeps its own run: the next pair it checks is two bytes on.)
			const p = (i & 1) as 0 | 1;
			const start = this.wide[p];
			const ok = printable(c) && i + 1 < b.length && b[i + 1] === 0;
			if (ok) {
				if (start < 0) this.wide[p] = i;
			} else if (start >= 0) {
				const n = (i - start) / 2;
				if (n >= this.min) this.keep(start, wideText(b, start, Math.min(n, MAX_LEN)), true);
				this.wide[p] = -1;
			}
		}
	}

	/** The runs still open at the end; then everything in offset order. */
	finish(): Found[] {
		const end = this.b.length;
		if (this.ascii >= 0 && end - this.ascii >= this.min) this.keep(this.ascii, latin1(this.b.subarray(this.ascii, Math.min(end, this.ascii + MAX_LEN))), false);
		for (const p of [0, 1] as const) {
			const s = this.wide[p];
			if (s >= 0 && (end - s) / 2 >= this.min) this.keep(s, wideText(this.b, s, Math.min(Math.floor((end - s) / 2), MAX_LEN)), true);
		}
		this.ascii = -1;
		this.wide = [-1, -1];
		return this.items.sort((a, b) => a.at - b.at);
	}
}

function wideText(b: Uint8Array, at: number, n: number): string {
	let s = "";
	for (let k = 0; k < n; k++) s += String.fromCharCode(b[at + k * 2]!);
	return s;
}

export function extractStrings(b: Uint8Array, min = 5, cap = 50_000): { items: Found[]; total: number } {
	const s = new StringScanner(b, min, cap);
	s.scan(0, b.length);
	return { items: s.finish(), total: s.total };
}

export interface StringFindings {
	/** What a script in the strings would do, at the offset it sits. */
	commands: { at: number; what: string; text: string }[];
	urls: string[];
	ips: string[];
	onion: string[];
	bitcoin: string[];
	registry: string[];
	userPaths: string[];
	marks: string[];
}

const MARKS: [RegExp, string][] = [
	[/Nullsoft Install System|NullsoftInst/, "an NSIS installer"],
	[/Inno Setup Setup Data|Inno Setup Messages/, "an Inno Setup installer"],
	[/InstallShield/, "an InstallShield installer"],
	[/pyi-windows-manifest-filename|PYZ-00\.pyz|_MEIPASS/, "a Python program frozen by PyInstaller"],
	[/AU3!EA06|AutoIt v3/, "an AutoIt script, compiled"],
	[/Go build ID:|runtime\.gopanic|go\.buildid/, "written in Go"],
	[/rust_panic|\/rustc\/[0-9a-f]{8}/, "written in Rust"],
	[/Electron|electron\.asar/, "an Electron app"],
	[/UPX!|\$Info: This file is packed with the UPX/, "packed with UPX"],
	[/\.themida|Themida/, "protected with Themida"],
	[/VMProtect/, "protected with VMProtect"],
	[/ConfuserEx/, "a .NET program obfuscated with ConfuserEx"],
	[/your (?:important )?files (?:have been|are) encrypted|decrypt(?:or|ion) (?:tool|key)|ransom/i, "words of a ransom note"],
	[/mimikatz|sekurlsa|gentilkiwi/i, "Mimikatz's own words (a credential stealer)"],
	[/cobaltstrike|beacon\.dll|ReflectiveLoader/i, "the names of Cobalt Strike's beacon (a red-team and criminal implant)"],
	[/meterpreter|metsrv/i, "Metasploit's Meterpreter"],
];

export function stringFindings(items: Found[]): StringFindings {
	const texts = items.map((s) => s.text);
	const joined = texts.join("\n");
	const report = scanScript(joined);
	const out: StringFindings = {
		commands: report.findings.map((f) => ({ at: items[f.line - 1]?.at ?? 0, what: f.what, text: f.excerpt })),
		urls: report.urls,
		ips: report.ips,
		onion: [...new Set(joined.match(/\b[a-z2-7]{56}\.onion\b/g) ?? [])].slice(0, 10),
		bitcoin: [...new Set(joined.match(/\bbc1[02-9ac-hj-np-z]{11,71}\b/g) ?? [])].slice(0, 10),
		registry: [...new Set(texts.filter((t) => /\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)|HKLM|HKCU)\\|\\CurrentVersion\\(?:Run|Policies|Winlogon)|\\Image File Execution Options/i.test(t)))].slice(0, 12),
		userPaths: [...new Set(texts.map((t) => /[A-Za-z]:\\(?:Users|Documents and Settings)\\([^\\]+)\\/i.exec(t)?.[0]).filter((x): x is string => !!x && !/\\(?:Public|Default|All Users)\\$/i.test(x)))].slice(0, 6),
		marks: [...new Set(MARKS.filter(([re]) => re.test(joined)).map(([, what]) => what))],
	};
	return out;
}
