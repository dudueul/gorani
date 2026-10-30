// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a script would do (commit 42f, docs/PREVIEWS.md › Text) — read, not
 * run: the lines an analyst looks for in a dropper, a macro's payload, a
 * web shell, a "fix your computer" one-liner.
 *
 *   download and run   IEX(...DownloadString), curl … | sh, certutil
 *                      -urlcache, bitsadmin, mshta http, regsvr32 /i:http
 *   hidden code        PowerShell -EncodedCommand (DECODED here, so the
 *                      command is seen), FromBase64String, eval(atob(…)),
 *                      Windows Script Encoder (#@~^…), obfuscator names
 *   staying            Run keys, scheduled tasks, services, crontab, an
 *                      authorized_keys line
 *   damage             shadow copies deleted, recovery disabled, logs
 *                      cleared, Defender switched off, AMSI bypassed
 *   shells             a reverse shell (/dev/tcp, nc -e, a socket
 *                      connected and a shell spawned), a web shell
 *                      (eval($_POST…), system($_GET…))
 *   where              every URL and IP address it names
 *
 * Patterns are written for the languages they belong to, but checked
 * across all: a "PowerShell" line inside a batch file is the point.
 * Pure: unit:preview-facts.
 */

export interface ScriptFinding {
	/** What it would do, in a few words. */
	what: string;
	/** The line it is on (1-based) and the line itself, trimmed. */
	line: number;
	excerpt: string;
}

export interface ScriptReport {
	findings: ScriptFinding[];
	/** PowerShell -EncodedCommand payloads, decoded. */
	decoded: { line: number; text: string }[];
	urls: string[];
	ips: string[];
	/** Long base64 runs (likely embedded payloads). */
	blobs: number;
	encoded: boolean;
	obfuscated: string | null;
}

const RULES: [string, RegExp][] = [
	// Download and run.
	["downloads and runs code (PowerShell)", /\b(?:iex|invoke-expression)\b[\s\S]{0,200}?(?:downloadstring|downloaddata|invoke-webrequest|\biwr\b|net\.webclient|invoke-restmethod|\birm\b)|(?:downloadstring|downloaddata)\s*\([^)]*\)\s*\|\s*(?:iex|invoke-expression)/i],
	["downloads a file (PowerShell)", /\b(?:downloadfile|invoke-webrequest|start-bitstransfer|invoke-restmethod)\b|new-object\s+(?:system\.)?net\.webclient/i],
	["downloads and runs code (shell)", /\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:curl|wget)\b[^\n]*-[a-zA-Z]*O-?\s+[^\n]*&&\s*(?:chmod\s+\+x|sh|bash)/i],
	["fetches a file with certutil (a Windows tool misused to download)", /\bcertutil(?:\.exe)?\b[^\n]*-(?:urlcache|verifyctl)\b/i],
	["decodes a file with certutil", /\bcertutil(?:\.exe)?\b[^\n]*-decode(?:hex)?\b/i],
	["downloads with bitsadmin", /\bbitsadmin(?:\.exe)?\b[^\n]*\/transfer\b/i],
	["runs a remote HTA with mshta", /\bmshta(?:\.exe)?\b[^\n]*(?:https?:|javascript:|vbscript:)/i],
	["runs a remote scriptlet with regsvr32 (\"Squiblydoo\")", /\bregsvr32(?:\.exe)?\b[^\n]*\/i:\s*https?:/i],
	["runs script through rundll32", /\brundll32(?:\.exe)?\b[^\n]*(?:javascript:|mshtml|url\.dll|shell32\.dll,\s*shellexec_rundll)/i],
	["starts a process with WMIC", /\bwmic(?:\.exe)?\b[^\n]*process\s+call\s+create\b/i],
	// Hidden code.
	["runs PowerShell hidden and unrestricted", /\bpowershell(?:\.exe)?\b[^\n]*(?:-w(?:indowstyle)?\s+hid|-nop\b|-noni\b|-ep\s+bypass|-exec(?:utionpolicy)?\s+bypass)/i],
	["decodes base64 and runs it", /(?:frombase64string|b64decode|base64_decode|atob)\s*\([\s\S]{0,300}?(?:\biex\b|invoke-expression|\beval\b|\bexec\b|assert|system|create_function)|(?:\beval\b|\bexec\b|\biex\b)\s*\(?\s*(?:\[[^\]]*convert\]::)?(?:frombase64string|b64decode|base64_decode|atob)/i],
	["loads an assembly from memory", /\[(?:system\.)?reflection\.assembly\]::load|assembly\.load\s*\(/i],
	["calls Windows APIs from PowerShell", /add-type\b[\s\S]{0,300}?dllimport|\[dllimport\(/i],
	["writes a file and runs it (VBScript/JScript)", /adodb\.stream[\s\S]{0,400}?savetofile|\.savetofile\b/i],
	["runs commands (VBScript/JScript)", /createobject\s*\(\s*["'](?:wscript\.shell|shell\.application)["']\s*\)[\s\S]{0,200}?\.(?:run|exec|shellexecute)\b/i],
	["fetches over HTTP (VBScript/JScript)", /createobject\s*\(\s*["'](?:msxml2\.(?:server)?xmlhttp|winhttp\.winhttprequest|microsoft\.xmlhttp)/i],
	["evaluates code it builds (JavaScript)", /\beval\s*\(\s*(?:unescape|atob|String\.fromCharCode|function|\w+\s*\()|new\s+Function\s*\(/],
	["runs commands (Node.js)", /require\s*\(\s*["'](?:node:)?child_process["']\s*\)|\bchild_process\b[\s\S]{0,100}?\.(?:exec|spawn)\b/],
	["runs commands (Python)", /\b(?:os\.system|subprocess\.(?:call|run|popen|check_output)|os\.popen|pty\.spawn)\s*\(/],
	// Staying.
	["adds itself to the Run keys (starts with Windows)", /\\(?:currentversion|current\s*version)\\run(?:once)?\b|reg(?:\.exe)?\s+add\s+[^\n]*\\run\b/i],
	["creates a scheduled task", /\bschtasks(?:\.exe)?\b[^\n]*\/create\b|register-scheduledtask\b/i],
	["creates a service", /\bsc(?:\.exe)?\s+create\b|new-service\b/i],
	["edits crontab", /\bcrontab\b[^\n]*(?:-e|-l|\|)|\/etc\/cron\./],
	["adds an SSH key to authorized_keys", />>?\s*[^\n]*\.ssh\/authorized_keys/],
	["adds a user", /\bnet\s+user\s+\S+\s+\S+\s+\/add\b|\buseradd\b|\bnet\s+localgroup\s+administrators\s+\S+\s+\/add/i],
	// Damage and cover.
	["deletes shadow copies (what ransomware does first)", /vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|win32_shadowcopy[\s\S]{0,60}?delete/i],
	["disables Windows recovery", /bcdedit(?:\.exe)?[^\n]*recoveryenabled\s+no|bcdedit[^\n]*bootstatuspolicy\s+ignoreallfailures/i],
	["clears event logs", /\bwevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|clear-eventlog\b|\bhistory\s+-c\b|rm\s+-rf?\s+[^\n]*\/var\/log/i],
	["switches Windows Defender off", /set-mppreference\b[^\n]*-disable|add-mppreference\b[^\n]*-exclusion|disableantispyware/i],
	["bypasses AMSI (Windows' script scanner)", /amsiinitfailed|amsiutils|amsiscanbuffer/i],
	// Shells.
	["opens a reverse shell", /\/dev\/tcp\/[\w.-]+\/\d+|\bnc(?:at)?\b[^\n]*\s-[a-z]*e\s+\/bin\/(?:ba)?sh|socket\.socket[\s\S]{0,300}?\.connect\s*\([\s\S]{0,300}?(?:subprocess|pty\.spawn|os\.dup2)|new-object\s+system\.net\.sockets\.tcpclient/i],
	["is a web shell (runs what a request sends)", /\b(?:eval|assert|system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*(?:base64_decode\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b|preg_replace\s*\(\s*["'][^"']*\/e["']/i],
];

const URL_RE = /\b(?:https?|ftp):\/\/[^\s"'<>()`]{4,300}/gi;
const IP_RE = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g;
const PRIVATE_IP = /^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/;

/** A PowerShell -EncodedCommand payload: base64 of UTF-16LE. */
function decodePs(b64: string): string | null {
	try {
		const bin = atob(b64);
		if (bin.length < 4 || bin.length % 2) return null;
		const u16 = new Uint16Array(bin.length / 2);
		for (let i = 0; i < u16.length; i++) u16[i] = bin.charCodeAt(2 * i) | (bin.charCodeAt(2 * i + 1) << 8);
		const text = String.fromCharCode(...u16.subarray(0, 4000));
		return /[\x00-\x08\x0e-\x1f]/.test(text) ? null : text;
	} catch {
		return null;
	}
}

export function scanScript(text: string): ScriptReport {
	const lines = text.length > 8 * 1024 * 1024 ? text.slice(0, 8 * 1024 * 1024).split("\n") : text.split("\n");
	const findings: ScriptFinding[] = [];
	const seen = new Set<string>();
	// Rules that span lines are run on the whole text; the line is where the match starts.
	const offsets: number[] = [];
	let at = 0;
	for (const l of lines) {
		offsets.push(at);
		at += l.length + 1;
	}
	const lineOf = (i: number) => {
		let lo = 0;
		let hi = offsets.length - 1;
		while (lo < hi) {
			const mid = (lo + hi + 1) >> 1;
			if (offsets[mid]! <= i) lo = mid;
			else hi = mid - 1;
		}
		return lo;
	};
	const body = lines.join("\n");
	// One finding a line: the rules are in order of weight, the first wins.
	const taken = new Set<number>();
	for (const [what, re] of RULES) {
		const m = re.exec(body);
		if (!m || seen.has(what)) continue;
		seen.add(what);
		const n = lineOf(m.index);
		if (taken.has(n)) continue;
		taken.add(n);
		findings.push({ what, line: n + 1, excerpt: lines[n]!.trim().slice(0, 160) });
	}
	const decoded: ScriptReport["decoded"] = [];
	const enc = /-e(?:nc(?:odedcommand)?|c)?\s+([A-Za-z0-9+/]{20,}={0,2})/gi;
	for (let m = enc.exec(body); m && decoded.length < 5; m = enc.exec(body)) {
		const d = decodePs(m[1]!);
		if (d) decoded.push({ line: lineOf(m.index) + 1, text: d.replace(/\s+/g, " ").trim().slice(0, 300) });
	}
	findings.sort((a, b) => a.line - b.line);
	// The addresses a decoded payload names are named too: hiding them is what the base64 was for.
	const named = [body, ...decoded.map((d) => d.text)].join("\n");
	const urls = [...new Set((named.match(URL_RE) ?? []).map((u) => u.replace(/[.,;:]+$/, "")))].slice(0, 50);
	const ips = [...new Set(named.match(IP_RE) ?? [])].filter((ip) => !PRIVATE_IP.test(ip) && !/^\d+\.0\.0\.0$/.test(ip) && !urls.some((u) => u.includes(ip))).slice(0, 50);
	const blobs = (body.match(/[A-Za-z0-9+/]{200,}={0,2}/g) ?? []).length;
	const encoded = /#@~\^[A-Za-z0-9+/]{6}==/.test(body);
	const obf = /\b_0x[a-f0-9]{4,6}\b/.test(body) && (body.match(/\b_0x[a-f0-9]{4,6}\b/g) ?? []).length > 20
		? "names like _0x1a2b (a JavaScript obfuscator)"
		: (body.match(/(?:String\.fromCharCode|chr|chrw)\s*\(\s*\d+/gi) ?? []).length > 40
			? "text built a character at a time (Chr / fromCharCode)"
			: (body.match(/["']\s*\+\s*["']/g) ?? []).length > 80
				? "strings cut into pieces and joined"
				: lines.some((l) => l.length > 5000) && lines.length < 20
					? "lines thousands of characters long"
					: null;
	return { findings, decoded, urls, ips, blobs, encoded, obfuscated: obf };
}
