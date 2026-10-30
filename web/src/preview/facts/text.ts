// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a text file holds that reading it would not make plain (commit
 * 42f, docs/PREVIEWS.md › Text): the secrets in it (masked), what a
 * script in it would do, where it points, and — for Markdown, HTML and
 * XML — what would load or run if another program rendered it.
 *
 * Pure: unit:preview-facts.
 */

import type { Fact } from "../host.ts";
import { linkFact, plural, shortUrl, some } from "../office.ts";
import { findSecrets } from "../text/secrets.ts";
import { scanScript } from "../text/script.ts";
import type { TextKind, XmlDanger } from "../text/structured.ts";

/** What a parsed Markdown or HTML page would do (the reader gathers it from an inert parse). */
export interface PageFindings {
	links: string[];
	remote: string[];
	scripts: number;
	forms: number;
	frames: number;
}

export interface TextFindings {
	name: string;
	kind: TextKind;
	language: string;
	encoding: string;
	bytes: number;
	text: string;
	page: PageFindings | null;
	xml: XmlDanger | null;
	/** JSON: how many values (JSON Lines) or keys at the top, and lines not JSON. */
	json: { values: number; bad: number; error: string | null } | null;
	/** It holds NUL bytes: binary under a text name. */
	binary?: boolean;
}

/** highlight.js's language names, as people say them. */
const NAMES: Record<string, string> = { powershell: "PowerShell", dos: "Batch", vbscript: "VBScript", javascript: "JavaScript", typescript: "TypeScript", python: "Python", bash: "Shell", php: "PHP", csharp: "C#", cpp: "C++", c: "C", java: "Java", go: "Go", rust: "Rust", ruby: "Ruby", perl: "Perl", lua: "Lua", sql: "SQL", css: "CSS", scss: "SCSS", less: "Less", yaml: "YAML", ini: "INI", properties: "properties", kotlin: "Kotlin", swift: "Swift", dockerfile: "Dockerfile", makefile: "Makefile", diff: "diff", x86asm: "assembly", objectivec: "Objective-C", groovy: "Groovy", scala: "Scala", r: "R", dart: "Dart", nim: "Nim", autohotkey: "AutoHotkey" };

const LABEL: Record<TextKind, string> = { markdown: "Markdown", json: "JSON", jsonl: "JSON Lines", xml: "XML", html: "a web page (shown as source, never as a page)", code: "" };
const size = (n: number) => (n < 1024 ? `${n} bytes` : n < 1048576 ? `${(n / 1024).toFixed(1)} kB` : `${(n / 1048576).toFixed(1)} MB`);
const q = (s: string, n = 90) => `“${s.slice(0, n)}${s.length > n ? "…" : ""}”`;

export function textFacts(f: TextFindings): Fact[] {
	const facts: Fact[] = [];
	const lines = f.text ? f.text.split("\n").length : 0;
	const what = LABEL[f.kind] || (f.language && f.language !== "plaintext" ? `${NAMES[f.language] ?? f.language} source` : "text");
	facts.push({ level: "info", text: [what.charAt(0).toUpperCase() + what.slice(1), plural(lines, "line"), size(f.bytes), f.encoding].join(" · ") });
	if (f.binary) facts.push({ level: "warn", text: `Its name says text, but it is binary (it holds NUL bytes) — a renamed file? Shown as characters, not parsed` });

	// Secrets, masked.
	const secrets = findSecrets(f.text);
	if (secrets.length) {
		const kinds = [...new Set(secrets.map((s) => s.kind))];
		facts.push({ level: "warn", text: `Holds what look like secrets — ${kinds.slice(0, 4).join(", ")}${kinds.length > 4 ? ", …" : ""}: ${some(secrets.map((s) => `${s.masked} (line ${s.line})`), 4)} — revoke them if this file got out` });
	}

	// What a script would do.
	const r = scanScript(f.text);
	for (const x of r.findings.slice(0, 12)) facts.push({ level: "warn", text: `Line ${x.line} ${x.what}: ${q(x.excerpt)}` });
	for (const d of r.decoded) facts.push({ level: "warn", text: `Line ${d.line} hides a PowerShell command in base64 — decoded: ${q(d.text, 160)}` });
	if (r.encoded) facts.push({ level: "warn", text: "Encoded with Windows Script Encoder (#@~^…) — its code is hidden from a reader's eye" });
	if (r.obfuscated) facts.push({ level: "warn", text: `Obfuscated: ${r.obfuscated}` });
	if (r.blobs) facts.push({ level: "info", text: `Carries ${plural(r.blobs, "long base64 run")} — an embedded file or payload, likely` });
	if (r.ips.length) facts.push({ level: "info", text: `Names ${plural(r.ips.length, "IP address", "IP addresses")}: ${some(r.ips, 5)}` });

	// Pages and XML: what another program would load or run.
	const p = f.page;
	if (p) {
		if (p.scripts) facts.push({ level: "warn", text: `Contains ${plural(p.scripts, "script")} — not run: shown as ${f.kind === "markdown" ? "cleaned text" : "source"}` });
		if (p.forms) facts.push({ level: "warn", text: `Contains ${plural(p.forms, "form")} — not drawn` });
		if (p.frames) facts.push({ level: "warn", text: `Contains ${plural(p.frames, "frame")} — not drawn` });
		if (p.remote.length) facts.push({ level: "warn", text: `Would load ${plural(p.remote.length, "thing")} from outside (not loaded): ${some(p.remote.map(shortUrl), 3)}` });
	}
	const x = f.xml;
	if (x) {
		if (x.entities) facts.push({ level: "warn", text: "Declares XML entities — the “billion laughs” pattern when they nest; not parsed, shown as source" });
		if (x.external) facts.push({ level: "warn", text: `Points at an outside DTD or entity (${q(x.external, 80)}) — XXE: how an XML parser is made to read a file or call out; not parsed` });
		if (x.xinclude) facts.push({ level: "warn", text: "Uses XInclude: it pulls in other files when processed" });
		if (x.xslScript) facts.push({ level: "warn", text: "An XSLT stylesheet with code in it (msxsl:script) — it runs when the stylesheet is applied" });
	}
	if (f.json?.error) facts.push({ level: "info", text: `Not valid JSON: ${f.json.error} — shown as source` });
	else if (f.json && f.kind === "jsonl") facts.push({ level: "info", text: `${plural(f.json.values, "record")}${f.json.bad ? `, ${plural(f.json.bad, "line")} not JSON` : ""}` });
	const links = linkFact([...(p?.links ?? []), ...r.urls]);
	if (links) facts.push(links);
	return facts;
}
