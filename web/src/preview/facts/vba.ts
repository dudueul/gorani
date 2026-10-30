// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What an Office file's macros say (commit 42h, docs/PREVIEWS.md ›
 * Macros): the facts that replace the bare "Contains macros" — which
 * modules, what runs by itself and when, what it would do and on which
 * line, the Windows functions it declares, how it hides, and whether the
 * source shown is what would run (VBA stomping, hidden modules).
 *
 * Pure: unit:preview-facts.
 */

import type { Fact } from "../host.ts";
import { plural, some } from "../office.ts";
import type { Macros } from "../vba/macros.ts";
import { dangerousApi, triage } from "../vba/triage.ts";

const q = (s: string, n = 110) => `“${s.slice(0, n)}${s.length > n ? "…" : ""}”`;
const WHEN = { open: "Runs by itself when the file is opened", new: "Runs by itself when a document is made from it (a template)", close: "Runs by itself when the file is closed", control: "Runs by itself when an ActiveX control in it is drawn — an automatic start that is not called AutoOpen" } as const;

export function macroFacts(m: Macros): Fact[] {
	const facts: Fact[] = [];
	const real = m.modules.filter((x) => x.source.split("\n").some((l) => l.trim() && !/^Attribute VB_/i.test(l.trim())) || x.stomped || x.unseen.length);
	facts.push({ level: "warn", text: `Contains macros — ${m.kind}${m.signed ? " (signed; the signature was not checked)" : ""}: ${plural(m.modules.length, "module")}${real.length !== m.modules.length ? `, ${real.length} with code` : ""} (${some(m.modules.map((x) => x.name), 6)}) — none of it was run; the Macros button shows the source` });
	const t = triage(m.modules);
	for (const when of ["open", "new", "close", "control"] as const) {
		const hits = t.autorun.filter((a) => a.when === when);
		if (hits.length) facts.push({ level: "warn", text: `${WHEN[when]}: ${some(hits.map((a) => `${a.what} (${a.module}, line ${a.line})`), 3)}` });
	}
	for (const f of t.findings.slice(0, 12)) facts.push({ level: "warn", text: `${f.module}, line ${f.line}: it ${f.what} — ${q(f.excerpt)}` });
	const api = t.declares.filter((d) => dangerousApi(d.name));
	if (api.length) facts.push({ level: "warn", text: `Calls Windows directly: ${some(api.map((d) => `${d.name} (${d.lib})`), 5)}${api.some((d) => /VirtualAlloc|RtlMoveMemory|CreateThread|EnumSystemLanguageGroups|CallWindowProc/i.test(d.name)) ? " — the calls that load shellcode into memory and run it" : ""}` });
	else if (t.declares.length) facts.push({ level: "info", text: `Declares ${plural(t.declares.length, "Windows function")}: ${some(t.declares.map((d) => `${d.name} (${d.lib})`), 4)}` });
	// The 42f triage, on the strings: command lines a macro builds or hides.
	const said = new Set(t.findings.map((f) => f.excerpt));
	for (const f of t.script.findings.filter((f) => !said.has(f.excerpt)).slice(0, 4)) facts.push({ level: "warn", text: `Its text: it ${f.what} — ${q(f.excerpt)}` });
	for (const d of t.script.decoded) facts.push({ level: "warn", text: `Hides a PowerShell command in base64 — decoded: ${q(d.text, 160)}` });
	if (t.obfuscation.length) facts.push({ level: "warn", text: `Obfuscated: ${t.obfuscation.join("; ")}` });

	// Is the source what would run?
	for (const x of m.modules.filter((x) => x.stomped)) facts.push({ level: "warn", text: `VBA stomping: ${x.name}'s source is gone, but its compiled code (${x.compiled} bytes) remains — Office runs the compiled code, which this source does not show` });
	for (const x of m.modules.filter((x) => !x.stomped && x.unseen.length)) facts.push({ level: "warn", text: `VBA stomping: ${x.name}'s compiled code holds text its source never says — ${some(x.unseen.map((s) => q(s, 70)), 3)}; what runs is not what is shown` });
	const hidden = m.modules.filter((x) => x.hidden);
	if (hidden.length) facts.push({ level: "warn", text: `${plural(hidden.length, "module")} hidden from the VBA editor (in the project, not in its list): ${some(hidden.map((x) => x.name), 4)} — its code runs all the same` });
	for (const x of m.modules.filter((x) => x.formText.length)) facts.push({ level: "info", text: `${x.name}'s controls hold text (where payloads hide): ${some(x.formText.map((s) => q(s, 60)), 3)}` });
	if (m.locked) facts.push({ level: "info", text: "Locked for viewing in the VBA editor (a password) — the source is read here anyway" });
	if (t.script.urls.length) facts.push({ level: "warn", text: `Names ${plural(t.script.urls.length, "address", "addresses")}: ${some(t.script.urls.map((u) => q(u, 90)), 4)}` });
	if (t.script.ips.length) facts.push({ level: "info", text: `Names ${plural(t.script.ips.length, "IP address", "IP addresses")}: ${some(t.script.ips, 5)}` });
	for (const w of m.warnings.slice(0, 3)) facts.push({ level: "warn", text: `Its VBA project is malformed: ${w}` });
	return facts;
}

/** A reader's facts, with the generic "Contains macros (…)" line replaced
 * by what the macros themselves say (when they could be read). */
export function withMacros(facts: Fact[], m: Macros | null): Fact[] {
	if (!m) return facts;
	const rest = facts.filter((f) => !/^Contains macros \(/.test(f.text));
	const at = Math.max(1, facts.findIndex((f) => /^Contains macros \(/.test(f.text)));
	return [...rest.slice(0, at), ...macroFacts(m), ...rest.slice(at)];
}
