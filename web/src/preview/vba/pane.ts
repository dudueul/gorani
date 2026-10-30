// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The Macros button and pane every Office reader shows (commit 42h): the
 * modules on the left, flagged (hidden from the editor, stomped, what runs
 * by itself); the chosen module's source on the right, as text. Open
 * hands it to the app, which shows it in the text reader (42f: VBA
 * highlighted, its own script facts); Save puts it into the vault as a
 * .bas or .cls file, after asking. Nothing here runs it.
 */

import { el, type Host } from "../host.ts";
import { addCss } from "../kit.ts";
import type { Macros } from "./macros.ts";
import type { VbaModule } from "./project.ts";
import { triage } from "./triage.ts";
import macroCss from "./macros.css?inline";

const realLines = (m: VbaModule) => m.source.split("\n").filter((l) => l.trim() && !/^Attribute VB_/i.test(l.trim())).length;

/** The button for a reader's bar, or nothing when the file has no macros. */
export function macroButton(host: Host, macros: Macros | null): HTMLElement | null {
	if (!macros || !macros.modules.length) return null;
	addCss(macroCss);
	const button = el("button", { class: "macrobtn", "data-test": "macros-open", title: "The macro source, as text (nothing runs)" }, `⚠ Macros (${macros.modules.length})`);
	let pane: HTMLElement | null = null;
	button.addEventListener("click", () => {
		if (pane) {
			pane.hidden = !pane.hidden;
			return;
		}
		pane = macroPane(host, macros, () => (pane!.hidden = true));
		host.root.append(pane);
	});
	return button;
}

function macroPane(host: Host, macros: Macros, close: () => void): HTMLElement {
	const t = triage(macros.modules);
	const auto = new Map(t.autorun.map((a) => [a.module, a.what]));
	const list = el("div", { class: "mlist", role: "listbox", "aria-label": "Modules" });
	const head = el("div", { class: "mhead" });
	const code = el("pre", { class: "msource", "data-test": "macros-source" });
	const gutter = el("pre", { class: "mgutter", "aria-hidden": "true" });
	const body = el("div", { class: "mbody" }, gutter, code);
	let current: VbaModule | null = null;
	const show = (m: VbaModule) => {
		current = m;
		for (const b of list.children) b.setAttribute("aria-selected", String(b.getAttribute("data-name") === m.name));
		const notes: string[] = [];
		if (m.hidden) notes.push("hidden from the VBA editor");
		if (m.stomped) notes.push("its source is gone — the compiled code is what runs (VBA stomping)");
		else if (m.unseen.length) notes.push(`its compiled code says what this source does not: ${m.unseen.slice(0, 3).map((s) => `“${s.slice(0, 60)}”`).join(", ")}`);
		if (auto.has(m.name)) notes.push(`runs by itself: ${auto.get(m.name)}`);
		head.replaceChildren(
			el("strong", {}, m.name),
			el("span", { class: "muted" }, ` · ${m.kind}${m.compiled ? ` · ${m.compiled} bytes compiled` : ""}`),
			...notes.map((n) => el("div", { class: "mnote" }, `⚠ ${n}`)),
			...(m.formText.length ? [el("div", { class: "muted" }, `Its controls hold: ${m.formText.slice(0, 4).map((s) => `“${s.slice(0, 60)}”`).join(", ")}`)] : []),
		);
		code.textContent = m.source || "(no source)";
		gutter.textContent = Array.from({ length: m.source.split("\n").length }, (_, i) => i + 1).join("\n");
	};
	for (const m of macros.modules) {
		const flags = [m.hidden ? "hidden" : "", m.stomped || m.unseen.length ? "stomped" : "", auto.has(m.name) ? "auto" : ""].filter(Boolean);
		const b = el("button", { class: "mitem", role: "option", "data-name": m.name, "data-test": "macros-module", "aria-selected": "false" }, el("span", {}, m.name), el("span", { class: "muted" }, ` ${realLines(m)} lines${flags.length ? ` · ${flags.join(" · ")}` : ""}`));
		if (flags.length) b.classList.add("flagged");
		b.addEventListener("click", () => show(m));
		list.append(b);
	}
	const file = (m: VbaModule) => ({ name: `${m.name.replace(/[^\w.-]+/g, "_")}.${m.kind === "module" ? "bas" : "cls"}`, mime: "text/plain", bytes: new TextEncoder().encode(m.source) });
	const open = el("button", { "data-test": "macros-module-open", title: "Open this module in the text reader (highlighted, with its own facts)" }, "Open as text");
	open.addEventListener("click", () => current && host.handOver("open", file(current)));
	const save = el("button", { "data-test": "macros-module-save", title: "Save this module's source into the vault (you are asked first)" }, "Save");
	save.addEventListener("click", () => current && host.handOver("save", file(current)));
	const shut = el("button", { "data-test": "macros-close" }, "Close");
	shut.addEventListener("click", close);
	const pane = el("div", { class: "macros", "data-test": "macros-pane" },
		el("div", { class: "bar" }, el("strong", {}, "Macros"), el("span", { class: "muted" }, ` — ${macros.kind}${macros.locked ? " · locked in the editor (read anyway)" : ""} · shown as text, never run`), el("span", { class: "grow" }), open, save, shut),
		el("div", { class: "mmain" }, list, el("div", { class: "mright" }, head, body)));
	// The module that matters first: one flagged, else one with code.
	show(macros.modules.find((m) => m.stomped || m.hidden || m.unseen.length) ?? macros.modules.find((m) => auto.has(m.name)) ?? macros.modules.find((m) => realLines(m) > 0) ?? macros.modules[0]!);
	return pane;
}
