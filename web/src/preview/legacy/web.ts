// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A web page or web archive (MHT) under a document's name (commit 42b).
 *
 * Word opens HTML and MHT files named .doc — and attackers send exactly
 * that: an "invoice.doc" that is an MHT archive (CVE-2021-40444's lures
 * were), or HTML that Word renders and that loads from a server. This
 * shows their TEXT only: the page is parsed with DOMParser as text/html —
 * an inert document, in which no script runs and nothing loads — its
 * text read out, and the parsed page thrown away. Nothing of it is ever
 * put in the frame's page. Facts: its scripts, the addresses it would load
 * from, its links.
 */

import type { Fact } from "../host.ts";
import { linkFact, plural, shortUrl, some } from "../office.ts";
import { paragraphs, type Legacy } from "./types.ts";

export function readWeb(bytes: Uint8Array, mht: boolean): Legacy {
	const kind = mht ? "a web archive (MHT)" : "a web page (HTML)";
	const raw = new TextDecoder("latin1").decode(bytes.subarray(0, 32 * 1024 * 1024));
	const html = mht ? firstHtmlPart(raw) : decodeHtml(bytes);
	const doc = new DOMParser().parseFromString(html, "text/html");
	const facts: Fact[] = [{ level: "info", text: doc.title ? `title ${doc.title.trim().slice(0, 80)}` : "" }];
	const scripts = doc.querySelectorAll("script").length + [...doc.querySelectorAll("*")].filter((e) => [...e.attributes].some((a) => /^on/i.test(a.name))).length;
	if (scripts) facts.push({ level: "warn", text: `Contains ${plural(scripts, "script")} — none of it was run` });
	const loads = [...doc.querySelectorAll("[src], link[href], object[data], iframe, frame, meta[http-equiv]")]
		.map((e) => e.getAttribute("src") ?? e.getAttribute("href") ?? e.getAttribute("data") ?? (/url=([^;]+)/i.exec(e.getAttribute("content") ?? "")?.[1] ?? ""))
		.filter((u) => /^(https?:|\\\\|file:|mhtml:|ms-)/i.test(u.trim()));
	if (loads.length) facts.push({ level: "warn", text: `Would load from outside when opened: ${some(loads.map(shortUrl), 2)} (not fetched)` });
	const links = [...doc.querySelectorAll("a[href]")].map((a) => a.getAttribute("href") ?? "").filter((h) => /^[a-z][a-z0-9+.-]*:/i.test(h) && !/^javascript:/i.test(h));
	if (doc.querySelector('a[href^="javascript:" i]')) facts.push({ level: "warn", text: "Has javascript: links — not followed" });
	const link = linkFact(links);
	if (link) facts.push(link);
	for (const s of doc.querySelectorAll("script, style, noscript, template")) s.remove();
	// An inert document has no layout, so no innerText: blocks are ended by hand.
	for (const b of doc.querySelectorAll("p, div, li, h1, h2, h3, h4, h5, h6, tr, table, section, article, blockquote, pre")) b.append("\n");
	for (const b of doc.querySelectorAll("br")) b.after("\n");
	for (const c of doc.querySelectorAll("td, th")) c.append("\t");
	const text = (doc.body?.textContent ?? "").replace(/\n{3,}/g, "\n\n");
	return { kind, sections: [{ paras: paragraphs(text) }], facts };
}

/** HTML bytes as text: the charset its <meta> names, else UTF-8. */
function decodeHtml(bytes: Uint8Array): string {
	const head = new TextDecoder("latin1").decode(bytes.subarray(0, 2048));
	const cs = /charset=["']?([\w-]+)/i.exec(head)?.[1] ?? "utf-8";
	try {
		return new TextDecoder(cs).decode(bytes);
	} catch {
		return new TextDecoder("utf-8").decode(bytes);
	}
}

/** An MHT (MIME) archive's first text/html part, decoded. */
function firstHtmlPart(raw: string): string {
	const boundary = /boundary="?([^"\r\n;]+)"?/i.exec(raw)?.[1];
	const parts = boundary ? raw.split(`--${boundary}`) : [raw];
	for (const part of parts) {
		const split = part.search(/\r?\n\r?\n/);
		if (split < 0) continue;
		const head = part.slice(0, split);
		if (!/content-type:\s*text\/html/i.test(head)) continue;
		let body = part.slice(split).trim();
		const enc = /content-transfer-encoding:\s*([\w-]+)/i.exec(head)?.[1]?.toLowerCase();
		const charset = /charset="?([\w-]+)/i.exec(head)?.[1] ?? "utf-8";
		let bytes: Uint8Array;
		if (enc === "base64") {
			try {
				bytes = Uint8Array.from(atob(body.replace(/\s+/g, "")), (c) => c.charCodeAt(0));
			} catch {
				bytes = new Uint8Array(0);
			}
		} else {
			if (enc === "quoted-printable") body = body.replace(/=\r?\n/g, "").replace(/=([0-9A-F]{2})/gi, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
			bytes = Uint8Array.from(body, (c) => c.charCodeAt(0) & 0xff);
		}
		try {
			return new TextDecoder(charset).decode(bytes);
		} catch {
			return new TextDecoder("utf-8").decode(bytes);
		}
	}
	return "";
}
