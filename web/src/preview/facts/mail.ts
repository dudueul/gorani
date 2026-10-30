// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What an email says about itself that its reader would not see (commit
 * 42c, docs/PREVIEWS.md › Email) — the facts a phishing triage starts with.
 * Pure: the parsed message (mail/parse.ts) and, for an HTML body, what the
 * reader found in it (HtmlFindings, gathered from an inert parse) go in;
 * sentences come out. unit:preview-facts runs it on the fixtures in Node.
 *
 *   Who sent it     the receiving server's Authentication-Results (SPF,
 *                   DKIM, DMARC); a display name that names another
 *                   address; Reply-To or the envelope sender elsewhere;
 *                   a domain in punycode, or dressed as another
 *                   (paypal.com.secure-login.example)
 *   How it came     the Received chain, oldest hop first: where it entered
 *   What it links   text that reads one address over a link to another;
 *                   punycode and IP hosts; user@host; shorteners; Windows
 *                   protocol handlers (search-ms:, ms-msdt:) and file shares
 *   What it loads   pictures and CSS from outside (a tracker learns the
 *                   message was read); forms; scripts; frames; redirects
 *   What it carries attachments judged by their NAME (a double extension,
 *                   a right-to-left mark, a kind that runs) and by their
 *                   BYTES (a "PDF" that is a Windows program, an encrypted
 *                   ZIP, HTML that builds a file in the browser)
 *
 * The Authentication-Results trusted is the topmost: the one the last
 * server — the receiving organisation's — added. Anything below it was
 * already in the message when it arrived, and a sender can write that.
 */

import type { Fact } from "../host.ts";
import type { Header, Mail, MailPart } from "../mail/parse.ts";
import { linkFact, plural, shortUrl, some } from "../office.ts";

export interface HtmlFindings {
	links: { href: string; text: string }[];
	/** Pictures, backgrounds and CSS url()s it would load from outside. */
	remote: string[];
	forms: { action: string; password: boolean }[];
	scripts: number;
	frames: string[];
	refresh: string | null;
}

export interface Hop {
	from: string;
	ip: string | null;
	by: string;
	at: Date | null;
}

const header = (h: Header[], name: string) => h.find((x) => x.name.toLowerCase() === name)?.value ?? null;
const domainOf = (address: string) => (address.split("@").pop() ?? "").trim().toLowerCase().replace(/[>\]]+$/, "");

/** The registrable part of a domain, approximately: two labels, or three
 * under a country's second level (co.kr, ac.uk, com.au). Enough to tell
 * paypal.com from secure-login.example; not a public-suffix list. */
export function orgDomain(domain: string): string {
	const labels = domain.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
	if (labels.length <= 2) return labels.join(".");
	const tld = labels.at(-1)!;
	const second = labels.at(-2)!;
	const n = tld.length === 2 && /^(co|com|net|org|ac|go|gov|or|ne|re|edu|mil|pe|ltd|plc)$/.test(second) ? 3 : 2;
	return labels.slice(-n).join(".");
}

/** The Received chain, in the order the message travelled (oldest first). */
export function receivedChain(headers: Header[]): Hop[] {
	return headers
		.filter((h) => h.name.toLowerCase() === "received")
		.map((h) => {
			const v = h.value.replace(/\s+/g, " ");
			const semi = v.lastIndexOf(";");
			const clause = semi >= 0 ? v.slice(0, semi) : v;
			const fromClause = /\bfrom\s+(.*?)(?=\s+by\s|$)/i.exec(clause)?.[1] ?? "";
			const at = semi >= 0 ? new Date(v.slice(semi + 1).trim()) : null;
			return {
				from: /^([^\s;()]+)/.exec(fromClause)?.[1] ?? "",
				ip: /\[(?:IPv6:)?([0-9a-f.:]+)\]/i.exec(fromClause)?.[1] ?? /\(([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)/.exec(fromClause)?.[1] ?? null,
				by: /\bby\s+([^\s;()]+)/i.exec(clause)?.[1] ?? "",
				at: at && !Number.isNaN(at.getTime()) ? at : null,
			};
		})
		.reverse();
}

/** SPF, DKIM, DMARC as the receiving server recorded them (the topmost result). */
export function authResults(headers: Header[]): Record<string, string> {
	const out: Record<string, string> = {};
	const ar = header(headers, "authentication-results") ?? header(headers, "arc-authentication-results");
	if (ar) for (const m of ar.matchAll(/\b(spf|dkim|dmarc|arc)\s*=\s*([a-z]+)/gi)) out[m[1]!.toLowerCase()] ??= m[2]!.toLowerCase();
	const spf = header(headers, "received-spf");
	if (!out.spf && spf) out.spf = (/^\s*(\w+)/.exec(spf)?.[1] ?? "").toLowerCase();
	return out;
}

const DANGER: [RegExp, string][] = [
	[/^(exe|scr|com|pif|cpl|msi|msp|dll|gadget)$/, "a Windows program"],
	[/^(js|jse|vbs|vbe|wsf|wsh|hta|ps1|psm1|bat|cmd)$/, "a script Windows runs when it is opened"],
	[/^(lnk|url|library-ms|search-ms|searchconnector-ms|settingcontent-ms|appref-ms|application)$/, "a Windows shortcut"],
	[/^(iso|img|vhd|vhdx)$/, "a disk image (what is inside slips past Windows' download warnings)"],
	[/^(one|onepkg)$/, "a OneNote file (used to hide scripts behind a picture)"],
	[/^(html?|shtml|xhtml|svg|mht|mhtml)$/, "a web page — the HTML smuggling route"],
	[/^(docm|dotm|xlsm|xltm|xlam|xll|pptm|potm|ppam|ppsm)$/, "an Office file that carries macros"],
	[/^(jar|jnlp)$/, "a Java program"],
	[/^(chm|hlp)$/, "a Help file (it runs script)"],
	[/^(reg|inf|scf)$/, "a file Windows acts on when it is opened"],
];

/** What the first bytes are, when they are something worth naming. */
function sniff(b: Uint8Array): { kind: string; family: RegExp } | null {
	const a = String.fromCharCode(...b.subarray(0, 8));
	if (a.startsWith("MZ")) return { kind: "a Windows program", family: /^(exe|scr|com|dll|cpl|sys|msi)$/ };
	if (a.startsWith("\u007fELF")) return { kind: "a Linux program", family: /^(elf|so|bin|run)$/ };
	if (a.startsWith("MSCF")) return { kind: "a Windows cabinet", family: /^cab$/ };
	if (b.length > 0x8006 && String.fromCharCode(...b.subarray(0x8001, 0x8006)) === "CD001") return { kind: "a disk image", family: /^(iso|img)$/ };
	const head = new TextDecoder("latin1").decode(b.subarray(0, 512)).trimStart().toLowerCase();
	if (/^(<!doctype html|<html|<script|<head|<body|<svg)/.test(head)) return { kind: "a web page", family: /^(html?|shtml|xhtml|svg|hta|mht)$/ };
	return null;
}

/** Why an attachment is dangerous, judged by its name and its bytes — or
 * null. Shared with the app (ui/viewer), which judges again for itself
 * before it offers to save an attachment: a reader in the frame is only
 * believed about what the app can see too. */
export function partRisk(name: string, bytes: Uint8Array): string | null {
	if (/[\u202a-\u202e\u2066-\u2069]/.test(name)) return "its name hides its real extension behind a right-to-left mark";
	const clean = name.toLowerCase().trim().replace(/[.\s]+$/, "");
	const ext = clean.includes(".") ? clean.split(".").pop()! : "";
	const danger = DANGER.find(([re]) => re.test(ext))?.[1] ?? null;
	const double = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|zip|rtf|mp4)\.([a-z0-9-]{2,16})$/.exec(clean);
	if (danger && double) return `it pretends to be .${double[1]} — it is ${danger}`;
	const real = sniff(bytes);
	if (real && !real.family.test(ext)) return `named .${ext || "(nothing)"}, but it is ${real.kind}`;
	if (danger) {
		if (/web page/.test(danger)) {
			const text = new TextDecoder("utf-8").decode(bytes.subarray(0, 1024 * 1024));
			if (/atob\s*\(|base64,/i.test(text) && /new\s+Blob\s*\(|msSaveOrOpenBlob|createObjectURL|\.download\s*=/.test(text)) return "a web page that builds a file in the browser and saves it — HTML smuggling";
		}
		return danger;
	}
	if (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04 && (bytes[6]! & 1) === 1) return "a password-protected archive — no scanner could look inside (the password is usually in the email)";
	return null;
}

const SHORTENERS = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rebrand\.ly|cutt\.ly|rb\.gy|tiny\.cc|shorturl\.at|t\.ly|lnkd\.in|s\.id|han\.gl|me2\.do|vo\.la)$/i;
const HANDLERS = /^(search-ms|search|ms-msdt|ms-officecmd|ms-word|ms-excel|ms-powerpoint|ms-cxh|ms-cxh-full|ms-appinstaller|ms-settings|ms-search|mhtml|its|jar|vbscript):/i;

function linkFacts(links: { href: string; text: string }[]): { facts: Fact[]; urls: string[] } {
	const facts: Fact[] = [];
	const urls: string[] = [];
	const mismatched: string[] = [];
	const odd = { punycode: new Set<string>(), ip: new Set<string>(), userinfo: new Set<string>(), short: new Set<string>(), handlers: new Set<string>(), shares: new Set<string>(), scripts: 0 };
	for (const { href, text } of links.slice(0, 2000)) {
		const h = href.trim();
		if (/^(javascript|data|vbscript):/i.test(h)) {
			odd.scripts++;
			continue;
		}
		if (HANDLERS.test(h)) {
			odd.handlers.add(h.split(":")[0]!.toLowerCase());
			continue;
		}
		if (/^(file:|smb:|\\\\)/i.test(h)) {
			odd.shares.add(shortUrl(h));
			continue;
		}
		let u: URL;
		try {
			u = new URL(h);
		} catch {
			continue;
		}
		if (!/^https?:$/.test(u.protocol)) continue;
		urls.push(h);
		const host = u.hostname.toLowerCase();
		if (host.split(".").some((l) => l.startsWith("xn--"))) odd.punycode.add(host);
		if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) odd.ip.add(host);
		if (u.username) odd.userinfo.add(`${u.username}@${host}`);
		if (SHORTENERS.test(host)) odd.short.add(host);
		// The words of the link name an address — is it the one it goes to?
		const t = text.trim();
		const shown = /^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?$/i.exec(t)?.[1]?.toLowerCase();
		if (shown && orgDomain(shown) !== orgDomain(host)) mismatched.push(`“${shortUrl(t)}” goes to ${shortUrl(h)}`);
	}
	if (mismatched.length) facts.push({ level: "warn", text: `${plural(mismatched.length, "link reads", "links read")} one address and ${mismatched.length === 1 ? "goes" : "go"} to another: ${some(mismatched, 2)}` });
	if (odd.handlers.size) facts.push({ level: "warn", text: `Links to Windows programs through their protocols (${some([...odd.handlers].map((x) => `${x}:`))}) — how Follina-style attacks start; not followed` });
	if (odd.shares.size) facts.push({ level: "warn", text: `Links to a file share (${some([...odd.shares], 2)}) — opening one makes Windows offer the reader's sign-in hash` });
	if (odd.scripts) facts.push({ level: "warn", text: `Has ${plural(odd.scripts, "javascript: or data: link")} — removed` });
	if (odd.punycode.size) facts.push({ level: "warn", text: `Links to ${plural(odd.punycode.size, "domain")} written in punycode — a look-alike of another: ${some([...odd.punycode])}` });
	if (odd.ip.size) facts.push({ level: "warn", text: `Links straight to an IP address: ${some([...odd.ip])}` });
	if (odd.userinfo.size) facts.push({ level: "warn", text: `Has links that hide their host behind user@: ${some([...odd.userinfo], 2)} — the host is what follows the @` });
	if (odd.short.size) facts.push({ level: "info", text: `Uses link shorteners (${some([...odd.short])}) — where they lead is not in the message` });
	return { facts, urls };
}

const fmtDate = (d: Date) => `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;

/** Everything the email reader says about a message. */
export function mailFacts(m: Mail, html: HtmlFindings | null): { facts: Fact[]; hops: Hop[]; auth: Record<string, string> } {
	const facts: Fact[] = [];
	const h = m.headers;
	const from = m.from?.address ?? "";
	const fromDomain = domainOf(from);

	// ── who sent it ──
	const auth = authResults(h);
	const failed = Object.entries(auth).filter(([, r]) => /^(fail|softfail|permerror|temperror)$/.test(r));
	if (failed.length) facts.push({ level: "warn", text: `The receiving server's checks failed: ${failed.map(([k, r]) => `${k.toUpperCase()} ${r}`).join(", ")} — the sender is not who the From line says, or the message was changed on the way` });
	else if (Object.keys(auth).length) facts.push({ level: "info", text: `Checked by the receiving server: ${Object.entries(auth).map(([k, r]) => `${k.toUpperCase()} ${r}`).join(" · ")}` });
	else if (m.format === "eml" || h.length) facts.push({ level: "info", text: "No authentication results recorded (SPF, DKIM, DMARC) — nothing vouches for the sender" });

	const name = m.from?.name ?? "";
	const named = /[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/.exec(name)?.[1]?.toLowerCase() ?? /\b((?:[a-z0-9-]+\.)+(?:com|net|org|kr|io|co|gov|edu))\b/i.exec(name)?.[1]?.toLowerCase();
	if (named && fromDomain && orgDomain(named) !== orgDomain(fromDomain)) facts.push({ level: "warn", text: `The sender's name says “${shortUrl(name)}”, but it was sent from ${from}` });
	if (fromDomain.split(".").some((l) => l.startsWith("xn--"))) facts.push({ level: "warn", text: `The sender's domain is written in punycode (${fromDomain}) — a look-alike of another` });
	const dressed = /^((?:[a-z0-9-]+\.)+(?:com|net|org|co\.kr|go\.kr|or\.kr|co\.uk|gov))\.(.+)$/i.exec(fromDomain);
	if (dressed && orgDomain(fromDomain) !== orgDomain(dressed[1]!)) facts.push({ level: "warn", text: `The sender's address starts with ${dressed[1]} but is at ${orgDomain(fromDomain)} — a domain dressed as another` });
	const replies = m.replyTo.filter((r) => r.address && orgDomain(domainOf(r.address)) !== orgDomain(fromDomain));
	if (replies.length && fromDomain) facts.push({ level: "warn", text: `Replies go to ${some(replies.map((r) => r.address))} — not the sender's domain` });
	const envelope = (m.returnPath ?? header(h, "return-path") ?? "").replace(/^<|>$/g, "").trim();
	if (envelope && fromDomain && orgDomain(domainOf(envelope)) !== orgDomain(fromDomain)) facts.push({ level: "info", text: `Sent with the envelope sender ${envelope} (what bounces go to) — usual for mailing services, and for spoofing` });

	// ── how it came ──
	// Every Received line below the receiving server's own was in the
	// message when it arrived: the sender's to write. The one line nobody
	// outside could forge is where the receiving server — the one that
	// wrote the topmost Authentication-Results — noted who connected to it.
	const hops = receivedChain(h);
	const authserv = (/^\s*([^;\s]+)/.exec(header(h, "authentication-results") ?? "")?.[1] ?? "").toLowerCase();
	const entry = (authserv && [...hops].reverse().find((x) => x.by.toLowerCase() === authserv && x.ip)) || null;
	if (entry) {
		const before = hops.indexOf(entry);
		facts.push({ level: "info", text: `Handed to ${entry.by} by ${entry.ip}${entry.from && entry.from !== entry.ip ? ` (${entry.from})` : ""} — the hop the sender could not write${before ? `; the ${plural(before, "hop")} before it ${before === 1 ? "is" : "are"} the sender's own account` : ""}` });
	} else if (hops.length) {
		const newest = [...hops].reverse().find((x) => x.ip);
		facts.push({ level: "info", text: `Passed through ${plural(hops.length, "server")}${newest ? `; the last handed it on from ${newest.ip}${newest.from && newest.from !== newest.ip ? ` (${newest.from})` : ""}` : ""}` });
	} else if (m.format === "eml") facts.push({ level: "info", text: "Has no Received headers — it never went through a mail server, or they were stripped" });
	const sent = m.date ? new Date(m.date) : null;
	const first = hops.find((x) => x.at)?.at;
	if (sent && first && !Number.isNaN(sent.getTime()) && Math.abs(first.getTime() - sent.getTime()) > 2 * 86400_000) facts.push({ level: "info", text: `Its Date (${fmtDate(sent)}) is days from when it was first received (${fmtDate(first)}) — the Date line is the sender's to write` });

	// ── what it links to and loads ──
	const links = html ? html.links : [...(m.text ?? "").matchAll(/\bhttps?:\/\/[^\s<>"')\]]+/gi)].map((x) => ({ href: x[0], text: x[0] }));
	const lf = linkFacts(links);
	facts.push(...lf.facts);
	if (html) {
		const hosts = [...new Set(html.remote.map((u) => (/^(?:https?:)?\/\/([^/:?#]+)/i.exec(u)?.[1] ?? u).toLowerCase()))];
		if (html.remote.length) facts.push({ level: "warn", text: `Would load ${plural(html.remote.length, "picture or style", "pictures and styles")} from outside when opened — a tracker learns it was read, and from where: ${some(hosts)} (not loaded)` });
		for (const f of html.forms.slice(0, 2)) facts.push({ level: "warn", text: `Has a form that sends what is typed to ${shortUrl(f.action || "(no address)")}${f.password ? " — and it asks for a password" : ""} (removed)` });
		if (html.scripts) facts.push({ level: "warn", text: `Contains ${plural(html.scripts, "script")} — removed, none of it run` });
		if (html.frames.length) facts.push({ level: "warn", text: `Embeds outside pages: ${some(html.frames.map(shortUrl), 2)} (removed)` });
		if (html.refresh) facts.push({ level: "warn", text: `Would redirect the reader to ${shortUrl(html.refresh)} (removed)` });
	}
	const link = linkFact(lf.urls);
	if (link) facts.push(link);

	// ── what it carries ──
	const attached = m.attachments.filter((a) => !a.inline);
	for (const a of m.attachments.slice(0, 50)) {
		const risk = partRisk(a.name, a.bytes);
		if (risk) facts.push({ level: "warn", text: `Attachment ${shortUrl(a.name)}: ${risk} — not opened` });
	}
	const mime = (re: RegExp) => m.attachments.some((a) => re.test(a.mime));
	if (mime(/pkcs7-signature|pgp-signature/i)) facts.push({ level: "info", text: "Signed (S/MIME or PGP) — the signature was not checked here" });
	if (mime(/pkcs7-mime|pgp-encrypted/i)) facts.push({ level: "info", text: "Encrypted (S/MIME or PGP) — its body cannot be read here" });
	if (mime(/^text\/calendar/i)) facts.push({ level: "info", text: "Carries a calendar invitation" });
	if (attached.some((a) => /^message\/rfc822$/i.test(a.mime) || /\.(eml|msg)$/i.test(a.name))) facts.push({ level: "info", text: "Carries a message of its own (a forward as an attachment) — it opens in its own preview" });

	const when = sent && !Number.isNaN(sent.getTime()) ? fmtDate(sent) : m.date ?? "";
	facts.unshift({
		level: "info",
		text: [`“${shortUrl(m.subject || "(no subject)")}”`, from ? `from ${from}` : "", when, attached.length ? plural(attached.length, "attachment") : "", m.format === "msg" ? "an Outlook .msg" : ""].filter(Boolean).join(" · "),
	});
	return { facts, hops, auth };
}

/** The parts an HTML body shows inline (cid: pictures), by Content-ID. */
export function inlineParts(m: Mail): Map<string, MailPart> {
	return new Map(m.attachments.filter((a) => a.cid).map((a) => [a.cid!.toLowerCase(), a]));
}
