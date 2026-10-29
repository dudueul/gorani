// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * An email, as the email reader sees it (commit 42c, docs/PREVIEWS.md ›
 * Email) — the same shape from both formats a security team receives:
 *
 *   .eml   the message as it travelled: MIME, parsed by postal-mime
 *          (Andris Reinman, MIT-0)
 *   .msg   Outlook's own file (an OLE container of MAPI properties), parsed
 *          by msgreader (Apache-2.0). Its headers as received are one
 *          property, PR_TRANSPORT_MESSAGE_HEADERS — present when the message
 *          came from outside, which is when they matter.
 *
 * Pure (no DOM): unit:preview-facts parses the fixtures with it in Node.
 * Nothing here decides anything about the message; facts/mail.ts does.
 */

import MsgReaderModule from "@kenjiuno/msgreader";
import PostalMime from "postal-mime";

// msgreader is CommonJS (exports.default = the class). From an ES module of
// a "type": "module" package — this one, in esbuild and in Node alike — a
// default import is the whole exports object, with the class on .default.
const MsgReader = ((MsgReaderModule as unknown as { default?: typeof MsgReaderModule }).default ?? MsgReaderModule) as typeof MsgReaderModule;

export interface Address {
	name: string;
	address: string;
}

export interface MailPart {
	name: string;
	mime: string;
	bytes: Uint8Array;
	/** The Content-ID an HTML body refers to it by (cid:…), if any. */
	cid: string | null;
	/** Shown in the body (an inline picture) rather than attached. */
	inline: boolean;
}

export interface Header {
	name: string;
	value: string;
}

export interface Mail {
	format: "eml" | "msg";
	headers: Header[];
	subject: string;
	from: Address | null;
	replyTo: Address[];
	returnPath: string | null;
	to: Address[];
	cc: Address[];
	date: string | null;
	messageId: string | null;
	html: string | null;
	text: string | null;
	attachments: MailPart[];
	/** The raw message, for the Source tab (.eml; capped). */
	source: string | null;
}

/** The raw source shown: 2 MB is a long email; beyond, the Source tab says so. */
export const SOURCE_CAP = 2 * 1024 * 1024;

export async function parseMail(bytes: Uint8Array): Promise<Mail> {
	return isOle(bytes) ? parseMsg(bytes) : parseEml(bytes);
}

const isOle = (b: Uint8Array) => b.length > 8 && b[0] === 0xd0 && b[1] === 0xcf && b[2] === 0x11 && b[3] === 0xe0;

async function parseEml(bytes: Uint8Array): Promise<Mail> {
	// rfc822Attachments: a forwarded message stays an attachment (opened in
	// its own preview), not merged into this one's body.
	const e = await PostalMime.parse(bytes, { attachmentEncoding: "arraybuffer", rfc822Attachments: true, maxNestingDepth: 50 });
	const addr = (a: unknown): Address[] => {
		const list = Array.isArray(a) ? a : a ? [a] : [];
		return list.flatMap((x: { name?: string; address?: string; group?: unknown[] }) => (x.group ? addr(x.group) : x.address !== undefined || x.name ? [{ name: x.name ?? "", address: x.address ?? "" }] : []));
	};
	const headers = (e.headers ?? []).map((h: { key: string; originalKey?: string; value: string }) => ({ name: h.originalKey ?? h.key, value: h.value }));
	const head = new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(0, SOURCE_CAP));
	return {
		format: "eml",
		headers,
		subject: e.subject ?? "",
		from: addr(e.from)[0] ?? null,
		replyTo: addr(e.replyTo),
		returnPath: typeof e.returnPath === "string" ? e.returnPath : null,
		to: addr(e.to),
		cc: addr(e.cc),
		date: e.date ?? null,
		messageId: e.messageId ?? null,
		html: e.html ?? null,
		text: e.text ?? null,
		attachments: (e.attachments ?? []).map((a, i) => ({
			name: a.filename || defaultName(i, a.mimeType ?? ""),
			mime: a.mimeType || "application/octet-stream",
			bytes: typeof a.content === "string" ? new TextEncoder().encode(a.content) : a.content instanceof Uint8Array ? a.content : new Uint8Array(a.content),
			cid: a.contentId ? a.contentId.replace(/^<|>$/g, "") : null,
			inline: a.disposition === "inline" || a.related === true,
		})),
		source: head,
	};
}

/** A name for a part that has none: "attachment-2.eml", by its type. */
function defaultName(i: number, mime: string): string {
	const ext = { "message/rfc822": "eml", "text/html": "html", "text/plain": "txt", "text/calendar": "ics", "application/pdf": "pdf", "image/png": "png", "image/jpeg": "jpg", "image/gif": "gif" }[mime.toLowerCase()] ?? "bin";
	return `attachment-${i + 1}.${ext}`;
}

/** Headers as text ("Name: value", folded lines unfolded) into a list. */
export function headerList(block: string): Header[] {
	const out: Header[] = [];
	for (const line of block.split(/\r?\n/)) {
		if (!line) break;
		if (/^[ \t]/.test(line) && out.length) out.at(-1)!.value += ` ${line.trim()}`;
		else {
			const at = line.indexOf(":");
			if (at > 0) out.push({ name: line.slice(0, at).trim(), value: line.slice(at + 1).trim() });
		}
		if (out.length > 2000) break;
	}
	return out;
}

/** "Name <a@b>" or "a@b" or "<a@b>", in a header's value. */
export function addressesIn(value: string): Address[] {
	const out: Address[] = [];
	for (const part of value.split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/)) {
		const m = /^\s*"?([^"<]*?)"?\s*<([^>]*)>\s*$/.exec(part);
		if (m) out.push({ name: m[1]!.trim(), address: m[2]!.trim() });
		else if (part.trim()) out.push({ name: "", address: part.trim() });
	}
	return out;
}

function parseMsg(bytes: Uint8Array): Mail {
	const reader = new MsgReader(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer);
	const d = reader.getFileData() as {
		error?: string;
		subject?: string;
		senderName?: string;
		senderEmail?: string;
		senderSmtpAddress?: string;
		body?: string;
		bodyHtml?: string;
		html?: Uint8Array;
		headers?: string;
		messageDeliveryTime?: string;
		clientSubmitTime?: string;
		recipients?: { name?: string; email?: string; smtpAddress?: string; recipType?: string }[];
		attachments?: { fileName?: string; fileNameShort?: string; name?: string; attachMimeTag?: string; pidContentId?: string; attachmentHidden?: boolean; innerMsgContent?: boolean }[];
	};
	if (d.error) throw new Error(d.error);
	const headers = headerList(d.headers ?? "");
	const get = (n: string) => headers.find((h) => h.name.toLowerCase() === n)?.value ?? null;
	const recips = (type: string) => (d.recipients ?? []).filter((r) => (r.recipType ?? "to") === type).map((r) => ({ name: r.name ?? "", address: r.smtpAddress ?? r.email ?? "" }));
	let html = d.bodyHtml ?? null;
	if (!html && d.html) {
		const head = new TextDecoder("latin1").decode(d.html.subarray(0, 2048));
		const cs = /charset=["']?([\w-]+)/i.exec(head)?.[1] ?? "utf-8";
		try {
			html = new TextDecoder(cs).decode(d.html);
		} catch {
			html = new TextDecoder("utf-8").decode(d.html);
		}
	}
	const attachments: MailPart[] = [];
	(d.attachments ?? []).forEach((att, i) => {
		let content: Uint8Array = new Uint8Array(0);
		let name = att.fileName || att.fileNameShort || att.name || "";
		try {
			const got = reader.getAttachment(att as never) as { fileName?: string; content?: Uint8Array };
			content = got.content ?? content;
			name = name || got.fileName || "";
		} catch {
			// an attachment that does not read is listed, empty
		}
		attachments.push({ name: name || defaultName(i, att.attachMimeTag ?? (att.innerMsgContent ? "message/rfc822" : "")), mime: att.attachMimeTag || "application/octet-stream", bytes: content, cid: att.pidContentId ? att.pidContentId.replace(/^<|>$/g, "") : null, inline: !!att.attachmentHidden });
	});
	const from: Address | null = d.senderEmail || d.senderSmtpAddress || d.senderName ? { name: d.senderName ?? "", address: d.senderSmtpAddress ?? d.senderEmail ?? "" } : (addressesIn(get("from") ?? "")[0] ?? null);
	return {
		format: "msg",
		headers,
		subject: d.subject ?? get("subject") ?? "",
		from,
		replyTo: addressesIn(get("reply-to") ?? ""),
		returnPath: get("return-path")?.replace(/^<|>$/g, "") ?? null,
		to: recips("to"),
		cc: recips("cc"),
		date: get("date") ?? d.clientSubmitTime ?? d.messageDeliveryTime ?? null,
		messageId: get("message-id"),
		html,
		text: d.body ?? null,
		attachments,
		source: null,
	};
}
