// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The upload-link page's code (web/r.html, commit 38b). The cryptography
 * and the protocol are vault/request-upload.ts — the same code the API
 * suite drives; this file is only the page around it.
 *
 * The page runs under the share page's CSP: Trusted Types with NO policy,
 * so every DOM write is textContent or classList — a file name or a note
 * the server (or the sender) chose can never become markup.
 */

import { LinkError, openLink, sendFile, sendToken, type OpenLink } from "./vault/request-upload.ts";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const say = (t: string, tone: "info" | "bad" | "good" = "info") => {
	const el = $("status");
	el.textContent = t;
	el.classList.toggle("text-red-400", tone === "bad");
	el.classList.toggle("text-emerald-400", tone === "good");
	el.classList.toggle("text-neutral-400", tone === "info");
};

// The link is read once, then its secret leaves the address bar and this
// history entry — no longer in view for a shoulder-surfer, a screenshot or
// the back/forward list (s.js does the same; a reload needs the link again).
const href = location.href;
if (location.hash) history.replaceState(null, "", location.pathname);

let link: OpenLink | null = null;

function fmt(n: number): string {
	const u = ["bytes", "KB", "MB", "GB", "TB"];
	let i = 0;
	let v = n;
	while (v >= 1000 && i < u.length - 1) {
		v /= 1000;
		i++;
	}
	return i === 0 ? `${n} bytes` : `${v.toFixed(1)} ${u[i]}`;
}

function showLimits(l: OpenLink): void {
	$("limits").textContent = `Up to ${l.filesLeft} more file${l.filesLeft === 1 ? "" : "s"}, ${fmt(l.bytesLeft)} in all · open until ${new Date(l.expiresAt).toLocaleString()}`;
}

function why(e: unknown): string {
	if (e instanceof LinkError) {
		if (e.status === 403) return "That password is not this link's. (After ten wrong tries the link locks.)";
		if (e.status === 423 || e.status === 410 || e.status === 404) return e.message;
	}
	return e instanceof Error ? e.message : String(e);
}

/** One line per file: name, size, progress, then the receipt. */
function row(file: File): { progress(p: string): void; done(sha256: string): void; failed(msg: string): void } {
	const li = document.createElement("li");
	li.className = "rounded-xl bg-neutral-950 p-3";
	const name = document.createElement("p");
	name.className = "break-all font-medium text-neutral-200";
	name.textContent = file.name;
	const line = document.createElement("p");
	line.className = "mt-1 text-neutral-500";
	line.textContent = `${fmt(file.size)} · sealing…`;
	li.append(name, line);
	$("sent").append(li);
	return {
		progress: (p) => (line.textContent = `${fmt(file.size)} · ${p}`),
		done: (sha256) => {
			line.textContent = `${fmt(file.size)} · sent, sealed · SHA-256 ${sha256}`;
			line.classList.add("break-all", "text-emerald-400");
			li.dataset.test = "request-sent-file";
		},
		failed: (msg) => {
			line.textContent = `${fmt(file.size)} · not sent: ${msg}`;
			line.classList.add("text-red-400");
		},
	};
}

async function send(): Promise<void> {
	if (!link) return;
	const files = [...($("files") as HTMLInputElement).files ?? []];
	const password = ($("password") as HTMLInputElement).value;
	if (!password) return say("Type the password you were given with the link.", "bad");
	if (!files.length) return say("Choose the files to send.", "bad");
	const button = $("send") as HTMLButtonElement;
	button.disabled = true;
	try {
		const token = await sendToken(link, password);
		const from = { sender: ($("sender") as HTMLInputElement).value, message: ($("message") as HTMLTextAreaElement).value };
		let sent = 0;
		for (const file of files) {
			const r = row(file);
			try {
				say(`Sealing and sending ${file.name}…`);
				const receipt = await sendFile(link, token, file, from, { progress: (s, t) => r.progress(`${Math.floor((100 * s) / t)}% sent`) });
				r.done(receipt.sha256);
				sent++;
				link.filesLeft = Math.max(0, link.filesLeft - 1);
				link.bytesLeft = Math.max(0, link.bytesLeft - file.size);
				showLimits(link);
			} catch (e) {
				r.failed(why(e));
				// A wrong password or a closed link stops the batch: the rest would fail the same way.
				if (e instanceof LinkError && [403, 404, 410, 423].includes(e.status)) {
					say(why(e), "bad");
					return;
				}
			}
		}
		say(sent === files.length ? `Sent ${sent} file${sent === 1 ? "" : "s"}. The recipient reviews each before filing it.` : `Sent ${sent} of ${files.length}.`, sent === files.length ? "good" : "bad");
		($("files") as HTMLInputElement).value = "";
	} finally {
		button.disabled = false;
	}
}

async function start(): Promise<void> {
	try {
		link = await openLink(location.origin, href);
	} catch (e) {
		say(why(e), "bad");
		return;
	}
	$("note").textContent = link.note || "(no message)";
	showLimits(link);
	$("details").classList.remove("hidden");
	say("");
	$("send").addEventListener("click", () => void send());
}

void start();
