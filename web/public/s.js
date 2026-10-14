// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The share recipient page's code (web/s.html). The link is
 * /s/f/<id>#<secret> — the part after # never reaches any server, so the
 * keys derived from it (GS01: data key + meta key) exist only in this tab.
 * The server holds the sealed copy, the sealed meta, the Argon2id settings
 * (password links) and a download counter; this page opens the name and
 * assembles the file from GC01 frames in the browser.
 *
 * It is a static file served from 'self' because the page's CSP allows
 * nothing else (no inline script, no inline style, Trusted Types with no
 * policies at all — so every DOM write here is textContent/classList).
 * Moved out of s.html in commit 24 (docs/SECURITY-REVIEW.md › O1).
 */

import { splitFrame, frameAad } from "/gorani-media-lib.js";
import { shareKeys, openShareMeta } from "/gorani-share-lib.js";

const CHUNK = 8 * 1024 * 1024; // GC01 frames, one per part (GS01's contract)
const $ = (id) => document.getElementById(id);
const say = (t) => ($("status").textContent = t);

const id = location.pathname.split("/").pop();
const secret = location.hash.startsWith("#") ? decodeURIComponent(location.hash.slice(1)) : "";
// The secret is read once, then removed from the address bar and from this
// history entry: it no longer sits in the URL for a shoulder-surfer, a
// screenshot, a bookmark or the back/forward list. (A reload therefore needs
// the original link again — the honest cost of not keeping a key in view.)
if (secret) history.replaceState(null, "", location.pathname);

let info = null;
let meta = null;
let keys = null;

async function show() {
	$("name").textContent = meta.name;
	$("meta").textContent = `${fmt(meta.size)} · expires ${new Date(info.expiresAt).toLocaleString()} · ${info.downloadsLeft} download${info.downloadsLeft === 1 ? "" : "s"} left`;
	// An emoji as TEXT — this used to be `innerHTML = "<span style=…>"`, which
	// the page's Trusted Types CSP now refuses outright.
	$("icon").textContent = kindGlyph(meta.name);
	$("details").classList.remove("hidden");
	say("");
}

/** The first key derivation, with whatever the server declared. */
async function derive(password) {
	keys = await shareKeys(id, secret, password, info.kdf);
	meta = await openShareMeta(keys.meta, id, info.metaSealed);
	await show();
}

try {
	if (!secret) throw new Error("This link is incomplete — the part after # is missing.");
	const mres = await fetch(`/s/f/${id}/meta`, { method: "GET" });
	if (!mres.ok) throw new Error((await mres.json().catch(() => ({}))).error ?? `link refused (${mres.status})`);
	info = await mres.json();
	if (!info.kdf) {
		await derive(null);
	} else {
		// Password links: ask here — the derivation needs BOTH the link's
		// secret and this password, and only this tab ever sees either.
		$("pwform").classList.remove("hidden");
		say("");
		$("unlock").addEventListener("click", unlock);
		$("pw").addEventListener("keydown", (e) => e.key === "Enter" && unlock());
	}
} catch (e) {
	say(e instanceof Error ? e.message : String(e));
}

async function unlock() {
	const pw = $("pw").value;
	if (!pw) return;
	const btn = $("unlock");
	btn.disabled = true;
	say("Stretching the password…");
	try {
		await derive(pw);
		$("pwform").classList.add("hidden");
	} catch (e) {
		// A wrong password is an AEAD failure in openShareMeta — say exactly
		// that, and let the recipient try again (the cost of each try is the
		// Argon2id stretch itself).
		say(e instanceof Error ? e.message : String(e));
		btn.disabled = false;
	}
}

$("download").addEventListener("click", async () => {
	const btn = $("download");
	btn.disabled = true;
	say("Downloading and decrypting…");
	try {
		// The claim spends one download; a refused claim (used up, expired,
		// revoked) ends here instead of being ignored.
		const claim = await fetch(`/s/f/${id}/claim`, { method: "POST" });
		if (!claim.ok) throw new Error((await claim.json().catch(() => ({}))).error ?? `download refused (${claim.status})`);
		const res = await fetch(`/s/f/${id}/data`);
		if (!res.ok) throw new Error(`download refused (${res.status})`);
		const sealed = new Uint8Array(await res.arrayBuffer());
		// At least one frame, even for an empty file: GC01 always seals one
		// (final) frame, and skipping it would accept ANY bytes for size 0.
		const frames = Math.max(1, Math.ceil(meta.size / CHUNK));
		const out = new Uint8Array(meta.size);
		let at = 0;
		for (let i = 0; i < frames; i++) {
			const f = i * (CHUNK + 28);
			const len = Math.min(CHUNK + 28, sealed.length - f);
			if (len < 28) throw new Error("The download was cut short.");
			const { iv, body } = splitFrame(sealed, f, len);
			const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: frameAad(i, i === frames - 1) }, keys.data, body);
			out.set(new Uint8Array(plain), at);
			at += plain.byteLength;
			say(`Decrypting… ${Math.round(((i + 1) / frames) * 100)}%`);
		}
		if (at !== meta.size) throw new Error("The download does not match the shared size.");
		// application/octet-stream ALWAYS: the sender's declared type is not a
		// reason for this browser to render anything (the blob URL lives on
		// gorani's origin) — it is a download, so it stays one.
		const url = URL.createObjectURL(new Blob([out], { type: "application/octet-stream" }));
		const a = document.createElement("a");
		a.href = url;
		a.download = meta.name;
		a.click();
		setTimeout(() => URL.revokeObjectURL(url), 5000);
		say("Saved. The link's download count was used.");
	} catch (e) {
		say(e instanceof Error ? e.message : String(e));
	} finally {
		btn.disabled = false;
	}
});

function fmt(n) {
	if (n < 1024) return `${n} B`;
	const u = ["KB", "MB", "GB", "TB"];
	let v = n;
	let i = -1;
	do {
		v /= 1024;
		i++;
	} while (v >= 1024 && i < u.length - 1);
	return `${v.toFixed(1)} ${u[i]}`;
}

function kindGlyph(name) {
	const ext = name.includes(".") ? name.split(".").pop().toLowerCase() : "";
	const glyph = { png: "🖼", jpg: "🖼", jpeg: "🖼", gif: "🖼", webp: "🖼", mp4: "🎬", mov: "🎬", mkv: "🎬", mp3: "🎵", m4a: "🎵", flac: "🎵", pdf: "📄", zip: "🗜", "7z": "🗜" }[ext];
	return glyph ?? "📁";
}
