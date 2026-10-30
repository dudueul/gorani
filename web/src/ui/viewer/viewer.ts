// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-viewer>: the file viewer, opened from either explorer skin.
 *
 * The trust model (docs/ARCHITECTURE.md): the bytes were decrypted in this
 * browser by the session's keys; everything shown is rendered by *this*
 * element and *this* CSP —
 *
 *   - images and media go through blob URLs that are revoked on close;
 *   - text/code is escaped by Lit and rendered as text (never as HTML);
 *   - nothing is fetched from anywhere; there is no eval, no remote fonts;
 *   - a file too big to show inline offers Download (model.download);
 *   - a malware sample — or a file whose sealed type does not verify — is
 *     never opened at all (commit 29e, docs/CUSTODY.md › stage 5): the mode
 *     is decided before a byte is decrypted, and Download zips it.
 *
 * Formats arrive in steps: images, text/code, audio/video now (played from
 * the decrypted blob — seeking works because the GC1 frames open on their
 * own); the styled document readers, PDF (pdf.js) and the sealed
 * `.hlsmeta`/MSE streamer land with commit ⑩b (docs/VIDEO.md).
 */

import { LitElement, html, nothing, type TemplateResult } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import type { FilesModel } from "../files/model.ts";
import { pickViewerMode, readerFor, renderMime, sniffReader, TEXT_CAP, MAX_INLINE, type ViewerMode } from "./mode.ts";
import { openPreview, type Fact, type HandedFile, type PreviewFrame } from "./sandbox.ts";
import { icon, kindOf, type FileKind } from "../files/icons.ts";
import { partRisk } from "../../preview/facts/mail.ts";
import { blobURL, revokeBlobURL } from "../../lib/blob-urls.ts";
import { fmtSize } from "../files/shared.ts";
import { forgetMedia } from "../../lib/media-worker.ts";
import { SAMPLE_PASSWORD } from "../../vault/samples.ts";
import { isMp4, readyCopy, type DrmState } from "../files/model.ts";
import { fairPlaySupported, playProtected, type FairPlayRoutes } from "./fairplay.ts";
import { MsePlayer, canPlayWithMse } from "./mse-player.ts";
import { mseType } from "../../vault/video-meta.ts";
import type { MediaIndex } from "../../lib/media-engine.ts";
import type { VideoMeta } from "../../vault/video-meta.ts";
import { posterFromVideo, posterTime } from "./poster.ts";

export interface ViewerTarget {
	id: string;
	name: string;
	kind: FileKind;
	size: number;
	version?: number;
	/** The file's folder — where its subtitles are looked for (39o). Absent:
	 * the folder on screen. */
	folderId?: string | null;
	/** The files around it, in the order the explorer showed them (41b): a
	 * swipe, or ← and →, opens the next one. Absent: this file alone. */
	siblings?: ViewerTarget[];
}

/** How far a finger must travel sideways for a swipe, and how little up or down. */
const SWIPE_MIN = 60;
const SWIPE_SLANT = 0.6;

@customElement("gorani-viewer")
export class GoraniViewer extends LitElement {
	@property({ type: Object }) model!: FilesModel;
	@property({ type: Object }) target!: ViewerTarget;

	@state() private mode: ViewerMode = "unsupported";
	@state() private url: string | null = null;
	@state() private streamed = false;
	@state() private text: string | null = null;
	@state() private truncated = false;
	@state() private busy = true;
	@state() private error: string | null = null;
	@state() private policy: "normal" | "sample" | "unverified" = "normal";
	@state() private shownType: string | null = null;
	/** The in-page player (commit 39p): set when this video plays through MSE. */
	@state() private mse: { index: MediaIndex; source: { read(o: number, l: number): Promise<Uint8Array>; clear(): void }; type: string; meta: VideoMeta; version: number; hasPoster: boolean } | null = null;
	private player: MsePlayer | null = null;
	/** The video's subtitles (39o): WebVTT as blob: URLs, revoked on close. */
	@state() private tracks: { url: string; lang: string | null; label: string }[] = [];
	/** Where this member left off (39o), offered on open. */
	@state() private resumeAt: number | null = null;
	private lastSaved = 0;
	private wired: HTMLVideoElement | null = null;
	/** Protection (commit 40c, docs/DRM.md): the file's state, as this
	 * member sees it. */
	@state() private drm: DrmState | null = null;
	/** A protected copy playing through FairPlay — or, where it cannot, why. */
	@state() private protectedPlay: FairPlayRoutes | null = null;
	@state() private protectedNote: string | null = null;
	/** A document's reader in the sandboxed frame (42a, sandbox.ts), and
	 * what it reported about the file — shown here, outside the frame,
	 * where the file cannot draw over it. */
	private frame: PreviewFrame | null = null;
	private docBytes: Uint8Array | null = null;
	private docMime: string | null = null;
	@state() private facts: Fact[] = [];
	/** Shown as bytes, in the hex reader (42g): a file the person asked to
	 * inspect — a malware sample among them (`sample`), only after the
	 * inspection is in the audit trail (inspect()). */
	private asHex: { sample: boolean } | null = null;
	/** Why an inspection did not open (shown in the panel that offered it). */
	@state() private inspectError: string | null = null;
	/** A fact's words just copied (its button says so for a moment). */
	@state() private copied: string | null = null;
	/**
	 * Files found inside the one opened — an email's attachments (42c) —
	 * opened in turn: the last is on screen, Back returns to the one
	 * before, and to the file itself when none is left. They are NOT files
	 * of the vault: nothing here downloads them; Save puts one in the vault
	 * (after asking), where it gets custody like any upload.
	 */
	@state() private inner: HandedFile[] = [];
	/** The Save-into-the-vault question, while it is asked. */
	@state() private saving: { file: HandedFile; sample: boolean; risk: string | null; busy: boolean; error: string | null } | null = null;
	/** A lead packaging the copy: how far. */
	@state() private protecting: { done: number; total: number } | null = null;
	private stopProtected: (() => void) | null = null;

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	protected override async firstUpdated(): Promise<void> {
		// Focus the overlay so its "Close (esc)" works at once — the key
		// handler sits on this element, which nothing focused before.
		this.refocus();
		await this.load();
	}

	/** Give the overlay the focus back. Protect and Remove protection swap
	 * the button that held it for a badge (or back), and a focus whose
	 * element is gone falls to the page's body — out of reach of the
	 * overlay's Escape handler. */
	private refocus(): void {
		this.querySelector<HTMLElement>("[data-viewer-root]")?.focus();
	}

	override disconnectedCallback(): void {
		super.disconnectedCallback();
		this.release();
	}

	/** Let go of the decrypted handle: revoke the blob URL, or tell the media
	 * service worker to forget this file's content key (streamed media). */
	private release(): void {
		this.frame?.close();
		this.frame = null;
		this.docBytes = null;
		this.savePosition(true);
		for (const t of this.tracks) revokeBlobURL(t.url);
		this.tracks = [];
		this.wired = null;
		this.player?.destroy();
		this.player = null;
		this.stopProtected?.();
		this.stopProtected = null;
		this.mse?.source.clear();
		this.mse = null;
		if (!this.url) return;
		if (this.streamed) {
			const url = this.url;
			void forgetMedia(url);
		} else {
			revokeBlobURL(this.url);
		}
		this.url = null;
	}

	/** What is on screen: an attachment opened from the file, or the file. */
	private shown(): { name: string; kind: FileKind; mime: string | null } {
		const top = this.inner.at(-1);
		return top ? { name: top.name, kind: kindOf(top.name, top.mime), mime: top.mime } : { name: this.target.name, kind: this.target.kind, mime: this.docMime };
	}

	/** Open a file the reader found inside this one, in its own preview. */
	private openInner(file: HandedFile): void {
		// A malware sample (out of an archive opened with "infected"): never
		// opened — offered to save, as a sample, instead.
		if (file.sample) return this.askSave(file);
		this.reset();
		this.inner = [...this.inner, file];
		this.loadInner();
	}

	/** One step back: the attachment before, or the file itself. */
	private back(): void {
		this.reset();
		this.inner = this.inner.slice(0, -1);
		if (this.inner.length) this.loadInner();
		else {
			this.busy = true;
			// (The Back button that had the focus is gone with the
			// attachment: give it back to the viewer, or Escape reaches
			// nothing.)
			void this.load().then(() => this.refocus());
		}
	}

	private reset(): void {
		this.release();
		this.asHex = null;
		this.inspectError = null;
		this.mode = "unsupported";
		this.text = null;
		this.truncated = false;
		this.error = null;
		this.facts = [];
	}

	/**
	 * An attachment, shown as its kind is: a format with a reader — a
	 * picture included (42d) — in a NEW sandboxed frame; text as the viewer
	 * shows any; anything else not at all (Save offers to keep it). Its
	 * bytes are the attachment's own — as untrusted as the message they
	 * came in.
	 */
	private loadInner(): void {
		const f = this.inner.at(-1)!;
		if (f.hex) {
			// Inspected (42g): bytes only, whatever its kind.
			this.mode = "document";
			this.docBytes = f.bytes.slice();
			this.docMime = f.mime;
			this.asHex = { sample: !!f.sample };
			this.busy = false;
			void this.updateComplete.then(() => this.refocus());
			return;
		}
		const kind = kindOf(f.name, f.mime);
		const mode = pickViewerMode(kind, f.mime, f.bytes.length, "normal", f.name);
		this.mode = mode === "video" || mode === "audio" ? "unsupported" : mode;
		if (this.mode === "document") {
			this.docBytes = f.bytes.slice();
			this.docMime = f.mime;
		} else if (this.mode === "text") {
			this.text = new TextDecoder().decode(f.bytes.subarray(0, TEXT_CAP));
			this.truncated = f.bytes.length > TEXT_CAP;
		}
		this.busy = false;
		void this.updateComplete.then(() => this.refocus());
	}

	/** A fact's words onto the clipboard — the app's, on the person's click
	 * (the frame has no clipboard; sandbox.ts › cleanFact kept only words
	 * the fact shows). */
	private async copyFact(text: string): Promise<void> {
		try {
			await navigator.clipboard.writeText(text);
			this.copied = text;
			setTimeout(() => (this.copied === text ? (this.copied = null) : undefined), 1500);
		} catch {
			this.model.notify("The browser did not allow copying here.");
		}
	}

	/** Save an attachment into the vault: the app judges it for itself
	 * (partRisk, on the bytes it was handed — not on what the frame said)
	 * and asks first; a risky one is offered as a malware sample. */
	private askSave(file: HandedFile): void {
		const risk = partRisk(file.name, file.bytes);
		this.saving = { file, sample: !!risk || !!file.sample, risk: risk ?? (file.sample ? "out of an archive opened with the password “infected” — a malware sample" : null), busy: false, error: null };
	}

	private async confirmSave(): Promise<void> {
		const s = this.saving;
		if (!s || s.busy) return;
		this.saving = { ...s, busy: true };
		try {
			const file = new File([s.file.bytes as BlobPart], s.file.name, { type: s.file.mime ?? "application/octet-stream" });
			// (A file the reader marked a sample is saved as one, whatever the box says.)
			await this.model.upload([file], { sample: s.sample || !!s.file.sample, into: this.target.folderId !== undefined ? this.target.folderId : undefined });
			this.model.notify(`Saved “${s.file.name}” beside “${this.target.name}”${s.sample ? ", as a malware sample" : ""}.`);
			this.saving = null;
		} catch (e) {
			this.saving = { ...s, busy: false, error: e instanceof Error ? e.message : String(e) };
		}
		await this.updateComplete;
		this.refocus();
	}

	/**
	 * Inspect this file as bytes (42g, docs/CUSTODY.md › Stage 5): its hex,
	 * strings and program headers, in the hex reader — the one way a
	 * malware sample (or a file whose type does not verify) is ever opened.
	 * The inspection goes on the record FIRST: if the server does not write
	 * the audit line, nothing is decrypted. A file with no reader of its
	 * own is inspected the same way, without the line (`sample` false: it
	 * is an ordinary read, in the read log like any other).
	 */
	private async inspect(sample: boolean): Promise<void> {
		const { id, size } = this.target;
		if (size > MAX_INLINE) {
			this.inspectError = `Too large to inspect here (${fmtSize(size)}; the limit is ${fmtSize(MAX_INLINE)}). Download it into an analysis environment.`;
			return;
		}
		this.busy = true;
		this.inspectError = null;
		try {
			if (sample) await this.model.inspect(id, this.target.version);
			const parts: Uint8Array[] = [];
			await this.model.openBytes(id, this.target.version, (plain) => void parts.push(plain));
			this.docBytes = concat(parts);
			this.docMime = null;
			this.asHex = { sample };
			this.mode = "document";
		} catch (e) {
			this.inspectError = `Not inspected: ${e instanceof Error ? e.message : String(e)}`;
		}
		this.busy = false;
		// (The button that had the focus is gone with its panel: give it back
		// to the viewer, or Escape reaches nothing.)
		await this.updateComplete;
		this.refocus();
	}

	/** An entry the reader found (a sample out of an "infected" archive)
	 * inspected as bytes: on the record against the file it came out of,
	 * its name sealed — then shown in the hex reader, nowhere else. */
	private async inspectInner(file: HandedFile): Promise<void> {
		try {
			if (file.sample) await this.model.inspect(this.target.id, this.target.version, file.name);
		} catch (e) {
			this.model.notify(`Not inspected: ${e instanceof Error ? e.message : String(e)}`);
			return;
		}
		this.reset();
		this.inner = [...this.inner, { ...file, hex: true }];
		this.loadInner();
	}

	private async load(): Promise<void> {
		this.asHex = null;
		const { id, kind, size } = this.target;
		const info = await this.model.renderInfo(id);
		const mime = info?.mime ?? null;
		this.mode = pickViewerMode(kind, mime, size, info?.policy ?? "unverified", this.target.name);
		this.policy = info?.policy ?? "unverified";
		this.shownType = info?.shownType ?? null;
		if (this.mode === "unsupported" || this.mode === "too-large" || this.mode === "refused") {
			this.busy = false;
			return;
		}
		try {
			if (this.mode === "text") {
				// Text via the capped preview: chunked files open only their
				// first frame; whole files are under the chunking threshold
				// anyway (48 MB) — and the render caps at TEXT_CAP regardless.
				const head = await this.model.preview(id, TEXT_CAP);
				if (head) {
					this.truncated = head.bytes.length >= TEXT_CAP && (info?.size ?? 0) > TEXT_CAP;
					this.text = new TextDecoder().decode(head.bytes.subarray(0, TEXT_CAP));
				}
			} else if (this.mode === "document") {
				// Read whole, then handed to the reader in the frame (updated()):
				// the bytes are transferred there, not kept here.
				const parts: Uint8Array[] = [];
				await this.model.openBytes(id, this.target.version, (plain) => void parts.push(plain));
				this.docBytes = concat(parts);
				this.docMime = mime;
			} else if (this.mode === "video" && (await this.startProtected(id))) {
				// A protected video this member gets only as its copy (40c):
				// FairPlay plays it, or the viewer says where it plays.
			} else if ((this.mode === "video" || this.mode === "audio") && isMp4(this.target.name, mime) && (await this.startMse(id))) {
				// Played in the page (39p, mse-player.ts) — films, and since
				// 39w music in MP4 (M4A): updated() attaches it.
			} else if (this.mode === "audio" || (this.mode === "video" && (info?.size ?? 0) > 8 * 1024 * 1024)) {
				// Streaming path: the scoped media worker serves decrypted
				// ranges; the browser's player seeks natively — what plays
				// MP3, FLAC, Ogg and WAV, which the MP4 engine does not cut.
				// Music streams at any size (39w): a track starts at once
				// instead of after its whole download. A small video is
				// simpler as a blob.
				const handle = await this.model.mediaHandle(id, renderMime(kind, mime, this.target.name));
				if (handle) {
					this.streamed = true;
					this.url = handle.url;
					return;
				}
				await this.readWhole(mime);
			} else {
				await this.readWhole(mime);
			}
		} catch (e) {
			this.error = e instanceof Error ? e.message : String(e);
			// Its bytes were confirmed gone and the file went to the Trash
			// (39t, routes.rs › lost_object): the list behind should not
			// still show it.
			if (/moved to the Trash/.test(this.error)) void this.model.refresh();
		} finally {
			this.busy = false;
			void this.requestUpdate();
		}
	}

	/**
	 * The in-page player (39p): an MP4 whose codecs this browser's MSE plays
	 * is fed segment by segment — keyframe-accurate seeks into a sealed file
	 * of any size, with no service worker in the way. Anything else (or any
	 * failure) plays the older way.
	 */
	private async startMse(id: string): Promise<boolean> {
		try {
			const p = await this.model.videoPlayback(id);
			if (!p) return false;
			// (The engine's codecs, not the stored sidecar's: an older engine
			// may have named them otherwise.)
			const codecs = p.index.summary.codecs;
			const type = mseType(codecs, p.index.summary.tracks.some((t) => t.type === "video"));
			if (!codecs || !canPlayWithMse(type)) {
				p.index.drop();
				p.source.clear();
				return false;
			}
			this.mse = { index: p.index, source: p.source, meta: p.meta, version: p.version, hasPoster: p.hasPoster, type };
			return true;
		} catch {
			return false;
		}
	}

	/**
	 * A protected video (40c): its state first — for everyone, so a lead's
	 * header can offer Protect. A member who does not get the original plays
	 * the copy through FairPlay where this browser has it, and is told where
	 * it plays where it does not (or that the copy is still being made).
	 * Answers true when the viewer is handled here.
	 */
	private async startProtected(id: string): Promise<boolean> {
		this.drm = await this.model.drmState(id);
		const d = this.drm;
		if (!d?.protected || d.original) return false;
		const copy = readyCopy(d);
		if (!copy) {
			this.protectedNote = "This video is protected, and its protected copy is still being made — a lead's browser makes it. Try again later.";
		} else if (!d.playable) {
			this.protectedNote = "This video is protected, and this deployment cannot play protected copies yet (FairPlay is not set up — it waits on Apple).";
		} else if (!(await fairPlaySupported())) {
			this.protectedNote = "This video is protected. It plays in Safari on a Mac, iPhone or iPad — not in this browser.";
		} else {
			this.protectedPlay = this.model.drmRoutes(id, copy.version);
		}
		return true;
	}

	/** A lead's Protect (40c): confirm, then package — with its progress. */
	private async protect(): Promise<void> {
		const ok = confirm(
			"Protect this video?\n\n" +
				"Everyone but leads will then get only a protected copy that plays in Safari (FairPlay) and cannot be saved. " +
				"The copy's key is held by the server — it is not end-to-end encrypted, unlike the original. " +
				"The copy takes about as much space as the video. Copies already downloaded or shared are not taken back.",
		);
		if (!ok) return;
		this.protecting = { done: 0, total: 1 };
		try {
			await this.model.protectVideo(this.target.id, (done, total) => (this.protecting = { done, total }));
			this.drm = await this.model.drmState(this.target.id);
			this.model.notify("Protected: everyone but leads now gets the protected copy.");
		} catch (e) {
			this.error = e instanceof Error ? e.message : String(e);
		} finally {
			this.protecting = null;
			await this.updateComplete;
			this.refocus();
		}
	}

	private async unprotect(): Promise<void> {
		if (!confirm("Remove protection? The protected copies and their keys are deleted, and everyone who may read this video gets the original again.")) return;
		try {
			await this.model.unprotectVideo(this.target.id);
			this.drm = await this.model.drmState(this.target.id);
		} catch (e) {
			this.error = e instanceof Error ? e.message : String(e);
		}
		await this.updateComplete;
		this.refocus();
	}

	/** The header's protection controls: a lead's Protect / Remove, and the
	 * badge that says what others get. */
	private protectionControls(): TemplateResult | typeof nothing {
		const d = this.drm;
		if (!d || this.mode !== "video") return nothing;
		if (this.protecting) return html`<span class="text-xs text-amber-300" data-test="viewer-protecting">Protecting… ${this.protecting.done}/${this.protecting.total}</span>`;
		if (d.protected) {
			const stale = !readyCopy(d);
			return html`
				<span class="rounded-full border border-amber-600/60 px-2 py-0.5 text-[11px] text-amber-300" data-test="viewer-protected-badge" title="Others get the protected copy only">🔒 Protected${stale && d.original ? " — copy not made for this version" : ""}</span>
				${d.canProtect && stale ? html`<button class="rounded-lg border border-neutral-700 px-3 py-1.5 text-xs hover:border-accent" data-test="viewer-protect" @click=${() => void this.protect()}>Make protected copy</button>` : nothing}
				${d.canProtect ? html`<button class="rounded-lg border border-neutral-700 px-3 py-1.5 text-xs hover:border-accent" data-test="viewer-unprotect" @click=${() => void this.unprotect()}>Remove protection</button>` : nothing}
			`;
		}
		return d.canProtect && isMp4(this.target.name, null) ? html`<button class="rounded-lg border border-neutral-700 px-3 py-1.5 text-xs hover:border-accent" data-test="viewer-protect" title="Others get a protected copy that plays in Safari and cannot be saved" @click=${() => void this.protect()}>🔒 Protect…</button>` : nothing;
	}

	protected override updated(): void {
		this.wireVideo();
		this.attachProtected();
		this.attachDocument();
		if (!this.mse || this.player) return;
		const video = this.querySelector<HTMLMediaElement>("main [data-engine=mse]");
		if (!video) return;
		const { index, source, type } = this.mse;
		this.player = new MsePlayer(video, index, source, type, {
			// The engine or the decoder refused a piece: play it the older way.
			onFail: () => void this.fallBack(),
		});
	}

	/** Once the document's place is on screen: its reader, in a sandboxed frame. */
	private attachDocument(): void {
		if (this.mode !== "document" || !this.docBytes || this.frame) return;
		const host = this.querySelector<HTMLElement>("[data-preview-host]");
		if (!host) return;
		const bytes = this.docBytes;
		this.docBytes = null;
		const shown = this.shown();
		// The name picks the reader; the first bytes correct it (a ".doc"
		// that is RTF, a ".docx" that is a Word 97 file — mode.ts).
		// (Inspected — 42g — it is the hex reader, whatever the bytes are.)
		const reader = this.asHex ? "hex" : sniffReader(bytes.subarray(0, 16), readerFor(shown.kind, this.docMime, shown.name) ?? "pdf", shown.name);
		this.frame = { close: () => {} };
		void openPreview(host, reader, { name: shown.name, mime: this.docMime, bytes }, {
			onKey: (key) => (key === "Escape" ? this.escape() : this.step(key === "ArrowRight" ? 1 : -1)),
			onStep: (delta) => this.step(delta),
			onShown: (facts) => (this.facts = facts),
			onError: (message) => (this.error = message),
			onHandover: (action, file) => (action === "open" ? this.openInner(file) : action === "inspect" ? void this.inspectInner(file) : this.askSave(file)),
		}, { sample: this.asHex?.sample === true })
			.then((f) => {
				if (this.frame && this.isConnected) this.frame = f;
				else f.close();
			})
			.catch((e: unknown) => (this.error = e instanceof Error ? e.message : String(e)));
	}

	/** Once the protected copy's `<video>` is on screen: FairPlay. */
	private attachProtected(): void {
		if (!this.protectedPlay || this.stopProtected) return;
		const video = this.querySelector<HTMLVideoElement>("video[data-engine=fairplay]");
		if (!video) return;
		this.stopProtected = () => {};
		void playProtected(video, this.protectedPlay, (message) => (this.error = message))
			.then((stop) => (this.stopProtected = stop))
			.catch((e: unknown) => {
				this.stopProtected = null;
				this.error = e instanceof Error ? e.message : String(e);
			});
	}

	private async fallBack(): Promise<void> {
		this.release();
		this.busy = true;
		const { id, kind } = this.target;
		const info = await this.model.renderInfo(id);
		try {
			const handle = await this.model.mediaHandle(id, renderMime(kind, info?.mime ?? null, this.target.name));
			if (handle) {
				this.streamed = true;
				this.url = handle.url;
			} else {
				await this.readWhole(info?.mime ?? null);
			}
		} catch (e) {
			this.error = e instanceof Error ? e.message : String(e);
		} finally {
			this.busy = false;
		}
	}

	// ── Resume, subtitles and posters (39o, docs/MOVIES.md) ────────────

	/** Once a video element is on screen: resume, save the position as it
	 * plays, and make a poster when the version has none. */
	private wireVideo(): void {
		const video = this.querySelector<HTMLVideoElement>("main video");
		if (!video || video === this.wired) return;
		this.wired = video;
		void this.loadExtras();
		video.addEventListener("loadedmetadata", () => {
			const at = this.resumeAt;
			if (at !== null && video.duration && at < video.duration - 5) video.currentTime = at;
		});
		video.addEventListener("timeupdate", () => {
			if (Date.now() - this.lastSaved > 10_000) this.savePosition(false);
		});
		video.addEventListener("pause", () => this.savePosition(true));
		video.addEventListener("playing", () => void this.backfillPoster(video), { once: true });
	}

	/**
	 * The whole file, decrypted into a blob — what an image always is, and
	 * media only when neither streaming path is there. Above MAX_INLINE it
	 * is not read at all: the viewer offers the Download (39w — the cap used
	 * to stop every kind before streaming was even tried).
	 */
	private async readWhole(mime: string | null): Promise<void> {
		if (this.target.size > MAX_INLINE) {
			this.mode = "too-large";
			return;
		}
		const parts: Uint8Array[] = [];
		await this.model.openBytes(this.target.id, this.target.version, (plain) => void parts.push(plain));
		this.url = blobURL(new Blob([concat(parts) as BlobPart], { type: renderMime(this.target.kind, mime, this.target.name) }));
	}

	/** The saved position and the subtitles, fetched beside the video. */
	private async loadExtras(): Promise<void> {
		const { id, name } = this.target;
		const folderId = this.target.folderId !== undefined ? this.target.folderId : this.model.state.get().folderId;
		const [positions, subs] = await Promise.all([this.model.positions().catch(() => new Map()), this.model.subtitlesFor(id, name, folderId).catch(() => [])]);
		const p = positions.get(id);
		this.resumeAt = p && worthResuming(p.at, p.of) ? p.at : null;
		const video = this.wired;
		if (video && this.resumeAt !== null && video.readyState >= 1 && video.currentTime < 1) video.currentTime = this.resumeAt;
		const tracks: { url: string; lang: string | null; label: string }[] = [];
		for (const s of subs) {
			try {
				const text = await this.model.subtitleText(s.id);
				tracks.push({ url: blobURL(new Blob([text], { type: "text/vtt" })), lang: s.lang, label: s.lang ? s.lang.toUpperCase() : s.name });
			} catch {
				// a subtitle file that does not open is left out
			}
		}
		this.tracks = tracks;
	}

	private savePosition(now: boolean): void {
		const video = this.wired;
		if (!video || !video.duration || !Number.isFinite(video.duration) || video.currentTime < 1) return;
		if (!now && Date.now() - this.lastSaved < 10_000) return;
		this.lastSaved = Date.now();
		void this.model.savePosition(this.target.id, video.currentTime, video.duration).catch(() => {});
	}

	/** A poster for a version without one (39o): the frame on screen a
	 * moment into playing — once, and only through the in-page player,
	 * which knows the version and its sidecar. */
	private async backfillPoster(video: HTMLVideoElement): Promise<void> {
		const m = this.mse;
		if (!m || m.hasPoster) return;
		const at = posterTime(m.meta.durationMs);
		if (video.currentTime < at) await new Promise<void>((ok) => {
			const tick = () => (video.currentTime >= at || !this.wired ? ok() : setTimeout(tick, 200));
			tick();
		});
		if (!this.wired) return;
		const webp = await posterFromVideo(video).catch(() => null);
		if (webp) await this.model.savePoster(this.target.id, m.version, m.meta, webp).catch(() => {});
		m.hasPoster = true;
	}

	private startOver(): void {
		this.resumeAt = null;
		if (this.wired) this.wired.currentTime = 0;
	}

	protected override render(): TemplateResult {
		const t = this.target;
		const top = this.inner.at(-1);
		const pos = top ? null : this.place();
		const details = top
			? `${fmtSize(top.bytes.length)} · an attachment of “${this.inner.length > 1 ? this.inner.at(-2)!.name : t.name}” — not a file in the vault`
			: `${fmtSize(t.size)} · v${t.version ?? 1} · ${this.drm?.protected && !this.drm.original ? "a protected copy, decrypted only inside Safari's DRM" : "decrypted here, sealed everywhere else"}`;
		return html`
			<div class="fixed inset-0 z-50 flex flex-col bg-black/80 outline-none max-sm:bg-black" tabindex="-1" data-viewer-root @keydown=${(e: KeyboardEvent) => this.onKey(e)}>
				<!-- On a phone (41b) the header is one short row: the name, Download
				     and ✕; the details line moves under the picture. -->
				<header class="flex items-center gap-2 border-b border-neutral-800 bg-neutral-900/95 px-2 py-2 pt-[max(0.5rem,env(safe-area-inset-top))] text-sm sm:gap-3 sm:px-4 sm:py-2.5">
					${top ? html`<button class="shrink-0 rounded-lg border border-neutral-700 px-2.5 py-1.5 text-xs hover:border-accent" data-test="viewer-back" title="Back (esc)" @click=${() => this.back()}>‹ Back</button>` : nothing}
					${icon(top ? kindOf(top.name, top.mime) : t.kind, "hidden h-5 w-5 text-neutral-400 sm:block")}
					<span class="min-w-0 flex-1 truncate pl-1 text-neutral-100 sm:pl-0" data-test="viewer-name">${top ? html`<span class="text-neutral-500">${[t.name, ...this.inner.slice(0, -1).map((f) => f.name)].join(" › ")} › </span>${top.name}` : t.name}</span>
					${pos ? html`<span class="shrink-0 tabular-nums text-xs text-neutral-500" data-test="viewer-position">${pos.at + 1} / ${pos.of}</span>` : nothing}
					${pos ? html`<span class="hidden shrink-0 sm:flex"><button class="rounded-l-lg border border-neutral-700 px-2 py-1 text-xs hover:border-accent disabled:opacity-30" title="Previous (←)" ?disabled=${pos.at === 0} @click=${() => this.step(-1)}>‹</button><button class="rounded-r-lg border border-l-0 border-neutral-700 px-2 py-1 text-xs hover:border-accent disabled:opacity-30" title="Next (→)" ?disabled=${pos.at === pos.of - 1} @click=${() => this.step(1)}>›</button></span>` : nothing}
					<span class="hidden shrink-0 text-xs text-neutral-500 sm:inline">${details}</span>
					${top ? nothing : this.protectionControls()}
					${top
						? html`<button class="shrink-0 rounded-lg bg-neutral-800 px-3 py-1.5 text-xs hover:bg-neutral-700" data-test="viewer-save-inner" title="Save this attachment into the vault (you are asked first)" @click=${() => this.askSave(top)}>Save to vault</button>`
						: this.drm?.protected && !this.drm.original
							? nothing
							: html`<button class="shrink-0 rounded-lg bg-neutral-800 px-3 py-1.5 text-xs hover:bg-neutral-700" @click=${() => void this.model.download(t.id, t.name)}>Download</button>`}
					<button class="shrink-0 rounded-lg border border-neutral-700 px-3 py-1.5 text-xs hover:border-accent" aria-label="Close" data-test="viewer-close" @click=${() => this.close()}><span class="sm:hidden" aria-hidden="true">✕</span><span class="hidden sm:inline">Close (esc)</span></button>
				</header>
				<main class="flex min-h-0 flex-1 touch-pan-y overflow-auto ${this.mode === "document" && !this.busy && !this.error ? "items-stretch p-0" : "items-center justify-center p-1 sm:p-6"}" @touchstart=${{ handleEvent: (e: TouchEvent) => this.onTouchStart(e), passive: true }} @touchend=${{ handleEvent: (e: TouchEvent) => this.onTouchEnd(e), passive: true }}>${this.content()}</main>
				<p class="truncate border-t border-neutral-900 px-3 py-1.5 pb-[max(0.375rem,env(safe-area-inset-bottom))] text-center text-[11px] text-neutral-500 sm:hidden">${details}${pos ? " · swipe for the next" : ""}</p>
				${this.saving ? this.saveDialog() : nothing}
			</div>
		`;
	}

	/** Save into the vault (42c): asked here, outside any frame — a reader
	 * can request it, never do it. */
	private saveDialog(): TemplateResult {
		const s = this.saving!;
		return html`
			<div class="absolute inset-0 z-10 flex items-center justify-center bg-black/60 p-4" data-test="viewer-save-dialog" @keydown=${(e: KeyboardEvent) => {
				if (e.key === "Escape") {
					e.stopPropagation();
					this.saving = null;
					this.refocus();
				}
			}}>
				<div class="w-full max-w-md rounded-2xl border border-neutral-700 bg-neutral-900 p-6 text-sm shadow-2xl" role="dialog" aria-label="Save into the vault">
					<p class="text-neutral-100">Save <strong class="break-all">“${s.file.name}”</strong> (${fmtSize(s.file.bytes.length)}) into the vault, beside “${this.target.name}”?</p>
					${s.risk ? html`<p class="mt-2 text-amber-300" data-test="viewer-save-risk">⚠ It is ${s.risk}.</p>` : nothing}
					<label class="mt-3 flex items-start gap-2 text-neutral-300">
						<input type="checkbox" class="mt-0.5" data-test="viewer-save-sample" .checked=${s.sample} ?disabled=${!!s.file.sample} @change=${(e: Event) => (this.saving = { ...s, sample: (e.target as HTMLInputElement).checked })} />
						<span>Mark it as a malware sample — never previewed here, and downloaded only zipped with the password <code>${SAMPLE_PASSWORD}</code></span>
					</label>
					${s.error ? html`<p class="mt-2 text-red-400">${s.error}</p>` : nothing}
					<div class="mt-4 flex justify-end gap-2">
						<button class="rounded-xl border border-neutral-700 px-4 py-2 hover:border-accent" @click=${() => {
							this.saving = null;
							this.refocus();
						}}>Cancel</button>
						<button class="rounded-xl bg-accent px-4 py-2 font-medium text-neutral-950 hover:opacity-90 disabled:opacity-50" data-test="viewer-save-confirm" ?disabled=${s.busy} @click=${() => void this.confirmSave()}>${s.busy ? "Saving…" : "Save"}</button>
					</div>
				</div>
			</div>
		`;
	}

	private content(): TemplateResult {
		if (this.busy) return html`<p class="text-sm text-neutral-400">Opening…</p>`;
		if (this.error) return html`<p class="max-w-md text-center text-sm text-red-400">${this.error}</p>`;
		switch (this.mode) {
			case "video": {
				const tracks = this.tracks.map((tr) => html`<track kind="subtitles" src=${tr.url} srclang=${tr.lang ?? nothing} label=${tr.label} />`);
				const resume = this.resumeAt !== null
					? html`<p class="mt-2 flex items-center justify-center gap-2 text-xs text-neutral-400" data-test="viewer-resumed">Resumed at ${fmtClock(this.resumeAt)} <button class="rounded border border-neutral-700 px-2 py-0.5 hover:border-accent" @click=${() => this.startOver()}>Start over</button></p>`
					: nothing;
				if (this.protectedNote) return this.protectedNotice();
				if (this.protectedPlay) return html`<div class="flex max-h-full max-w-full flex-col items-center"><video class="max-h-[calc(100%-2rem)] max-w-full rounded-lg shadow-2xl" data-engine="fairplay" controls playsinline></video><p class="mt-2 text-xs text-neutral-500">Protected copy · an external display needs HDCP</p></div>`;
				if (this.mse) return html`<div class="flex max-h-full max-w-full flex-col items-center"><video class="max-h-[calc(100%-2rem)] max-w-full rounded-lg shadow-2xl" data-engine="mse" controls playsinline>${tracks}</video>${resume}</div>`;
				return this.url
					? html`<div class="flex max-h-full max-w-full flex-col items-center"><video class="max-h-[calc(100%-2rem)] max-w-full rounded-lg shadow-2xl" src=${this.url} controls ${this.streamed ? nothing : html`autoplay`}>${tracks}</video>${resume}</div>`
					: this.unknown();
			}
			case "audio":
				// Music in MP4 through the in-page engine (39w), the rest
				// through the media worker (or, when it is missing, a blob).
				return this.mse || this.url
					? html`<div class="w-full max-w-xl rounded-2xl bg-neutral-900 p-8 text-center shadow-2xl">
							${icon("audio", "h-16 w-16 text-neutral-600 mx-auto")}
							<p class="mt-2 truncate text-sm text-neutral-200">${this.target.name}</p>
							${this.mse ? html`<audio class="mt-4 w-full" data-engine="mse" controls></audio>` : html`<audio class="mt-4 w-full" src=${this.url!} controls></audio>`}
						</div>`
					: this.unknown();
			case "text":
				return html`
					<div class="h-full w-full max-w-5xl overflow-auto rounded-xl bg-neutral-950 shadow-2xl">
						<pre class="whitespace-pre-wrap break-words p-5 font-mono text-xs leading-relaxed text-neutral-200">${this.text ?? ""}</pre>
						${this.truncated ? html`<p class="border-t border-neutral-800 px-5 py-2 text-xs text-neutral-500">Shown: the first ${fmtSize(TEXT_CAP)} — Download for the rest.</p>` : nothing}
					</div>
				`;
			case "document":
				return html`<div class="flex h-full w-full flex-col">
					${this.facts.length
						? html`<ul class="max-h-[30vh] shrink-0 space-y-0.5 overflow-y-auto border-b border-neutral-800 bg-neutral-900/95 px-3 py-1.5 text-xs" data-test="viewer-facts" aria-label="What this file holds">
								${this.facts.map((f) => html`<li class=${f.level === "warn" ? "text-amber-300" : "text-neutral-400"}>${f.level === "warn" ? "⚠ " : ""}${f.text}${f.copy ? html` <button class="ml-1 rounded border border-neutral-700 px-1.5 text-[11px] text-neutral-300 hover:border-accent" data-test="viewer-fact-copy" title="Copy ${f.copy}" @click=${() => void this.copyFact(f.copy!)}>${this.copied === f.copy ? "Copied" : "Copy"}</button>` : nothing}</li>`)}
							</ul>`
						: nothing}
					<div class="min-h-0 flex-1" data-preview-host></div>
				</div>`;
			case "refused":
				return this.refused();
			default:
				return this.unknown();
		}
	}

	/** A protected video this browser cannot play, or whose copy is not
	 * ready (40c) — said plainly, with no way around it. */
	private protectedNotice(): TemplateResult {
		return html`
			<div class="max-w-md rounded-2xl border border-amber-700/60 bg-neutral-900 p-8 text-center" data-test="viewer-protected">
				<p class="text-4xl">🔒</p>
				<p class="mt-3 text-sm text-neutral-200">${this.protectedNote}</p>
				<p class="mt-2 text-xs text-neutral-500">Protected videos play as a copy that cannot be saved; only a lead downloads the original.</p>
			</div>
		`;
	}

	/** A sample is never rendered here (commit 29e). Download zips it;
	 * Inspect shows its bytes in the hex reader, on the record (42g). */
	private refused(): TemplateResult {
		const sample = this.policy === "sample";
		return html`
			<div class="max-w-md rounded-2xl border border-amber-700/60 bg-neutral-900 p-8 text-center" data-test="viewer-refused">
				${icon("sample", "h-16 w-16 text-amber-500 mx-auto")}
				<p class="mt-3 text-sm text-neutral-200">${sample ? "A malware sample — never run or rendered in this app." : "This file's type does not verify in its place — not rendered, as if it were a sample."}</p>
				${this.shownType ? html`<p class="mt-1 text-xs text-neutral-500">Type: ${this.shownType}</p>` : nothing}
				<p class="mt-1 text-xs text-neutral-500">Download saves it as a zip encrypted with the password <code class="text-neutral-300">${SAMPLE_PASSWORD}</code>, the convention antivirus and analysts expect. Open it only inside an analysis environment.</p>
				<div class="mt-4 flex flex-wrap justify-center gap-2">
					<button class="rounded-xl bg-amber-500 px-4 py-2 text-sm font-medium text-neutral-950 hover:opacity-90" @click=${() => void this.model.download(this.target.id, this.target.name)}>Download zipped</button>
					<button class="rounded-xl border border-amber-700/70 px-4 py-2 text-sm text-amber-200 hover:border-amber-500" data-test="viewer-inspect" title="Its bytes, strings and program headers — nothing in it runs or is drawn. The inspection is written into the audit trail first." @click=${() => void this.inspect(true)}>Inspect as bytes</button>
				</div>
				<p class="mt-2 text-[11px] text-neutral-500">Inspect shows its bytes, strings and program headers in a sandboxed frame, and is recorded in the audit trail.</p>
				${this.inspectError ? html`<p class="mt-2 text-xs text-red-400" data-test="viewer-inspect-error">${this.inspectError}</p>` : nothing}
			</div>
		`;
	}

	/** Nothing to show here: a format the viewer has no reader for, or
	 * something only shown by reading it whole that is too big for that. */
	private unknown(): TemplateResult {
		const top = this.inner.at(-1);
		if (top)
			return html`
				<div class="max-w-md rounded-2xl border border-neutral-800 bg-neutral-900 p-8 text-center" data-test="viewer-no-preview">
					${icon(kindOf(top.name, top.mime), "h-16 w-16 text-neutral-600 mx-auto")}
					<p class="mt-3 text-sm text-neutral-300">${this.mode === "too-large" ? "Too large to open in the page." : "No preview for this kind of attachment."}</p>
					<p class="mt-1 text-xs text-neutral-500">It is not opened here. Save it into the vault to keep it — as a malware sample, if it is one.</p>
					<div class="mt-4 flex flex-wrap justify-center gap-2">
						<button class="rounded-xl bg-accent px-4 py-2 text-sm font-medium text-neutral-950 hover:opacity-90" data-test="viewer-save-inner-body" @click=${() => this.askSave(top)}>Save to vault</button>
						${this.mode === "too-large" ? nothing : html`<button class="rounded-xl border border-neutral-700 px-4 py-2 text-sm text-neutral-200 hover:border-accent" data-test="viewer-inspect-hex" @click=${() => void this.inspectInner(top)}>Inspect as hex</button>`}
					</div>
				</div>
			`;
		const large = this.mode === "too-large";
		return html`
			<div class="max-w-md rounded-2xl border border-neutral-800 bg-neutral-900 p-8 text-center" data-test=${large ? "viewer-too-large" : "viewer-no-preview"}>
				${icon(this.target.kind, "h-16 w-16 text-neutral-600 mx-auto")}
				<p class="mt-3 text-sm text-neutral-300">${large ? "Too large to open in the page." : "No preview for this format."}</p>
				<p class="mt-1 text-xs text-neutral-500">${large
					? `Shown only by reading it whole, and ${fmtSize(this.target.size)} is more than a tab should hold (${fmtSize(MAX_INLINE)}). Download it to open it.`
					: "No reader takes this format. Inspect shows its bytes and strings; Download opens it on this computer."}</p>
				<div class="mt-4 flex flex-wrap justify-center gap-2">
					<button class="rounded-xl bg-accent px-4 py-2 text-sm font-medium text-neutral-950 hover:opacity-90" @click=${() => void this.model.download(this.target.id, this.target.name)}>Download</button>
					${large ? nothing : html`<button class="rounded-xl border border-neutral-700 px-4 py-2 text-sm text-neutral-200 hover:border-accent" data-test="viewer-inspect-hex" title="Its bytes and strings (and, for a program, its headers), in a sandboxed frame" @click=${() => void this.inspect(false)}>Inspect as hex</button>`}
				</div>
				${this.inspectError ? html`<p class="mt-2 text-xs text-red-400" data-test="viewer-inspect-error">${this.inspectError}</p>` : nothing}
			</div>
		`;
	}

	close(): void {
		this.release();
		this.dispatchEvent(new CustomEvent("closed", { bubbles: true, composed: true }));
	}

	// ── the next file (41b): a swipe on a phone, ← and → on a keyboard ──

	/** Where this file sits among its siblings, or null when it has none. */
	private place(): { at: number; of: number } | null {
		const list = this.target.siblings;
		if (!list || list.length < 2) return null;
		const at = list.findIndex((t) => t.id === this.target.id);
		return at < 0 ? null : { at, of: list.length };
	}

	/** Open the file `delta` places away. The shell mounts a fresh viewer
	 * for it (keyed by id), so nothing of this file's — its blob URL, its
	 * player, its key in the media worker — carries over: release() runs as
	 * this element leaves. */
	private step(delta: number): void {
		if (this.inner.length) return; // the siblings are the vault's files, not the attachment's
		const p = this.place();
		const next = p ? this.target.siblings![p.at + delta] : undefined;
		if (!next) return;
		this.dispatchEvent(new CustomEvent("navigate", { detail: { ...next, siblings: this.target.siblings } as ViewerTarget, bubbles: true, composed: true }));
	}

	private touch: { x: number; y: number; ignore: boolean } | null = null;

	private onTouchStart(e: TouchEvent): void {
		const t = e.touches[0];
		// Not a swipe: two fingers (a pinch), a finger on a player's controls
		// (scrubbing), or a page the person has zoomed into (panning).
		const onMedia = (e.target as HTMLElement | null)?.closest?.("video, audio");
		const zoomed = (globalThis.visualViewport?.scale ?? 1) > 1.01;
		this.touch = t ? { x: t.clientX, y: t.clientY, ignore: e.touches.length > 1 || Boolean(onMedia) || zoomed } : null;
	}

	private onTouchEnd(e: TouchEvent): void {
		const start = this.touch;
		this.touch = null;
		const t = e.changedTouches[0];
		if (!start || start.ignore || !t) return;
		const dx = t.clientX - start.x;
		const dy = t.clientY - start.y;
		if (Math.abs(dx) < SWIPE_MIN || Math.abs(dy) > Math.abs(dx) * SWIPE_SLANT) return;
		this.step(dx < 0 ? 1 : -1); // finger to the left: the next file, as a photo roll
	}

	/** Escape: out of an attachment first, then the viewer. */
	private escape(): void {
		if (this.saving) {
			this.saving = null;
			this.refocus();
		} else if (this.inner.length) this.back();
		else this.close();
	}

	private onKey(e: KeyboardEvent): void {
		if (e.key === "Escape") return this.escape();
		// ← → belong to a player that has the focus (it seeks with them).
		if ((e.target as HTMLElement | null)?.closest?.("video, audio, input, textarea")) return;
		if (e.key === "ArrowRight") this.step(1);
		if (e.key === "ArrowLeft") this.step(-1);
	}
}

/** Is a saved place worth offering? Not near the start or the end: within
 * 5 % of the length, at most 5 s — a film's last credits, a 6-second clip's
 * last third of a second. (A fixed 5 s made every clip under 10 s
 * unresumable.) */
export function worthResuming(at: number, of: number): boolean {
	const margin = Math.min(5, of * 0.05);
	return at > margin && at < of - margin;
}

/** Seconds as h:mm:ss or m:ss. */
function fmtClock(sec: number): string {
	const s = Math.floor(sec % 60);
	const m = Math.floor(sec / 60) % 60;
	const h = Math.floor(sec / 3600);
	return h ? `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}` : `${m}:${String(s).padStart(2, "0")}`;
}

function concat(parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let at = 0;
	for (const p of parts) {
		out.set(p, at);
		at += p.length;
	}
	return out;
}