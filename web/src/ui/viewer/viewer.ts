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
import { pickViewerMode, renderMime, TEXT_CAP, type ViewerMode } from "./mode.ts";
import { icon, type FileKind } from "../files/icons.ts";
import { blobURL, revokeBlobURL } from "../../lib/blob-urls.ts";
import { fmtSize } from "../files/shared.ts";
import { forgetMedia } from "../../lib/media-worker.ts";
import { SAMPLE_PASSWORD } from "../../vault/samples.ts";

export interface ViewerTarget {
	id: string;
	name: string;
	kind: FileKind;
	size: number;
	version?: number;
}

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

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	protected override async firstUpdated(): Promise<void> {
		// Focus the overlay so its "Close (esc)" works at once — the key
		// handler sits on this element, which nothing focused before.
		this.querySelector<HTMLElement>("[data-viewer-root]")?.focus();
		await this.load();
	}

	override disconnectedCallback(): void {
		super.disconnectedCallback();
		this.release();
	}

	/** Let go of the decrypted handle: revoke the blob URL, or tell the media
	 * service worker to forget this file's content key (streamed media). */
	private release(): void {
		if (!this.url) return;
		if (this.streamed) {
			const url = this.url;
			void forgetMedia(url);
		} else {
			revokeBlobURL(this.url);
		}
		this.url = null;
	}

	private async load(): Promise<void> {
		const { id, kind, size } = this.target;
		const info = await this.model.info(id);
		const mime = info?.mime ?? null;
		this.mode = pickViewerMode(kind, mime, size, info?.policy ?? "unverified");
		this.policy = info?.policy ?? "unverified";
		this.shownType = info?.shownType ?? null;
		if (this.mode === "unsupported" || this.mode === "refused") {
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
			} else if ((this.mode === "video" || this.mode === "audio") && (info?.size ?? 0) > 8 * 1024 * 1024) {
				// Streaming path: the scoped media worker serves decrypted
				// ranges; the browser's player seeks natively. Only for larger
				// media — small ones are simpler as blobs.
				const handle = await this.model.mediaHandle(id, renderMime(kind, mime, this.target.name));
				if (handle) {
					this.streamed = true;
					this.url = handle.url;
					return;
				}
				const parts: Uint8Array[] = [];
				await this.model.openBytes(id, this.target.version, (plain) => { parts.push(plain); });
				this.url = blobURL(new Blob([concat(parts) as BlobPart], { type: renderMime(kind, mime, this.target.name) }));
			} else {
				const parts: Uint8Array[] = [];
				await this.model.openBytes(id, this.target.version, (plain) => {
					parts.push(plain);
					return Promise.resolve();
				});
				const whole = concat(parts);
				this.url = blobURL(new Blob([whole as BlobPart], { type: renderMime(kind, mime, this.target.name) }));
			}
		} catch (e) {
			this.error = e instanceof Error ? e.message : String(e);
		} finally {
			this.busy = false;
			void this.requestUpdate();
		}
	}

	protected override render(): TemplateResult {
		const t = this.target;
		return html`
			<div class="fixed inset-0 z-50 flex flex-col bg-black/80 outline-none" tabindex="-1" data-viewer-root @keydown=${(e: KeyboardEvent) => e.key === "Escape" && this.close()}>
				<header class="flex items-center gap-3 border-b border-neutral-800 bg-neutral-900/95 px-4 py-2.5 text-sm">
					${icon(t.kind, "h-5 w-5 text-neutral-400")}
					<span class="min-w-0 flex-1 truncate text-neutral-100">${t.name}</span>
					<span class="shrink-0 text-xs text-neutral-500">${fmtSize(t.size)} · v${t.version ?? 1} · decrypted here, sealed everywhere else</span>
					<button class="rounded-lg bg-neutral-800 px-3 py-1.5 text-xs hover:bg-neutral-700" @click=${() => void this.model.download(t.id, t.name)}>Download</button>
					<button class="rounded-lg border border-neutral-700 px-3 py-1.5 text-xs hover:border-accent" @click=${() => this.close()}>Close (esc)</button>
				</header>
				<main class="flex min-h-0 flex-1 items-center justify-center overflow-auto p-6">${this.content()}</main>
			</div>
		`;
	}

	private content(): TemplateResult {
		if (this.busy) return html`<p class="text-sm text-neutral-400">Opening…</p>`;
		if (this.error) return html`<p class="max-w-md text-center text-sm text-red-400">${this.error}</p>`;
		switch (this.mode) {
			case "image":
				return this.url ? html`<img class="max-h-full max-w-full rounded-lg object-contain shadow-2xl" src=${this.url} alt=${this.target.name} />` : this.unknown();
			case "video":
				return this.url ? html`<video class="max-h-full max-w-full rounded-lg shadow-2xl" src=${this.url} controls ${this.streamed ? nothing : html`autoplay`}></video>` : this.unknown();
			case "audio":
				return this.url
					? html`<div class="w-full max-w-xl rounded-2xl bg-neutral-900 p-8 text-center shadow-2xl">
							${icon("audio", "h-16 w-16 text-neutral-600 mx-auto")}
							<p class="mt-2 truncate text-sm text-neutral-200">${this.target.name}</p>
							<audio class="mt-4 w-full" src=${this.url} controls></audio>
						</div>`
					: this.unknown();
			case "text":
				return html`
					<div class="h-full w-full max-w-5xl overflow-auto rounded-xl bg-neutral-950 shadow-2xl">
						<pre class="whitespace-pre-wrap break-words p-5 font-mono text-xs leading-relaxed text-neutral-200">${this.text ?? ""}</pre>
						${this.truncated ? html`<p class="border-t border-neutral-800 px-5 py-2 text-xs text-neutral-500">Shown: the first ${fmtSize(TEXT_CAP)} — Download for the rest.</p>` : nothing}
					</div>
				`;
			case "refused":
				return this.refused();
			default:
				return this.unknown();
		}
	}

	/** A sample is never rendered here (commit 29e). Download zips it. */
	private refused(): TemplateResult {
		const sample = this.policy === "sample";
		return html`
			<div class="max-w-md rounded-2xl border border-amber-700/60 bg-neutral-900 p-8 text-center" data-test="viewer-refused">
				${icon("sample", "h-16 w-16 text-amber-500 mx-auto")}
				<p class="mt-3 text-sm text-neutral-200">${sample ? "A malware sample — never opened in this app." : "This file's type does not verify in its place — not opened, as if it were a sample."}</p>
				${this.shownType ? html`<p class="mt-1 text-xs text-neutral-500">Type: ${this.shownType}</p>` : nothing}
				<p class="mt-1 text-xs text-neutral-500">Download saves it as a zip encrypted with the password <code class="text-neutral-300">${SAMPLE_PASSWORD}</code>, the convention antivirus and analysts expect. Open it only inside an analysis environment.</p>
				<button class="mt-4 rounded-xl bg-amber-500 px-4 py-2 text-sm font-medium text-neutral-950 hover:opacity-90" @click=${() => void this.model.download(this.target.id, this.target.name)}>Download zipped</button>
			</div>
		`;
	}

	private unknown(): TemplateResult {
		return html`
			<div class="max-w-md rounded-2xl border border-neutral-800 bg-neutral-900 p-8 text-center">
				${icon(this.target.kind, "h-16 w-16 text-neutral-600 mx-auto")}
				<p class="mt-3 text-sm text-neutral-300">No inline preview yet for this format.</p>
				<p class="mt-1 text-xs text-neutral-500">The document readers, PDF and the sealed video streamer land with the next commit. Download works today.</p>
				<button class="mt-4 rounded-xl bg-accent px-4 py-2 text-sm font-medium text-neutral-950 hover:opacity-90" @click=${() => void this.model.download(this.target.id, this.target.name)}>Download</button>
			</div>
		`;
	}

	close(): void {
		this.release();
		this.dispatchEvent(new CustomEvent("closed", { bubbles: true, composed: true }));
	}
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