// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A small picture — the explorer's Quick Look, its details pane — drawn in
 * the preview frame's compact mode (commit 42d, docs/PREVIEWS.md ›
 * Images), never as an <img> in the app's page. A decrypted picture is
 * attacker-made bytes like any other file, and the browser's decoders are
 * code a crafted picture attacks (CVE-2023-4863: a WebP, exploited through
 * an ordinary <img>); in the frame, a decoder that falls holds that
 * picture and nothing of the vault's.
 *
 *   <gorani-picture .file=${{ name, mime, bytes }} .fallback=${icon(…)}>
 *
 * The frame takes no clicks and no keyboard (sandbox.ts, compact): it is
 * there to be looked at. A format the browser does not draw, a picture
 * too large, or bytes that do not decode show the fallback instead.
 */

import { LitElement, html, nothing, type TemplateResult } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { openPreview, type PreviewFrame } from "./sandbox.ts";

export interface PictureFile {
	name: string;
	mime: string | null;
	bytes: Uint8Array;
}

@customElement("gorani-picture")
export class GoraniPicture extends LitElement {
	@property({ attribute: false }) file: PictureFile | null = null;
	@property({ attribute: false }) fallback: TemplateResult | null = null;
	@state() private failed = false;
	private frame: PreviewFrame | null = null;
	private opening: PictureFile | null = null;

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	protected override render(): TemplateResult | typeof nothing {
		if (!this.file || this.failed) return this.fallback ?? nothing;
		return html`<div class="h-full w-full" data-picture-host></div>`;
	}

	protected override willUpdate(changed: Map<string, unknown>): void {
		if (changed.has("file")) {
			this.frame?.close();
			this.frame = null;
			this.opening = null;
			this.failed = false;
		}
	}

	protected override updated(): void {
		const file = this.file;
		if (!file || this.failed || this.opening === file) return;
		const host = this.querySelector<HTMLElement>("[data-picture-host]");
		if (!host) return;
		this.opening = file;
		// A copy: the frame takes its bytes (they are transferred to it).
		void openPreview(host, "image", { name: file.name, mime: file.mime, bytes: file.bytes.slice() }, {
			onKey: () => {},
			onStep: () => {},
			onShown: () => {},
			onError: () => {
				if (this.opening === file) this.failed = true;
			},
		}, { compact: true })
			.then((f) => {
				if (this.opening === file && this.isConnected) this.frame = f;
				else f.close();
			})
			.catch(() => {
				if (this.opening === file) this.failed = true;
			});
	}

	override disconnectedCallback(): void {
		super.disconnectedCallback();
		this.frame?.close();
		this.frame = null;
		this.opening = null;
	}
}

declare global {
	interface HTMLElementTagNameMap {
		"gorani-picture": GoraniPicture;
	}
}
