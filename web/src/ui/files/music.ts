// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-music>: the family's music library (docs/MUSIC.md). One feed of
 * sealed metadata blobs opened with the store key — the audio itself is
 * never decrypted for browsing; a row's play hands the file to the same
 * viewer the explorers use, and THAT is the only moment audio plaintext
 * exists. Rows sort by artist → album → title, the way a shelf would.
 */

import { LitElement, html } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import type { FilesModel } from "./model.ts";
import type { ViewerTarget } from "../viewer/viewer.ts";

type Track = Awaited<ReturnType<FilesModel["musicLibrary"]>>[number];

const fmtTime = (sec: number) => `${Math.floor(sec / 60)}:${String(Math.floor(sec % 60)).padStart(2, "0")}`;

@customElement("gorani-music")
export class GoraniMusic extends LitElement {
	@property({ type: Object }) model!: FilesModel;
	@property({ type: String }) memberName = "";

	@state() private tracks: Track[] | null = null;
	@state() private error = "";

	protected override createRenderRoot(): HTMLElement {
		return this; // global Tailwind stylesheet
	}

	override connectedCallback(): void {
		super.connectedCallback();
		void this.load();
	}

	private async load(): Promise<void> {
		this.error = "";
		try {
			this.tracks = await this.model.musicLibrary();
		} catch (e) {
			this.error = e instanceof Error ? e.message : String(e);
		}
	}

	protected override render() {
		if (this.error) return html`<p class="p-6 text-sm text-red-400">${this.error}</p>`;
		if (this.tracks === null) return html`<p class="p-6 text-sm text-neutral-500">Opening the library…</p>`;
		if (!this.tracks.length)
			return html`<div class="p-6 text-sm text-neutral-500">
				<p class="text-lg text-neutral-300">♪ ${this.memberName}'s library is empty</p>
				<p class="mt-2">Audio files uploaded in the explorer carry their tags here — parsed and sealed in the browser, the server never sees them.</p>
			</div>`;
		return html`
			<div class="h-full overflow-auto p-3 sm:p-6" data-test="music">
				<h2 class="text-lg font-medium text-neutral-200">Music</h2>
				<p class="mt-1 text-xs text-neutral-500">${this.tracks.length} track${this.tracks.length === 1 ? "" : "s"} · metadata sealed per version, opened from one feed</p>
				<table class="mt-4 w-full text-left text-sm">
					<thead class="text-xs uppercase tracking-wide text-neutral-500">
						<tr>
							<!-- On a phone (41b) one column: artist and album fold under the title. -->
							<th class="hidden py-2 pr-4 sm:table-cell">#</th>
							<th class="py-2 pr-4">Title</th>
							<th class="hidden py-2 pr-4 sm:table-cell">Artist</th>
							<th class="hidden py-2 pr-4 sm:table-cell">Album</th>
							<th class="py-2 text-right sm:pr-4">Length</th>
						</tr>
					</thead>
					<tbody>
						${this.tracks.map(
							(t, i) => html`
								<tr
									class="cursor-pointer border-t border-neutral-800 hover:bg-neutral-800/50"
									title="Open in the viewer"
									@click=${() =>
										this.dispatchEvent(
											new CustomEvent("open-viewer", { detail: { id: t.id, name: t.title ?? `${t.artist ?? "Unknown"} — track`, kind: "audio", size: t.size, version: t.version } as ViewerTarget, bubbles: true, composed: true }),
										)}
								>
									<td class="hidden py-2 pr-4 text-neutral-500 sm:table-cell">${t.track ?? i + 1}</td>
									<td class="py-3 pr-4 text-neutral-200 sm:py-2" data-test="track">
										${t.title ?? "Unknown title"}
										<span class="block truncate text-xs text-neutral-500 sm:hidden">${t.artist ?? "Unknown artist"} · ${t.album ?? "Unknown album"}</span>
									</td>
									<td class="hidden py-2 pr-4 text-neutral-400 sm:table-cell">${t.artist ?? "Unknown artist"}</td>
									<td class="hidden py-2 pr-4 text-neutral-400 sm:table-cell">${t.album ?? "Unknown album"}</td>
									<td class="py-3 text-right text-neutral-500 sm:py-2 sm:pr-4">${t.durationSec ? fmtTime(t.durationSec) : "—"}</td>
								</tr>
							`,
						)}
					</tbody>
				</table>
			</div>
		`;
	}
}

