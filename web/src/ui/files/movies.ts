// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-movies>: the area's videos as a shelf (commit 39o, docs/MOVIES.md)
 * — family videos as much as films: every folder that holds videos is a
 * collection, and each video a card with its poster, its length, its
 * picture size, its size on disk, and how far the person watching got.
 *
 * Nothing here decrypts a video. Names open with the store key; length and
 * picture size come from one feed of sealed sidecars (39p); a poster (a
 * small sealed WebP) is fetched only for the cards on screen. Playing opens
 * the same viewer the explorers use — which resumes, finds the subtitles,
 * and, for a video without a poster, makes one from the frame on screen.
 */

import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import type { FilesModel, Movie, MovieCollection } from "./model.ts";
import type { ViewerTarget } from "../viewer/viewer.ts";
import { icon } from "./icons.ts";
import { fmtSize, cssom } from "./shared.ts";
import "../viewer/picture.ts";
import type { PictureFile } from "../viewer/picture.ts";

/** 1:02:03, or 4:05. */
function fmtLength(ms: number): string {
	const sec = Math.round(ms / 1000);
	const h = Math.floor(sec / 3600);
	const m = Math.floor(sec / 60) % 60;
	const s = sec % 60;
	return h ? `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}` : `${m}:${String(s).padStart(2, "0")}`;
}

/** "1080p", "4K" — what people call a picture size. */
function fmtPicture(width: number, height: number): string {
	if (!width || !height) return "";
	const short = Math.min(width, height);
	if (short >= 2100) return "4K";
	return `${short}p`;
}

@customElement("gorani-movies")
export class GoraniMovies extends LitElement {
	@property({ type: Object }) model!: FilesModel;
	@property({ type: String }) memberName = "";

	@state() private collections: MovieCollection[] | null = null;
	@state() private error = "";
	/** Each card's poster, as bytes: drawn in the preview frame (viewer/picture.ts), not in this page. */
	@state() private posters = new Map<string, PictureFile>();
	private observer: IntersectionObserver | null = null;
	private asked = new Set<string>();

	protected override createRenderRoot(): HTMLElement {
		return this; // global Tailwind stylesheet
	}

	override connectedCallback(): void {
		super.connectedCallback();
		void this.load();
	}

	override disconnectedCallback(): void {
		super.disconnectedCallback();
		this.observer?.disconnect();
		this.posters = new Map();
	}

	private async load(): Promise<void> {
		this.error = "";
		try {
			this.collections = await this.model.movieLibrary();
		} catch (e) {
			this.error = e instanceof Error ? e.message : String(e);
		}
	}

	/** Posters for the cards that scroll into view — a library of hundreds
	 * fetches only what is shown. */
	protected override updated(): void {
		this.observer ??= new IntersectionObserver((entries) => {
			for (const e of entries) {
				if (!e.isIntersecting) continue;
				const el = e.target as HTMLElement;
				this.observer?.unobserve(el);
				void this.fetchPoster(el.dataset.id ?? "", Number(el.dataset.version));
			}
		});
		for (const el of this.querySelectorAll<HTMLElement>("[data-movie][data-has-poster]")) {
			if (!this.asked.has(el.dataset.id ?? "")) this.observer.observe(el);
		}
	}

	private async fetchPoster(id: string, version: number): Promise<void> {
		if (!id || this.asked.has(id)) return;
		this.asked.add(id);
		const poster = await this.model.posterOf(id, version);
		if (poster) this.posters = new Map(this.posters).set(id, poster);
	}

	private play(m: Movie): void {
		const target: ViewerTarget = { id: m.id, name: m.name, kind: "video", size: m.size, version: m.version, folderId: m.folderId };
		this.dispatchEvent(new CustomEvent("open-viewer", { detail: target, bubbles: true, composed: true }));
	}

	protected override render() {
		if (this.error) return html`<p class="p-6 text-sm text-red-400">${this.error}</p>`;
		if (this.collections === null) return html`<p class="p-6 text-sm text-neutral-500">Opening the movies…</p>`;
		const all = this.collections.flatMap((c) => c.movies);
		if (!all.length)
			return html`<div class="p-6 text-sm text-neutral-500" data-test="movies-empty">
				<p class="text-lg text-neutral-300">🎬 No videos in ${this.memberName} yet</p>
				<p class="mt-2">Videos uploaded in the explorer appear here, grouped by their folder — a poster, the length and the picture size made in your browser and sealed; the server sees none of it.</p>
			</div>`;
		const total = all.reduce((n, m) => n + (m.durationMs ?? 0), 0);
		return html`
			<div class="h-full overflow-auto p-3 sm:p-6" data-test="movies">
				<h2 class="text-lg font-medium text-neutral-200">Movies</h2>
				<p class="mt-1 text-xs text-neutral-500">${all.length} video${all.length === 1 ? "" : "s"}${total ? ` · ${fmtLength(total)} in all` : ""} · in ${this.collections.length} collection${this.collections.length === 1 ? "" : "s"}</p>
				${this.collections.map((c) => this.collection(c))}
			</div>
		`;
	}

	private collection(c: MovieCollection) {
		return html`
			<section class="mt-6" data-test="movie-collection" data-path=${c.path}>
				<h3 class="flex items-center gap-2 text-sm font-medium text-neutral-300">${icon("folder", "h-4 w-4 text-neutral-500")} ${c.path || "Top folder"} <span class="text-xs font-normal text-neutral-500">${c.movies.length}</span></h3>
				<!-- One poster per row on a phone (41b): a full-width picture, not two thumbnails. -->
				<div class="mt-3 grid grid-cols-1 gap-4 sm:grid-cols-[repeat(auto-fill,minmax(11rem,1fr))]" data-test="movie-grid">${c.movies.map((m) => this.card(m))}</div>
			</section>
		`;
	}

	private card(m: Movie) {
		const poster = this.posters.get(m.id);
		const watched = m.position && m.position.of ? Math.min(1, m.position.at / m.position.of) : 0;
		const title = m.name.replace(/\.[^.]+$/, "");
		return html`
			<button class="group text-left" data-movie data-id=${m.id} data-version=${String(m.version)} ?data-has-poster=${m.hasPoster} data-test="movie-card" title=${m.name} @click=${() => this.play(m)}>
				<div class="relative aspect-video overflow-hidden rounded-lg bg-neutral-800 ring-accent group-hover:ring-2">
					${poster ? html`<gorani-picture class="block h-full w-full" data-test="movie-poster" .file=${poster} .fallback=${html`<div class="flex h-full items-center justify-center">${icon("video", "h-10 w-10 text-neutral-600")}</div>`}></gorani-picture>` : html`<div class="flex h-full items-center justify-center">${icon("video", "h-10 w-10 text-neutral-600")}</div>`}
					${m.durationMs ? html`<span class="absolute bottom-1.5 right-1.5 rounded bg-black/75 px-1.5 py-0.5 text-[11px] text-neutral-100" data-test="movie-length">${fmtLength(m.durationMs)}</span>` : nothing}
					${watched > 0.01 ? html`<span class="absolute inset-x-0 bottom-0 h-1 bg-neutral-700/80"><span class="block h-full bg-accent" ${cssom({ width: `${Math.round(watched * 100)}%` })}></span></span>` : nothing}
				</div>
				<p class="mt-1.5 truncate text-sm text-neutral-200">${title}</p>
				<p class="truncate text-xs text-neutral-500">${[fmtPicture(m.width, m.height), fmtSize(m.size), watched > 0.01 && watched < 0.97 ? `${Math.round(watched * 100)}% watched` : watched >= 0.97 ? "watched" : ""].filter(Boolean).join(" · ")}</p>
			</button>
		`;
	}
}
