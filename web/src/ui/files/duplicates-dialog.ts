// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Find duplicates (commit 39n): the files of the open area that have
 * exactly the same bytes as another, in groups — each copy with its folder
 * and time — to keep one and move the rest to the Trash. "The same bytes"
 * is the keyed tag of the upload check (model.ts › fingerprint), compared
 * by the server only as opaque strings it already stores; the names are
 * opened here.
 *
 * In each group every copy but the OLDEST starts ticked: the first copy is
 * usually the one others link to or remember. Nothing is deleted outright —
 * the Trash keeps it 30 days (an evidence case refuses, and says so).
 */

import { html, render, nothing } from "lit";
import type { DuplicateGroup, FilesModel } from "./model.ts";
import { fmtDate, fmtSize } from "./shared.ts";

const button = "rounded-lg border border-neutral-700 px-3 py-1.5 text-xs hover:border-accent disabled:opacity-40";
const primary = "rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-neutral-950 hover:opacity-90 disabled:opacity-40";

/** Open the view; `show` goes to a copy (the dialog closes first). */
export function showDuplicates(model: FilesModel, show: (folderId: string | null, fileId: string) => void): void {
	const host = document.createElement("div");
	document.body.append(host);
	let groups: DuplicateGroup[] | null = null;
	let ticked = new Set<string>();
	let error = "";
	let busy = false;
	const close = () => {
		document.removeEventListener("keydown", onKey, true);
		render(nothing, host);
		host.remove();
	};
	const onKey = (e: KeyboardEvent) => {
		if (e.key === "Escape") {
			e.preventDefault();
			e.stopPropagation();
			close();
		}
	};
	document.addEventListener("keydown", onKey, true);
	const load = async () => {
		try {
			groups = await model.findDuplicates();
			ticked = new Set(groups.flatMap((g) => g.files.slice(1).map((f) => f.id)));
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
			groups = [];
		}
		draw();
	};
	const trash = async () => {
		busy = true;
		error = "";
		draw();
		try {
			await model.trashItems([...ticked].map((id) => ({ kind: "file" as const, id })));
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			busy = false;
			draw();
		}
	};
	const wasted = () => (groups ?? []).reduce((n, g) => n + g.size * g.files.filter((f) => ticked.has(f.id)).length, 0);
	const draw = () =>
		render(
			html`<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" data-test="duplicates-dialog" role="dialog" aria-modal="true" aria-labelledby="duplicates-title">
				<div class="flex max-h-[85vh] w-full max-w-2xl flex-col gap-3 rounded-2xl border border-neutral-800 bg-neutral-900 p-5 text-sm text-neutral-200">
					<h2 id="duplicates-title" class="text-base font-medium">Duplicates</h2>
					${groups === null
						? html`<p class="text-xs text-neutral-400">Looking…</p>`
						: groups.length === 0
							? html`<p class="text-xs text-neutral-400" data-test="duplicates-none">No two files here have the same bytes.</p>`
							: html`<p class="text-xs text-neutral-400">${groups.length} set${groups.length === 1 ? "" : "s"} of identical files. The ticked copies go to the Trash (kept 30 days); the oldest of each set stays.</p>
									<div class="min-h-0 flex-1 space-y-3 overflow-y-auto">
										${groups.map(
											(g) => html`<section class="rounded-lg border border-neutral-800 p-2" data-test="duplicate-group">
												<p class="px-1 pb-1 text-xs text-neutral-400">${fmtSize(g.size)} · ${g.files.length} copies</p>
												${g.files.map(
													(f) => html`<label class="flex items-center gap-2 rounded px-1 py-1 hover:bg-neutral-800/60" data-test="duplicate-copy">
														<input type="checkbox" .checked=${ticked.has(f.id)} @change=${(e: Event) => {
															(e.target as HTMLInputElement).checked ? ticked.add(f.id) : ticked.delete(f.id);
															draw();
														}} />
														<span class="min-w-0 flex-1 truncate">${f.name} <span class="text-neutral-500">in ${f.where || "the top folder"}</span></span>
														<span class="shrink-0 text-xs text-neutral-500">${fmtDate(f.updatedAt)}</span>
														<button type="button" class="shrink-0 text-xs text-accent hover:underline" @click=${(e: Event) => {
															e.preventDefault();
															close();
															show(f.folderId, f.id);
														}}>Show</button>
													</label>`,
												)}
											</section>`,
										)}
									</div>`}
					${error ? html`<p class="text-xs text-red-400" data-test="duplicates-error">${error}</p>` : nothing}
					<div class="flex items-center justify-end gap-2">
						<button class=${button} @click=${close}>Close</button>
						${groups?.length
							? html`<button class=${primary} ?disabled=${busy || !ticked.size} data-test="duplicates-trash" @click=${() => void trash()}>
									Move ${ticked.size} to the Trash${ticked.size ? ` (${fmtSize(wasted())})` : ""}
								</button>`
							: nothing}
					</div>
				</div>
			</div>`,
			host,
		);
	draw();
	void load();
}
