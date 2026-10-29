// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The duplicate prompt (commit 39n): a file being uploaded has exactly the
 * same bytes as one already in this area. Until 39n this was the browser's
 * own OK/Cancel box with a count — "1 identical file already here" — that
 * never said WHICH file, or where, and asked once per twin in a batch.
 *
 * How "the same bytes" is known without the server reading anything:
 * model.ts › fingerprint — a keyed tag (HMAC of the file's SHA-256 under a
 * secret only the area's members hold) compared in the browser with the
 * tags of the files of exactly that size.
 *
 * Rendered with Lit into the document, like the intake form: every name is
 * escaped by construction.
 */

import { html, render, nothing } from "lit";
import type { DuplicateAnswer, DuplicateQuestion } from "./model.ts";
import { fmtSize } from "./shared.ts";

const button = "rounded-lg border border-neutral-700 px-3 py-1.5 text-xs hover:border-accent";
const primary = "rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-neutral-950 hover:opacity-90";

/** Ask what to do with one duplicate; null when the person stops the upload (Esc). */
export function askDuplicate(q: DuplicateQuestion): Promise<DuplicateAnswer> {
	return new Promise((resolve) => {
		const host = document.createElement("div");
		document.body.append(host);
		const before = document.activeElement instanceof HTMLElement ? document.activeElement : null;
		let forRest = false;
		const done = (answer: DuplicateAnswer) => {
			document.removeEventListener("keydown", onKey, true);
			render(nothing, host);
			host.remove();
			before?.focus({ preventScroll: true });
			resolve(answer);
		};
		const onKey = (e: KeyboardEvent) => {
			if (e.key === "Escape") {
				e.preventDefault();
				e.stopPropagation();
				done(null);
			}
		};
		document.addEventListener("keydown", onKey, true);
		const draw = () =>
			render(
				html`<div class="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4" data-test="duplicate-dialog" role="dialog" aria-modal="true" aria-labelledby="duplicate-title">
					<div class="w-full max-w-md space-y-3 rounded-2xl border border-neutral-800 bg-neutral-900 p-5 text-sm text-neutral-200">
						<h2 id="duplicate-title" class="text-base font-medium">“${q.file.name}” is already here</h2>
						<p class="text-xs text-neutral-400">Exactly the same ${fmtSize(q.file.size)} ${q.twins.length === 1 ? "is already stored as" : `are already stored ${q.twins.length} times`}:</p>
						<ul class="max-h-48 space-y-1 overflow-y-auto rounded-lg bg-neutral-950 p-2 text-xs" data-test="duplicate-twins">
							${q.twins.map((t) => html`<li class="flex items-baseline gap-2"><span class="truncate text-neutral-100">${t.name}</span><span class="shrink-0 text-neutral-500">in ${t.where || "the top folder"}</span></li>`)}
						</ul>
						${q.later > 0
							? html`<label class="flex items-center gap-2 text-xs text-neutral-300">
									<input type="checkbox" data-test="duplicate-for-rest" .checked=${forRest} @change=${(e: Event) => {
										forRest = (e.target as HTMLInputElement).checked;
										draw();
									}} />
									Do the same for every other duplicate in this upload (${q.later} more file${q.later === 1 ? "" : "s"} to go)
								</label>`
							: nothing}
						<div class="flex items-center justify-end gap-2">
							<button class="mr-auto text-xs text-neutral-500 hover:text-neutral-300" @click=${() => done(null)}>Stop the upload</button>
							<button class=${button} data-test="duplicate-keep" @click=${() => done({ action: "keep", forRest })}>Keep both</button>
							<button class=${primary} data-test="duplicate-skip" @click=${() => done({ action: "skip", forRest })}>Skip this file</button>
						</div>
					</div>
				</div>`,
				host,
			);
		draw();
		requestAnimationFrame(() => host.querySelector<HTMLElement>('[data-test="duplicate-skip"]')?.focus());
	});
}
