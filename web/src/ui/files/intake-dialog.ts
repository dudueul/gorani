// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The intake form (commit 29g, docs/CUSTODY.md › Stage 6, D5.6): asked once
 * per evidence upload batch, before a byte is sealed. What it collects is
 * sealed and signed per file (vault/intake.ts) — the server never reads it.
 *
 * A plain overlay rendered with Lit into the document (no framework, no
 * innerHTML): the fields are escaped by construction, like every view here.
 */

import { html, render, nothing } from "lit";
import type { IntakeFields } from "../../vault/intake.ts";

const input = "w-full rounded-lg border border-neutral-700 bg-neutral-950 px-2.5 py-1.5 text-sm outline-none focus:border-accent";

/** Ask for the intake record of `files`; null when the person cancels. */
export function askIntake(files: File[], collector: string): Promise<IntakeFields | null> {
	return new Promise((resolve) => {
		const host = document.createElement("div");
		document.body.append(host);
		const now = new Date();
		const local = new Date(now.getTime() - now.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
		let error = "";
		const done = (value: IntakeFields | null) => {
			render(nothing, host);
			host.remove();
			resolve(value);
		};
		const draw = () =>
			render(
				html`<div class="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4" data-test="intake-dialog">
					<form class="w-full max-w-lg space-y-3 rounded-2xl border border-neutral-800 bg-neutral-900 p-5 text-sm text-neutral-200" @submit=${(e: Event) => {
						e.preventDefault();
						const v = (name: string) => ((e.target as HTMLFormElement).elements.namedItem(name) as HTMLInputElement).value;
						const when = new Date(v("collectedAt"));
						const fields = { source: v("source"), collector: v("collector"), method: v("method"), collectedAt: Number.isNaN(when.getTime()) ? "" : when.toISOString(), notes: v("notes") };
						if (!fields.source.trim() || !fields.collector.trim() || !fields.method.trim() || !fields.collectedAt) {
							error = "Source, collector, method and when are required — they are what a review asks first.";
							draw();
							return;
						}
						done(fields);
					}}>
						<h2 class="text-base font-medium">Intake record — ${files.length === 1 ? files[0]!.name : `${files.length} files`}</h2>
						<p class="text-xs text-neutral-400">This is an evidence case: each file carries where it came from, sealed and signed by you. The server never reads it.</p>
						<label class="block">Source <span class="text-neutral-500">(host, device, account)</span><input class=${input} name="source" placeholder="laptop WS-042, disk 0" data-test="intake-source" /></label>
						<label class="block">Collected by<input class=${input} name="collector" .value=${collector} data-test="intake-collector" /></label>
						<label class="block">Method <span class="text-neutral-500">(tool, format, safeguards)</span><input class=${input} name="method" placeholder="FTK Imager 4.7, E01, write-blocked" data-test="intake-method" /></label>
						<label class="block">Collected at<input class=${input} type="datetime-local" name="collectedAt" .value=${local} data-test="intake-collected-at" /></label>
						<label class="block">Notes<textarea class=${input} name="notes" rows="2" data-test="intake-notes"></textarea></label>
						${error ? html`<p class="text-xs text-red-400">${error}</p>` : nothing}
						<div class="flex justify-end gap-2">
							<button type="button" class="rounded-lg border border-neutral-700 px-3 py-1.5 text-xs" @click=${() => done(null)}>Cancel</button>
							<button class="rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-neutral-950" data-test="intake-submit">Seal and upload</button>
						</div>
					</form>
				</div>`,
				host,
			);
		draw();
		host.querySelector<HTMLInputElement>('[name="source"]')?.focus();
	});
}
