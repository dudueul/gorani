// Copyright 2026- Seongwoo Hong. All rights reserved.

//! <gorani-app>: the application shell.
//!
//! What you see now is the lock screen — the state the app starts in. The
//! unlock flow arrives at commit ⑨ (passkey PRF / Argon2id password /
//! recovery code, exactly as docs/VAULT.md will describe); until then this
//! component demonstrates the house rules every Gorani component follows:
//!
//!  1. **No Shadow DOM.** `createRenderRoot()` returns the element itself,
//!     so the one global Tailwind stylesheet applies (see global.css).
//!  2. **No strings-turned-HTML.** Lit's `html` tagged template escapes by
//!     default and is Trusted-Types compatible — the only way markup is
//!     built here. `innerHTML` never appears in this codebase.
//!  3. **State lives outside components.** Components read stores and
//!     re-render; the stores (src/lib/store.ts, commit ⑨) are plain,
//!     testable TypeScript. This component holds none for now.
//!  4. **Every file teaches.** Headers like this one say what the file is,
//!     why it exists and where it is going next (docs/COURSE.md tracks it).

import { LitElement, html } from "lit";
import { customElement } from "lit/decorators.js";

@customElement("gorani-app")
export class GoraniApp extends LitElement {
	// Rule 1: no Shadow DOM, so Tailwind's global utilities apply.
	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	protected override render() {
		return html`
			<div class="flex h-full flex-col items-center justify-center gap-6 px-6">
				<header class="text-center">
					<h1 class="text-4xl font-semibold tracking-tight text-accent">Gorani</h1>
					<p class="mt-2 text-neutral-400">The family's encrypted NAS.</p>
				</header>

				<!-- The vault lock screen placeholder: the real unlock (passkey
				     first) replaces this at commit ⑨. -->
				<section
					class="w-full max-w-sm rounded-2xl border border-neutral-800 bg-neutral-900 p-6 text-center shadow-xl"
					aria-label="Vault locked"
				>
					<p class="text-sm text-neutral-300">
						The vault is locked. Contents stay sealed — the server holds
						ciphertext only.
					</p>
					<button
						class="mt-4 w-full rounded-xl bg-accent px-4 py-2.5 font-medium text-neutral-950 hover:opacity-90"
						disabled
						title="Unlock arrives with the vault commit"
					>
						Unlock
					</button>
					<p class="mt-3 text-xs text-neutral-500">
						Commit ① scaffold · <a class="underline" href="/api/healthz">/api/healthz</a>
					</p>
				</section>
			</div>
		`;
	}
}