// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Is this a phone? (commit 41b, docs/PHONE.md)
 *
 * The rule is the WIDTH, not the device: under 640 CSS pixels the Windows
 * and Finder explorers cannot show their panes, their columns or their
 * tiny targets, so the touch layout takes over. A phone turned sideways
 * (wider than 640) and every tablet keep the desktop looks, which work
 * there with a finger and are what people asked for on a big screen.
 *
 * 640 is Tailwind's `sm:` breakpoint, so the stylesheet's responsive
 * classes (`sm:…`) and this switch agree on what "narrow" means: a
 * component never shows a desktop part with phone styling, or the reverse.
 */
export const PHONE_QUERY = "(max-width: 639.98px)";

/** True when the window is phone-narrow now. False where there is no window (Node tests). */
export function isPhone(): boolean {
	return typeof matchMedia === "function" && matchMedia(PHONE_QUERY).matches;
}

/** Call `changed` whenever the window crosses the line; returns the unsubscribe. */
export function watchPhone(changed: (phone: boolean) => void): () => void {
	if (typeof matchMedia !== "function") return () => {};
	const q = matchMedia(PHONE_QUERY);
	const on = (e: MediaQueryListEvent) => changed(e.matches);
	q.addEventListener("change", on);
	return () => q.removeEventListener("change", on);
}
