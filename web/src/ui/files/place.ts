// Copyright 2026- Seongwoo Hong. All rights reserved.

// ── the explorer's place, in the address (commit 39l) ───────────────
//
// `#a=<area>&f=<folder>`: the area (the member's own id, or case:<id>) and
// the folder open in it — so the browser's Back and Forward move between
// folders, and a reload (or the unlock after a lock) opens where you were.
// Ids only — random, never a name — and a fragment never reaches a server.
//
// A module of its own, with no Lit in it: the model imports it, and the
// model's unit test runs in Node, which loads TypeScript by stripping types
// and cannot load decorators (shared.ts has components). Outside a browser
// (that test) there is no address, so both functions do nothing.

const PLACE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const PLACE_AREA = /^(case:)?[A-Za-z0-9_-]{1,64}$/;

/** Where the address says the explorer is (anything malformed is ignored). */
export function readPlace(): { area: string | null; folder: string | null } {
	if (typeof location === "undefined") return { area: null, folder: null };
	const p = new URLSearchParams(location.hash.slice(1));
	const area = p.get("a");
	const folder = p.get("f");
	return { area: area && PLACE_AREA.test(area) ? area : null, folder: folder && PLACE_ID.test(folder) ? folder : null };
}

/** Put the explorer's place in the address: a new history entry for a
 * navigation, or in place (Back/Forward inside the app, an area opening). */
export function writePlace(area: string, folder: string | null, mode: "push" | "replace"): void {
	if (typeof location === "undefined" || typeof history === "undefined") return;
	const p = new URLSearchParams();
	p.set("a", area);
	if (folder) p.set("f", folder);
	const hash = `#${p.toString()}`;
	if (location.hash === hash) return;
	const url = `${location.pathname}${location.search}${hash}`;
	if (mode === "push") history.pushState({ gorani: true }, "", url);
	else history.replaceState({ gorani: true }, "", url);
}
