// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The image reader (commit 42d, docs/PREVIEWS.md › Images): every picture
 * the vault shows is shown here, in the preview frame, never in the app's
 * page. The browser's own decoders are code a crafted picture attacks too
 * — CVE-2023-4863, a WebP heap overflow, was exploited through ordinary
 * <img> tags — and in the frame a decoder that falls holds one picture
 * and nothing of the vault's.
 *
 *   JPEG PNG GIF WebP AVIF BMP ICO   the browser draws them, as an <img>
 *   SVG                              drawn as an <img> too: an SVG drawn
 *                                    as a picture runs no script and
 *                                    loads nothing; its source in a tab
 *   TIFF, HEIF (HEIC)                decoded in the worker (UTIF, libheif)
 *   RAW (DNG, CR2, CR3, NEF, ARW…)   the camera's own JPEG preview
 *
 * Zoom, pan and pinch (image/stage.ts); every page or picture a TIFF or
 * HEIF holds; the metadata in an Info panel; the facts (facts/image.ts)
 * outside the frame. Before anything decodes a picture, its declared size
 * is checked (structure.ts): a decompression bomb is named, not drawn.
 *
 * Compact mode (the explorer's Quick Look and details pane): the picture
 * alone, fitted, for the formats the browser draws — no worker, no facts.
 */

import { boot, el, type Host } from "../host.ts";
import { addCss, Finder, findCss } from "../kit.ts";
import { imageFacts, metaGroups, MAX_PIXELS, type ImageFindings, type SvgFindings } from "../facts/image.ts";
import { orientationOf } from "../image/tags.ts";
import { jpegStructure, sniffImage, structureOf, type Sniffed } from "../image/structure.ts";
import { Stage } from "../image/stage.ts";
import type { Done, Job } from "./image.worker.ts";
import imageCss from "./image.css?inline";

const SOURCE_CAP = 2 * 1024 * 1024;

export const start = boot(async (host) => {
	addCss(imageCss, findCss);
	const bytes = new Uint8Array(host.file.bytes);
	const sniff = sniffImage(bytes, host.file.name);
	const structure = structureOf(bytes, sniff.format);
	const declared = structure.width && structure.height ? structure.width * structure.height : 0;

	if (host.compact) return compact(host, bytes, sniff, declared);

	// ── the frame's layout ──
	const stage = new Stage();
	const zoomLabel = el("span", { class: "muted zoomlabel", "data-test": "img-zoom" });
	const button = (label: string, title: string, test: string, act: () => void) => {
		const b = el("button", { title, "aria-label": title, "data-test": test }, label);
		b.addEventListener("click", act);
		return b;
	};
	const tools = el("span", { class: "tools" },
		button("−", "Zoom out (−)", "img-out", () => stage.zoomBy(1 / 1.25)),
		zoomLabel,
		button("+", "Zoom in (+)", "img-in", () => stage.zoomBy(1.25)),
		button("Fit", "Fit (0)", "img-fit", () => stage.fit()),
		button("1:1", "Actual pixels (1)", "img-actual", () => stage.zoomTo(1)),
		button("⟳", "Turn a quarter (R)", "img-turn", () => stage.turn()),
	);
	stage.onChange = () => (zoomLabel.textContent = `${Math.round(stage.now() * 100)}%`);
	const pageBar = el("span", { class: "pages", hidden: "" });
	const tabs = el("span", { class: "tabs", hidden: "" });
	const infoBtn = el("button", { title: "Info (I)", "aria-pressed": "false", "data-test": "img-info-toggle" }, "Info");
	const bar = el("div", { class: "bar" }, tools, pageBar, tabs, el("span", { class: "grow" }), infoBtn);
	const info = el("aside", { class: "info", "data-test": "img-info", hidden: "" });
	const source = el("div", { class: "source-pane", hidden: "" });
	const body = el("div", { class: "body" }, stage.el, source, info);
	host.root.append(bar, body);
	const setInfo = (open: boolean) => {
		info.hidden = !open;
		infoBtn.setAttribute("aria-pressed", String(open));
		requestAnimationFrame(() => stage.render());
	};
	infoBtn.addEventListener("click", () => setInfo(info.hidden));
	setInfo(!host.phone && innerWidth >= 900);
	// Zoomed in, a finger on the picture pans it; it does not ask for the next file.
	host.setSwipeGuard((t) => stage.zoomed() || (t instanceof Element && !!t.closest(".info, .source-pane")));
	window.addEventListener("keydown", (e) => {
		if ((e.target as HTMLElement | null)?.closest?.("input, textarea") || e.ctrlKey || e.metaKey || e.altKey) return;
		const k = e.key.toLowerCase();
		if (k === "+" || k === "=") stage.zoomBy(1.25);
		else if (k === "-") stage.zoomBy(1 / 1.25);
		else if (k === "0") stage.fit();
		else if (k === "1") stage.zoomTo(1);
		else if (k === "r") stage.turn();
		else if (k === "i") setInfo(info.hidden);
		else return;
		e.preventDefault();
	});
	const notice = (title: string, why = "") => {
		const p = el("p", { class: "notice", "data-test": "img-refused" }, el("strong", {}, title));
		if (why) p.append(el("br"), why);
		stage.el.replaceChildren(p);
	};
	stage.el.append(el("p", { class: "notice" }, "Opening the picture…"));

	const findings: ImageFindings = { name: host.file.name, sniff, structure, meta: null, previews: [], pages: 0, shown: null, refused: null, thumb: null, svg: null };
	const finish = (thumb?: Uint8Array | null) => {
		renderInfo(info, findings, thumb ?? null);
		host.shown(imageFacts(findings));
	};

	// ── not a picture; too large ──
	if (!sniff.format) {
		findings.refused = "not-a-picture";
		notice("This is not a picture.", `It is ${sniff.other ?? "a file of another kind"}, under a picture's name. Nothing was drawn.`);
		return finish();
	}
	if (declared > MAX_PIXELS) findings.refused = "too-large";

	// ── SVG: drawn as a picture; read as text, never as a page ──
	if (sniff.format === "svg" || sniff.format === "svgz") {
		const text = await svgText(bytes, sniff.format === "svgz");
		const svg = svgFindings(text);
		findings.svg = svg;
		showSource(tabs, source, stage, text);
		if (svg.entities) {
			findings.refused = "entities";
			notice("This drawing is not drawn.", "It declares XML entities that expand into one another — its source is in the Source tab.");
			return finish();
		}
		const img = await drawNative(new Blob([text], { type: "image/svg+xml" }));
		if (!img) {
			findings.refused = "failed";
			notice("This drawing could not be drawn.", "It may be damaged — its source is in the Source tab.");
			return finish();
		}
		findings.shown = { width: img.naturalWidth || 300, height: img.naturalHeight || 150, what: "picture" };
		stage.show(img, findings.shown.width, findings.shown.height);
		return finish();
	}

	// ── everything else: the worker reads it; the browser draws what it can ──
	const native = sniff.native && findings.refused !== "too-large";
	const drawn = native ? drawNative(new Blob([bytes as BlobPart], { type: sniff.mime ?? "image/png" })) : Promise.resolve(null);
	const job: Job = { bytes: bytes.slice().buffer, name: host.file.name };
	if (sniff.format === "heic" && findings.refused !== "too-large") {
		try {
			const [glue, wasm] = await Promise.all([host.asset("libheif.js"), host.asset("libheif.wasm")]);
			job.heif = { glue: new TextDecoder().decode(glue), wasm: wasm.slice().buffer };
		} catch {
			// no decoder: the metadata is still read
		}
	}
	const worker = host.worker();
	const done: Done | null = worker
		? await new Promise<Done | null>((ok) => {
				worker.onmessage = (e: MessageEvent<Done | { t: "error" }>) => ok(e.data.t === "done" ? e.data : null);
				worker.onerror = () => ok(null);
				worker.postMessage(job, [job.bytes, ...(job.heif ? [job.heif.wasm] : [])]);
			})
		: null;
	if (done) {
		Object.assign(findings, { meta: done.meta, previews: done.previews, thumb: done.thumb, pages: done.pageCount > 1 ? done.pageCount : 0 });
		if (done.refused && !findings.refused) findings.refused = done.refused;
	}

	if (native) {
		const img = await drawn;
		if (img) {
			findings.shown = { width: img.naturalWidth, height: img.naturalHeight, what: "picture" };
			stage.show(img, img.naturalWidth, img.naturalHeight);
		} else {
			findings.refused = "failed";
			notice("This picture could not be drawn.", "It may be damaged, or made to break picture decoders.");
		}
	} else if (done?.preview) {
		// A RAW file: the camera's own preview. Turned here unless the
		// preview says how to turn itself (the browser then does).
		const own = jpegStructure(new Uint8Array(done.preview), 0).orientation ?? 1;
		const img = await drawNative(new Blob([done.preview], { type: "image/jpeg" }));
		if (img) {
			findings.shown = { width: img.naturalWidth, height: img.naturalHeight, what: "preview" };
			stage.show(img, img.naturalWidth, img.naturalHeight, own === 1 ? (structure.orientation ?? orientationOf(done.meta)) : 1);
		} else notice("This RAW file's preview could not be drawn.");
	} else if (done?.pages.length) {
		const canvases = done.pages.map((p) => {
			const c = el("canvas", { width: String(p.width), height: String(p.height) });
			c.getContext("bitmaprenderer")?.transferFromImageBitmap(p.bitmap);
			return { c, w: p.width, h: p.height };
		});
		// A TIFF's pages are turned by its Orientation; libheif turns a HEIF's itself.
		const turn = sniff.format === "tiff" ? (structure.orientation ?? 1) : 1;
		let at = 0;
		const label = el("span", { class: "muted", "data-test": "img-page" });
		const prev = el("button", { title: "Previous page", "aria-label": "Previous page" }, "‹");
		const next = el("button", { title: "Next page", "aria-label": "Next page", "data-test": "img-next-page" }, "›");
		const go = (i: number) => {
			at = Math.max(0, Math.min(canvases.length - 1, i));
			const p = canvases[at]!;
			stage.show(p.c, p.w, p.h, turn);
			label.textContent = `${at + 1} / ${done.pageCount}`;
			prev.disabled = at === 0;
			next.disabled = at === canvases.length - 1;
		};
		prev.addEventListener("click", () => go(at - 1));
		next.addEventListener("click", () => go(at + 1));
		if (done.pageCount > 1) {
			pageBar.append(prev, label, next);
			pageBar.hidden = false;
		}
		findings.shown = { width: canvases[0]!.w, height: canvases[0]!.h, what: done.pageCount > 1 ? "page" : "picture" };
		go(0);
	} else if (findings.refused === "too-large") {
		notice("This picture is not drawn.", `It declares ${structure.width}×${structure.height} pixels — more than this viewer draws. Its metadata is in the Info panel.`);
	} else if (findings.refused === "no-decoder") {
		notice("There is no decoder here for this kind of picture.", `It is ${sniff.label}. Its metadata is in the Info panel.`);
	} else if (findings.refused === "no-preview") {
		notice("This RAW file carries no preview this viewer could find.", "The sensor data is not decoded here. Its metadata is in the Info panel.");
	} else {
		findings.refused = "failed";
		notice("This picture could not be decoded.", done?.error ?? "It may be damaged, or made to break picture decoders.");
	}
	finish(done?.thumbBytes ? new Uint8Array(done.thumbBytes) : null);
});

/** An <img> of `blob`, once decoded — or null if the browser cannot. */
async function drawNative(blob: Blob): Promise<HTMLImageElement | null> {
	const img = new Image();
	img.alt = "";
	img.decoding = "async";
	img.src = URL.createObjectURL(blob);
	try {
		await img.decode();
		return img;
	} catch {
		URL.revokeObjectURL(img.src);
		return null;
	}
}

function compact(host: Host, bytes: Uint8Array, sniff: Sniffed, declared: number): void {
	if (!sniff.native || sniff.format === "svgz" || declared > MAX_PIXELS) {
		host.fail("no quick preview for this picture");
		return;
	}
	void drawNative(new Blob([bytes as BlobPart], { type: sniff.mime ?? "image/png" })).then((img) => {
		if (!img) return host.fail("the picture could not be drawn");
		img.className = "compact-picture";
		img.setAttribute("data-test", "img-picture");
		host.root.append(img);
		host.shown([]);
	});
}

// ── SVG ─────────────────────────────────────────────────────────────

async function svgText(bytes: Uint8Array, gzipped: boolean): Promise<string> {
	if (!gzipped) return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
	// .svgz: inflated as a stream, and stopped at 32 MB (a gzip bomb).
	const reader = new Blob([bytes as BlobPart]).stream().pipeThrough(new DecompressionStream("gzip")).getReader();
	const parts: Uint8Array[] = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.length;
		if (total > 32 * 1024 * 1024) {
			await reader.cancel();
			throw new Error("this compressed drawing inflates past 32 MB — not opened");
		}
		parts.push(value);
	}
	return new TextDecoder().decode(await new Blob(parts as BlobPart[]).arrayBuffer());
}

const REMOTE = /^\s*(?:https?:)?\/\//i;

/** What an SVG would do, from an inert parse (nothing in a parsed document
 * loads or runs) — or, if it declares entities, from no parse at all. */
export function svgFindings(text: string): SvgFindings {
	const f: SvgFindings = { scripts: 0, handlers: 0, foreign: 0, password: false, remote: [], links: [], jsLinks: 0, entities: false, embedded: 0 };
	if (/<!ENTITY/i.test(text.slice(0, 256 * 1024))) {
		f.entities = true;
		return f;
	}
	const doc = new DOMParser().parseFromString(text, "image/svg+xml");
	const all = [...doc.getElementsByTagName("*")];
	for (const e of all) {
		const name = e.localName;
		if (name === "script") f.scripts++;
		if (name === "foreignObject") f.foreign++;
		if (name === "input" && (e.getAttribute("type") ?? "").toLowerCase() === "password") f.password = true;
		if ([...e.attributes].some((a) => /^on/i.test(a.name))) f.handlers++;
		for (const a of e.attributes) {
			if (a.localName !== "href" && a.localName !== "src") continue;
			const v = a.value.trim();
			if (/^javascript:/i.test(v.replace(/[\s\u0000-\u001f]/g, ""))) f.jsLinks++;
			else if (/^data:image\//i.test(v)) f.embedded++;
			else if (name === "a") {
				if (!v.startsWith("#")) f.links.push(v);
			} else if (REMOTE.test(v)) f.remote.push(v);
		}
		const css = name === "style" ? (e.textContent ?? "") : (e.getAttribute("style") ?? "");
		for (const m of css.matchAll(/@import\s+(?:url\()?\s*['"]?([^'")\s;]+)|url\(\s*['"]?([^'")]+)/gi)) {
			const u = (m[1] ?? m[2] ?? "").trim();
			if (REMOTE.test(u)) f.remote.push(u);
		}
	}
	return f;
}

function showSource(tabs: HTMLElement, pane: HTMLElement, stage: Stage, text: string): void {
	const pre = el("pre", { class: "source", "data-test": "img-source" });
	pre.textContent = text.length > SOURCE_CAP ? `${text.slice(0, SOURCE_CAP)}\n\n… (the first 2 MB of ${(text.length / 1048576).toFixed(1)} MB)` : text;
	const finder = new Finder(() => pre, pane, "Find in the source");
	pane.append(el("div", { class: "bar" }, finder.input, finder.found), pre);
	const picture = el("button", { "aria-pressed": "true", "data-test": "img-tab-picture" }, "Picture");
	const src = el("button", { "aria-pressed": "false", "data-test": "img-tab-source" }, "Source");
	const show = (which: "picture" | "source") => {
		stage.el.hidden = which !== "picture";
		pane.hidden = which !== "source";
		picture.setAttribute("aria-pressed", String(which === "picture"));
		src.setAttribute("aria-pressed", String(which === "source"));
		if (which === "picture") requestAnimationFrame(() => stage.render());
	};
	picture.addEventListener("click", () => show("picture"));
	src.addEventListener("click", () => show("source"));
	tabs.append(picture, src);
	tabs.hidden = false;
}

// ── the Info panel ──────────────────────────────────────────────────

function renderInfo(panel: HTMLElement, f: ImageFindings, thumb: Uint8Array | null): void {
	panel.replaceChildren();
	if (thumb) {
		const img = el("img", { alt: "The embedded thumbnail" });
		img.src = URL.createObjectURL(new Blob([thumb as BlobPart], { type: "image/jpeg" }));
		const verdict = f.thumb?.shape ? "another shape than the picture" : f.thumb && (f.thumb.mean > 22 || f.thumb.far > 0.03) ? "a different picture" : "matches the picture";
		panel.append(el("figure", { class: "thumb", "data-test": "img-thumb" }, img, el("figcaption", { class: "muted" }, `Embedded thumbnail${f.thumb ? ` ${f.thumb.width}×${f.thumb.height}` : ""} — ${verdict}`)));
	}
	for (const g of metaGroups(f)) {
		const rows = g.rows.map(([k, v]) => el("div", { class: "row" }, el("span", { class: "k" }, k), el("span", { class: "v" }, v)));
		if (g.title === "All metadata") {
			const d = el("details", {}, el("summary", {}, `All metadata (${g.rows.length})`), ...rows);
			panel.append(el("section", { "data-test": "img-meta-all" }, d));
		} else panel.append(el("section", { "data-test": `img-meta-${g.title.toLowerCase().replace(/\W+/g, "-")}` }, el("h3", {}, g.title), ...rows));
	}
	if (!panel.childElementCount) panel.append(el("p", { class: "muted" }, "No metadata in this file."));
}
