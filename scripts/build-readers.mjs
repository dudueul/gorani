// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Build the preview frame's readers (commit 42a, docs/PREVIEWS.md):
 * web/src/preview/readers/<name>.ts → web/public/readers/<name>.js, each ONE
 * self-contained ES module. The frame (public/preview.html) runs a reader
 * from a blob: URL it makes from the code the app hands it, so a reader
 * cannot import anything at run time: everything it needs is bundled in.
 *
 * Also copied, as-is, for the readers that need them:
 *   readers/pdf.worker.js   pdf.js's worker (parses the PDF), re-bundled as a
 *                           classic script (see below)
 *   readers/pdf/            its CMaps (CJK text), standard fonts and image
 *                           decoders, which the frame asks the app for by
 *                           name (ui/viewer/sandbox.ts › assetPath)
 *
 * Run by `npm run build` in web/ before Vite (Vite copies public/ into
 * dist/). Skipped when every output is newer than every source. The
 * outputs are build products, git-ignored.
 */

import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WEB = path.join(ROOT, "web");
const OUT = path.join(WEB, "public/readers");
const SRC = path.join(WEB, "src/preview");
const require = createRequire(path.join(WEB, "package.json"));

/** Each reader, and what it needs beside its bundle. */
const READERS = {
	pdf: {
		// The legacy build, as the reader (see readers/pdf.ts).
		worker: "pdfjs-dist/legacy/build/pdf.worker.min.mjs",
		assets: [
			["pdfjs-dist/cmaps", "cmaps"],
			// (Each set with its LICENSE_* files: the licences travel with what they cover.)
			["pdfjs-dist/standard_fonts", "standard_fonts"],
			// The image decoders (JPEG 2000, JBIG2) and colour management.
			// quickjs-eval is pdf.js's sandbox for PDF scripts: never sent.
			["pdfjs-dist/wasm", "wasm", (f) => (/\.wasm$|_nowasm_fallback\.js$|^LICENSE_/.test(f)) && !/quickjs/i.test(f)],
		],
	},
};

const pkgDir = (spec) => path.dirname(require.resolve(`${spec.split("/").slice(0, spec.startsWith("@") ? 2 : 1).join("/")}/package.json`));
const resolveIn = (spec) => {
	const parts = spec.split("/");
	const n = spec.startsWith("@") ? 2 : 1;
	return path.join(pkgDir(spec), ...parts.slice(n));
};

const newest = (p) => {
	if (!fs.existsSync(p)) return 0;
	const st = fs.statSync(p);
	return st.isDirectory() ? Math.max(0, ...fs.readdirSync(p).map((f) => newest(path.join(p, f)))) : st.mtimeMs;
};
const oldest = (p) => {
	if (!fs.existsSync(p)) return 0;
	const st = fs.statSync(p);
	return st.isDirectory() ? Math.min(Infinity, ...fs.readdirSync(p).map((f) => oldest(path.join(p, f)))) : st.mtimeMs;
};

const sourcesAt = Math.max(newest(SRC), newest(path.join(WEB, "package-lock.json")), newest(fileURLToPath(import.meta.url)));
const outputs = Object.keys(READERS).map((n) => path.join(OUT, `${n}.js`));
if (outputs.every((o) => fs.existsSync(o)) && oldest(OUT) >= sourcesAt) process.exit(0);

const { build } = await import(require.resolve("esbuild"));

/** `import css from "./x.css?inline"`: the file's text, as Vite does it. */
const inlineCss = {
	name: "inline-css",
	setup(b) {
		b.onResolve({ filter: /\.css\?inline$/ }, (args) => ({ path: path.resolve(args.resolveDir, args.path.replace(/\?inline$/, "")), namespace: "inline-css" }));
		b.onLoad({ filter: /.*/, namespace: "inline-css" }, (args) => ({ contents: fs.readFileSync(args.path, "utf8"), loader: "text" }));
	},
};

fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(OUT, { recursive: true });
for (const [name, spec] of Object.entries(READERS)) {
	await build({
		entryPoints: [path.join(SRC, "readers", `${name}.ts`)],
		outfile: path.join(OUT, `${name}.js`),
		bundle: true,
		format: "esm",
		platform: "browser",
		target: "es2022",
		minify: true,
		legalComments: "eof",
		plugins: [inlineCss],
		logLevel: "warning",
	});
	// The worker as a CLASSIC script (an IIFE), though pdf.js ships it as a
	// module: an opaque-origin frame cannot start a module worker from a
	// blob: URL (Chromium fails it with a bare error event), and a classic
	// one starts fine. Its two `import.meta.url`s are Emscripten's guess at
	// a script directory, inside a try — empty here, and unused.
	if (spec.worker) {
		await build({
			entryPoints: [resolveIn(spec.worker)],
			outfile: path.join(OUT, `${name}.worker.js`),
			bundle: true,
			format: "iife",
			platform: "browser",
			target: "es2022",
			minify: true,
			legalComments: "eof",
			logLevel: "warning",
			logOverride: { "empty-import-meta": "silent" },
		});
	}
	for (const [from, to, keep = () => true] of spec.assets ?? []) {
		const src = resolveIn(from);
		const dest = path.join(OUT, name, to);
		fs.mkdirSync(dest, { recursive: true });
		for (const f of fs.readdirSync(src)) if (keep(f) && fs.statSync(path.join(src, f)).isFile()) fs.copyFileSync(path.join(src, f), path.join(dest, f));
	}
}
console.log(`readers: ${Object.keys(READERS).join(", ")} → web/public/readers/`);
