#!/usr/bin/env node
// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The web app's build, step 0 (web/package.json › build, dev): are web/'s
 * own packages installed?
 *
 * web/ has its own package.json and lockfile, apart from the root's. When
 * only the root was installed (`bun install`, or `npm install` with scripts
 * off, so its postinstall never ran), the build used to get through the
 * WebAssembly build and then fail inside esbuild — `Could not resolve
 * "dompurify"` — or at `vite: not found`, neither of which says what to do.
 * esbuild resolved at all only by walking up to the root's node_modules,
 * where wrangler had brought in a copy of its own.
 *
 * Checked: each of web/'s declared packages has a package.json under
 * web/node_modules/<name>/, where npm, bun and pnpm all put a project's
 * direct dependencies. Not checked: their versions — that is the
 * lockfile's job, and `npm ci` (the root postinstall) installs exactly it.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const WEB = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "web");
const pkg = JSON.parse(fs.readFileSync(path.join(WEB, "package.json"), "utf8"));
const declared = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
const missing = declared.filter((name) => !fs.existsSync(path.join(WEB, "node_modules", name, "package.json")));

if (missing.length) {
	const named = missing.length > 6 ? `${missing.slice(0, 6).join(", ")} and ${missing.length - 6} more` : missing.join(", ");
	console.error(
		[
			`build: web/'s own packages are not installed (${missing.length} of ${declared.length} missing: ${named}).`,
			"",
			"  The web app has its own package.json and lockfile, apart from the root's.",
			"  Install them, then build again:",
			"",
			"      npm --prefix web ci",
			"",
			"  (`npm install` at the root does it too, through its postinstall, unless",
			"  install scripts are turned off.)",
		].join("\n"),
	);
	process.exit(1);
}
