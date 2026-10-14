// Copyright 2026- Seongwoo Hong. All rights reserved.

// Vite builds the SPA into web/dist, which wrangler serves as static assets
// (see wrangler.jsonc → assets) with the security headers of
// public/_headers. Every script and stylesheet is a same-origin file — the
// CSP allows 'self' and nothing inline.

import { defineConfig } from "vite";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
	plugins: [tailwindcss()],
	build: {
		target: "es2022",
		sourcemap: false,
		// es2022 browsers all support <link rel=modulepreload>; the polyfill
		// would only add a script to every page (the share page included).
		modulePreload: { polyfill: false },
		// Two pages: the app, and the public share recipient page (s.html).
		// Both are built so both get their stylesheet compiled and hashed —
		// the share page used to live in public/ and shipped with none.
		rollupOptions: {
			input: { main: "index.html", share: "s.html" },
		},
	},
	// The Worker serves /api and /s; during web-only development, proxy them
	// to a local `wrangler dev` if one is running (see docs/COURSE.md → Lab).
	server: {
		proxy: {
			"/api": "http://127.0.0.1:8787",
		},
	},
});