// Copyright 2026- Seongwoo Hong. All rights reserved.

// Vite builds the SPA into web/dist, which wrangler serves as static assets
// (see wrangler.jsonc → assets). Hashed file names make the strict CSP's
// script hashes stable per build.

import { defineConfig } from "vite";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
	plugins: [tailwindcss()],
	build: {
		target: "es2022",
		sourcemap: false,
	},
	// The Worker serves /api and /s; during web-only development, proxy them
	// to a local `wrangler dev` if one is running (see docs/COURSE.md → Lab).
	server: {
		proxy: {
			"/api": "http://127.0.0.1:8787",
		},
	},
});