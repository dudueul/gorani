// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The suite map: which tests exist, in which group, and what env each group
 * runs with. tests/run.mjs reads this.
 *
 * kind:  "api" — the Worker under `wrangler dev` (one server per run)
 *        "e2e" — the browser against the same server (commit ⑨+)
 *        "client" — the native Rust engines (commit ⑬+)
 */

export const GROUPS = {
	core: {
		vars: () => ({}),
	},
};

export const SUITES = [{ kind: "api", name: "family", group: "core" }];