// Copyright 2026- Seongwoo Hong. All rights reserved.

/** A stylesheet imported as its text (scripts/build-readers.mjs loads
 * `*.css?inline` that way; Vite's own types say the same). */
declare module "*.css?inline" {
	const css: string;
	export default css;
}
