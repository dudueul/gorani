// Copyright 2026- Seongwoo Hong. All rights reserved.
//
// Render one SVG to one PNG, to look at while drawing (commit 39h):
//   node tools/icons/preview.mjs <in.svg> <out.png> <size> [background]
import { chromium } from "playwright";
import fs from "node:fs";

const [svgPath, out, size = "512", background = "#ffffff"] = process.argv.slice(2);
const svg = fs.readFileSync(svgPath, "utf8").replace("<svg ", `<svg width="${size}" height="${size}" `);
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: +size, height: +size } });
await page.setContent(`<!doctype html><body style="margin:0;background:${background}">${svg}</body>`);
await page.screenshot({ path: out });
await browser.close();
