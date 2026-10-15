// Copyright 2026- Seongwoo Hong. All rights reserved.
//
// Every icon, from the one drawing (commit 39h): docs/assets/gorani.svg,
// the water deer the README opens with. The images are made here — with
// the browser the e2e suite already installs — and committed, so no build
// machine needs a renderer:
//
//   node tools/icons/render.mjs          (after editing the drawing)
//
// writes
//   web/public/favicon.svg                                   the deer alone, for the browser tab
//   clients/windows/packaging/Assets/*.png                   the package's logos (MSIX), on a tile
//   clients/windows/packaging/gorani.ico                     Explorer's navigation pane (16–256 px)
//   clients/macos/App/Assets.xcassets/AppIcon.appiconset/    the Mac app's icon, on Apple's grid
import { chromium } from "playwright";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "../..");
const out = (p) => path.join(root, p);
const deer = fs.readFileSync(out("docs/assets/gorani.svg"), "utf8");
// The drawing's insides (its own <svg> and <title> left behind).
const inner = deer
	.replace(/^[\s\S]*?<svg[^>]*>/, "")
	.replace(/<\/svg>\s*$/, "")
	.replace(/<title[\s\S]*?<\/title>/, "")
	.replace(/<!--[\s\S]*?-->/g, "");

// The deer's own middle (ears' tips to tusks' ends), so it sits centred.
const MIDDLE = 250;

/** The deer at `scale`, on a plate or none. 512 units square. */
function compose({ plate, scale }) {
	const deerAt = `<g transform="translate(256 256) scale(${scale}) translate(-256 -${MIDDLE})">${inner}</g>`;
	const gradient = `<linearGradient id="plate" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#17938a"/><stop offset="1" stop-color="#0c665f"/></linearGradient>`;
	let back = "";
	if (plate === "tile") back = `<rect x="0" y="0" width="512" height="512" rx="96" fill="url(#plate)"/>`;
	// Apple's grid: the shape is 824 of 1024 units, corners about 22% of it.
	if (plate === "mac") back = `<rect x="44" y="44" width="424" height="424" rx="94" fill="url(#plate)"/>`;
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><defs>${gradient}</defs>${back}${deerAt}</svg>`;
}

const browser = await chromium.launch();
const page = await browser.newPage();

/** One PNG of `svg` at `size` px, transparent where the drawing is not. */
async function png(svg, size) {
	await page.setViewportSize({ width: size, height: size });
	await page.setContent(`<!doctype html><body style="margin:0;background:transparent">${svg.replace("<svg ", `<svg width="${size}" height="${size}" `)}</body>`);
	return page.screenshot({ omitBackground: true, clip: { x: 0, y: 0, width: size, height: size } });
}

function write(p, bytes) {
	fs.mkdirSync(path.dirname(out(p)), { recursive: true });
	fs.writeFileSync(out(p), bytes);
	console.log(`wrote ${p}`);
}

// The browser: the deer alone, as a vector.
write("web/public/favicon.svg", compose({ plate: "none", scale: 1.08 }).replace(">", ">\n<!-- Copyright 2026- Seongwoo Hong. All rights reserved. Made by tools/icons/render.mjs from docs/assets/gorani.svg — edit that, not this. -->\n"));

// Windows: the package's logos on a tile; Explorer's .ico (PNG entries — every
// Windows since Vista reads them).
const tile = compose({ plate: "tile", scale: 0.9 });
for (const [name, size] of [["Square44x44Logo", 44], ["Square150x150Logo", 150], ["StoreLogo", 50]]) {
	write(`clients/windows/packaging/Assets/${name}.png`, await png(tile, size));
}
const icoSizes = [16, 24, 32, 48, 64, 256];
const icoImages = [];
for (const s of icoSizes) icoImages.push(await png(tile, s));
write("clients/windows/packaging/gorani.ico", ico(icoSizes, icoImages));

// macOS: the asset catalog's icon set.
const mac = compose({ plate: "mac", scale: 0.74 });
const images = [];
for (const base of [16, 32, 128, 256, 512]) {
	for (const scale of [1, 2]) {
		const file = `icon_${base}x${base}${scale === 2 ? "@2x" : ""}.png`;
		write(`clients/macos/App/Assets.xcassets/AppIcon.appiconset/${file}`, await png(mac, base * scale));
		images.push({ idiom: "mac", size: `${base}x${base}`, scale: `${scale}x`, filename: file });
	}
}
write("clients/macos/App/Assets.xcassets/AppIcon.appiconset/Contents.json", JSON.stringify({ images, info: { author: "tools/icons/render.mjs", version: 1 } }, null, 2) + "\n");
write("clients/macos/App/Assets.xcassets/Contents.json", JSON.stringify({ info: { author: "tools/icons/render.mjs", version: 1 } }, null, 2) + "\n");

await browser.close();

/** An .ico holding PNGs: the 6-byte header, a 16-byte entry each, then the images. */
function ico(sizes, pngs) {
	const head = Buffer.alloc(6 + 16 * pngs.length);
	head.writeUInt16LE(0, 0); // reserved
	head.writeUInt16LE(1, 2); // 1: an icon
	head.writeUInt16LE(pngs.length, 4);
	let offset = head.length;
	pngs.forEach((data, i) => {
		const e = 6 + 16 * i;
		head.writeUInt8(sizes[i] >= 256 ? 0 : sizes[i], e); // width (0 means 256)
		head.writeUInt8(sizes[i] >= 256 ? 0 : sizes[i], e + 1); // height
		head.writeUInt8(0, e + 2); // no palette
		head.writeUInt8(0, e + 3);
		head.writeUInt16LE(1, e + 4); // planes
		head.writeUInt16LE(32, e + 6); // bits per pixel
		head.writeUInt32LE(data.length, e + 8);
		head.writeUInt32LE(offset, e + 12);
		offset += data.length;
	});
	return Buffer.concat([head, ...pngs]);
}
