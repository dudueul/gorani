// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Forensic artefacts, built when a test runs (commit 42i): Windows
 * shortcuts ([MS-SHLLINK]) and Prefetch files (SCCA, compressed with
 * [MS-XCA] Xpress Huffman as Windows 10 and 11 write them). A shortcut that
 * runs PowerShell hidden behind a PDF's icon is what an antivirus flags on
 * disk, so it is assembled here, not kept. Independent readers agree with
 * what these write: LnkParse3 for the shortcuts; dissect's decompressor
 * for the Xpress Huffman streams (checked when this was written).
 */

const enc = new TextEncoder();
const utf16 = (s) => Uint8Array.from([...s].flatMap((c) => [c.charCodeAt(0) & 0xff, c.charCodeAt(0) >> 8]));
const cat = (parts) => {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let at = 0;
	for (const p of parts) (out.set(p, at), (at += p.length));
	return out;
};
const u16 = (x) => Uint8Array.from([x & 0xff, (x >> 8) & 0xff]);
const u32 = (x) => Uint8Array.from([x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >>> 24) & 0xff]);
/** A Date as a FILETIME (100 ns since 1601), little-endian. */
const filetime = (d) => {
	if (!d) return new Uint8Array(8);
	const t = BigInt(d.getTime() + 11644473600000) * 10000n;
	const b = new Uint8Array(8);
	new DataView(b.buffer).setBigUint64(0, t, true);
	return b;
};
const guid = (s) => {
	const h = s.replace(/[{}-]/g, "");
	const b = Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
	// The first three fields are little-endian.
	return Uint8Array.from([b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], ...b.subarray(8)]);
};
/** A version-1 UUID: its time, and the MAC address of the card that made it. */
const uuidV1 = (date, mac) => {
	const ticks = BigInt(date.getTime() + 12219292800000) * 10000n;
	const b = new Uint8Array(16);
	const v = new DataView(b.buffer);
	v.setUint32(0, Number(ticks & 0xffffffffn), true);
	v.setUint16(4, Number((ticks >> 32n) & 0xffffn), true);
	v.setUint16(6, Number((ticks >> 48n) & 0x0fffn) | 0x1000, true);
	b[8] = 0x80 | 0x12;
	b[9] = 0x34;
	b.set(mac.split(":").map((x) => parseInt(x, 16)), 10);
	return b;
};

/** A shell item for a file or folder: its 8.3 name, and its long name in a BEEF0004 (version 3) extension. */
function fileItem(name, folder) {
	const short = enc.encode(`${name.toUpperCase().slice(0, 12)}\0`);
	const shortPadded = short.length % 2 ? cat([short, new Uint8Array(1)]) : short;
	const longName = cat([utf16(name), new Uint8Array(2)]);
	const ext = cat([u16(0), u16(3), u32(0xbeef0004), u32(0), u32(0), u16(0x14), longName, u16(0x14 + 0)]);
	new DataView(ext.buffer).setUint16(0, ext.length, true);
	const body = cat([Uint8Array.from([folder ? 0x31 : 0x32, 0]), u32(0), u16(0), u16(0), u16(folder ? 0x10 : 0x20), shortPadded, ext]);
	return cat([u16(body.length + 2), body]);
}

function idList(path) {
	const [drive, ...rest] = path.split("\\");
	const items = [
		cat([u16(0x14), Uint8Array.from([0x1f, 0x50]), guid("20D04FE0-3AEA-1069-A2D8-08002B30309D")]),
		(() => {
			const v = new Uint8Array(0x19);
			v[0] = 0x19;
			v[2] = 0x2f;
			v.set(enc.encode(`${drive}\\`), 3);
			return v;
		})(),
		...rest.map((n, i) => fileItem(n, i < rest.length - 1)),
	];
	const list = cat([...items, u16(0)]);
	return cat([u16(list.length), list]);
}

/**
 * A shortcut. `target` a local path (C:\…) or a share (\\server\share\file).
 * Options: args, workingDir, icon, iconIndex, name, show (1 normal, 7
 * minimized), runAsAdmin, times {created, accessed, written}, size,
 * volume {type, serial, label}, envTarget, tracker {machine, mac, time},
 * appended (bytes after its end).
 */
export function buildLnk(o) {
	const unc = o.target.startsWith("\\\\");
	let flags = 0x80 | 0x2;
	if (!unc) flags |= 0x1;
	if (o.name) flags |= 0x4;
	if (o.workingDir) flags |= 0x10;
	if (o.args !== undefined) flags |= 0x20;
	if (o.icon) flags |= 0x40;
	if (o.envTarget) flags |= 0x200;
	if (o.runAsAdmin) flags |= 0x2000;
	const header = new Uint8Array(76);
	const h = new DataView(header.buffer);
	h.setUint32(0, 0x4c, true);
	header.set([0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46], 4);
	h.setUint32(20, flags, true);
	h.setUint32(24, 0x20, true);
	header.set(filetime(o.times?.created), 28);
	header.set(filetime(o.times?.accessed), 36);
	header.set(filetime(o.times?.written), 44);
	h.setUint32(52, o.size ?? 0, true);
	h.setInt32(56, o.iconIndex ?? 0, true);
	h.setUint32(60, o.show ?? 1, true);

	// LinkInfo: a volume and a local path, or a share and its file.
	let info;
	if (unc) {
		const m = /^(\\\\[^\\]+\\[^\\]+)\\?(.*)$/.exec(o.target);
		const net = cat([u32(0), u32(0), u32(0x14), u32(0), u32(0x20000), enc.encode(`${m[1]}\0`)]);
		new DataView(net.buffer).setUint32(0, net.length, true);
		const suffix = enc.encode(`${m[2]}\0`);
		const head = 0x1c;
		info = cat([u32(0), u32(head), u32(2), u32(0), u32(0), u32(head), u32(head + net.length), net, suffix]);
	} else {
		const vol = o.volume ?? { type: 3, serial: 0x1234abcd, label: "OS" };
		const volume = cat([u32(0), u32(vol.type), u32(vol.serial), u32(0x10), enc.encode(`${vol.label}\0`)]);
		new DataView(volume.buffer).setUint32(0, volume.length, true);
		const head = 0x1c;
		const base = enc.encode(`${o.target}\0`);
		info = cat([u32(0), u32(head), u32(1), u32(head), u32(head + volume.length), u32(0), u32(head + volume.length + base.length), volume, base, Uint8Array.from([0])]);
	}
	new DataView(info.buffer).setUint32(0, info.length, true);

	const str = (s) => cat([u16(s.length), utf16(s)]);
	const strings = [o.name ? str(o.name) : null, o.workingDir ? str(o.workingDir) : null, o.args !== undefined ? str(o.args) : null, o.icon ? str(o.icon) : null].filter(Boolean);

	const extra = [];
	if (o.envTarget) {
		const b = new Uint8Array(0x314);
		const v = new DataView(b.buffer);
		v.setUint32(0, 0x314, true);
		v.setUint32(4, 0xa0000001, true);
		b.set(enc.encode(o.envTarget).subarray(0, 259), 8);
		b.set(utf16(o.envTarget).subarray(0, 518), 268);
		extra.push(b);
	}
	if (o.tracker) {
		const t = o.tracker;
		const vol = guid("6A2B33E1-5C0D-4A8E-9F3B-2C1D0E9F8A7B");
		const file = uuidV1(t.time, t.mac);
		extra.push(cat([u32(0x60), u32(0xa0000003), u32(0x58), u32(0), (() => {
			const m = new Uint8Array(16);
			m.set(enc.encode(t.machine).subarray(0, 15));
			return m;
		})(), vol, file, vol, file]));
	}
	extra.push(u32(0));
	return cat([header, unc ? new Uint8Array(0) : idList(o.target), info, ...strings, ...extra, o.appended ?? new Uint8Array(0)]);
}

// ── Prefetch ──────────────────────────────────────────────────────────

/** Xpress Huffman, compressed ([MS-XCA] 2.1): flat 9-bit codes for all 512
 * symbols (a valid, if unambitious, table), greedy matches, laid out in the
 * order the decoder reads: two 16-bit words primed, another whenever fewer
 * than 16 bits remain, a long match's extra length bytes where the decoder
 * meets them. Two zero bytes end the stream, for readers that stop at the
 * input's end rather than at the declared size. */
export function xpressCompress(data) {
	const out = [];
	const words = (c) => 2 + (c <= 16 ? 0 : Math.ceil((c - 16) / 16));
	for (let start = 0; start < data.length || start === 0; start += 65536) {
		const end = Math.min(data.length, start + 65536);
		const bits = [];
		const raw = [];
		const put = (n, v) => {
			for (let i = n - 1; i >= 0; i--) bits.push((v >> i) & 1);
		};
		const heads = new Map();
		let pos = start;
		while (pos < end) {
			let best = 0;
			let bestOff = 0;
			if (pos + 3 <= end) {
				const key = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2];
				const list = heads.get(key) ?? [];
				for (let i = list.length - 1; i >= 0 && i >= list.length - 32; i--) {
					const off = pos - list[i];
					if (off >= 65536) break;
					let len = 0;
					while (pos + len < end && data[list[i] + len] === data[pos + len] && len < 65535) len++;
					if (len > best) (best = len), (bestOff = off);
				}
				list.push(pos);
				heads.set(key, list);
			}
			if (best >= 3) {
				const offBits = 31 - Math.clz32(bestOff);
				put(9, 256 + (offBits << 4) + Math.min(best - 3, 15));
				if (best - 3 >= 15) raw.push([bits.length, best - 3 - 15 < 255 ? [best - 3 - 15] : [255, (best - 3) & 0xff, (best - 3) >> 8]]);
				put(offBits, bestOff - (1 << offBits));
				pos += best;
			} else put(9, data[pos++]);
		}
		for (let i = 0; i < 256; i++) out.push(0x99);
		const total = words(bits.length);
		let r = 0;
		for (let k = 0; k < total; k++) {
			let w = 0;
			for (let i = 0; i < 16; i++) w = (w << 1) | (bits[k * 16 + i] ?? 0);
			out.push(w & 0xff, w >> 8);
			while (r < raw.length && words(raw[r][0]) === k + 1) out.push(...raw[r++][1]);
		}
		while (r < raw.length) out.push(...raw[r++][1]);
		if (data.length === 0) break;
	}
	out.push(0, 0);
	return Uint8Array.from(out);
}

/**
 * A Prefetch file, version 30 (Windows 10/11), as Windows writes it: the
 * SCCA header and file information (dissect's FILE_INFORMATION_26 layout),
 * the file metrics, the filename strings, one volume; then compressed
 * ("MAM\x04", the size, Xpress Huffman) unless `compressed` is false.
 */
export function buildPrefetch({ exe, hash, runCount, runs, files, volume, compressed = true }) {
	const names = cat(files.map((f) => cat([utf16(f), u16(0)])));
	const metricsAt = 84 + 224;
	const metrics = cat(files.map((f, i) => {
		const offset = files.slice(0, i).reduce((n, x) => n + (x.length + 1) * 2, 0);
		return cat([u32(0), u32(0), u32(0), u32(offset), u32(f.length), u32(0x200), new Uint8Array(8)]);
	}));
	const namesAt = metricsAt + metrics.length;
	const volAt = namesAt + names.length;
	const dev = cat([utf16(volume.device), u16(0)]);
	const dirs = cat(volume.dirs.map((d) => cat([u16(d.length), utf16(d), u16(0)])));
	const volInfoSize = 96;
	const devOff = volInfoSize;
	const dirsOff = devOff + dev.length;
	const volEntry = cat([u32(devOff), u32(volume.device.length), filetime(volume.created), u32(volume.serial), u32(0), u32(0), u32(dirsOff), u32(volume.dirs.length), new Uint8Array(60)]);
	const vol = cat([volEntry, dev, dirs]);
	const fileInfo = new Uint8Array(224);
	const v = new DataView(fileInfo.buffer);
	[metricsAt, files.length, 0, 0, namesAt, names.length, volAt, 1, vol.length].forEach((x, i) => v.setUint32(i * 4, x, true));
	runs.slice(0, 8).forEach((d, i) => fileInfo.set(filetime(d), 44 + i * 8));
	v.setUint32(124, runCount, true);
	const head = new Uint8Array(84);
	const hv = new DataView(head.buffer);
	hv.setUint32(0, 30, true);
	head.set(enc.encode("SCCA"), 4);
	hv.setUint32(8, 0x11, true);
	head.set(utf16(exe).subarray(0, 58), 16);
	hv.setUint32(76, hash, true);
	const body = cat([head, fileInfo, metrics, names, vol]);
	new DataView(body.buffer).setUint32(12, body.length, true);
	if (!compressed) return body;
	return cat([enc.encode("MAM\x04"), u32(body.length), xpressCompress(body)]);
}
