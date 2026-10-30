// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Reading a picture's parsed metadata (commit 42d, docs/PREVIEWS.md ›
 * Images): where it was taken, and how it is turned. Kept apart from
 * meta.ts, which parses (exifr): this file is what the reader in the
 * frame needs, and the parser runs only in the worker.
 *
 * Pure: unit:preview-facts.
 */

/** Each block of metadata (ifd0, exif, gps, xmp, iptc, icc…), by tag name. */
export type Meta = Record<string, Record<string, unknown>>;

export interface Gps {
	lat: number;
	lon: number;
	/** Metres; negative below sea level. */
	alt?: number;
	/** Degrees the camera faced (true or magnetic north). */
	direction?: number;
	directionRef?: string;
	/** Metres (GPSHPositioningError). */
	accuracy?: number;
	/** GPS time, UTC: "2026-01-01 18:04:05 UTC". */
	when?: string;
	/** All zero: written, but empty (some apps strip the location this way). */
	zeroed: boolean;
}

const asNumbers = (v: unknown): number[] => (Array.isArray(v) ? v.map(Number) : typeof v === "number" ? [v] : v && typeof v === "object" ? Object.values(v).map(Number) : []);
const dms = (v: unknown): number | null => {
	const [d = NaN, m = 0, s = 0] = asNumbers(v);
	return Number.isFinite(d) ? d + m / 60 + s / 3600 : null;
};

/** Where it was taken, from the GPS block. */
export function gpsOf(m: Meta | null): Gps | null {
	const g = m?.gps;
	if (!g) return null;
	let lat = typeof g.latitude === "number" ? g.latitude : null;
	let lon = typeof g.longitude === "number" ? g.longitude : null;
	if (lat === null || lon === null) {
		const a = dms(g.GPSLatitude);
		const o = dms(g.GPSLongitude);
		if (a === null || o === null) return null;
		lat = String(g.GPSLatitudeRef ?? "N").toUpperCase().startsWith("S") ? -a : a;
		lon = String(g.GPSLongitudeRef ?? "E").toUpperCase().startsWith("W") ? -o : o;
	}
	if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
	const out: Gps = { lat, lon, zeroed: lat === 0 && lon === 0 };
	const altRef = asNumbers(g.GPSAltitudeRef)[0];
	if (typeof g.GPSAltitude === "number") out.alt = altRef === 1 ? -g.GPSAltitude : g.GPSAltitude;
	if (typeof g.GPSImgDirection === "number") {
		out.direction = g.GPSImgDirection;
		out.directionRef = String(g.GPSImgDirectionRef ?? "") === "M" ? "magnetic" : "true";
	}
	if (typeof g.GPSHPositioningError === "number") out.accuracy = g.GPSHPositioningError;
	const t = asNumbers(g.GPSTimeStamp);
	if (typeof g.GPSDateStamp === "string" && t.length === 3) {
		const pad = (n: number) => String(Math.floor(n)).padStart(2, "0");
		out.when = `${g.GPSDateStamp.replace(/:/g, "-")} ${pad(t[0]!)}:${pad(t[1]!)}:${pad(t[2]!)} UTC`;
	}
	return out;
}

/** "37.56630° N, 126.97790° E" */
export function formatPosition(p: { lat: number; lon: number }): string {
	return `${Math.abs(p.lat).toFixed(5)}° ${p.lat < 0 ? "S" : "N"}, ${Math.abs(p.lon).toFixed(5)}° ${p.lon < 0 ? "W" : "E"}`;
}

const ORIENTATIONS = ["Horizontal (normal)", "Mirror horizontal", "Rotate 180", "Mirror vertical", "Mirror horizontal and rotate 270 CW", "Rotate 90 CW", "Mirror horizontal and rotate 90 CW", "Rotate 270 CW"];

/** EXIF Orientation as its number (1–8), from exifr's words or a number. */
export function orientationOf(m: Meta | null): number {
	const v = m?.ifd0?.Orientation;
	if (typeof v === "number" && v >= 1 && v <= 8) return v;
	const at = typeof v === "string" ? ORIENTATIONS.indexOf(v) : -1;
	return at >= 0 ? at + 1 : 1;
}
