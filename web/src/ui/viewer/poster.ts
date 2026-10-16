// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Poster frames for the Movie tab (commit 39o, docs/MOVIES.md).
 *
 * A poster is one frame, drawn by THIS browser from plaintext it already
 * holds, made small (320 px wide, WebP) and sealed into the version's
 * `file.poster` place beside its sidecar. The server stores ~20 KB it
 * cannot read. Two moments make one:
 *
 * - **at upload**, from the local file (a blob: URL of the File the person
 *   picked — no network, the browser decodes what it can);
 * - **while playing**, for a video uploaded before posters existed or by a
 *   client that makes none: the frame on screen a moment in.
 *
 * The DOM is touched only when a function runs (canvas, <video>), so the
 * model imports this module and its Node tests load it without one.
 */

const WIDTH = 320;

/** Draw the frame a <video> is showing, at most WIDTH wide. */
export async function posterFromVideo(video: HTMLVideoElement): Promise<Uint8Array | null> {
	if (!video.videoWidth || !video.videoHeight) return null;
	const scale = Math.min(1, WIDTH / video.videoWidth);
	const canvas = document.createElement("canvas");
	canvas.width = Math.round(video.videoWidth * scale);
	canvas.height = Math.round(video.videoHeight * scale);
	const ctx = canvas.getContext("2d");
	if (!ctx) return null;
	ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
	// WebP where the browser encodes it; otherwise it hands back PNG, and
	// imageType() names it by its bytes when it is shown.
	const blob = await new Promise<Blob | null>((ok) => canvas.toBlob(ok, "image/webp", 0.72));
	return blob ? new Uint8Array(await blob.arrayBuffer()) : null;
}

/** A frame `at` seconds into a local source (a blob: URL), or null when the
 * browser cannot decode it (a codec it lacks) within a few seconds. */
export async function posterFromUrl(src: string, at: number): Promise<Uint8Array | null> {
	const video = document.createElement("video");
	video.muted = true;
	video.preload = "auto";
	video.playsInline = true;
	try {
		const ready = new Promise<boolean>((ok) => {
			const t = setTimeout(() => ok(false), 8000);
			video.addEventListener("loadeddata", () => (clearTimeout(t), ok(true)), { once: true });
			video.addEventListener("error", () => (clearTimeout(t), ok(false)), { once: true });
		});
		video.src = src;
		if (!(await ready)) return null;
		const target = Math.min(at, Math.max(0, (video.duration || at) - 0.1));
		if (target > 0) {
			const sought = new Promise<boolean>((ok) => {
				const t = setTimeout(() => ok(false), 8000);
				video.addEventListener("seeked", () => (clearTimeout(t), ok(true)), { once: true });
			});
			video.currentTime = target;
			if (!(await sought)) return null;
		}
		return await posterFromVideo(video);
	} finally {
		video.removeAttribute("src");
		video.load();
	}
}

/** Where a poster should come from: a couple of seconds in (past a fade
 * from black), or a tenth of a short clip. */
export function posterTime(durationMs: number | null): number {
	if (!durationMs) return 1;
	return Math.min(2, (durationMs / 1000) * 0.1);
}

/** An image's type by its first bytes (a poster may be WebP or PNG). */
export function imageType(b: Uint8Array): string {
	if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
	if (b[0] === 0xff && b[1] === 0xd8) return "image/jpeg";
	return "image/webp";
}
