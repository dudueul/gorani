// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Playing a sealed MP4 through Media Source Extensions (commit 39p,
 * docs/VIDEO.md).
 *
 * ```text
 * the <video> wants time T
 *   → the index's segment table: T is in segment n (cut on keyframes)
 *   → its planned plaintext blocks, read through the FrameReader
 *     (one ciphertext range, frames decrypted here, a few kept)
 *   → gorani-media (WebAssembly) builds segment n as fMP4 (moof + mdat)
 *   → SourceBuffer.appendBuffer
 * ```
 *
 * The browser's own player still does the decoding, the controls and the
 * picture; this only feeds it. Nothing here touches a key: the reader's
 * `open` closure holds the content key, and the engine gets plaintext.
 *
 * What it keeps in mind:
 *
 * - **Ahead, not everything.** It appends until `AHEAD` seconds past the
 *   playhead are buffered, then waits for `timeupdate`. A two-hour film is
 *   never held whole; what is behind is let go (`BEHIND`), and a full buffer
 *   (QuotaExceededError) lets go more and tries once again.
 * - **Seeks are just a new playhead.** The next segment is always "the first
 *   one from the playhead that the buffer does not hold"
 *   (video-meta.ts › nextSegment), so a seek needs no special path — a
 *   segment built for the old place, if one was in flight, is simply
 *   appended where it belongs (segments carry their own times).
 * - **Safari's ManagedMediaSource** (iOS 17.1+) is used where plain
 *   MediaSource is missing; it asks to pause appending when it likes
 *   (`streaming`), and requires remote playback off.
 * - **Failure is a fallback, not an error page.** Anything the engine or the
 *   decoder refuses calls `onFail` once; the viewer then plays the file the
 *   older way (the media service worker's Range responses).
 */

import type { MediaIndex } from "../../lib/media-engine.ts";
import { nextSegment } from "../../vault/video-meta.ts";

/** Plaintext bytes of the file (frame-reader.ts). */
export interface PlainSource {
	read(offset: number, length: number): Promise<Uint8Array>;
}

/** Seconds of video to keep buffered ahead of the playhead. */
const AHEAD = 30;
/** Seconds behind the playhead to keep (a short step back needs no fetch). */
const BEHIND = 20;

type MediaSourceLike = MediaSource & { streaming?: boolean };
type MediaSourceClass = { new (): MediaSourceLike; isTypeSupported(type: string): boolean };

/** The MediaSource this browser has: Safari's managed one, or the standard. */
function mediaSourceClass(): MediaSourceClass | null {
	const g = globalThis as unknown as { ManagedMediaSource?: MediaSourceClass; MediaSource?: MediaSourceClass };
	return g.MediaSource ?? g.ManagedMediaSource ?? null;
}

/** Can this browser play `type` (`video/mp4; codecs="…"`) through MSE? */
export function canPlayWithMse(type: string): boolean {
	const MS = mediaSourceClass();
	try {
		return Boolean(MS?.isTypeSupported(type));
	} catch {
		return false;
	}
}

export interface MsePlayerOptions {
	/** Called once, when this way of playing cannot go on. */
	onFail?: (e: Error) => void;
}

export class MsePlayer {
	private readonly ms: MediaSourceLike;
	private sb: SourceBuffer | null = null;
	private readonly url: string;
	private pumping = false;
	private closed = false;
	private failed = false;
	/** Segments built and appended (for the tests and the panel). */
	appended = 0;

	/** A `<video>` — or, for music (39w), an `<audio>`: MSE feeds either. */
	private readonly video: HTMLMediaElement;
	private readonly index: MediaIndex;
	private readonly source: PlainSource;
	private readonly type: string;
	private readonly opts: MsePlayerOptions;

	constructor(video: HTMLMediaElement, index: MediaIndex, source: PlainSource, type: string, opts: MsePlayerOptions = {}) {
		this.video = video;
		this.index = index;
		this.source = source;
		this.type = type;
		this.opts = opts;
		const MS = mediaSourceClass();
		if (!MS) throw new Error("this browser has no Media Source Extensions");
		this.ms = new MS();
		// ManagedMediaSource plays only with remote playback (AirPlay) off,
		// unless an alternative source is offered — there is none here: the
		// bytes exist only in this page.
		(video as HTMLMediaElement & { disableRemotePlayback?: boolean }).disableRemotePlayback = true;
		this.url = URL.createObjectURL(this.ms);
		this.ms.addEventListener("sourceopen", this.onOpen, { once: true });
		this.ms.addEventListener("startstreaming", this.kick);
		video.addEventListener("timeupdate", this.kick);
		video.addEventListener("seeking", this.kick);
		video.addEventListener("waiting", this.kick);
		video.addEventListener("error", this.onVideoError);
		video.src = this.url;
	}

	private readonly kick = (): void => {
		this.stepOverGap();
		void this.pump();
	};

	/**
	 * A small hole at the playhead — the first segment of a B-frame video
	 * starts a few milliseconds after 0 (its composition offset), or two
	 * segments meet a frame apart — leaves the player waiting forever for
	 * bytes that will never come. Step over it when it is under a second.
	 */
	private stepOverGap(): void {
		const t = this.video.currentTime;
		const ahead = this.bufferedRanges().find(([a]) => a > t);
		const inside = this.bufferedRanges().some(([a, b]) => a <= t && t < b);
		if (!inside && ahead && ahead[0] - t < 1) this.video.currentTime = ahead[0] + 0.001;
	}

	private readonly onVideoError = (): void => {
		const err = this.video.error;
		this.fail(new Error(`the browser could not decode this file${err?.message ? ` (${err.message})` : ""}`));
	};

	private readonly onOpen = async (): Promise<void> => {
		try {
			this.sb = this.ms.addSourceBuffer(this.type);
			this.sb.mode = "segments";
			await this.append(this.index.init());
			this.ms.duration = this.index.summary.durationMs / 1000;
			await this.pump();
		} catch (e) {
			this.fail(e);
		}
	};

	/** Append what the playhead needs next, until AHEAD seconds are buffered. */
	private async pump(): Promise<void> {
		if (this.pumping || this.closed || !this.sb) return;
		this.pumping = true;
		try {
			for (;;) {
				if (this.closed || !this.sb) return;
				if (this.ms.streaming === false) return; // Safari asked to wait: startstreaming resumes
				const n = nextSegment(this.index.segments, this.bufferedRanges(), this.video.currentTime, AHEAD);
				if (n < 0) {
					this.endIfComplete();
					return;
				}
				const bytes = await this.build(n);
				if (this.closed) return;
				await this.append(bytes);
				this.appended++;
				this.stepOverGap();
			}
		} catch (e) {
			this.fail(e);
		} finally {
			this.pumping = false;
		}
	}

	/** Segment n as fMP4: its planned blocks read, joined, and assembled. */
	private async build(n: number): Promise<Uint8Array> {
		const blocks = this.index.plan(n);
		const parts = await Promise.all(blocks.map(([offset, length]) => this.source.read(offset, length)));
		const total = parts.reduce((a, p) => a + p.length, 0);
		const joined = new Uint8Array(total);
		let at = 0;
		for (const p of parts) {
			joined.set(p, at);
			at += p.length;
		}
		return this.index.segment(n, joined);
	}

	private bufferedRanges(): [number, number][] {
		const b = this.sb?.buffered;
		const out: [number, number][] = [];
		if (!b) return out;
		for (let i = 0; i < b.length; i++) out.push([b.start(i), b.end(i)]);
		return out;
	}

	/** appendBuffer, waited for; a full buffer lets go of what is behind and tries once more. */
	private async append(bytes: Uint8Array): Promise<void> {
		await this.trimBehind(BEHIND);
		try {
			await this.whenDone(() => this.sb!.appendBuffer(bytes as BufferSource));
		} catch (e) {
			if ((e as DOMException)?.name !== "QuotaExceededError") throw e;
			await this.trimBehind(2);
			await this.whenDone(() => this.sb!.appendBuffer(bytes as BufferSource));
		}
	}

	/** Remove what is more than `keep` seconds behind the playhead. */
	private async trimBehind(keep: number): Promise<void> {
		const sb = this.sb;
		if (!sb || !sb.buffered.length) return;
		const until = this.video.currentTime - keep;
		if (sb.buffered.start(0) < until) await this.whenDone(() => sb.remove(0, until));
	}

	/** Run one SourceBuffer operation and wait for its updateend (or error). */
	private whenDone(op: () => void): Promise<void> {
		const sb = this.sb!;
		return new Promise<void>((resolve, reject) => {
			const done = () => (cleanup(), resolve());
			const bad = () => (cleanup(), reject(new Error("the browser refused a piece of this video")));
			const cleanup = () => {
				sb.removeEventListener("updateend", done);
				sb.removeEventListener("error", bad);
			};
			sb.addEventListener("updateend", done);
			sb.addEventListener("error", bad);
			try {
				op();
			} catch (e) {
				cleanup();
				reject(e);
			}
		});
	}

	/** Every segment is in: say so, so the player can play to the end. (A
	 * later seek back reopens the source by itself when it appends again.) */
	private endIfComplete(): void {
		const segs = this.index.segments;
		const last = segs[segs.length - 1];
		if (!last || this.ms.readyState !== "open" || this.sb?.updating) return;
		const mid = last[0] + last[1] / 2;
		if (this.bufferedRanges().some(([a, b]) => a <= mid && mid <= b)) {
			try {
				this.ms.endOfStream();
			} catch {
				// already ended, or a buffer still updating: the next pump tries again
			}
		}
	}

	private fail(e: unknown): void {
		if (this.failed || this.closed) return;
		this.failed = true;
		this.opts.onFail?.(e instanceof Error ? e : new Error(String(e)));
	}

	/** Stop, let go of the object URL and of the index's tables. */
	destroy(): void {
		if (this.closed) return;
		this.closed = true;
		this.video.removeEventListener("timeupdate", this.kick);
		this.video.removeEventListener("seeking", this.kick);
		this.video.removeEventListener("waiting", this.kick);
		this.video.removeEventListener("error", this.onVideoError);
		this.ms.removeEventListener("startstreaming", this.kick);
		try {
			if (this.ms.readyState === "open") this.ms.endOfStream();
		} catch {
			// nothing left to end
		}
		this.video.removeAttribute("src");
		this.video.load();
		URL.revokeObjectURL(this.url);
		this.index.drop();
	}
}
