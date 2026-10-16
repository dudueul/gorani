// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Playing a protected copy (commit 40c, docs/DRM.md): Safari's own HLS
 * player, with FairPlay through standard EME.
 *
 *   1. The `<video>` gets the playlist (worker/src/drm.rs › playlist) as its
 *      source; Safari's player reads it, meets `skd://<key id>`, and fires
 *      `encrypted` with that URI as its init data.
 *   2. The page answers with MediaKeys for `com.apple.fps`, given the FPS
 *      certificate (public); FairPlay builds an SPC — a request sealed to
 *      that certificate — and the page posts it to the license route.
 *   3. The Worker checks who is asking and answers with a CKC: the content
 *      key sealed to THIS session of Apple's DRM module. The page passes it
 *      on with `session.update` and never sees the key.
 *
 * Nothing here decrypts anything; the page only carries opaque messages
 * between the player and the Worker. Elsewhere (Chrome, Firefox, Edge) the
 * key system does not exist and the viewer says where it plays instead —
 * there is no fallback that would put the key in the page (docs/DRM.md ›
 * How it plays).
 *
 * (The share recipient page has the same few steps in plain JavaScript,
 * web/public/s.js, under its own stricter CSP.)
 */

/** What Safari is asked for: FairPlay with `skd` init data, streaming only
 * (no persisted licences — nothing outlives the session). */
const CONFIG: MediaKeySystemConfiguration[] = [
	{
		initDataTypes: ["skd"],
		videoCapabilities: [{ contentType: 'application/vnd.apple.mpegurl; codecs="avc1.640028"' }],
		distinctiveIdentifier: "not-allowed",
		persistentState: "not-allowed",
		sessionTypes: ["temporary"],
	},
];

/** Can this browser play a protected copy at all? (Safari on macOS, iOS
 * and iPadOS; nothing else has FairPlay.) */
export async function fairPlaySupported(): Promise<boolean> {
	if (typeof navigator === "undefined" || !navigator.requestMediaKeySystemAccess) return false;
	if (!document.createElement("video").canPlayType("application/vnd.apple.mpegurl")) return false;
	try {
		await navigator.requestMediaKeySystemAccess("com.apple.fps", CONFIG);
		return true;
	} catch {
		return false;
	}
}

export interface FairPlayRoutes {
	/** The playlist URL, as the `<video>` will fetch it. */
	playlist: string;
	/** The FPS certificate's URL. */
	certificate: string;
	/** SPC in, CKC out — the license route, with whatever credential it takes. */
	license(spc: Uint8Array): Promise<Uint8Array>;
}

/**
 * Attach a protected copy to `video`. Errors (a refused license, a display
 * without HDCP) reach `onError` in words a person can act on.
 */
export async function playProtected(video: HTMLVideoElement, routes: FairPlayRoutes, onError: (message: string) => void): Promise<() => void> {
	const access = await navigator.requestMediaKeySystemAccess("com.apple.fps", CONFIG);
	const keys = await access.createMediaKeys();
	const cert = await fetch(routes.certificate);
	if (!cert.ok) throw new Error((await cert.json().catch(() => ({ error: `HTTP ${cert.status}` }))).error ?? "the FairPlay certificate is not available");
	await keys.setServerCertificate(new Uint8Array(await cert.arrayBuffer()));
	await video.setMediaKeys(keys);
	const sessions: MediaKeySession[] = [];
	const onEncrypted = (e: MediaEncryptedEvent) => {
		if (!e.initData) return;
		const session = keys.createSession("temporary");
		sessions.push(session);
		session.addEventListener("message", (m) => {
			void (async () => {
				try {
					const ckc = await routes.license(new Uint8Array(m.message));
					await session.update(ckc as BufferSource);
				} catch (err) {
					onError(err instanceof Error ? err.message : String(err));
				}
			})();
		});
		// An output-protection refusal (HDCP Type 0 is required) arrives as a
		// key status, not an error: say what it means.
		session.addEventListener("keystatuseschange", () => {
			for (const [, status] of session.keyStatuses) {
				if (status === "output-restricted" || status === "output-downscaled") onError("This display or its connection is not HDCP-protected, which protected videos require — play it on this screen, or over AirPlay, or an HDCP-capable cable");
				if (status === "expired" || status === "internal-error") onError("The protected video's license stopped working — open it again");
			}
		});
		void session.generateRequest(e.initDataType, e.initData).catch((err: unknown) => onError(err instanceof Error ? err.message : String(err)));
	};
	video.addEventListener("encrypted", onEncrypted);
	video.src = routes.playlist;
	return () => {
		video.removeEventListener("encrypted", onEncrypted);
		for (const s of sessions) void s.close().catch(() => {});
		video.removeAttribute("src");
		video.load();
	};
}
