// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a stored KDF setting may ask of this device (docs/SECURITY-REVIEW.md
 * › O8). The Rust twin is crates/formats/src/unlock.rs › check_argon2 /
 * check_salt; both are exercised by tests/unit/kdf-bounds.test.ts and the
 * Rust unit tests.
 *
 * Argon2id parameters arrive in data the SERVER stores and serves: a vault's
 * password methods, a share link's `kdf`. So they are an attack surface in
 * two directions:
 *
 * - **Too weak**, and a password is cheap to guess offline. The floor is
 *   OWASP's minimum for Argon2id — 19 MiB with 2 passes (RFC 9106's
 *   "second recommended" 64 MiB / 3 passes is what gorani writes). Before
 *   commit 25 the floor allowed ONE pass at 19 MiB, below that minimum.
 * - **Too strong**, and the device freezes: a server that serves "1 GiB,
 *   20 passes" makes a phone allocate a gigabyte and spin for a minute —
 *   per method tried. The ceiling is 256 MiB and 10 passes (a few seconds
 *   on a laptop at worst), and at most `MAX_PASSWORD_METHODS` password
 *   methods are tried per unlock: a settings row padded with fifty methods
 *   costs four Argon2 runs, not fifty.
 *
 * Salts: 16 to 64 bytes (RFC 9106 recommends 16; anything shorter is a
 * malformed record, anything longer a padding trick).
 *
 * This module has no imports on purpose: the public share page bundles it,
 * and that page should carry as little code as it can.
 */

export interface Argon2Cost {
	/** Memory, KiB. */
	m: number;
	/** Passes. */
	t: number;
	/** Lanes. */
	p: number;
}

export const ARGON2_BOUNDS = {
	m: { min: 19 * 1024, max: 256 * 1024 },
	t: { min: 2, max: 10 },
	p: { min: 1, max: 8 },
} as const;

export const SALT_BOUNDS = { min: 16, max: 64 } as const;

/** At most this many password methods are tried per unlock (each one is an Argon2 run). */
export const MAX_PASSWORD_METHODS = 4;

const inRange = (v: unknown, r: { min: number; max: number }) => Number.isInteger(v) && (v as number) >= r.min && (v as number) <= r.max;

/** Throws unless every parameter is inside the bounds. */
export function checkArgon2(a: Argon2Cost | null | undefined): asserts a is Argon2Cost {
	if (!a || !inRange(a.m, ARGON2_BOUNDS.m) || !inRange(a.t, ARGON2_BOUNDS.t) || !inRange(a.p, ARGON2_BOUNDS.p)) throw new Error("Unsupported password parameters");
}

/** Throws unless the salt's length is inside the bounds. */
export function checkSalt(salt: Uint8Array): void {
	if (salt.length < SALT_BOUNDS.min || salt.length > SALT_BOUNDS.max) throw new Error("Unsupported salt length");
}
