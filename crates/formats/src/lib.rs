// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

//! Gorani's sealed byte formats — **the reference implementation**.
//!
//! One crate, three users, one byte layout: the Rust Worker (shape checks),
//! the native clients (seal/open on device) and the test vectors that prove
//! the browser's TypeScript implementation writes the same bytes. It is
//! dependency-light and crypto-crate-only: nothing here implements a
//! primitive; AES-256-GCM, P-256, HKDF and ML-KEM-768 come from the audited
//! RustCrypto and RustCrypto-adjacent crates (docs/ENCRYPTION.md §Primitives).
//!
//! The formats (docs/ENCRYPTION.md has every byte):
//!
//! - **GV01** — sealing to a P-256 public key (ECIES: fresh ephemeral key per
//!   object, ECDH, HKDF-SHA256 → AES-256-GCM, the header as AAD).
//! - **GV02** — content under a 32-byte content key (AES-256-GCM).
//! - **GV03** — hybrid post-quantum sealing: P-256 **and** ML-KEM-768, both
//!   needed to open (the "X-Wing"-style combiner binds the two).
//! - **GK01** — a hybrid private key's bytes (P-256 PKCS#8 ‖ ML-KEM seed ‖
//!   P-256 public), what unlock methods wrap and sealed keys hold.
//! - **GW01** — a private key wrapped under a key-encryption key (unlock
//!   methods, device copies).
//! - **GC01** (`chunked`) — a large file in authenticated 8 MiB frames that
//!   each open on their own (position and finality bound as AAD).
//! - **GBAK1** (`backup`) — the `.gbak` container: segments under a per-backup
//!   file key whose only unwrapped copy is sealed to the owner's key file.
//!
//! Text columns carry `"GV01:"`, `"GV02:"` or `"GV03:"` followed by standard
//! base64. The HKDF info strings ("gorani-vault-v1", "gorani-vault-v3", the
//! unlock derivations in `unlock`) are part of the format: changing one
//! changes every byte downstream, so they are constants here and nowhere
//! else. Everything secret-bearing is `Zeroizing`: dropped keys wipe.
//!
//! Tests: `cargo test` round-trips every format, refuses tampered bytes,
//! opens the browser's vectors (tests/vectors.json) and — with
//! `GORANI_RUST_OUT=<path>` — writes what Rust sealed for the TypeScript
//! tests to open. Both directions, every commit.

pub mod backup;
pub mod chunked;
pub mod formats;
pub mod placed;
pub mod records;
pub mod unlock;

/// The crate's errors: a shape problem (`Format`), a key or corruption
/// problem (`Open`), a derivation problem (`Kdf`). Messages are for logs and
/// tests, never for deciding anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
	Format(&'static str),
	Open(&'static str),
	Kdf(&'static str),
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Error::Format(what) => write!(f, "format: {what}"),
			Error::Open(what) => write!(f, "open: {what}"),
			Error::Kdf(what) => write!(f, "kdf: {what}"),
		}
	}
}

impl std::error::Error for Error {}