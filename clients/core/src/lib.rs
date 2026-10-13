// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare's desktop core (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

//! The client core: one module per concern, the protocol of docs/DESKTOP.md.
//!
//! ```text
//! gorani-sync enrol   → the device's wrapped root copy lands on the server (token shown once)
//! gorani-sync ls      → the change feed, names opened with the vault key
//! gorani-sync pull    → a file fetched (Range if chunked) and decrypted to disk
//! gorani-sync push    → a file sealed (GV02 under a fresh content key, key wrapped GV03) and uploaded
//! ```
//!
//! Zero-trust from the client's side too: everything sent is sealed; the
//! device secret never leaves the machine; the vault key lives in memory
//! only while a command runs (`Zeroizing` everywhere, dropped at exit).

pub mod api;
pub mod session;

// Re-export the formats module at the crate root so bins can use
// gorani_formats paths via the client's dependency.
pub use gorani_formats as formats_crate;

use zeroize::Zeroizing;

#[derive(Debug)]
pub enum Error {
	Io(std::io::Error),
	Http(u16, String),
	Format(&'static str),
	Open(&'static str),
	Config(String),
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Error::Io(e) => write!(f, "io: {e}"),
			Error::Http(status, body) => write!(f, "http {status}: {body}"),
			Error::Format(what) => write!(f, "format: {what}"),
			Error::Open(what) => write!(f, "open: {what}"),
			Error::Config(what) => write!(f, "config: {what}"),
		}
	}
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
	fn from(e: std::io::Error) -> Self {
		Error::Io(e)
	}
}

/// The persisted device profile (the CLI keeps it in a JSON file next to
/// its state; platform shells put it in their credential stores).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceProfile {
	pub server: String,
	pub member: String,
	pub device_id: String,
	pub token: String,
	#[serde(default)]
	pub access_id: Option<String>,
	#[serde(default)]
	pub access_secret: Option<String>,
	/// Dev-mode identity (wrangler dev only; production uses Access).
	#[serde(default)]
	pub dev_email: Option<String>,
}

/// The unlocked session: the root bundle (bytes, Zeroizing) + the settings.
/// Import to a non-extractable CryptoKey is a browser luxury; native clients
/// hold bytes in `Zeroizing` and wipe on drop.
pub struct Session {
	pub settings: api::VaultSettings,
	pub root: Zeroizing<Vec<u8>>,
}

impl Session {
	/// The files store's private key, opened from the root.
	pub fn files_store(&self) -> Result<gorani_formats::formats::VaultPrivateKey, Error> {
		let key = self.settings.stores.get("files").ok_or(Error::Open("no files store key"))?;
		let root = gorani_formats::formats::VaultPrivateKey::from_bytes(&self.root).map_err(|_| Error::Open("root bundle"))?;
		// private_key_sealed is GV* TEXT sealed to the root; opening yields the
		// store bundle's bytes (base64), which import into a private key.
		let bundle_b64 = gorani_formats::formats::open_text(&root, &key.private_key_sealed).map_err(|_| Error::Open("store key"))?;
		let bytes = decode(&bundle_b64)?;
		gorani_formats::formats::VaultPrivateKey::from_bytes(bytes.as_slice()).map_err(|_| Error::Open("store bundle"))
	}

	/// Seal text to the files store's public half (names, types).
	pub fn seal_for_files(&self, text: &str) -> Result<String, Error> {
		let key = self.settings.stores.get("files").ok_or(Error::Open("no files store key"))?;
		let pub_key = gorani_formats::formats::VaultPublicKey::from_jwk(&key.public_key.x, &key.public_key.y, key.pq_public_key.as_deref()).map_err(|_| Error::Format("bad store JWK"))?;
		Ok(gorani_formats::formats::seal_text(&pub_key, text))
	}
}

pub fn encode(b: &[u8]) -> String {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.encode(b)
}

pub fn decode(s: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD
		.decode(s)
		.map(Zeroizing::new)
		.map_err(|_| Error::Format("bad base64"))
}