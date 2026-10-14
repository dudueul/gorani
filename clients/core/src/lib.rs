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
pub mod area;
pub mod cases;
pub mod engine;
pub mod identity;
pub mod session;
pub mod transfer;

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
///
/// `Debug` by hand (O16): the device token, the Access service secret and
/// the device secret print as `[redacted]` — the derived impl printed all
/// three for any `{:?}`, and the device secret plus the server's copy IS
/// the root key.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceProfile {
	pub server: String,
	pub member: String,
	pub device_id: String,
	pub token: String,
	/// How this computer signs in as its MEMBER (commit 33a): a command that
	/// prints the member's Cloudflare Access token — `cloudflared access
	/// token -app=https://<host>` — run once per process; the token rides
	/// every request as `cf-access-token`, so the Worker sees the member's
	/// email and applies their rules (own area, case grants). The variable
	/// `GORANI_ACCESS_TOKEN` takes precedence (a shell that already has one).
	#[serde(default)]
	pub access_token_cmd: Option<String>,
	/// A Cloudflare Access service-token pair, sent as
	/// `CF-Access-Client-Id/Secret`. NOT enough alone: a service token's JWT
	/// carries no email, and the Worker takes identity from the email — it
	/// passes an Access policy that requires one in front of the user token.
	/// (Until commit 33a this was the documented way to sign in, and every
	/// desktop request was refused in production — docs/DESKTOP.md.)
	#[serde(default)]
	pub access_id: Option<String>,
	#[serde(default, rename = "accessClientSecret")]
	pub access_secret: Option<String>,
	/// The device secret (hex) — the input to this computer's KEK. It must
	/// NEVER leave the machine: the server holds the wrapped root copy and
	/// its salt, so server + device secret = the root.
	///
	/// Security review, commit 23: the dev CLI stored this in the
	/// `access_secret` slot, and the API client sends that slot as
	/// `CF-Access-Client-Secret` — so with an Access id configured, every
	/// request handed the server (and Access, and any log of either) the
	/// one secret the device design keeps on the device. Old profiles named
	/// the field `accessSecret` and always meant the device secret by it;
	/// the alias reads them into the right slot.
	#[serde(default, alias = "accessSecret")]
	pub device_secret: Option<String>,
	/// Dev-mode identity (wrangler dev only; production uses Access).
	#[serde(default)]
	pub dev_email: Option<String>,
}

impl std::fmt::Debug for DeviceProfile {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let redact = |o: &Option<String>| if o.is_some() { "[redacted]" } else { "None" };
		f.debug_struct("DeviceProfile")
			.field("server", &self.server)
			.field("member", &self.member)
			.field("device_id", &self.device_id)
			.field("token", &"[redacted]")
			.field("access_token_cmd", &self.access_token_cmd)
			.field("access_id", &self.access_id)
			.field("access_secret", &redact(&self.access_secret))
			.field("device_secret", &redact(&self.device_secret))
			.field("dev_email", &self.dev_email)
			.finish()
	}
}

/// The unlocked session: the root bundle (bytes, Zeroizing) + the settings.
/// Import to a non-extractable CryptoKey is a browser luxury; native clients
/// hold bytes in `Zeroizing` and wipe on drop.
pub struct Session {
	pub settings: api::VaultSettings,
	pub root: Zeroizing<Vec<u8>>,
}

impl Session {
	/// The files store's private key, opened from the root — and only once the
	/// record has proven it belongs to this member (docs/SECURITY-REVIEW.md ›
	/// O3). Every name, type and content key this client seals goes to the
	/// files store's public half; a record swapped by the server would hand
	/// all of it to whoever minted the swap. So, before anything is opened:
	///
	/// 1. the record's MAC must verify under this root's record key — the
	///    CLI never pins (it does not write settings), so a record without a
	///    MAC is refused: the web app pins on first open;
	/// 2. the opened private key must reproduce the record's public halves
	///    and key id.
	pub fn files_store(&self) -> Result<gorani_formats::formats::VaultPrivateKey, Error> {
		use gorani_formats::formats::{self, VaultPrivateKey, VaultPublicKey};
		use gorani_formats::records::{record_key, verify_record, StoreRecord};
		let key = self.settings.stores.get("files").ok_or(Error::Open("no files store key"))?;
		let root = VaultPrivateKey::from_bytes(&self.root).map_err(|_| Error::Open("root bundle"))?;
		let record_pub = VaultPublicKey::from_jwk(&key.public_key.x, &key.public_key.y, key.pq_public_key.as_deref()).map_err(|_| Error::Format("bad store JWK"))?;
		let VaultPublicKey::Hybrid { ec, kem } = &record_pub else { return Err(Error::Open("the files store record is not a hybrid key")) };
		let ec_raw = formats::raw_public_bytes(ec);
		let mac = key.mac.as_deref().ok_or(Error::Open("the files store record is not authenticated (open the vault once in the web app to pin it)"))?;
		let rk = record_key(&root).map_err(|_| Error::Open("record key"))?;
		let rec = StoreRecord { name: "files", key_id: &key.key_id, ec_public: &ec_raw, kem_public: kem, private_key_sealed: &key.private_key_sealed };
		if !verify_record(&rk, &rec, mac) {
			return Err(Error::Open("the files store record failed authentication — it was changed by someone without this vault's root; nothing was opened or sealed"));
		}
		// Sealed text only (an unsealed "private key" is refused), then the
		// consistency check: the opened key IS the record's key.
		if !formats::is_sealed_text(&key.private_key_sealed) {
			return Err(Error::Open("the files store private key is not sealed"));
		}
		let bundle_b64 = formats::open_text(&root, &key.private_key_sealed).map_err(|_| Error::Open("store key"))?;
		let bytes = decode(&bundle_b64)?;
		let store = VaultPrivateKey::from_bytes(bytes.as_slice()).map_err(|_| Error::Open("store bundle"))?;
		if formats::key_id(&formats::public_of(&store)) != key.key_id || formats::key_id(&record_pub) != key.key_id {
			return Err(Error::Open("the files store record does not match its private key"));
		}
		Ok(store)
	}

	/// Seal text INTO a place of the files store (GV04, commit 25 — O6).
	///
	/// The history of this function is the O3 → O6 story in two steps. It
	/// once sealed to the record's public JWK, read straight off the settings
	/// row — so a swapped record received every upload (O3a). Commit 24 made
	/// it derive the public half from the VERIFIED private key. Commit 25
	/// removes the public-key path altogether: a store seals to itself, with
	/// a secret only its private key computes, so there is no public key to
	/// get wrong — and nothing the server holds can seal here.
	pub fn seal_into(&self, place: &gorani_formats::placed::Place, text: &str) -> Result<String, Error> {
		gorani_formats::placed::seal_placed_text(&self.files_store()?, place, text).map_err(|_| Error::Open("files store key"))
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

/// A fresh file or folder id, chosen before sealing (128 random bits,
/// base64url — the Worker's id allow-list). The twin of `places.ts ›
/// newItemId`: the name, type and key are sealed into places that NAME the
/// id, so it must exist first.
pub fn new_item_id() -> String {
	use base64::Engine;
	let mut b = [0u8; 16];
	rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
	base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
