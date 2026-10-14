// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare's desktop core (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

//! The session: opening the vault on a native machine. The unlock secret is
//! presented by the person (password / recovery code — the passkey path
//! lives in the platform shells, which own WebAuthn), the root bundle is
//! unwrapped and held in `Zeroizing` for the command's lifetime.

use gorani_formats::unlock::{Secret, UnlockMethod};
use zeroize::Zeroizing;

use crate::{api, decode, DeviceProfile, Error, Session};
use rand_core::RngCore;

/// Open the vault with a typed password or recovery code.
pub fn unlock(profile: &DeviceProfile, secret_text: &str) -> Result<Session, Error> {
	let client = api::Client::new(profile.clone());
	let settings = client.vault()?;
	let root = unlock_root(&settings, secret_text)?;
	Ok(Session { settings, root })
}

/// Whether this profile holds what a device unlock needs: an enrolled
/// device (id + token) and the device secret.
pub fn has_device_copy(profile: &DeviceProfile) -> bool {
	!profile.device_id.is_empty() && !profile.token.is_empty() && profile.device_secret.as_deref().is_some_and(|s| s.len() == 64)
}

/// Open the vault with THIS computer's copy (docs/DESKTOP.md › Security
/// model): the server releases the wrapped root only to the device's token,
/// and only the device secret, which never leaves the machine, opens it.
/// Neither half alone is the root. (Until commit 33d the client asked for
/// a typed secret every time; its unlock call also dropped the salt.)
pub fn unlock_device(profile: &DeviceProfile) -> Result<Session, Error> {
	let client = api::Client::new(profile.clone());
	let (key_id, wrapped, salt, settings) = client.unlock(&profile.device_id, &profile.token)?;
	let secret = Zeroizing::new(decode_hex(profile.device_secret.as_deref().unwrap_or_default())?);
	let root = gorani_formats::unlock::open_device_copy(&wrapped, &salt, &secret).map_err(|_| Error::Open("this computer's copy of the root does not open with its device secret"))?;
	// The copy must be of THIS vault's root (a stale copy after a rotation
	// opens, and would then fail on every record — say so here instead).
	let opened = gorani_formats::formats::VaultPrivateKey::from_bytes(&root).map_err(|_| Error::Open("root bundle"))?;
	if gorani_formats::formats::key_id(&gorani_formats::formats::public_of(&opened)) != settings.key_id || key_id != settings.key_id {
		return Err(Error::Open("this computer's copy is of another root (rotated since?) — enrol it again"));
	}
	Ok(Session { settings, root })
}

/// Try every method of the matching kind (a vault may have several).
fn unlock_root(settings: &api::VaultSettings, secret_text: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
	let kinds: [(&str, fn(&str) -> Secret); 2] = [
		("password", |s| Secret::Password(s)),
		("recovery", |s| Secret::RecoveryCode(s)),
	];
	let mut last = Error::Open("no unlock method of this kind");
	for (kind, wrap) in kinds {
		for method in settings.methods.iter().filter(|m| m.kind == kind) {
			match unlock_method(method, wrap(secret_text)) {
				Ok(bundle) => return Ok(bundle),
				Err(e) => last = e,
			}
		}
	}
	Err(last)
}

fn unlock_method(method: &UnlockMethod, secret: Secret) -> Result<Zeroizing<Vec<u8>>, Error> {
	let salt = decode(&method.salt)?;
	let kek = match (&secret, method.kind.as_str()) {
		(Secret::Password(p), "password") => {
			let core = to_core_method(method);
			gorani_formats::unlock::password_kek(p, &salt, &core).map_err(|e| Error::Open(match e { gorani_formats::Error::Open(w) => w, _ => "kek" }))?
		}
		(Secret::RecoveryCode(c), "recovery") => gorani_formats::unlock::recovery_kek(c, &salt),
		_ => return Err(Error::Open("this method needs another kind of secret")),
	};
	gorani_formats::formats::unwrap_private_key(&kek, &method.wrapped).map_err(|_| Error::Open("wrong password or key"))
}

/// The settings' method shape maps 1:1 onto the formats crate's.
fn to_core_method(m: &UnlockMethod) -> UnlockMethod {
	m.clone()
}

/// Enrol this machine: the root must open once with a typed secret (or the
/// guardian code), then the device's own wrapped copy lands on the server.
pub fn enrol(profile: &mut DeviceProfile, device_name: &str, secret_text: &str, protection: &str) -> Result<Session, Error> {
	let client = api::Client::new(profile.clone());
	let settings = client.vault()?;
	let root = unlock_root(&settings, secret_text)?;
	let key_id = settings.key_id.clone();
	let mut salt = [0u8; 16];
	rand_core::OsRng.fill_bytes(&mut salt);
	// The device secret on the CLI is generated and stored in the profile
	// (platform shells replace this with TPM/Enclave-backed secrets).
	let device_secret = profile_device_secret(profile)?;
	let copy = gorani_formats::unlock::make_device_copy(&root, &device_secret);
	let (device_id, token) = client.enrol(device_name, std::env::consts::OS, &key_id, &copy.wrapped, &copy.salt, protection)?;
	profile.device_id = device_id;
	profile.token = token;
	Ok(Session { settings, root })
}

/// The device secret: 32 random bytes persisted in the profile (dev CLI).
/// Platform shells: a TPM signature behind Windows Hello, a Secure Enclave
/// agreement, a keyring + TPM pair — docs/DESKTOP.md.
fn profile_device_secret(profile: &mut DeviceProfile) -> Result<Zeroizing<Vec<u8>>, Error> {
	if let Some(hex_secret) = &profile.device_secret {
		if hex_secret.len() == 64 {
			return Ok(Zeroizing::new(decode_hex(hex_secret)?));
		}
	}
	let mut s = Zeroizing::new(vec![0u8; 32]);
	rand_core::OsRng.fill_bytes(s.as_mut_slice());
	profile.device_secret = Some(hex_of(&s));
	Ok(s)
}

fn hex_of(b: &[u8]) -> String {
	b.iter().map(|x| format!("{x:02x}")).collect()
}

fn decode_hex(s: &str) -> Result<Vec<u8>, Error> {
	(0..s.len() / 2)
		.map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16))
		.collect::<Result<Vec<u8>, _>>()
		.map_err(|_| Error::Format("bad device secret hex"))
}

/// Persist the profile (the CLI writes it; shells use their key stores).
///
/// The file holds the device token AND the device secret — together with
/// the server's wrapped copy, the root. So (commit 23): owner-only
/// permissions from the first byte (0600 at creation, not a chmod after a
/// world-readable write), and an atomic rename so a crash never leaves a
/// half-written profile.
pub fn save_profile(path: &std::path::Path, profile: &DeviceProfile) -> Result<(), Error> {
	use std::io::Write;
	let bytes = serde_json::to_vec_pretty(profile).map_err(|e| Error::Config(e.to_string()))?;
	let tmp = path.with_extension("tmp");
	let mut opts = std::fs::OpenOptions::new();
	opts.write(true).create(true).truncate(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		opts.mode(0o600);
	}
	let mut f = opts.open(&tmp)?;
	f.write_all(&bytes)?;
	f.sync_all()?;
	std::fs::rename(&tmp, path)?;
	Ok(())
}

pub fn load_profile(path: &std::path::Path) -> Result<DeviceProfile, Error> {
	let bytes = std::fs::read(path)?;
	serde_json::from_slice(&bytes).map_err(|e| Error::Config(format!("profile: {e}")))
}