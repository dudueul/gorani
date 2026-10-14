// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare's desktop core (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

//! The session: opening the vault on a native machine. The unlock secret is
//! presented by the person (password / recovery code — the passkey path
//! lives in the platform shells, which own WebAuthn), the root bundle is
//! unwrapped and held in `Zeroizing` for the command's lifetime.

use gorani_formats::unlock::{Secret, UnlockMethod};
use zeroize::Zeroizing;

use crate::{api, decode, devicekey, DeviceProfile, Error, Session};

/// Open the vault with a typed password or recovery code.
pub fn unlock(profile: &DeviceProfile, secret_text: &str) -> Result<Session, Error> {
	let client = api::Client::new(profile.clone());
	let settings = client.vault()?;
	let root = unlock_root(&settings, secret_text)?;
	Ok(Session { settings, root })
}

/// Whether this profile can unlock on its own: an enrolled device (id +
/// token) and somewhere its secret lives — protectors (commit 34), or the
/// in-file secret of an older or dev profile.
pub fn has_device_copy(profile: &DeviceProfile) -> bool {
	!profile.device_id.is_empty() && !profile.token.is_empty() && (legacy_secret(profile).is_some() || !profile.device_protectors.is_empty() || !profile.pending_protectors.is_empty())
}

fn legacy_secret(profile: &DeviceProfile) -> Option<&str> {
	profile.device_secret.as_deref().filter(|s| s.len() == 64)
}

/// Which of a profile's secrets opened the server's copy.
#[derive(Debug, PartialEq)]
enum Opened {
	Current,
	Pending,
}

/// Open the server's wrapped copy with this profile's device secret: the
/// current one, then — if a `protect` run died after the server took its
/// new copy — the pending one. A protector that cannot give its part (no
/// TPM, a locked keyring) is reported as such, not as "wrong key".
fn open_copy(profile: &DeviceProfile, wrapped: &str, salt: &str) -> Result<(Zeroizing<Vec<u8>>, Opened), Error> {
	let mut first_error = None;
	let current = match legacy_secret(profile) {
		Some(hex) => Some(decode_hex(hex).map(Zeroizing::new)),
		None if !profile.device_protectors.is_empty() => Some(devicekey::open(&profile.device_protectors).map(|s| Zeroizing::new(s.to_vec()))),
		None => None,
	};
	let pending = (!profile.pending_protectors.is_empty()).then(|| devicekey::open(&profile.pending_protectors).map(|s| Zeroizing::new(s.to_vec())));
	for (which, secret) in [(Opened::Current, current), (Opened::Pending, pending)] {
		match secret {
			Some(Ok(secret)) => match gorani_formats::unlock::open_device_copy(wrapped, salt, &secret) {
				Ok(root) => return Ok((root, which)),
				Err(_) => {
					first_error.get_or_insert(Error::Open("this computer's copy of the root does not open with its device secret"));
				}
			},
			Some(Err(e)) => {
				first_error.get_or_insert(e);
			}
			None => {}
		}
	}
	Err(first_error.unwrap_or(Error::Config("this profile holds no device secret".into())))
}

/// Open the vault with THIS computer's copy (docs/DESKTOP.md › Security
/// model): the server releases the wrapped root only to the device's token,
/// and only the device secret — from this machine's TPM and/or the user's
/// login keyring (devicekey.rs) — opens it. Neither half alone is the root.
/// (Until commit 33d the client asked for a typed secret every time; its
/// unlock call also dropped the salt.)
pub fn unlock_device(profile: &DeviceProfile) -> Result<Session, Error> {
	let client = api::Client::new(profile.clone());
	let (key_id, wrapped, salt, settings) = client.unlock(&profile.device_id, &profile.token)?;
	let (root, _) = open_copy(profile, &wrapped, &salt)?;
	check_root(&root, &key_id, &settings)?;
	Ok(Session { settings, root })
}

/// The copy must be of THIS vault's root (a stale copy after a rotation
/// opens, and would then fail on every record — say so here instead).
fn check_root(root: &[u8], key_id: &str, settings: &api::VaultSettings) -> Result<(), Error> {
	let opened = gorani_formats::formats::VaultPrivateKey::from_bytes(root).map_err(|_| Error::Open("root bundle"))?;
	if gorani_formats::formats::key_id(&gorani_formats::formats::public_of(&opened)) != settings.key_id || key_id != settings.key_id {
		return Err(Error::Open("this computer's copy is of another root (rotated since?) — enrol it again"));
	}
	Ok(())
}

/// Move this computer's device secret to new protectors (`gorani-sync
/// protect`, commit 34) — e.g. out of the profile file into the TPM and
/// the keyring — without enrolling again:
///
/// ```text
/// 1. open the server's copy with the secret the profile has now
/// 2. make the new protectors (fresh parts → a new device secret)
/// 3. write them into the profile as PENDING          ← a crash here: the old copy still opens
/// 4. re-wrap the root under the new secret; the server replaces its copy
/// 5. promote them, drop the old secret, forget its keyring items
///                                                     ← a crash before 5: the pending set opens
/// ```
///
/// Returns the new protection label (also recorded by the server).
pub fn protect(path: &std::path::Path, profile: &mut DeviceProfile, want: devicekey::Want) -> Result<String, Error> {
	let client = api::Client::new(profile.clone());
	let (key_id, wrapped, salt, settings) = client.unlock(&profile.device_id, &profile.token)?;
	let (root, which) = open_copy(profile, &wrapped, &salt)?;
	check_root(&root, &key_id, &settings)?;
	if which == Opened::Pending {
		// A run that died after step 4: finish it before starting this one.
		let old = std::mem::take(&mut profile.device_protectors);
		profile.device_protectors = std::mem::take(&mut profile.pending_protectors);
		profile.device_secret = None;
		save_profile(path, profile)?;
		devicekey::forget(&old);
	} else if !profile.pending_protectors.is_empty() {
		// A run that died before step 4: its parts were never used.
		devicekey::forget(&std::mem::take(&mut profile.pending_protectors));
	}
	let (fresh, secret) = devicekey::create(want, &keyring_label(profile))?;
	let label = devicekey::label(&fresh);
	profile.pending_protectors = fresh;
	save_profile(path, profile)?;
	let copy = gorani_formats::unlock::make_device_copy(&root, &secret[..]);
	if let Err(e) = client.rekey(&profile.device_id, &profile.token, &settings.key_id, &copy.wrapped, &copy.salt, &label) {
		devicekey::forget(&std::mem::take(&mut profile.pending_protectors));
		save_profile(path, profile)?;
		return Err(e);
	}
	let old = std::mem::replace(&mut profile.device_protectors, std::mem::take(&mut profile.pending_protectors));
	profile.device_secret = None;
	save_profile(path, profile)?;
	devicekey::forget(&old);
	Ok(label)
}

/// What the keyring item is called (what a person sees in Seahorse or
/// KWallet): the product and the server — nothing about the vault.
fn keyring_label(profile: &DeviceProfile) -> String {
	format!("gorani device secret part ({})", profile.server.trim_end_matches('/'))
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

/// Enrol this machine: the root must open once with a typed secret, then
/// the device's own wrapped copy lands on the server, under a device
/// secret whose parts `want` puts in the TPM and/or the keyring (commit 34).
/// A profile that already carries `device_secret` (`--device-secret`, dev
/// and CI) keeps it, protected by nothing but the file.
pub fn enrol(profile: &mut DeviceProfile, device_name: &str, secret_text: &str, want: devicekey::Want) -> Result<Session, Error> {
	let client = api::Client::new(profile.clone());
	let settings = client.vault()?;
	let root = unlock_root(&settings, secret_text)?;
	let key_id = settings.key_id.clone();
	let (device_secret, protection): (Zeroizing<Vec<u8>>, String) = match legacy_secret(profile) {
		Some(hex) => (Zeroizing::new(decode_hex(hex)?), "file".into()),
		None => {
			let (protectors, secret) = devicekey::create(want, &keyring_label(profile))?;
			let label = devicekey::label(&protectors);
			profile.device_protectors = protectors;
			(Zeroizing::new(secret.to_vec()), label)
		}
	};
	let copy = gorani_formats::unlock::make_device_copy(&root, &device_secret);
	match client.enrol(device_name, std::env::consts::OS, &key_id, &copy.wrapped, &copy.salt, &protection) {
		Ok((device_id, token)) => {
			profile.device_id = device_id;
			profile.token = token;
		}
		Err(e) => {
			// The parts made for an enrolment that did not happen go again.
			devicekey::forget(&std::mem::take(&mut profile.device_protectors));
			return Err(e);
		}
	}
	Ok(Session { settings, root })
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