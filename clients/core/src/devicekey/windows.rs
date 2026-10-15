// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Windows' protectors (commit 39d, docs/DESKTOP.md › 39d): the same three
//! words as Linux — the hardware, the login, a person — each held by the
//! store Windows itself trusts, through its own APIs (no tool to install):
//!
//! | word | store | the profile keeps | what opens it |
//! |---|---|---|---|
//! | `tpm` | a 2048-bit RSA key in the **Platform Crypto Provider** — created in the TPM, never exportable; the part is encrypted to it (OAEP-SHA256) | the key's name, the ciphertext | this computer's chip, as this user |
//! | `dpapi` (`keyring`) | **DPAPI**, user scope: a key derived from the user's logon secret | the protected blob | this user's logon, on this computer |
//! | `hello` | a **Windows Hello** key (TPM-backed where there is one); the part is SHA-256 of its signature over a random challenge — RSA PKCS#1 v1.5 signs the same bytes the same way, so the part comes back each time | the key's name, the challenge | a PIN, a face or a finger, each unlock |
//!
//! What each does not do, said where a person reads it (DESKTOP.md):
//! DPAPI's user keys can be recovered by a domain's backup key on a
//! domain-joined computer, and by anyone who knows the user's password
//! with the disk in hand — so `auto` pairs it with the TPM, never trusts it
//! alone where a TPM answers. Hello asks a person, so `auto` never picks it:
//! a shell that starts at sign-in must not wait for a face.
//!
//! Every `unsafe` block here is one call to the platform, its buffers ours
//! and alive for that call.

use std::ffi::c_void;

use super::*;
use base64::Engine as _;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::*;

fn b64(bytes: &[u8]) -> String {
	base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>, Error> {
	base64::engine::general_purpose::STANDARD.decode(s).map_err(|_| Error::Format("a device protector's blob is not base64"))
}

fn part_of(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
	if bytes.len() != 32 {
		return Err(Error::Open("a protector gave back something that is not this computer's part"));
	}
	let mut out = Zeroizing::new([0u8; 32]);
	out.copy_from_slice(bytes);
	Ok(out)
}

fn why(what: &str) -> impl Fn(windows::core::Error) -> Error + '_ {
	move |e| Error::Config(format!("{what}: {} (0x{:08x})", e.message(), e.code().0))
}

// ── the five calls devicekey.rs makes ─────────────────────────────────

pub fn auto() -> Result<u8, Error> {
	// DPAPI is always there; the TPM where its provider opens. (Whether it
	// will make a key is only known by asking — `create` says so aloud and
	// keeps the login part if it will not.)
	Ok(if cng::available(cng::Provider::Tpm) { Want::HARDWARE | Want::LOGIN } else { Want::LOGIN })
}

pub fn hardware(_: &TpmOptions) -> Result<(Protector, Zeroizing<[u8; 32]>), Error> {
	let part = random_part();
	Ok((cng::seal(&part, cng::Provider::Tpm)?, part))
}

pub fn presence(_: &str) -> Result<(Protector, Zeroizing<[u8; 32]>), Error> {
	hello::create()
}

pub fn login(_: &str) -> Result<(Protector, Zeroizing<[u8; 32]>), Error> {
	let part = random_part();
	Ok((dpapi::seal(&part)?, part))
}

pub fn open(p: &Protector) -> Result<Zeroizing<[u8; 32]>, Error> {
	match p {
		Protector::Dpapi { blob } => dpapi::open(blob),
		Protector::Cng { provider, key, wrapped } => cng::open(cng::Provider::from_tag(provider)?, key, wrapped),
		Protector::Hello { key, challenge } => hello::open(key, challenge),
		other => Err(elsewhere(other)),
	}
}

pub fn forget(p: &Protector) {
	match p {
		Protector::Cng { provider, key, .. } => {
			if let Ok(provider) = cng::Provider::from_tag(provider) {
				cng::delete(provider, key);
			}
		}
		Protector::Hello { key, .. } => hello::delete(key),
		// (A DPAPI blob is only data: dropping it from the profile is enough.)
		_ => {}
	}
}

/// DPAPI, user scope: CryptProtectData with an entropy only this client
/// passes (another program running as the user can still ask DPAPI — the
/// same limit as the keyring — but must know to ask for this).
pub mod dpapi {
	use super::*;

	const ENTROPY: &[u8] = b"gorani-device-part-v1";

	fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
		CRYPT_INTEGER_BLOB { cbData: bytes.len() as u32, pbData: bytes.as_ptr() as *mut u8 }
	}

	/// The bytes DPAPI allocated, copied out and freed.
	fn take(out: CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
		// SAFETY: DPAPI wrote `cbData` bytes at `pbData`, ours to free with LocalFree.
		let v = Zeroizing::new(unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec());
		// SAFETY: the allocation DPAPI made, freed once.
		unsafe { LocalFree(Some(HLOCAL(out.pbData as *mut _))) };
		v
	}

	pub fn seal(part: &[u8; 32]) -> Result<Protector, Error> {
		let (input, entropy) = (blob(&part[..]), blob(ENTROPY));
		let mut out = CRYPT_INTEGER_BLOB::default();
		// SAFETY: input and entropy point at live buffers; `out` is written by the call.
		unsafe { CryptProtectData(&input, &HSTRING::from("gorani device part"), Some(&entropy as *const _), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out) }.map_err(why("DPAPI did not protect this computer's part"))?;
		Ok(Protector::Dpapi { blob: b64(&take(out)) })
	}

	pub fn open(text: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
		let sealed = unb64(text)?;
		let (input, entropy) = (blob(&sealed), blob(ENTROPY));
		let mut out = CRYPT_INTEGER_BLOB::default();
		// SAFETY: as in `seal`.
		unsafe { CryptUnprotectData(&input, None, Some(&entropy as *const _), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out) }.map_err(why("DPAPI did not give this computer's part back (another user, another computer, or a reset password)"))?;
		part_of(&take(out))
	}
}

/// A CNG key that never leaves its provider — the TPM's (Platform Crypto
/// Provider) for real use; the software one (its keys DPAPI-protected)
/// only so the same code is tested where a runner has no TPM.
pub mod cng {
	use super::*;

	#[derive(Clone, Copy, Debug, PartialEq)]
	pub enum Provider {
		Tpm,
		Software,
	}

	impl Provider {
		fn name(self) -> PCWSTR {
			match self {
				Provider::Tpm => MS_PLATFORM_CRYPTO_PROVIDER,
				Provider::Software => MS_KEY_STORAGE_PROVIDER,
			}
		}

		pub fn tag(self) -> &'static str {
			match self {
				Provider::Tpm => "tpm",
				Provider::Software => "software",
			}
		}

		pub fn from_tag(s: &str) -> Result<Self, Error> {
			match s {
				"tpm" => Ok(Provider::Tpm),
				"software" => Ok(Provider::Software),
				_ => Err(Error::Format("a CNG protector names a provider this client does not know")),
			}
		}
	}

	struct Prov(NCRYPT_PROV_HANDLE);

	impl Drop for Prov {
		fn drop(&mut self) {
			// SAFETY: a handle we opened, freed once.
			let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(self.0 .0)) };
		}
	}

	/// A key, and the provider it came from (freed after it: fields drop
	/// after `drop`).
	struct Key {
		h: NCRYPT_KEY_HANDLE,
		_prov: Prov,
		/// NCryptDeleteKey frees the handle itself.
		deleted: bool,
	}

	impl Drop for Key {
		fn drop(&mut self) {
			if !self.deleted {
				// SAFETY: as above.
				let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(self.h.0)) };
			}
		}
	}

	fn provider(p: Provider) -> Result<Prov, Error> {
		let mut h = NCRYPT_PROV_HANDLE::default();
		// SAFETY: `h` is written by the call.
		unsafe { NCryptOpenStorageProvider(&mut h, p.name(), 0) }.map_err(why(match p {
			Provider::Tpm => "this computer's TPM did not answer (none, disabled in the firmware, or TPM 1.2)",
			Provider::Software => "the software key provider did not open",
		}))?;
		Ok(Prov(h))
	}

	pub fn available(p: Provider) -> bool {
		provider(p).is_ok()
	}

	/// OAEP with SHA-256, no label.
	fn padding() -> BCRYPT_OAEP_PADDING_INFO {
		BCRYPT_OAEP_PADDING_INFO { pszAlgId: BCRYPT_SHA256_ALGORITHM, pbLabel: std::ptr::null_mut(), cbLabel: 0 }
	}

	pub fn seal(part: &[u8; 32], p: Provider) -> Result<Protector, Error> {
		let prov = provider(p)?;
		let name = format!("gorani-device-{}", crate::new_item_id());
		let mut h = NCRYPT_KEY_HANDLE::default();
		// SAFETY: `h` is written by the call; the strings outlive it.
		unsafe { NCryptCreatePersistedKey(prov.0, &mut h, BCRYPT_RSA_ALGORITHM, &HSTRING::from(name.as_str()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)) }.map_err(why("the key store did not make a key"))?;
		let key = Key { h, _prov: prov, deleted: false };
		// SAFETY: a property of the key we hold, from a live buffer.
		unsafe { NCryptSetProperty(NCRYPT_HANDLE(key.h.0), NCRYPT_LENGTH_PROPERTY, &2048u32.to_le_bytes(), NCRYPT_FLAGS(0)) }.map_err(why("the key store refused a 2048-bit key"))?;
		if p == Provider::Software {
			// (The software provider's default already; said, not assumed. A
			// TPM key cannot be exported at all.)
			// SAFETY: as above.
			unsafe { NCryptSetProperty(NCRYPT_HANDLE(key.h.0), NCRYPT_EXPORT_POLICY_PROPERTY, &0u32.to_le_bytes(), NCRYPT_FLAGS(0)) }.map_err(why("the key store refused a non-exportable key"))?;
		}
		// SAFETY: the key we hold. (A TPM makes an RSA key in a few seconds.)
		unsafe { NCryptFinalizeKey(key.h, NCRYPT_SILENT_FLAG) }.map_err(why("the key store did not finish the key"))?;
		let pad = padding();
		let mut size = 0u32;
		// SAFETY: a size query — no output buffer.
		unsafe { NCryptEncrypt(key.h, Some(&part[..]), Some(&pad as *const _ as *const c_void), None, &mut size, NCRYPT_PAD_OAEP_FLAG) }.map_err(why("the key would not encrypt"))?;
		let mut wrapped = vec![0u8; size as usize];
		// SAFETY: an output buffer of the size just asked for.
		unsafe { NCryptEncrypt(key.h, Some(&part[..]), Some(&pad as *const _ as *const c_void), Some(&mut wrapped), &mut size, NCRYPT_PAD_OAEP_FLAG) }.map_err(why("the key would not encrypt"))?;
		wrapped.truncate(size as usize);
		Ok(Protector::Cng { provider: p.tag().into(), key: name, wrapped: b64(&wrapped) })
	}

	fn key(p: Provider, name: &str) -> Result<Key, Error> {
		let prov = provider(p)?;
		let mut h = NCRYPT_KEY_HANDLE::default();
		// SAFETY: `h` is written by the call.
		unsafe { NCryptOpenKey(prov.0, &mut h, &HSTRING::from(name), CERT_KEY_SPEC(0), NCRYPT_SILENT_FLAG) }.map_err(why("this computer's key for the part is gone (another user, another computer, or the TPM was cleared)"))?;
		Ok(Key { h, _prov: prov, deleted: false })
	}

	pub fn open(p: Provider, name: &str, wrapped: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
		let k = key(p, name)?;
		let wrapped = unb64(wrapped)?;
		let pad = padding();
		let mut out = Zeroizing::new(vec![0u8; 512]);
		let mut size = 0u32;
		// SAFETY: input and output are live buffers; the key is ours.
		unsafe { NCryptDecrypt(k.h, Some(&wrapped), Some(&pad as *const _ as *const c_void), Some(&mut out[..]), &mut size, NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG) }.map_err(why("the key did not give this computer's part back"))?;
		part_of(&out[..size as usize])
	}

	/// Delete the key (forgetting a protector; a test's cleanup).
	pub fn delete(p: Provider, name: &str) {
		if let Ok(mut k) = key(p, name) {
			// SAFETY: a key we hold; on success its handle is freed by the call.
			if unsafe { NCryptDeleteKey(k.h, 0) }.is_ok() {
				k.deleted = true;
			}
		}
	}
}

/// Windows Hello: KeyCredentialManager — a key per profile, its signature
/// over the stored challenge the part's source. Asking for it shows the
/// system's own Hello prompt.
pub mod hello {
	use super::*;
	use sha2::Digest;
	use windows::Security::Credentials::{KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus};
	use windows::Security::Cryptography::CryptographicBuffer;

	pub fn available() -> bool {
		KeyCredentialManager::IsSupportedAsync().and_then(|op| op.get()).unwrap_or(false)
	}

	fn status(s: windows::core::Result<KeyCredentialStatus>, what: &str) -> Result<(), Error> {
		match s.map_err(why(what))? {
			KeyCredentialStatus::Success => Ok(()),
			KeyCredentialStatus::UserCanceled => Err(Error::Config(format!("{what}: cancelled at the Windows Hello prompt"))),
			KeyCredentialStatus::NotFound => Err(Error::Config(format!("{what}: this computer's Hello key is gone (Hello was reset, or another user)"))),
			KeyCredentialStatus::SecurityDeviceLocked => Err(Error::Config(format!("{what}: the security device is locked after too many tries — wait, then try again"))),
			other => Err(Error::Config(format!("{what}: Windows Hello answered {other:?}"))),
		}
	}

	fn part(credential: &KeyCredential, challenge: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
		let data = CryptographicBuffer::CreateFromByteArray(challenge).map_err(why("a buffer for Hello"))?;
		let signed = credential.RequestSignAsync(&data).and_then(|op| op.get()).map_err(why("Windows Hello did not sign"))?;
		status(signed.Status(), "Windows Hello did not sign")?;
		let mut sig = windows::core::Array::<u8>::new();
		CryptographicBuffer::CopyToByteArray(&signed.Result().map_err(why("Windows Hello's signature"))?, &mut sig).map_err(why("Windows Hello's signature"))?;
		let mut h = sha2::Sha256::new();
		h.update(b"gorani-hello-part-v1");
		h.update(&sig[..]);
		let mut out = Zeroizing::new([0u8; 32]);
		out.copy_from_slice(&h.finalize());
		Ok(out)
	}

	pub fn create() -> Result<(Protector, Zeroizing<[u8; 32]>), Error> {
		if !available() {
			return Err(Error::Config("Windows Hello is not set up for this user (Settings › Accounts › Sign-in options: a PIN, a face or a finger) — set it up, or protect with tpm+keyring".into()));
		}
		let name = format!("gorani-device-{}", crate::new_item_id());
		let made = KeyCredentialManager::RequestCreateAsync(&HSTRING::from(name.as_str()), KeyCredentialCreationOption::FailIfExists).and_then(|op| op.get()).map_err(why("Windows Hello did not make a key"))?;
		status(made.Status(), "Windows Hello did not make a key")?;
		let credential = made.Credential().map_err(why("Windows Hello's new key"))?;
		let challenge = random_part();
		let first = part(&credential, &challenge[..])?;
		// Asked twice at setup, on purpose: a part that did not come back
		// the same would lock this computer out at its next unlock.
		let again = part(&credential, &challenge[..])?;
		if *first != *again {
			delete(&name);
			return Err(Error::Config("this computer's Windows Hello does not sign the same bytes the same way — it cannot hold a part; protect with tpm+keyring".into()));
		}
		Ok((Protector::Hello { key: name, challenge: b64(&challenge[..]) }, first))
	}

	pub fn open(name: &str, challenge: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
		let found = KeyCredentialManager::OpenAsync(&HSTRING::from(name)).and_then(|op| op.get()).map_err(why("Windows Hello"))?;
		status(found.Status(), "Windows Hello")?;
		part(&found.Credential().map_err(why("Windows Hello's key"))?, &unb64(challenge)?)
	}

	pub fn delete(name: &str) {
		let _ = KeyCredentialManager::DeleteAsync(&HSTRING::from(name)).and_then(|op| op.get());
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn dpapi_gives_the_part_back_and_nothing_for_a_changed_blob() {
		let part = random_part();
		let p = dpapi::seal(&part).unwrap();
		assert_eq!(*open(&p).unwrap(), *part);
		let Protector::Dpapi { blob } = &p else { unreachable!() };
		let mut bytes = unb64(blob).unwrap();
		let at = bytes.len() - 5;
		bytes[at] ^= 1;
		assert!(open(&Protector::Dpapi { blob: b64(&bytes) }).is_err(), "a changed blob opens nothing");
	}

	#[test]
	fn a_cng_key_holds_the_part_and_forgetting_deletes_it() {
		// The software provider: the same calls the TPM's takes, where a
		// runner has no TPM.
		let part = random_part();
		let p = cng::seal(&part, cng::Provider::Software).unwrap();
		assert_eq!(label(std::slice::from_ref(&p)), "cng[software]");
		assert_eq!(*open(&p).unwrap(), *part);
		forget(&p);
		assert!(open(&p).is_err(), "the key is gone with the protector");
	}

	#[test]
	fn the_tpm_where_the_runner_has_one() {
		// (Hosted runners may have no TPM: then only that it says why.)
		if !cng::available(cng::Provider::Tpm) {
			eprintln!("no TPM on this machine: {}", hardware(&TpmOptions::default()).err().map(|e| e.to_string()).unwrap_or_default());
			return;
		}
		match hardware(&TpmOptions::default()) {
			Ok((p, part)) => {
				assert_eq!(label(std::slice::from_ref(&p)), "tpm");
				assert_eq!(*open(&p).unwrap(), *part);
				forget(&p);
			}
			Err(e) => eprintln!("the TPM's provider opened but made no key: {e}"),
		}
	}

	#[test]
	fn hello_where_it_is_not_set_up_says_how() {
		if hello::available() {
			eprintln!("Windows Hello is set up here — not exercised: it would wait for a person");
			return;
		}
		let e = presence("test").map(|_| ()).expect_err("no Hello, no part").to_string();
		assert!(e.contains("Sign-in options"), "{e}");
	}

	#[test]
	fn auto_never_asks_a_person() {
		let set = auto().unwrap();
		assert_eq!(set & Want::PRESENCE, 0);
		assert_ne!(set & Want::LOGIN, 0, "DPAPI is always there");
	}
}
