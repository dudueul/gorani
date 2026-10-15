// Copyright 2026- Seongwoo Hong. All rights reserved.

//! macOS' protectors (commit 39d, docs/DESKTOP.md › 39d): the same words as
//! Linux and Windows, held by the Mac's own stores.
//!
//! | word | store | the profile keeps | what opens it |
//! |---|---|---|---|
//! | `enclave` | a P-256 key made IN the **Secure Enclave** (CryptoKit); the part is agreed (ECDH, then HKDF) between it and a peer key whose private half is thrown away at once | the key's encrypted representation (only this Mac's enclave can use it), the peer's public key | this Mac's enclave |
//! | `presence` | the same, the key made to ask for Touch ID or the password at each use | the same | this Mac's enclave and a person |
//! | `keychain` (`keyring`) | a generic password in the **login Keychain** | a random item reference | this user's unlocked login |
//!
//! CryptoKit is Swift's, so the work is a small Swift helper's —
//! `gorani-keystore` (clients/macos/GoraniKit), installed beside this
//! program — spoken to as Linux's TPM is: parts cross only pipes, never
//! argv or a file. (The clevis approach again: the platform's own code doing
//! the talking, none of it linked into the client.)
//!
//! A debug build of the helper can stand in a software key for the
//! enclave, for tests on machines without one (CI's virtual Macs); its keys
//! say so (`software:`), and this client refuses them outside its tests.

use super::*;

#[derive(serde::Deserialize)]
struct Probe {
	enclave: bool,
	keychain: bool,
}

#[derive(serde::Deserialize)]
struct Sealed {
	key: String,
	peer: String,
	part: String,
}

/// The helper: `GORANI_KEYSTORE`, else beside this program, else on PATH.
fn helper() -> String {
	if let Ok(p) = std::env::var("GORANI_KEYSTORE") {
		return p;
	}
	if let Some(p) = std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join("gorani-keystore"))).filter(|p| p.is_file()) {
		return p.to_string_lossy().into_owned();
	}
	"gorani-keystore".into()
}

fn ask(args: &[&str], input: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>, Error> {
	run(&helper(), args, input, None)
}

fn probe() -> Result<Probe, Error> {
	let out = ask(&["probe"], None)?;
	serde_json::from_slice(&out).map_err(|_| Error::Format("gorani-keystore answered something that is not its probe"))
}

/// Refuse the tests' stand-in anywhere but the tests.
fn real(key: &str) -> Result<(), Error> {
	if key.starts_with("software:") && !cfg!(test) {
		return Err(Error::Config("this enclave part was made by a test build's software stand-in, not the Secure Enclave — protect this Mac again".into()));
	}
	Ok(())
}

pub fn auto() -> Result<u8, Error> {
	let p = probe().map_err(|e| Error::Config(format!("gorani-keystore (the Secure Enclave and Keychain helper, installed beside gorani-sync) did not answer — {e}. Install it, or pass --protect file to keep the secret in the profile — then anyone who copies the profile, with the member's sign-in, can open this computer's copy")))?;
	match (p.enclave, p.keychain) {
		(true, true) => Ok(Want::HARDWARE | Want::LOGIN),
		(true, false) => Ok(Want::HARDWARE),
		(false, true) => Ok(Want::LOGIN),
		(false, false) => Err(Error::Config("this Mac offers neither a Secure Enclave nor an unlocked login Keychain — pass --protect file to keep the secret in the profile (anyone who copies it, with the member's sign-in, can then open this computer's copy)".into())),
	}
}

pub fn hardware(_: &TpmOptions) -> Result<(Protector, Zeroizing<[u8; 32]>), Error> {
	enclave::seal(false)
}

pub fn presence(_: &str) -> Result<(Protector, Zeroizing<[u8; 32]>), Error> {
	enclave::seal(true)
}

pub fn login(label_text: &str) -> Result<(Protector, Zeroizing<[u8; 32]>), Error> {
	let part = random_part();
	Ok((keychain::store(&part, label_text)?, part))
}

pub fn open(p: &Protector) -> Result<Zeroizing<[u8; 32]>, Error> {
	match p {
		Protector::Enclave { key, peer, .. } => enclave::open(key, peer),
		Protector::Keychain { item } => keychain::lookup(item),
		other => Err(elsewhere(other)),
	}
}

pub fn forget(p: &Protector) {
	// (An enclave key exists only as the representation in the profile:
	// dropping it is enough.)
	if let Protector::Keychain { item } = p {
		keychain::clear(item);
	}
}

pub mod enclave {
	use super::*;

	pub fn available() -> bool {
		probe().is_ok_and(|p| p.enclave)
	}

	pub fn seal(presence: bool) -> Result<(Protector, Zeroizing<[u8; 32]>), Error> {
		let args: &[&str] = if presence { &["enclave-seal", "--presence"] } else { &["enclave-seal"] };
		let out = ask(args, None)?;
		let s: Sealed = serde_json::from_slice(&out).map_err(|_| Error::Format("gorani-keystore's sealed part is not what it should be"))?;
		real(&s.key)?;
		let part = hex32(&s.part).ok_or(Error::Format("gorani-keystore's part is not 32 bytes of hex"))?;
		Ok((Protector::Enclave { key: s.key, peer: s.peer, presence }, part))
	}

	pub fn open(key: &str, peer: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
		real(key)?;
		let request = Zeroizing::new(serde_json::json!({ "key": key, "peer": peer }).to_string());
		let out = ask(&["enclave-open"], Some(request.as_bytes())).map_err(|e| Error::Config(format!("the Secure Enclave did not give this Mac's part — another Mac, or a cancelled prompt? ({e})")))?;
		let v: serde_json::Value = serde_json::from_slice(&out).map_err(|_| Error::Format("gorani-keystore's answer is not JSON"))?;
		v["part"].as_str().and_then(hex32).ok_or(Error::Format("gorani-keystore's part is not 32 bytes of hex"))
	}
}

/// The login Keychain: a generic password (service `io.gorani.device`), by
/// a random reference — nothing in it names the vault.
pub mod keychain {
	use super::*;

	pub fn available() -> bool {
		probe().is_ok_and(|p| p.keychain)
	}

	pub fn store(part: &[u8; 32], label_text: &str) -> Result<Protector, Error> {
		let mut r = [0u8; 16];
		rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut r);
		let item = crate::transfer::hex(&r);
		let hex = Zeroizing::new(crate::transfer::hex(&part[..]));
		ask(&["keychain-store", &item, label_text], Some(hex.as_bytes()))?;
		Ok(Protector::Keychain { item })
	}

	pub fn lookup(item: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
		let out = ask(&["keychain-lookup", item], None).map_err(|e| Error::Config(format!("the login Keychain did not give this Mac's part — is the login unlocked? ({e})")))?;
		let text = Zeroizing::new(String::from_utf8_lossy(&out).to_string());
		hex32(&text).ok_or(Error::Open("the login Keychain holds no part for this Mac (cleared, or another login)"))
	}

	pub fn clear(item: &str) {
		let _ = ask(&["keychain-clear", item], None);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// These need the helper built (`swift build --product gorani-keystore`
	// in clients/macos/GoraniKit) and named by GORANI_KEYSTORE — CI's macOS
	// job runs them with `--ignored`, the enclave as the debug build's
	// software stand-in where the Mac has none (GORANI_KEYSTORE_SOFTWARE=1).

	#[test]
	#[ignore]
	fn the_enclave_agrees_the_same_part_again() {
		let (p, part) = enclave::seal(false).unwrap();
		assert_eq!(*open(&p).unwrap(), *part);
		let Protector::Enclave { key, .. } = &p else { unreachable!() };
		if let Ok(again) = enclave::open(key, &P256Peer::new().0) {
			assert_ne!(*again, *part, "another peer, another part");
		}
	}

	#[test]
	#[ignore]
	fn the_keychain_holds_the_part_until_forgotten() {
		let part = random_part();
		let p = keychain::store(&part, "gorani test").unwrap();
		assert_eq!(*open(&p).unwrap(), *part);
		forget(&p);
		assert!(open(&p).is_err(), "cleared with the protector");
	}

	#[test]
	#[ignore]
	fn auto_finds_what_this_mac_has() {
		let set = auto().unwrap();
		assert_eq!(set & Want::PRESENCE, 0, "auto never waits for a person");
		assert_ne!(set, 0);
	}

	#[test]
	fn a_test_stand_in_is_refused_outside_the_tests() {
		assert!(real("software:AAAA").is_ok(), "(in a test build it is allowed)");
		assert!(real("BAAA").is_ok());
	}

	/// A peer public key that is not the sealed one (X9.63, base64).
	struct P256Peer(String);

	impl P256Peer {
		fn new() -> Self {
			use base64::Engine as _;
			let k = p256::SecretKey::random(&mut rand_core::OsRng);
			let pt = p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&k.public_key(), false);
			Self(base64::engine::general_purpose::STANDARD.encode(pt.as_bytes()))
		}
	}
}
