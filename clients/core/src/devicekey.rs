// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Where this computer's device secret lives (commit 34, docs/DESKTOP.md ›
//! Security model). The device secret is the input to the KEK that opens
//! the server's wrapped copy of the root:
//!
//! ```text
//! KEK  = HKDF-SHA256(device secret, salt, "gorani-device-v1")      (formats::unlock::device_kek)
//! root = open(GW01 copy the server releases only to this device's token, KEK)
//! ```
//!
//! So the secret must never sit next to the token in a file anyone can copy.
//! Until this commit it did: 32 random bytes as hex in the profile JSON
//! (0600, but a backup, a stolen disk or any program running as the user
//! copies it). Now it is made of **parts**, each held by a protector, and
//! the profile keeps only what is useless without them:
//!
//! | protector | holds the part | the profile keeps | a copy of the profile alone |
//! |---|---|---|---|
//! | `tpm`     | sealed by this machine's TPM 2.0 (the chip's storage key, never exported) | the sealed blobs | cannot be unsealed on any other chip |
//! | `keyring` | in the user's login keyring (Secret Service — GNOME Keyring, KWallet), encrypted under their login | a random item reference | holds nothing |
//! | `file`    | as hex in the profile — dev and CI only, chosen explicitly | the part itself | is the part |
//!
//! ```text
//! device secret = HKDF-SHA256(salt "gorani-device-parts-v1", ikm = part₁ ‖ part₂ …, info = kinds)
//! ```
//!
//! With `tpm+keyring` (the default where both exist) a thief needs this
//! machine's chip AND the user's unlocked login session.
//!
//! **What this does not do** — the same limit the browser has: while the
//! vault is open, the root is in this process's memory, and code running
//! as the user can ask the TPM and the keyring exactly as this client does.
//! Protectors defeat copies (backups, a stolen disk, the profile file) and
//! bind unlocking to this machine and this login; they do not stop malware
//! already running in the session. Revoking the device (`gorani-sync revoke`
//! from any other computer — the web app has no devices screen yet) deletes
//! the server's copy — then no part opens anything.
//!
//! Mechanism: the TPM through `tpm2-tools` and the keyring through
//! `secret-tool` (libsecret), as subprocesses — the clevis approach: no C
//! library linked into the client, the platform's own audited tools doing
//! the talking. Secrets cross only pipes (stdin/stdout), never argv or a
//! file; the TPM's working files (contexts and the sealed blobs, all
//! encrypted by the chip) go to a private 0700 directory removed after.

use std::io::Write;
use std::process::{Command, Stdio};

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::Error;

/// One part of the device secret and where it is held.
#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Protector {
	/// Sealed by the TPM: TPM2B_PUBLIC and TPM2B_PRIVATE (base64), the
	/// latter encrypted under the chip's storage key.
	Tpm { public: String, private: String },
	/// An item in the login keyring, found by this reference.
	Keyring { item: String },
	/// The part itself, in the clear (dev and CI only).
	File { part: String },
}

impl Protector {
	pub fn kind(&self) -> &'static str {
		match self {
			Protector::Tpm { .. } => "tpm",
			Protector::Keyring { .. } => "keyring",
			Protector::File { .. } => "file",
		}
	}
}

/// What a person asks for at setup (`--protect`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Want {
	/// Everything this machine has: the TPM and the keyring where both
	/// answer, either alone otherwise — and an error, not a silent file,
	/// where neither does.
	Auto,
	Tpm,
	Keyring,
	TpmKeyring,
	File,
}

impl std::str::FromStr for Want {
	type Err = Error;
	fn from_str(s: &str) -> Result<Self, Error> {
		Ok(match s {
			"auto" => Want::Auto,
			"tpm" => Want::Tpm,
			"keyring" => Want::Keyring,
			"tpm+keyring" | "keyring+tpm" => Want::TpmKeyring,
			"file" => Want::File,
			other => return Err(Error::Config(format!("--protect {other}: one of auto, tpm, keyring, tpm+keyring, file"))),
		})
	}
}

/// The label the server records for the device (its `protection`): the
/// kinds, joined. The client's word — shown to the member and their leads,
/// not attested (a TPM attestation of the sealing key is future work).
pub fn label(protectors: &[Protector]) -> String {
	protectors.iter().map(Protector::kind).collect::<Vec<_>>().join("+")
}

/// Combine parts into the device secret.
fn combine(parts: &[(&'static str, Zeroizing<[u8; 32]>)]) -> Zeroizing<[u8; 32]> {
	let mut ikm = Zeroizing::new(Vec::with_capacity(32 * parts.len()));
	for (_, p) in parts {
		ikm.extend_from_slice(&p[..]);
	}
	let info = parts.iter().map(|(k, _)| *k).collect::<Vec<_>>().join("+");
	let mut out = Zeroizing::new([0u8; 32]);
	Hkdf::<Sha256>::new(Some(b"gorani-device-parts-v1"), &ikm).expand(info.as_bytes(), &mut out[..]).expect("32 bytes is a valid HKDF length");
	out
}

/// Make the protectors `want` names (each with a fresh random part) and
/// the device secret they give. Nothing is written but into the TPM blobs
/// returned and the keyring.
pub fn create(want: Want, label_text: &str) -> Result<(Vec<Protector>, Zeroizing<[u8; 32]>), Error> {
	let kinds: Vec<&'static str> = match want {
		Want::Tpm => vec!["tpm"],
		Want::Keyring => vec!["keyring"],
		Want::TpmKeyring => vec!["tpm", "keyring"],
		Want::File => vec!["file"],
		Want::Auto => {
			let (tpm, keyring) = (tpm::available(), keyring::available());
			match (tpm, keyring) {
				(true, true) => vec!["tpm", "keyring"],
				(true, false) => vec!["tpm"],
				(false, true) => vec!["keyring"],
				(false, false) => {
					return Err(Error::Config(
						"this machine offers neither a TPM (tpm2-tools and /dev/tpmrm0 — the user must be in the `tss` group) nor a login keyring (secret-tool and a Secret Service such as GNOME Keyring). Install one, or pass --protect file to keep the secret in the profile — then anyone who copies the profile, with the member's sign-in, can open this computer's copy".into(),
					))
				}
			}
		}
	};
	let mut protectors = Vec::new();
	let mut parts = Vec::new();
	for kind in kinds {
		let mut part = Zeroizing::new([0u8; 32]);
		rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut part[..]);
		let p = match kind {
			"tpm" => tpm::seal(&part)?,
			"keyring" => keyring::store(&part, label_text)?,
			_ => Protector::File { part: crate::transfer::hex(&part[..]) },
		};
		protectors.push(p);
		parts.push((kind, part));
	}
	Ok((protectors, combine(&parts)))
}

/// The device secret, from its protectors — each asked for its part.
pub fn open(protectors: &[Protector]) -> Result<Zeroizing<[u8; 32]>, Error> {
	if protectors.is_empty() {
		return Err(Error::Config("this profile has no device protectors".into()));
	}
	let mut parts = Vec::new();
	for p in protectors {
		let part = match p {
			Protector::Tpm { public, private } => tpm::unseal(public, private)?,
			Protector::Keyring { item } => keyring::lookup(item)?,
			Protector::File { part } => hex32(part).ok_or(Error::Format("a file protector's part is not 32 bytes of hex"))?,
		};
		parts.push((p.kind(), part));
	}
	Ok(combine(&parts))
}

/// Remove what the protectors hold outside the profile (keyring items; a
/// TPM blob is only data — dropping it from the profile is enough).
pub fn forget(protectors: &[Protector]) {
	for p in protectors {
		if let Protector::Keyring { item } = p {
			keyring::clear(item);
		}
	}
}

fn hex32(s: &str) -> Option<Zeroizing<[u8; 32]>> {
	let s = s.trim();
	if s.len() != 64 {
		return None;
	}
	let mut out = Zeroizing::new([0u8; 32]);
	for i in 0..32 {
		out[i] = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
	}
	Some(out)
}

/// Run a platform tool: `input` on stdin (the only way a secret goes in),
/// stdout back (the only way one comes out), stderr into the error.
fn run(program: &str, args: &[&str], input: Option<&[u8]>, dir: Option<&std::path::Path>) -> Result<Zeroizing<Vec<u8>>, Error> {
	let mut cmd = Command::new(program);
	cmd.args(args).stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
	if let Some(d) = dir {
		cmd.current_dir(d);
	}
	let mut child = cmd.spawn().map_err(|e| Error::Config(format!("{program} did not run ({e}) — is it installed?")))?;
	if let Some(bytes) = input {
		let mut stdin = child.stdin.take().expect("piped");
		stdin.write_all(bytes)?;
	}
	let out = child.wait_with_output()?;
	if !out.status.success() {
		let why = String::from_utf8_lossy(&out.stderr);
		let why = why.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("no reason given").trim().to_string();
		return Err(Error::Config(format!("{program} failed: {why}")));
	}
	Ok(Zeroizing::new(out.stdout))
}

/// The TPM 2.0, through tpm2-tools (5.x).
///
/// The part is sealed as a keyed-hash object under the owner hierarchy's
/// storage primary key — re-derived each time from the chip's seed with a
/// fixed template, so no persistent handle is needed. The blob is
/// encrypted under that key: on any other chip it does not even load.
///
/// The TCTI is the tools' own choice — `/dev/tpmrm0` (the kernel's
/// resource manager) by default, `TPM2TOOLS_TCTI` to point elsewhere (the
/// tests use a software TPM). After each step the transient objects are
/// flushed: the kernel's resource manager does that on its own, a raw or
/// simulated TPM runs out of object slots without it.
///
/// Not yet: an authorization value (a PIN, which the TPM's dictionary-
/// attack lockout would protect) or a PCR policy (sealing to the boot
/// state). Both are options of the same `tpm2_create`.
pub mod tpm {
	use super::*;

	const PRIMARY: [&str; 9] = ["tpm2_createprimary", "-Q", "-C", "o", "-g", "sha256", "-G", "ecc256:aes128cfb", "-c"];

	/// A private working directory (0700), removed when dropped.
	struct Workdir(std::path::PathBuf);

	impl Workdir {
		fn new() -> Result<Self, Error> {
			let base = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
			let dir = base.join(format!("gorani-tpm-{}", crate::new_item_id()));
			let mut b = std::fs::DirBuilder::new();
			#[cfg(unix)]
			{
				use std::os::unix::fs::DirBuilderExt;
				b.mode(0o700);
			}
			b.create(&dir)?;
			Ok(Self(dir))
		}
	}

	impl Drop for Workdir {
		fn drop(&mut self) {
			let _ = std::fs::remove_dir_all(&self.0);
		}
	}

	fn flush() {
		let _ = run("tpm2_flushcontext", &["-t"], None, None);
	}

	fn primary(dir: &std::path::Path) -> Result<(), Error> {
		let (program, args) = PRIMARY.split_first().expect("non-empty");
		let mut args = args.to_vec();
		args.push("primary.ctx");
		let r = run(program, &args, None, Some(dir));
		flush();
		r.map(|_| ())
	}

	/// Whether a TPM answers (tpm2-tools installed, a device we may use).
	pub fn available() -> bool {
		let ok = run("tpm2_getrandom", &["--hex", "8"], None, None).is_ok();
		flush();
		ok
	}

	pub fn seal(part: &[u8; 32]) -> Result<Protector, Error> {
		let w = Workdir::new()?;
		primary(&w.0)?;
		let r = run("tpm2_create", &["-Q", "-C", "primary.ctx", "-g", "sha256", "-i", "-", "-u", "seal.pub", "-r", "seal.priv"], Some(part), Some(&w.0));
		flush();
		r?;
		let b64 = |name: &str| -> Result<String, Error> { Ok(crate::encode(&std::fs::read(w.0.join(name))?)) };
		Ok(Protector::Tpm { public: b64("seal.pub")?, private: b64("seal.priv")? })
	}

	pub fn unseal(public: &str, private: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
		let w = Workdir::new()?;
		std::fs::write(w.0.join("seal.pub"), &*crate::decode(public)?)?;
		std::fs::write(w.0.join("seal.priv"), &*crate::decode(private)?)?;
		primary(&w.0).map_err(|e| Error::Config(format!("no TPM to unseal this computer's part ({e})")))?;
		let loaded = run("tpm2_load", &["-Q", "-C", "primary.ctx", "-u", "seal.pub", "-r", "seal.priv", "-c", "seal.ctx"], None, Some(&w.0));
		flush();
		loaded.map_err(|_| Error::Open("this TPM cannot load the sealed part — it was sealed by another machine's TPM (or this one's was cleared)"))?;
		let out = run("tpm2_unseal", &["-Q", "-c", "seal.ctx"], None, Some(&w.0));
		flush();
		let out = out?;
		if out.len() != 32 {
			return Err(Error::Open("the TPM unsealed something that is not a 32-byte part"));
		}
		let mut part = Zeroizing::new([0u8; 32]);
		part.copy_from_slice(&out);
		Ok(part)
	}
}

/// The login keyring, through secret-tool (libsecret): the Secret Service
/// on the user's session bus — GNOME Keyring, KWallet, KeePassXC. The item
/// is found by two attributes (an application tag and a random reference),
/// never by anything that names the vault, and holds the part as hex.
pub mod keyring {
	use super::*;

	const APP: &str = "gorani-device";

	/// Whether a Secret Service answers on this session: a lookup of an
	/// item that does not exist fails quietly; with no service it says why.
	pub fn available() -> bool {
		let out = Command::new("secret-tool").args(["lookup", "application", APP, "item", "probe-0"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).output();
		matches!(out, Ok(o) if o.stderr.iter().all(u8::is_ascii_whitespace))
	}

	pub fn store(part: &[u8; 32], label_text: &str) -> Result<Protector, Error> {
		// Hex, not base64url: a reference starting with "-" would be read
		// by secret-tool as an option (found by the live suite).
		let mut r = [0u8; 16];
		rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut r);
		let item = crate::transfer::hex(&r);
		let hex = Zeroizing::new(crate::transfer::hex(&part[..]));
		// ASCII only: secret-tool converts argv from the locale's charset, and
		// under a C/POSIX locale anything else is "an invalid byte sequence".
		let label_arg = format!("--label={}", label_text.chars().map(|c| if c.is_ascii() && !c.is_ascii_control() { c } else { '?' }).collect::<String>());
		run("secret-tool", &["store", &label_arg, "application", APP, "item", &item], Some(hex.as_bytes()), None)?;
		Ok(Protector::Keyring { item })
	}

	pub fn lookup(item: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
		let out = run("secret-tool", &["lookup", "application", APP, "item", item], None, None).map_err(|e| Error::Config(format!("the login keyring did not give this computer's part — is the session's keyring unlocked? ({e})")))?;
		let text = Zeroizing::new(String::from_utf8_lossy(&out).to_string());
		hex32(&text).ok_or(Error::Open("the login keyring holds no part for this computer (cleared, or another login)"))
	}

	pub fn clear(item: &str) {
		let _ = run("secret-tool", &["clear", "application", APP, "item", item], None, None);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_secret_needs_every_part_and_knows_which_kinds_made_it() {
		let a = ("tpm", Zeroizing::new([1u8; 32]));
		let b = ("keyring", Zeroizing::new([2u8; 32]));
		let both = combine(&[a.clone(), b]);
		assert_ne!(*both, *combine(std::slice::from_ref(&a)), "one part is not the secret");
		assert_ne!(*both, *combine(&[(a.0, Zeroizing::new([1u8; 32])), ("keyring", Zeroizing::new([3u8; 32]))]), "another keyring part, another secret");
		assert_ne!(*combine(&[("tpm", Zeroizing::new([7u8; 32]))]), *combine(&[("file", Zeroizing::new([7u8; 32]))]), "the same bytes from a file are not a TPM's part");
	}

	#[test]
	fn a_file_protector_round_trips_and_labels_say_what_protects() {
		let (ps, secret) = create(Want::File, "test").unwrap();
		assert_eq!(label(&ps), "file");
		assert_eq!(*open(&ps).unwrap(), *secret);
		let json = serde_json::to_string(&ps).unwrap();
		assert!(json.contains("\"kind\":\"file\""), "{json}");
		assert_eq!(label(&[Protector::Tpm { public: String::new(), private: String::new() }, Protector::Keyring { item: "x".into() }]), "tpm+keyring");
		assert!("tpm+keyring".parse::<Want>().is_ok() && "usb".parse::<Want>().is_err());
		assert!(open(&[]).is_err(), "no protectors, no secret");
	}
}
