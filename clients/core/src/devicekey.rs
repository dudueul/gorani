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
//! Windows and macOS (commit 39d — `devicekey/windows.rs`, `devicekey/macos.rs`)
//! hold parts in their own stores, under the same three words, so
//! `--protect tpm+keyring` means the same on every computer: the machine's
//! hardware, and the person's login.
//!
//! | word | Linux | Windows | macOS |
//! |---|---|---|---|
//! | the hardware (`tpm`; `enclave` on a Mac) | TPM 2.0, tpm2-tools | the TPM, as a non-exportable CNG key (Platform Crypto Provider) | the Secure Enclave (a CryptoKit key) |
//! | the login (`keyring`) | Secret Service | DPAPI (the user's logon secret) | the login Keychain |
//! | a person, each unlock (`hello`; `presence` on a Mac) | — (a TPM PIN, `--tpm-pin`) | Windows Hello (a PIN, a face, a finger) | the Secure Enclave with user presence (Touch ID or the password) |
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
//! already running in the session. Revoking the device (the web app's Team ›
//! Devices, or `gorani-sync revoke` from any other computer) deletes the
//! server's copy — then no part opens anything.
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
	Tpm {
		public: String,
		private: String,
		/// Which storage-key template sealed it (commit 36): 0 the first
		/// (subject to the chip's lockout), 1 the `noda` one — a lockout from
		/// PIN guessing must not lock out every other part on the chip.
		#[serde(default)]
		srk: u8,
		/// Unsealing needs a PIN (the object's authorization value), which
		/// the TPM's dictionary-attack lockout protects (commit 36).
		#[serde(default)]
		pin: bool,
		/// Unsealing needs these PCRs (SHA-256 bank) to hold the values they
		/// held at sealing: the machine's boot state (commit 36).
		#[serde(default, skip_serializing_if = "Vec::is_empty")]
		pcrs: Vec<u8>,
	},
	/// An item in the login keyring, found by this reference.
	Keyring { item: String },
	/// The part itself, in the clear (dev and CI only).
	File { part: String },
	/// Windows (commit 39d): the part as DPAPI protected it for this user
	/// (base64) — only their logon opens it, on this computer.
	Dpapi { blob: String },
	/// Windows: the part encrypted (RSA-OAEP, base64) to a key that never
	/// leaves its store — `provider` "tpm" (the Platform Crypto Provider:
	/// the TPM) or "software" (tests) — found by `key`, its name.
	Cng { provider: String, key: String, wrapped: String },
	/// Windows Hello: the part is a hash of the Hello key's signature over
	/// `challenge` (base64) — a gesture each time it is asked for.
	Hello { key: String, challenge: String },
	/// macOS: an item in the login Keychain, found by this reference.
	Keychain { item: String },
	/// macOS: a Secure Enclave key (its encrypted representation, base64 —
	/// only this Mac's enclave can use it) and the peer public key the part
	/// is agreed with; `presence`: each use asks for Touch ID or the password.
	Enclave {
		key: String,
		peer: String,
		#[serde(default)]
		presence: bool,
	},
}

impl Protector {
	pub fn kind(&self) -> &'static str {
		match self {
			Protector::Tpm { .. } => "tpm",
			Protector::Keyring { .. } => "keyring",
			Protector::File { .. } => "file",
			Protector::Dpapi { .. } => "dpapi",
			Protector::Cng { .. } => "cng",
			Protector::Hello { .. } => "hello",
			Protector::Keychain { .. } => "keychain",
			Protector::Enclave { .. } => "enclave",
		}
	}
}

/// What a person asks for at setup (`--protect`): `auto`, or words joined
/// with `+` — each the same idea on every system (the table above), made
/// by that system's own store.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Want {
	/// Everything this machine has without asking anyone: the hardware and
	/// the login where both answer, either alone otherwise — and an error,
	/// not a silent file, where neither does.
	Auto,
	/// These (`HARDWARE | LOGIN | PRESENCE | FILE`).
	Set(u8),
}

impl Want {
	/// The machine's hardware: a TPM, the Secure Enclave.
	pub const HARDWARE: u8 = 1;
	/// The person's login: the keyring, DPAPI, the login Keychain.
	pub const LOGIN: u8 = 2;
	/// A person at each unlock: Windows Hello, the enclave with presence.
	pub const PRESENCE: u8 = 4;
	pub const FILE_PART: u8 = 8;
	pub const FILE: Want = Want::Set(Self::FILE_PART);
	pub const TPM_KEYRING: Want = Want::Set(Self::HARDWARE | Self::LOGIN);
}

/// The words `--protect` takes here, with what each is.
fn words() -> &'static [(&'static str, u8)] {
	if cfg!(target_os = "macos") {
		&[("enclave", Want::HARDWARE), ("keychain", Want::LOGIN), ("keyring", Want::LOGIN), ("presence", Want::PRESENCE), ("file", Want::FILE_PART)]
	} else if cfg!(windows) {
		&[("tpm", Want::HARDWARE), ("dpapi", Want::LOGIN), ("keyring", Want::LOGIN), ("hello", Want::PRESENCE), ("presence", Want::PRESENCE), ("file", Want::FILE_PART)]
	} else {
		&[("tpm", Want::HARDWARE), ("keyring", Want::LOGIN), ("file", Want::FILE_PART)]
	}
}

impl std::str::FromStr for Want {
	type Err = Error;
	fn from_str(s: &str) -> Result<Self, Error> {
		if s == "auto" {
			return Ok(Want::Auto);
		}
		let mut set = 0u8;
		for w in s.split('+') {
			let Some((_, bit)) = words().iter().find(|(name, _)| *name == w) else {
				let names: Vec<&str> = words().iter().map(|(n, _)| *n).collect();
				return Err(Error::Config(format!("--protect {s}: auto, or one or more of {} joined with + (on this system)", names.join(", "))));
			};
			set |= bit;
		}
		if set & Want::FILE_PART != 0 && set != Want::FILE_PART {
			return Err(Error::Config("--protect file stands alone: a part in the profile beside a protected one only looks stronger".into()));
		}
		Ok(Want::Set(set))
	}
}

/// How a TPM part is sealed (commit 36): a PIN, and the PCRs whose values
/// it is bound to. Both off by default.
#[derive(Default)]
pub struct TpmOptions {
	pub pin: Option<Zeroizing<String>>,
	pub pcrs: Vec<u8>,
}

impl TpmOptions {
	/// `--tpm-pcrs 7` or `0,7`: PCR indexes 0–23.
	pub fn parse_pcrs(s: &str) -> Result<Vec<u8>, Error> {
		let mut out = Vec::new();
		for x in s.split(',').map(str::trim).filter(|x| !x.is_empty()) {
			let n: u8 = x.parse().ok().filter(|n| *n <= 23).ok_or_else(|| Error::Config(format!("--tpm-pcrs {s}: PCR indexes are 0–23 (7 is the Secure Boot state)")))?;
			if !out.contains(&n) {
				out.push(n);
			}
		}
		out.sort_unstable();
		Ok(out)
	}
}

/// The label the server records for the device (its `protection`): the
/// kinds, joined, a TPM's options in brackets — `tpm[pin,pcr:7]+keyring`.
/// The client's word — shown to the member and their leads, not attested
/// (a TPM attestation of the sealing key is future work).
pub fn label(protectors: &[Protector]) -> String {
	protectors
		.iter()
		.map(|p| match p {
			// (The words a person reads — "tpm" is the TPM on either system.)
			Protector::Cng { provider, .. } if provider == "tpm" => "tpm".to_string(),
			Protector::Cng { provider, .. } => format!("cng[{provider}]"),
			Protector::Enclave { presence: true, .. } => "enclave[presence]".to_string(),
			Protector::Tpm { pin, pcrs, .. } if *pin || !pcrs.is_empty() => {
				let mut opts: Vec<String> = Vec::new();
				if *pin {
					opts.push("pin".into());
				}
				opts.extend(pcrs.iter().map(|n| format!("pcr:{n}")));
				format!("tpm[{}]", opts.join(","))
			}
			other => other.kind().to_string(),
		})
		.collect::<Vec<_>>()
		.join("+")
}

/// A PIN for unsealing: `GORANI_TPM_PIN` (automation, tests), else asked on
/// the terminal. Never an argument: argv is readable by other users.
pub fn ask_pin(prompt: &str) -> Result<Zeroizing<String>, Error> {
	if let Ok(p) = std::env::var("GORANI_TPM_PIN") {
		return Ok(Zeroizing::new(p));
	}
	rpassword::prompt_password(prompt).map(Zeroizing::new).map_err(|e| Error::Config(format!("no TPM PIN given ({e}) — run it on a terminal, or set GORANI_TPM_PIN")))
}

/// A new PIN: asked twice (or `GORANI_TPM_PIN`), at least 6 characters —
/// the TPM's lockout limits guessing, length limits the luck.
pub fn choose_pin() -> Result<Zeroizing<String>, Error> {
	let pin = match std::env::var("GORANI_TPM_PIN") {
		Ok(p) => Zeroizing::new(p),
		Err(_) => {
			let a = ask_pin("Choose a PIN for this computer's TPM: ")?;
			let b = ask_pin("The same PIN again: ")?;
			if *a != *b {
				return Err(Error::Config("the two PINs differ".into()));
			}
			a
		}
	};
	if pin.chars().count() < 6 {
		return Err(Error::Config("a TPM PIN is at least 6 characters".into()));
	}
	Ok(pin)
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

/// Make the protectors `want` names (each with a fresh part — random and
/// sealed, or, for Hello and the enclave, derived from what the hardware
/// answers) and the device secret they give. Nothing is written but into
/// the blobs returned and the platform's own stores.
pub fn create(want: Want, label_text: &str, tpm_options: &TpmOptions) -> Result<(Vec<Protector>, Zeroizing<[u8; 32]>), Error> {
	if cfg!(any(windows, target_os = "macos")) && (tpm_options.pin.is_some() || !tpm_options.pcrs.is_empty()) {
		return Err(Error::Config("--tpm-pin and --tpm-pcrs are for Linux's TPM (tpm2-tools); here a person is asked with --protect …+hello (Windows) or …+presence (macOS)".into()));
	}
	let (set, auto) = match want {
		Want::Set(s) => (s, false),
		Want::Auto => (platform::auto()?, true),
	};
	let mut protectors = Vec::new();
	let mut parts = Vec::new();
	for bit in [Want::HARDWARE, Want::PRESENCE, Want::LOGIN, Want::FILE_PART] {
		if set & bit == 0 {
			continue;
		}
		let made = match bit {
			Want::HARDWARE => platform::hardware(tpm_options),
			Want::PRESENCE => platform::presence(label_text),
			Want::LOGIN => platform::login(label_text),
			_ => {
				let part = random_part();
				Ok((Protector::File { part: crate::transfer::hex(&part[..]) }, part))
			}
		};
		match made {
			Ok((p, part)) => {
				parts.push((p.kind(), part));
				protectors.push(p);
			}
			// `auto` found the hardware there but could not use it (a TPM
			// that answers and will not make keys): the login alone, said
			// aloud — the label printed at setup says it too.
			Err(e) if auto && bit == Want::HARDWARE && set & Want::LOGIN != 0 => eprintln!("warning: this machine's hardware key store did not take a part ({e}) — the login protects it alone"),
			Err(e) => {
				forget(&protectors);
				return Err(e);
			}
		}
	}
	Ok((protectors, combine(&parts)))
}

fn random_part() -> Zeroizing<[u8; 32]> {
	let mut part = Zeroizing::new([0u8; 32]);
	rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut part[..]);
	part
}

/// A part another system holds (a profile copied between computers).
fn elsewhere(p: &Protector) -> Error {
	let whose = match p {
		Protector::Dpapi { .. } | Protector::Cng { .. } | Protector::Hello { .. } => "Windows",
		Protector::Keychain { .. } | Protector::Enclave { .. } => "macOS",
		_ => "Linux",
	};
	Error::Config(format!("this profile's {} part is held by {whose} on the computer that enrolled it — a profile does not move between computers: enrol this one", p.kind()))
}

/// The device secret, from its protectors — each asked for its part.
pub fn open(protectors: &[Protector]) -> Result<Zeroizing<[u8; 32]>, Error> {
	if protectors.is_empty() {
		return Err(Error::Config("this profile has no device protectors".into()));
	}
	let mut parts = Vec::new();
	for p in protectors {
		let part = match p {
			Protector::File { part } => hex32(part).ok_or(Error::Format("a file protector's part is not 32 bytes of hex"))?,
			other => platform::open(other)?,
		};
		parts.push((p.kind(), part));
	}
	Ok(combine(&parts))
}

/// Remove what the protectors hold outside the profile (keyring items; a
/// TPM blob is only data — dropping it from the profile is enough).
pub fn forget(protectors: &[Protector]) {
	for p in protectors {
		platform::forget(p);
	}
}

/// Each system's stores, behind the same five calls. (Linux's, and any
/// other Unix with tpm2-tools and a Secret Service.)
#[cfg(not(any(windows, target_os = "macos")))]
mod platform {
	use super::*;

	pub fn auto() -> Result<u8, Error> {
		match (tpm::available(), keyring::available()) {
			(true, true) => Ok(Want::HARDWARE | Want::LOGIN),
			(true, false) => Ok(Want::HARDWARE),
			(false, true) => Ok(Want::LOGIN),
			(false, false) => Err(Error::Config(
				"this machine offers neither a TPM (tpm2-tools and /dev/tpmrm0 — the user must be in the `tss` group) nor a login keyring (secret-tool and a Secret Service such as GNOME Keyring). Install one, or pass --protect file to keep the secret in the profile — then anyone who copies the profile, with the member's sign-in, can open this computer's copy".into(),
			)),
		}
	}

	pub fn hardware(o: &TpmOptions) -> Result<(Protector, Zeroizing<[u8; 32]>), Error> {
		let part = random_part();
		Ok((tpm::seal(&part, o)?, part))
	}

	pub fn presence(_: &str) -> Result<(Protector, Zeroizing<[u8; 32]>), Error> {
		Err(Error::Config("on Linux a person is asked through the TPM: --protect tpm --tpm-pin".into()))
	}

	pub fn login(label_text: &str) -> Result<(Protector, Zeroizing<[u8; 32]>), Error> {
		let part = random_part();
		Ok((keyring::store(&part, label_text)?, part))
	}

	pub fn open(p: &Protector) -> Result<Zeroizing<[u8; 32]>, Error> {
		match p {
			Protector::Tpm { public, private, srk, pin, pcrs } => {
				let pin = if *pin { Some(ask_pin("TPM PIN for this computer: ")?) } else { None };
				tpm::unseal(public, private, *srk, pin.as_deref().map(String::as_str), pcrs)
			}
			Protector::Keyring { item } => keyring::lookup(item),
			other => Err(elsewhere(other)),
		}
	}

	pub fn forget(p: &Protector) {
		if let Protector::Keyring { item } = p {
			keyring::clear(item);
		}
	}
}

#[cfg(windows)]
#[path = "devicekey/windows.rs"]
pub mod win;
#[cfg(windows)]
use self::win as platform;

#[cfg(target_os = "macos")]
#[path = "devicekey/macos.rs"]
pub mod mac;
#[cfg(target_os = "macos")]
use self::mac as platform;

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
		// Every line: the TPM's reason (a lockout, a policy check) is often
		// above the tool's own last word.
		let why = String::from_utf8_lossy(&out.stderr);
		let why = why.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" | ");
		return Err(Error::Config(format!("{program} failed: {}", if why.is_empty() { "no reason given" } else { &why })));
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
/// Options (commit 36), each a property of the sealed object itself:
///
/// | option | the object | unsealing needs | what it adds |
/// |---|---|---|---|
/// | — | empty auth, `noda` | this chip | the machine binding |
/// | PIN | an authorization value, DA-protected | this chip and the PIN | a person; guesses lock the chip out (after a few, for its recovery time) |
/// | PCRs | a policy (PolicyPCR), `noda` | this chip in the boot state it was sealed in | a disk moved to another boot (another OS, Secure Boot off) opens nothing |
/// | both | PolicyPCR + PolicyAuthValue, DA-protected | all of the above | |
///
/// The PIN never travels in argv (readable by every user): unsealing reads
/// it from stdin (`file:-`); sealing — tpm2-tools needs a seekable file
/// there — from a 0600 file in the 0700 working directory, on the per-user
/// tmpfs (`XDG_RUNTIME_DIR`) where there is one, removed at once.
///
/// When the boot state changes on purpose (a firmware update that changes
/// the Secure Boot keys), the part stops unsealing: unlock with the
/// password or recovery code and seal again —
/// `gorani-sync protect --secret … --tpm-pcrs 7`.
pub mod tpm {
	use super::*;

	/// The storage key's template, by `srk` version. 1 adds `noda`: the
	/// key's own (empty) authorization is not subject to the lockout, so PIN
	/// guessing on one part cannot lock out every other part on the chip.
	fn primary_args(srk: u8) -> Vec<&'static str> {
		let mut a = vec!["-Q", "-C", "o", "-g", "sha256", "-G", "ecc256:aes128cfb"];
		if srk >= 1 {
			a.extend(["-a", "restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda"]);
		}
		a.extend(["-c", "primary.ctx"]);
		a
	}

	/// The template new parts are sealed under.
	const SRK: u8 = 1;

	/// A private working directory (0700), removed when dropped.
	struct Workdir(std::path::PathBuf);

	impl Workdir {
		fn new() -> Result<Self, Error> {
			let base = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
			let dir = base.join(format!("gorani-tpm-{}", crate::new_item_id()));
			#[cfg_attr(not(unix), allow(unused_mut))]
			let mut b = std::fs::DirBuilder::new();
			#[cfg(unix)]
			{
				use std::os::unix::fs::DirBuilderExt;
				b.mode(0o700);
			}
			b.create(&dir)?;
			Ok(Self(dir))
		}

		/// A 0600 file in the working directory (for the one value
		/// tpm2-tools will only read from a seekable file: a new PIN).
		fn secret_file(&self, name: &str, bytes: &[u8]) -> Result<(), Error> {
			let mut o = std::fs::OpenOptions::new();
			o.write(true).create_new(true);
			#[cfg(unix)]
			{
				use std::os::unix::fs::OpenOptionsExt;
				o.mode(0o600);
			}
			o.open(self.0.join(name))?.write_all(bytes)?;
			Ok(())
		}
	}

	impl Drop for Workdir {
		fn drop(&mut self) {
			let _ = std::fs::remove_dir_all(&self.0);
		}
	}

	fn flush() {
		let _ = run("tpm2_flushcontext", &["-t"], None, None);
		let _ = run("tpm2_flushcontext", &["-s"], None, None);
	}

	fn primary(dir: &std::path::Path, srk: u8) -> Result<(), Error> {
		let r = run("tpm2_createprimary", &primary_args(srk), None, Some(dir));
		flush();
		r.map(|_| ())
	}

	/// Whether a TPM answers (tpm2-tools installed, a device we may use).
	pub fn available() -> bool {
		let ok = run("tpm2_getrandom", &["--hex", "8"], None, None).is_ok();
		flush();
		ok
	}

	fn pcr_list(pcrs: &[u8]) -> String {
		format!("sha256:{}", pcrs.iter().map(u8::to_string).collect::<Vec<_>>().join(","))
	}

	/// What the TPM's refusal means, for a person.
	fn explain(e: Error, pcrs: &[u8]) -> Error {
		let text = e.to_string();
		let low = text.to_ascii_lowercase();
		if low.contains("0x921") || low.contains("lockout") {
			Error::Open("the TPM is locked out after too many wrong PINs — wait for the chip's recovery time, or have its administrator clear it (tpm2_dictionarylockout -c)")
		} else if low.contains("policy") || low.contains("0x99d") {
			Error::Config(format!("the boot state changed since this computer's part was sealed (PCR {}) — unlock with your password or recovery code and seal it again: gorani-sync protect --secret … --tpm-pcrs {}", pcr_list(pcrs).trim_start_matches("sha256:"), pcr_list(pcrs).trim_start_matches("sha256:")))
		} else if low.contains("authorization") || low.contains("auth_fail") || low.contains("bad_auth") || low.contains("98e") || low.contains("9a2") {
			Error::Open("wrong TPM PIN (the TPM counts wrong PINs, and locks out after a few)")
		} else {
			e
		}
	}

	pub fn seal(part: &[u8; 32], o: &TpmOptions) -> Result<Protector, Error> {
		let w = Workdir::new()?;
		primary(&w.0, SRK)?;
		let mut args: Vec<String> = ["-Q", "-C", "primary.ctx", "-g", "sha256", "-i", "-", "-u", "seal.pub", "-r", "seal.priv"].iter().map(|s| s.to_string()).collect();
		if !o.pcrs.is_empty() {
			// The policy digest, computed in a trial session: PolicyPCR over the
			// PCRs' values NOW (+ PolicyAuthValue when there is a PIN).
			let r = run("tpm2_startauthsession", &["-S", "trial.ctx"], None, Some(&w.0)).and_then(|_| {
				let mut pcr = vec!["-Q", "-S", "trial.ctx"];
				let list = pcr_list(&o.pcrs);
				pcr.extend(["-l", &list]);
				if o.pin.is_none() {
					pcr.extend(["-L", "seal.policy"]);
				}
				run("tpm2_policypcr", &pcr, None, Some(&w.0))?;
				if o.pin.is_some() {
					run("tpm2_policyauthvalue", &["-Q", "-S", "trial.ctx", "-L", "seal.policy"], None, Some(&w.0))?;
				}
				Ok(())
			});
			let _ = run("tpm2_flushcontext", &["trial.ctx"], None, Some(&w.0));
			flush();
			r?;
			args.extend(["-L".into(), "seal.policy".into(), "-a".into(), if o.pin.is_some() { "fixedtpm|fixedparent".into() } else { "fixedtpm|fixedparent|noda".into() }]);
		} else if o.pin.is_none() {
			args.extend(["-a".into(), "fixedtpm|fixedparent|userwithauth|noda".into()]);
		}
		if let Some(pin) = &o.pin {
			w.secret_file("auth", pin.as_bytes())?;
			args.extend(["-p".into(), "file:auth".into()]);
		}
		let argv: Vec<&str> = args.iter().map(String::as_str).collect();
		let r = run("tpm2_create", &argv, Some(part), Some(&w.0));
		let _ = std::fs::remove_file(w.0.join("auth"));
		flush();
		r?;
		let b64 = |name: &str| -> Result<String, Error> { Ok(crate::encode(&std::fs::read(w.0.join(name))?)) };
		Ok(Protector::Tpm { public: b64("seal.pub")?, private: b64("seal.priv")?, srk: SRK, pin: o.pin.is_some(), pcrs: o.pcrs.clone() })
	}

	pub fn unseal(public: &str, private: &str, srk: u8, pin: Option<&str>, pcrs: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
		let w = Workdir::new()?;
		std::fs::write(w.0.join("seal.pub"), &*crate::decode(public)?)?;
		std::fs::write(w.0.join("seal.priv"), &*crate::decode(private)?)?;
		primary(&w.0, srk).map_err(|e| explain(Error::Config(format!("no TPM to unseal this computer's part ({e})")), pcrs))?;
		let loaded = run("tpm2_load", &["-Q", "-C", "primary.ctx", "-u", "seal.pub", "-r", "seal.priv", "-c", "seal.ctx"], None, Some(&w.0));
		flush();
		if let Err(e) = loaded {
			let e = explain(e, pcrs);
			return Err(if matches!(e, Error::Config(_)) { Error::Open("this TPM cannot load the sealed part — it was sealed by another machine's TPM (or this one's was cleared)") } else { e });
		}
		let stdin = pin.map(str::as_bytes);
		let out = if pcrs.is_empty() {
			run("tpm2_unseal", if pin.is_some() { &["-Q", "-c", "seal.ctx", "-p", "file:-"][..] } else { &["-Q", "-c", "seal.ctx"][..] }, stdin, Some(&w.0))
		} else {
			// A policy session that satisfies the sealing policy — if, and only
			// if, the PCRs hold the values they held then.
			let r = run("tpm2_startauthsession", &["--policy-session", "-S", "s.ctx"], None, Some(&w.0)).and_then(|_| {
				let list = pcr_list(pcrs);
				run("tpm2_policypcr", &["-Q", "-S", "s.ctx", "-l", &list], None, Some(&w.0))?;
				if pin.is_some() {
					run("tpm2_policyauthvalue", &["-Q", "-S", "s.ctx"], None, Some(&w.0))?;
				}
				run("tpm2_unseal", &["-Q", "-c", "seal.ctx", "-p", if pin.is_some() { "session:s.ctx+file:-" } else { "session:s.ctx" }], stdin, Some(&w.0))
			});
			let _ = run("tpm2_flushcontext", &["s.ctx"], None, Some(&w.0));
			r
		};
		flush();
		let out = out.map_err(|e| explain(e, pcrs))?;
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
		let (ps, secret) = create(Want::FILE, "test", &TpmOptions::default()).unwrap();
		assert_eq!(label(&ps), "file");
		assert_eq!(*open(&ps).unwrap(), *secret);
		let json = serde_json::to_string(&ps).unwrap();
		assert!(json.contains("\"kind\":\"file\""), "{json}");
		let tpm = |pin, pcrs: Vec<u8>| Protector::Tpm { public: String::new(), private: String::new(), srk: 1, pin, pcrs };
		assert_eq!(label(&[tpm(false, vec![]), Protector::Keyring { item: "x".into() }]), "tpm+keyring");
		assert_eq!(label(&[tpm(true, vec![0, 7])]), "tpm[pin,pcr:0,pcr:7]");
		assert_eq!(TpmOptions::parse_pcrs("7, 0,7").unwrap(), vec![0, 7]);
		assert!(TpmOptions::parse_pcrs("24").is_err());
		assert!("keyring".parse::<Want>().is_ok() && "usb".parse::<Want>().is_err());
		assert!("file+keyring".parse::<Want>().is_err(), "a file part beside a protected one is refused");
		assert!(open(&[]).is_err(), "no protectors, no secret");
		let cng = |provider: &str| Protector::Cng { provider: provider.into(), key: "k".into(), wrapped: String::new() };
		assert_eq!(label(&[cng("tpm"), Protector::Dpapi { blob: String::new() }]), "tpm+dpapi", "the TPM is \"tpm\" on Windows too");
		assert_eq!(label(&[cng("software")]), "cng[software]");
		assert_eq!(label(&[Protector::Enclave { key: String::new(), peer: String::new(), presence: true }, Protector::Keychain { item: "x".into() }]), "enclave[presence]+keychain");
	}

	#[test]
	fn the_same_words_mean_the_same_on_every_system() {
		let hw = if cfg!(target_os = "macos") { "enclave" } else { "tpm" };
		assert_eq!(format!("{hw}+keyring").parse::<Want>().unwrap(), Want::TPM_KEYRING);
		assert_eq!("file".parse::<Want>().unwrap(), Want::FILE);
		if cfg!(not(any(windows, target_os = "macos"))) {
			assert!("hello".parse::<Want>().is_err() && "dpapi".parse::<Want>().is_err(), "Windows' words are not Linux's");
		}
	}

	#[test]
	fn a_part_from_another_system_says_so() {
		let foreign = if cfg!(windows) { Protector::Keychain { item: "x".into() } } else { Protector::Dpapi { blob: "AA==".into() } };
		let e = open(&[foreign]).map(|_| ()).expect_err("not openable here").to_string();
		assert!(e.contains("does not move between computers"), "{e}");
	}

	#[test]
	fn a_commit_34_tpm_part_still_reads_as_the_first_template_without_options() {
		let old: Protector = serde_json::from_str(r#"{"kind":"tpm","public":"AA==","private":"AA=="}"#).unwrap();
		assert!(matches!(old, Protector::Tpm { srk: 0, pin: false, ref pcrs, .. } if pcrs.is_empty()), "its blob loads under the storage key it was sealed under");
	}
}
