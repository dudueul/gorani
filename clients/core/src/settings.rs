// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The desktop apps' settings (commit 40a, docs/DESKTOP.md › Settings).
//!
//! Until 40a every setting was a flag typed once to `gorani-sync setup`.
//! The Windows and macOS apps now have a Settings window. Everything that
//! window does lives here, in one place, so that:
//!
//! - both apps behave the same: the same checks, the same words;
//! - the CLI does it too (`gorani-sync whoami`, `signout`, `settings`);
//! - every flow is tested on Linux against the real Worker
//!   (tests/api/client-live.test.ts), not only by clicking.
//!
//! ```text
//! Account     server URL, signed in as (GET /api/v1/me), this computer's name,
//!             enrol with the vault password, sign out
//! Sync        the folder (Windows), the area (own files or a case), start at
//!             login, keep local copies, pause
//! Devices     how this computer's key part is protected (change it), the
//!             member's other computers (revoke)
//! Advanced    an Access service token, accept unverified files, the scanner
//!             command, the sign-in command itself
//! ```
//!
//! One server per computer (decided 2026-10-19). A computer's wrapped copy
//! of the root and its token exist on ONE server, so a new server URL
//! means sign out there, then enrol on the new one. The window says so
//! and does both. There is no "edit the URL" that leaves a copy behind.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{api, devicekey, session, DeviceProfile, Error};

/// What the Settings window keeps beside the enrolment, in the same
/// profile file (`DeviceProfile::app`). Every field has a default, so a
/// profile written before 40a reads as "nothing set".
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppSettings {
	/// The name this computer was enrolled under. The server lists it in
	/// Team › Devices; kept here so the window can show it offline.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub device_name: Option<String>,
	/// Windows: the folder Explorer shows the area in (a Cloud Files sync
	/// root). macOS needs none: Finder puts it under Locations.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub folder: Option<String>,
	/// The area shown: None for the member's own files, or a case id.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub case: Option<String>,
	/// Start the app when the person signs in to the computer.
	pub start_at_login: bool,
	/// Keep fetched files' bytes after the app stops. Off by default: the
	/// plaintext then lives on this disk only while the app runs. On, the
	/// disk's own encryption (BitLocker, FileVault) is what protects it.
	pub keep_local: bool,
	/// Accept files whose uploader's signature cannot be checked (no
	/// identity record yet). Off by default: such files are refused.
	pub accept_unverified: bool,
	/// The scanner `gorani-sync accept` runs on an outsider's item when no
	/// `--scan` is given (scan.rs: no shell; `{}` is the file's path).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub scan_command: Option<String>,
	/// Syncing paused from the tray or menu bar.
	pub paused: bool,
}

impl AppSettings {
	pub fn is_default(&self) -> bool {
		self == &Self::default()
	}

	/// Refuse what would only fail later, in words the window can show.
	pub fn check(&self) -> Result<(), Error> {
		if let Some(name) = &self.device_name {
			check_device_name(name)?;
		}
		if let Some(case) = &self.case {
			if case.is_empty() || case.len() > 64 || !case.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
				return Err(Error::Config(format!("“{case}” is not a case id")));
			}
		}
		if let Some(folder) = &self.folder {
			if !Path::new(folder).is_absolute() {
				return Err(Error::Config(format!("the folder must be a full path (“{folder}” is not)")));
			}
		}
		if let Some(cmd) = &self.scan_command {
			crate::scan::split_words(cmd)?;
		}
		Ok(())
	}

	/// What changing from `self` to `next` needs: the sync restarted (the
	/// folder, the area or what it keeps changed), or nothing more than
	/// saving. The apps read this to decide whether Apply restarts syncing.
	pub fn restart_needed(&self, next: &AppSettings) -> bool {
		self.folder != next.folder || self.case != next.case || self.keep_local != next.keep_local || self.accept_unverified != next.accept_unverified || self.paused != next.paused
	}
}

/// A device name the Team › Devices list can show: 1–64 characters, no
/// control characters.
pub fn check_device_name(name: &str) -> Result<(), Error> {
	let n = name.trim();
	if n.is_empty() || n.chars().count() > 64 || n.chars().any(char::is_control) {
		return Err(Error::Config("this computer's name: 1 to 64 characters, on one line".into()));
	}
	Ok(())
}

/// A server URL as the profile keeps it: `https://host[:port]`, no path,
/// no trailing slash, the host in lower case. Plain `http://` only for
/// this machine (`wrangler dev`): anything else would send the Access
/// token and the device token in the clear.
pub fn normalize_server(input: &str) -> Result<String, Error> {
	let t = input.trim();
	let t = if t.contains("://") { t.to_string() } else { format!("https://{t}") };
	let (scheme, rest) = t.split_once("://").ok_or_else(|| Error::Config("the server: an address like https://gorani.example".into()))?;
	let scheme = scheme.to_ascii_lowercase();
	let host = rest.trim_end_matches('/');
	if host.is_empty() || host.contains(['/', '?', '#', '@', ' ']) {
		return Err(Error::Config(format!("the server: just the address, like https://gorani.example (not “{input}”)")));
	}
	let host = host.to_ascii_lowercase();
	let bare = host.rsplit_once(':').map(|(h, p)| if p.bytes().all(|b| b.is_ascii_digit()) { h } else { host.as_str() }).unwrap_or(&host);
	let local = matches!(bare, "localhost" | "127.0.0.1" | "[::1]");
	match scheme.as_str() {
		"https" => Ok(format!("https://{host}")),
		"http" if local => Ok(format!("http://{host}")),
		"http" => Err(Error::Config("the server must use https:// — plain http would send your sign-in and this computer's token in the clear".into())),
		_ => Err(Error::Config(format!("the server: https://, not {scheme}://"))),
	}
}

/// How the apps reach a server before (and after) enrolment: the address
/// and the sign-in, without any device.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SignIn {
	pub server: String,
	/// The member's Access token, handed over by their browser (40c,
	/// signin.rs) — how the apps sign in. Never written out by serde.
	#[serde(skip_serializing)]
	pub access_token: Option<String>,
	/// The command that prints the member's Access token (cloudflared): the
	/// older way, kept for the Advanced tab and scripts.
	pub access_token_cmd: Option<String>,
	/// An Access service-token pair (Advanced): only for a deployment
	/// whose Access policy asks for one in front of the member's token.
	pub access_id: Option<String>,
	#[serde(skip_serializing)]
	pub access_secret: Option<String>,
	/// `wrangler dev` only (the tests).
	pub dev_email: Option<String>,
}

/// By hand, as DeviceProfile's (O16): the token and the secret never print.
impl std::fmt::Debug for SignIn {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let redact = |o: &Option<String>| if o.is_some() { "[redacted]" } else { "None" };
		f.debug_struct("SignIn")
			.field("server", &self.server)
			.field("access_token", &redact(&self.access_token))
			.field("access_token_cmd", &self.access_token_cmd)
			.field("access_id", &self.access_id)
			.field("access_secret", &redact(&self.access_secret))
			.field("dev_email", &self.dev_email)
			.finish()
	}
}

impl SignIn {
	/// The sign-in of an enrolled profile.
	pub fn of(profile: &DeviceProfile) -> Self {
		Self { server: profile.server.clone(), access_token: profile.access_token.clone(), access_token_cmd: profile.access_token_cmd.clone(), access_id: profile.access_id.clone(), access_secret: profile.access_secret.clone(), dev_email: profile.dev_email.clone() }
	}

	/// Whether this sign-in can reach the server as a member at all: a
	/// token (the browser's, the variable's), a command, or dev mode. The
	/// apps offer Sign in when it cannot, or when the token has expired.
	pub fn signed_in(&self) -> bool {
		let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
		let live = self.access_token.as_deref().is_some_and(|t| crate::api::jwt_exp(t).is_none_or(|exp| exp > now));
		live || self.access_token_cmd.is_some() || self.dev_email.is_some() || std::env::var("GORANI_ACCESS_TOKEN").is_ok_and(|t| !t.trim().is_empty())
	}

	/// A profile with no member and no device: enough for the team routes.
	fn bare_profile(&self) -> DeviceProfile {
		DeviceProfile {
			server: self.server.clone(),
			member: String::new(),
			device_id: String::new(),
			token: String::new(),
			access_token: self.access_token.clone(),
			access_token_cmd: self.access_token_cmd.clone(),
			access_id: self.access_id.clone(),
			access_secret: self.access_secret.clone(),
			device_secret: None,
			device_protectors: Vec::new(),
			pending_protectors: Vec::new(),
			dev_email: self.dev_email.clone(),
			app: AppSettings::default(),
		}
	}
}

/// Who is signed in, as the server sees it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Me {
	pub email: String,
	/// The team account of that email, or None: signed in to Access, but no
	/// lead has added this address in Team › People.
	pub member: Option<Member>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Member {
	pub id: String,
	pub name: String,
	pub role: String,
	pub active: bool,
}

/// `GET /api/v1/me` with this sign-in: the Account tab's "Signed in as".
pub fn whoami(sign_in: &SignIn) -> Result<Me, Error> {
	let v = api::Client::new(sign_in.bare_profile()).me().map_err(explain_refusal)?;
	me_of(&v)
}

fn me_of(v: &serde_json::Value) -> Result<Me, Error> {
	let email = v.get("email").and_then(|e| e.as_str()).filter(|e| !e.is_empty()).ok_or_else(|| Error::Config("the server did not say who is signed in".into()))?;
	let member = v.get("member").filter(|m| !m.is_null()).map(|m| Member {
		id: m.get("id").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
		name: m.get("name").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
		role: m.get("role").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
		active: m.get("active").and_then(|x| x.as_bool()).unwrap_or(false),
	});
	Ok(Me { email: email.to_string(), member })
}

/// A refusal in the words a person acts on. Access answers a missing or
/// expired sign-in with a redirect (the client follows none) or a 401/403.
fn explain_refusal(e: Error) -> Error {
	match e {
		Error::Http(301..=303 | 307 | 308 | 401, _) => Error::Config("not signed in to this server — Sign in again".into()),
		Error::Http(403, body) if body.contains("Access") || body.trim_start().starts_with('<') => Error::Config("Cloudflare Access refused this sign-in — Sign in again, or ask a lead whether this address may use the team's server".into()),
		other => other,
	}
}

// ── signing in with cloudflared ──────────────────────────────────────

/// Where cloudflared usually is, beyond PATH: the Windows installer's
/// folders and Homebrew's.
fn cloudflared_candidates() -> Vec<PathBuf> {
	let exe = if cfg!(windows) { "cloudflared.exe" } else { "cloudflared" };
	let mut out: Vec<PathBuf> = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).map(|d| d.join(exe)).collect()).unwrap_or_default();
	if cfg!(windows) {
		for var in ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"] {
			if let Some(dir) = std::env::var_os(var) {
				out.push(PathBuf::from(&dir).join("cloudflared").join(exe));
			}
		}
		if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
			out.push(PathBuf::from(dir).join("Microsoft").join("WinGet").join("Links").join(exe));
		}
	} else {
		out.push(PathBuf::from("/opt/homebrew/bin").join(exe));
		out.push(PathBuf::from("/usr/local/bin").join(exe));
	}
	out
}

/// The cloudflared this computer has, if any.
pub fn find_cloudflared() -> Option<PathBuf> {
	cloudflared_candidates().into_iter().find(|p| p.is_file())
}

/// The sign-in command the profile keeps for `server`, its program quoted
/// when the path has spaces (api.rs splits it as a command line).
pub fn token_command(cloudflared: &Path, server: &str) -> String {
	let program = cloudflared.to_string_lossy();
	let program = if program.contains(char::is_whitespace) { format!("\"{program}\"") } else { program.to_string() };
	format!("{program} access token -app={}", server.trim_end_matches('/'))
}

/// What to say when cloudflared is missing.
pub const CLOUDFLARED_MISSING: &str = if cfg!(windows) {
	"Signing in needs Cloudflare's cloudflared. Install it (winget install Cloudflare.cloudflared, or the installer from developers.cloudflare.com), then press Sign in again."
} else {
	"Signing in needs Cloudflare's cloudflared. Install it (brew install cloudflared), then press Sign in again."
};

/// Sign in to `server` through Cloudflare Access: `cloudflared access
/// login` opens the browser at the team's sign-in page and waits for it.
/// Then the token command is run once, to prove it works. Returns that
/// command, for the profile. Blocks for as long as the person takes, so
/// the apps call it off their window's thread.
pub fn sign_in_with_cloudflared(server: &str) -> Result<String, Error> {
	let server = normalize_server(server)?;
	let cloudflared = find_cloudflared().ok_or_else(|| Error::Config(CLOUDFLARED_MISSING.into()))?;
	let mut login = std::process::Command::new(&cloudflared);
	login.args(["access", "login", &server]);
	api::hide_console(&mut login);
	let out = login.output().map_err(|e| Error::Config(format!("cloudflared did not run: {e}")))?;
	if !out.status.success() {
		let said = String::from_utf8_lossy(&out.stderr);
		return Err(Error::Config(format!("signing in did not finish: {}", said.lines().last().unwrap_or("cloudflared stopped").trim())));
	}
	let cmd = token_command(&cloudflared, &server);
	api::access_token_from(None, Some(&cmd))?;
	Ok(cmd)
}

// ── enrolment and signing out ───────────────────────────────────────

/// What enrolling this computer takes.
pub struct Enrolment<'a> {
	pub sign_in: SignIn,
	/// The member id: given, or (None) the account of whoever is signed in.
	pub member: Option<String>,
	pub device_name: String,
	/// The vault password or recovery code: opens the root once, here.
	pub secret: &'a str,
	pub protect: devicekey::Want,
	pub tpm_options: devicekey::TpmOptions,
	/// `--device-secret` (dev and CI only): the secret kept in the file.
	pub device_secret: Option<String>,
	pub app: AppSettings,
}

/// Enrol this computer and write its profile at `path`. Refuses when
/// `path` already holds an enrolled computer: sign out first, so a second
/// enrolment never leaves the first one's copy of the root on a server
/// with nothing left on this computer to revoke it.
pub fn enrol(path: &Path, e: Enrolment<'_>) -> Result<DeviceProfile, Error> {
	check_device_name(&e.device_name)?;
	e.app.check()?;
	if let Ok(old) = session::load_profile(path) {
		if session::has_device_copy(&old) {
			return Err(Error::Config(format!("this computer is already enrolled ({} on {}) — sign out first", old.app.device_name.as_deref().unwrap_or(&old.device_id), old.server)));
		}
	}
	let mut sign_in = e.sign_in;
	sign_in.server = normalize_server(&sign_in.server)?;
	let member = match e.member.filter(|m| !m.trim().is_empty()) {
		Some(m) => m.trim().to_string(),
		None => {
			let me = whoami(&sign_in)?;
			match me.member {
				Some(m) if m.active => m.id,
				Some(m) => return Err(Error::Config(format!("{}'s account ({}) is not active — a lead reactivates it in Team › People", me.email, m.id))),
				None => return Err(Error::Config(format!("{} has no account on this team — a lead adds the address in Team › People", me.email))),
			}
		}
	};
	let mut profile = DeviceProfile { member, device_secret: e.device_secret, app: AppSettings { device_name: Some(e.device_name.trim().to_string()), ..e.app }, ..sign_in.bare_profile() };
	session::enrol(&mut profile, e.device_name.trim(), e.secret, e.protect, &e.tpm_options).map_err(explain_refusal)?;
	if let Err(err) = session::save_profile(path, &profile) {
		// Enrolled on the server but not saved here: give the copy back, so
		// nothing is left that this computer cannot revoke.
		let _ = api::Client::new(profile.clone()).leave(&profile.device_id, &profile.token);
		devicekey::forget(&profile.device_protectors);
		return Err(err);
	}
	Ok(profile)
}

/// What signing out did.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedOut {
	/// Whether the server deleted this computer's copy now (or had already).
	pub server_told: bool,
	/// Said when the server could not be told: what the person should do.
	pub warning: Option<String>,
}

/// Sign this computer out (Account › Sign out, `gorani-sync signout`):
///
/// 1. The server deletes this computer's wrapped copy of the root
///    (`leave`, with its own token). If it cannot be reached, the rest still
///    happens and the person is told to revoke the computer from another
///    one (Team › Devices).
/// 2. The device secret's parts are forgotten: keyring and Keychain items,
///    CNG keys. A TPM blob is only data in the profile.
/// 3. The profile and its upload journal are deleted.
///
/// The files themselves are the shell's to remove. The Windows app
/// unregisters its folder, which drops every local copy.
pub fn sign_out(path: &Path) -> Result<SignedOut, Error> {
	let profile = match session::load_profile(path) {
		Ok(p) => p,
		Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SignedOut { server_told: true, warning: None }),
		Err(e) => return Err(e),
	};
	let (server_told, warning) = if profile.device_id.is_empty() {
		(true, None)
	} else {
		match api::Client::new(profile.clone()).leave(&profile.device_id, &profile.token) {
			Ok(()) => (true, None),
			// Already revoked or unknown there: nothing is left to delete.
			Err(Error::Http(401 | 403 | 404, body)) if !body.trim_start().starts_with('<') => (true, None),
			Err(e) => (false, Some(format!("the server could not be told ({e}) — revoke “{}” from another computer or the web app (Team › Devices)", profile.app.device_name.as_deref().unwrap_or(&profile.device_id)))),
		}
	};
	devicekey::forget(&profile.device_protectors);
	devicekey::forget(&profile.pending_protectors);
	std::fs::remove_file(path)?;
	let _ = std::fs::remove_file(path.with_extension("tmp"));
	let _ = std::fs::remove_dir_all(path.with_extension("uploads"));
	Ok(SignedOut { server_told, warning })
}

/// Whether moving to `server` means signing out and enrolling again.
pub fn server_changes(profile: &DeviceProfile, server: &str) -> Result<bool, Error> {
	Ok(normalize_server(server)? != normalize_server(&profile.server)?)
}

/// Save the Settings window's choices into an enrolled profile.
pub fn save(path: &Path, app: &AppSettings) -> Result<DeviceProfile, Error> {
	app.check()?;
	let mut profile = session::load_profile(path)?;
	profile.app = app.clone();
	session::save_profile(path, &profile)?;
	Ok(profile)
}

/// The Advanced tab's sign-in fields, into an enrolled profile. (The server
/// itself is not among them: a new server is a new enrolment.)
pub fn save_sign_in(path: &Path, access_token_cmd: Option<String>, access_id: Option<String>, access_secret: Option<String>) -> Result<DeviceProfile, Error> {
	let mut profile = session::load_profile(path)?;
	let clean = |v: Option<String>| v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
	profile.access_token_cmd = clean(access_token_cmd);
	if let Some(cmd) = &profile.access_token_cmd {
		crate::scan::split_words(cmd)?;
	}
	match (clean(access_id), clean(access_secret)) {
		(Some(id), Some(secret)) => {
			profile.access_id = Some(id);
			profile.access_secret = Some(secret);
		}
		(None, None) => {
			profile.access_id = None;
			profile.access_secret = None;
		}
		// The id typed, the secret left blank: keep the stored secret.
		(Some(id), None) if profile.access_secret.is_some() => profile.access_id = Some(id),
		_ => return Err(Error::Config("an Access service token is an id AND a secret — give both, or clear both".into())),
	}
	session::save_profile(path, &profile)?;
	Ok(profile)
}

/// Keep a sign-in the browser handed over (40c) in an enrolled profile.
/// A shell already running picks it up when its own token runs out
/// (api.rs › stored_token).
pub fn save_access_token(path: &Path, token: &str) -> Result<DeviceProfile, Error> {
	let mut profile = session::load_profile(path)?;
	profile.access_token = Some(token.to_string());
	session::save_profile(path, &profile)?;
	Ok(profile)
}

/// Sign in through the browser and wait (the CLI's whole flow; the apps
/// drive signin::BrowserSignIn themselves, to show the page's address
/// and a Cancel). `open`: open the browser here.
pub fn sign_in_with_browser(server: &str, open: bool, timeout: std::time::Duration) -> Result<zeroize::Zeroizing<String>, Error> {
	let s = crate::signin::BrowserSignIn::start(server)?;
	eprintln!("Sign in in your browser: {}", s.url);
	if open {
		if let Err(e) = crate::signin::open_browser(&s.url) {
			eprintln!("{e}");
		}
	}
	s.wait(timeout, None)
}

// ── this computer and the others ────────────────────────────────────

/// One of the member's computers, as the Devices tab lists it.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
	pub id: String,
	pub name: String,
	pub platform: String,
	pub protection: Option<String>,
	pub created_at: Option<String>,
	pub last_seen: Option<String>,
	pub revoked: bool,
	/// This computer.
	pub this: bool,
}

/// The member's computers (revoked ones last).
pub fn devices(profile: &DeviceProfile) -> Result<Vec<Device>, Error> {
	let listed = api::Client::new(profile.clone()).devices().map_err(explain_refusal)?;
	let s = |d: &serde_json::Value, k: &str| d.get(k).and_then(|x| x.as_str()).map(str::to_string);
	let mut out: Vec<Device> = listed
		.as_array()
		.cloned()
		.unwrap_or_default()
		.iter()
		.map(|d| Device {
			id: s(d, "id").unwrap_or_default(),
			name: s(d, "name").unwrap_or_default(),
			platform: s(d, "platform").unwrap_or_default(),
			protection: s(d, "protection"),
			created_at: s(d, "createdAt"),
			last_seen: s(d, "lastSeen"),
			revoked: d.get("revoked").and_then(|x| x.as_bool()).unwrap_or(false),
			this: s(d, "id").as_deref() == Some(profile.device_id.as_str()),
		})
		.collect();
	out.sort_by_key(|d| (d.revoked, !d.this));
	Ok(out)
}

/// Revoke ANOTHER of the member's computers. This one signs out instead,
/// which also forgets its parts here.
pub fn revoke(profile: &DeviceProfile, device_id: &str) -> Result<(), Error> {
	if device_id == profile.device_id {
		return Err(Error::Config("that is this computer — use Sign out, which also forgets its key here".into()));
	}
	api::Client::new(profile.clone()).revoke_device(device_id).map_err(explain_refusal)
}

/// This computer's protection, in the words the server records.
pub fn protection(profile: &DeviceProfile) -> String {
	if profile.device_secret.is_some() {
		"file".into()
	} else {
		devicekey::label(&profile.device_protectors)
	}
}

/// One entry of the protection menu.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionChoice {
	/// What `--protect` takes (devicekey.rs).
	pub value: &'static str,
	pub label: &'static str,
	pub detail: &'static str,
}

/// The protection menu of this system, the recommended entry first. A
/// choice the machine cannot make (no TPM, say) is refused when chosen,
/// in the store's own words.
pub fn protection_choices() -> Vec<ProtectionChoice> {
	let c = |value, label, detail| ProtectionChoice { value, label, detail };
	if cfg!(windows) {
		vec![
			c("auto", "Automatic (recommended)", "The TPM and your Windows sign-in, whichever this computer has. Never asks at startup."),
			c("tpm+hello", "TPM and Windows Hello", "Your face, finger or PIN each time Gorani starts."),
			c("hello", "Windows Hello", "Your face, finger or PIN each time Gorani starts."),
			c("tpm", "TPM only", "Bound to this computer's chip."),
			c("dpapi", "Windows sign-in only", "Bound to your Windows account (DPAPI)."),
			c("file", "In the profile file (not recommended)", "Anyone who copies the profile, with your sign-in, can open this computer's copy."),
		]
	} else if cfg!(target_os = "macos") {
		vec![
			c("auto", "Automatic (recommended)", "The Secure Enclave and your login Keychain. Never asks at startup."),
			c("presence", "Touch ID each time", "The Secure Enclave, with Touch ID or your password each time Gorani starts."),
			c("enclave", "Secure Enclave only", "Bound to this Mac's chip."),
			c("keychain", "Login Keychain only", "Bound to your macOS account."),
			c("file", "In the profile file (not recommended)", "Anyone who copies the profile, with your sign-in, can open this computer's copy."),
		]
	} else {
		vec![
			c("auto", "Automatic (recommended)", "The TPM and your login keyring, whichever this machine has."),
			c("tpm+keyring", "TPM and keyring", "Both, or nothing."),
			c("tpm", "TPM only", "Bound to this machine's chip."),
			c("keyring", "Keyring only", "Bound to your login."),
			c("file", "In the profile file (not recommended)", "Anyone who copies the profile, with your sign-in, can open this computer's copy."),
		]
	}
}

/// One case in the Sync tab's area menu.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseChoice {
	pub id: String,
	/// The title, opened with the case key, or a word on why it is not
	/// shown: a grant whose signer this member has not verified is listed,
	/// and named as such (as `gorani-sync cases` does).
	pub title: String,
	pub kind: String,
	pub permission: String,
	pub closed: bool,
	pub verified: bool,
}

/// The cases granted to this member, for the Sync tab's area menu. Their
/// titles are sealed to each case's key, so this needs the unlocked
/// session the app holds while it runs.
pub fn cases(profile: &DeviceProfile, sess: &crate::Session) -> Result<Vec<CaseChoice>, Error> {
	use gorani_formats::formats::VaultPrivateKey;
	let client = api::Client::new(profile.clone());
	let listed = crate::area::listed_cases(&client).map_err(explain_refusal)?;
	let trust = crate::area::open_team(&client, sess, &profile.member)?.map(|(_, t)| t);
	let root = VaultPrivateKey::from_bytes(&sess.root).map_err(|_| Error::Open("root bundle"))?;
	Ok(listed
		.iter()
		.filter_map(|c| {
			let g = c.grant.as_ref()?;
			let opened = trust.as_ref().map(|t| crate::cases::open_case_key(&root, c, t));
			let (title, verified) = match opened {
				Some(Ok(k)) => (crate::cases::open_title(&k, c).unwrap_or_else(|| "(untitled)".into()), true),
				Some(Err(e)) => (format!("{} (not opened: {e})", c.id), false),
				None => (format!("{} (open the vault once in the web app to verify grants)", c.id), false),
			};
			Some(CaseChoice { id: c.id.clone(), title, kind: c.kind.clone(), permission: g.permission.clone(), closed: c.closed, verified })
		})
		.collect())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn an_old_profile_reads_with_nothing_set_and_writes_nothing_new() {
		let old = r#"{"server":"https://gorani.at.day","member":"jinu","deviceId":"d1","token":"t"}"#;
		let p: DeviceProfile = serde_json::from_str(old).unwrap();
		assert!(p.app.is_default());
		let back = serde_json::to_string(&p).unwrap();
		assert!(!back.contains("\"app\""), "an untouched profile keeps its old shape: {back}");
		let mut p = p;
		p.app.case = Some("c42".into());
		p.app.keep_local = true;
		let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
		assert_eq!(v["app"]["case"], "c42");
		assert_eq!(v["app"]["keepLocal"], true);
		assert!(v["app"].get("folder").is_none(), "unset options stay out of the file");
	}

	#[test]
	fn a_server_url_is_tidied_and_https_only() {
		assert_eq!(normalize_server("gorani.at.day").unwrap(), "https://gorani.at.day");
		assert_eq!(normalize_server(" HTTPS://Gorani.At.Day/ ").unwrap(), "https://gorani.at.day");
		assert_eq!(normalize_server("https://files.example:8443").unwrap(), "https://files.example:8443");
		assert_eq!(normalize_server("http://localhost:8787").unwrap(), "http://localhost:8787", "this machine's wrangler dev");
		assert_eq!(normalize_server("http://127.0.0.1:8787/").unwrap(), "http://127.0.0.1:8787");
		assert!(normalize_server("http://gorani.at.day").unwrap_err().to_string().contains("in the clear"));
		assert!(normalize_server("http://localhost.evil.example").is_err(), "only this machine itself is spared https");
		assert!(normalize_server("https://gorani.at.day/app?x=1").is_err(), "just the address");
		assert!(normalize_server("https://user@gorani.at.day").is_err());
		assert!(normalize_server("ftp://gorani.at.day").is_err());
		assert!(normalize_server("").is_err());
	}

	#[test]
	fn the_window_refuses_what_would_fail_later() {
		assert!(AppSettings::default().check().is_ok());
		assert!(AppSettings { case: Some("../x".into()), ..Default::default() }.check().is_err());
		assert!(AppSettings { folder: Some("relative\\dir".into()), ..Default::default() }.check().is_err());
		assert!(AppSettings { scan_command: Some("clamscan \"open".into()), ..Default::default() }.check().is_err());
		assert!(AppSettings { device_name: Some("two\nlines".into()), ..Default::default() }.check().is_err());
		assert!(check_device_name("Jinu's ThinkPad").is_ok());
		assert!(check_device_name(&"x".repeat(65)).is_err());
	}

	#[test]
	fn only_what_the_sync_reads_restarts_it() {
		let a = AppSettings::default();
		assert!(!a.restart_needed(&AppSettings { start_at_login: true, scan_command: Some("clamscan".into()), ..a.clone() }));
		assert!(a.restart_needed(&AppSettings { case: Some("c1".into()), ..a.clone() }));
		assert!(a.restart_needed(&AppSettings { paused: true, ..a.clone() }));
	}

	#[test]
	fn the_token_command_quotes_a_path_with_spaces() {
		let p = Path::new("/Program Files (x86)/cloudflared/cloudflared.exe");
		let cmd = token_command(p, "https://gorani.at.day/");
		assert_eq!(cmd, "\"/Program Files (x86)/cloudflared/cloudflared.exe\" access token -app=https://gorani.at.day");
		assert_eq!(crate::scan::split_words(&cmd).unwrap()[0], "/Program Files (x86)/cloudflared/cloudflared.exe", "and api.rs reads it back whole");
		assert_eq!(token_command(Path::new("/opt/homebrew/bin/cloudflared"), "https://h"), "/opt/homebrew/bin/cloudflared access token -app=https://h");
	}

	#[test]
	fn me_reads_the_account_or_says_there_is_none() {
		let v = serde_json::json!({ "email": "jinu@family.test", "member": { "id": "jinu", "name": "Jinu", "role": "lead", "active": true } });
		assert_eq!(me_of(&v).unwrap().member.unwrap().id, "jinu");
		let none = serde_json::json!({ "email": "stranger@example.com", "member": null });
		assert_eq!(me_of(&none).unwrap(), Me { email: "stranger@example.com".into(), member: None });
		assert!(me_of(&serde_json::json!({})).is_err());
	}

	#[test]
	fn access_refusals_say_sign_in_again() {
		assert!(explain_refusal(Error::Http(302, String::new())).to_string().contains("Sign in again"));
		assert!(explain_refusal(Error::Http(403, "<html>Forbidden".into())).to_string().contains("Access refused"));
		assert!(matches!(explain_refusal(Error::Http(403, "{\"error\":\"not yours\"}".into())), Error::Http(403, _)), "the Worker's own refusal passes through");
	}

	#[test]
	fn the_menu_starts_with_the_recommended_choice_and_every_value_parses() {
		let choices = protection_choices();
		assert_eq!(choices[0].value, "auto");
		for c in &choices {
			c.value.parse::<devicekey::Want>().unwrap_or_else(|e| panic!("{}: {e}", c.value));
		}
	}

	#[test]
	fn signing_out_without_a_profile_is_done_already() {
		let dir = std::env::temp_dir().join(format!("gorani-signout-{}", crate::new_item_id()));
		std::fs::create_dir_all(&dir).unwrap();
		let path = dir.join("profile.json");
		assert_eq!(sign_out(&path).unwrap(), SignedOut { server_told: true, warning: None });
		// A profile never enrolled (no device): nothing to tell, the file goes.
		let p = SignIn { server: "https://gorani.at.day".into(), ..Default::default() }.bare_profile();
		session::save_profile(&path, &p).unwrap();
		std::fs::create_dir_all(path.with_extension("uploads")).unwrap();
		assert_eq!(sign_out(&path).unwrap(), SignedOut { server_told: true, warning: None });
		assert!(!path.exists() && !path.with_extension("uploads").exists());
		std::fs::remove_dir_all(&dir).unwrap();
	}
}
