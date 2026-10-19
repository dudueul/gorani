// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The Mac app's half of the bridge (commit 40d, docs/DESKTOP.md › 40d):
//! what its Settings window and menu-bar item ask, one JSON request, one
//! JSON answer, through `gorani_app` (lib.rs). Every decision is the core's
//! (gorani_client_core::settings), the same the Windows app calls.
//!
//! ```text
//! defaults                              the default server, the protection menu
//! status      {profile}                 enrolled?, server, member, name, protection,
//!                                       signed in?, the app's settings
//! normalize   {server}                  the server as the profile keeps it
//! signin.start {server}                 → {id, url}: open url in the browser
//! signin.wait {id, profile?}            blocks until the browser hands the sign-in over
//!                                       (≤ 5 min); enrolled: saved in the profile
//! signin.cancel {id}
//! whoami      {server, signin?|profile} → {email, member}
//! enrol       {profile, server, signin, deviceName, secret, protect}
//! signout     {profile}                 → {serverTold, warning}
//! save        {profile, app}            the Settings window's choices
//! saveSignIn  {profile, accessTokenCmd, accessId, accessSecret?}
//! devices     {profile}  ·  revoke {profile, id}  ·  protect {profile, want}
//! cases       {profile}                 the cases' titles (opens this Mac's copy)
//! ```
//!
//! The browser's token never crosses to Swift. `signin.wait` keeps it here,
//! under the sign-in's id, until `whoami` or `enrol` uses it (or saves it
//! into an enrolled profile), and it is wiped when dropped.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use gorani_client_core::settings::{self, AppSettings, SignIn};
use gorani_client_core::signin::BrowserSignIn;
use gorani_client_core::{devicekey, session, DeviceProfile, Error};
use serde_json::{json, Value};
use zeroize::Zeroizing;

/// Sign-ins under way: the listener, and its Cancel.
struct Pending {
	listener: Option<BrowserSignIn>,
	cancel: Arc<AtomicBool>,
}

fn pending() -> &'static Mutex<HashMap<String, Pending>> {
	static P: OnceLock<Mutex<HashMap<String, Pending>>> = OnceLock::new();
	P.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Tokens handed over and not used yet, by sign-in id.
fn tokens() -> &'static Mutex<HashMap<String, Zeroizing<String>>> {
	static T: OnceLock<Mutex<HashMap<String, Zeroizing<String>>>> = OnceLock::new();
	T.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
	m.lock().unwrap_or_else(|p| p.into_inner())
}

fn err(e: impl std::fmt::Display) -> Value {
	json!({ "error": e.to_string() })
}

fn s<'a>(req: &'a Value, k: &str) -> Option<&'a str> {
	req.get(k).and_then(|v| v.as_str()).filter(|v| !v.is_empty())
}

fn profile_of(req: &Value) -> Result<(std::path::PathBuf, DeviceProfile), Error> {
	let path = std::path::PathBuf::from(s(req, "profile").ok_or_else(|| Error::Config("no profile path".into()))?);
	let p = session::load_profile(&path)?;
	Ok((path, p))
}

/// One request of the app; errors answered as `{error}`.
pub fn call(req: &Value) -> Value {
	match s(req, "op").unwrap_or_default() {
		"defaults" => json!({
			"server": gorani_client_core::DEFAULT_SERVER,
			"protections": settings::protection_choices(),
		}),
		"status" => status(req),
		"normalize" => match settings::normalize_server(s(req, "server").unwrap_or_default()) {
			Ok(server) => json!({ "server": server }),
			Err(e) => err(e),
		},
		"signin.start" => match BrowserSignIn::start(s(req, "server").unwrap_or_default()) {
			Ok(b) => {
				let id = gorani_client_core::new_item_id();
				let url = b.url.clone();
				lock(pending()).insert(id.clone(), Pending { listener: Some(b), cancel: Arc::new(AtomicBool::new(false)) });
				json!({ "id": id, "url": url })
			}
			Err(e) => err(e),
		},
		"signin.wait" => signin_wait(req),
		"signin.cancel" => {
			if let Some(p) = lock(pending()).get(s(req, "id").unwrap_or_default()) {
				p.cancel.store(true, Ordering::SeqCst);
			}
			lock(tokens()).remove(s(req, "id").unwrap_or_default());
			json!({})
		}
		"whoami" => match sign_in_of(req) {
			Ok(si) => match settings::whoami(&si) {
				Ok(me) => json!(me),
				Err(e) => err(e),
			},
			Err(e) => err(e),
		},
		"enrol" => enrol(req),
		"signout" => match s(req, "profile").map(|p| settings::sign_out(Path::new(p))) {
			Some(Ok(o)) => json!(o),
			Some(Err(e)) => err(e),
			None => err("no profile path"),
		},
		"save" => {
			let app: AppSettings = match serde_json::from_value(req.get("app").cloned().unwrap_or_default()) {
				Ok(a) => a,
				Err(e) => return err(format!("the settings: {e}")),
			};
			match s(req, "profile").map(|p| settings::save(Path::new(p), &app)) {
				Some(Ok(p)) => json!({ "app": p.app }),
				Some(Err(e)) => err(e),
				None => err("no profile path"),
			}
		}
		"saveSignIn" => match s(req, "profile").map(|p| settings::save_sign_in(Path::new(p), s(req, "accessTokenCmd").map(str::to_string), s(req, "accessId").map(str::to_string), s(req, "accessSecret").map(str::to_string))) {
			Some(Ok(_)) => json!({}),
			Some(Err(e)) => err(e),
			None => err("no profile path"),
		},
		"devices" => match profile_of(req).and_then(|(_, p)| settings::devices(&p)) {
			Ok(d) => json!({ "devices": d }),
			Err(e) => err(e),
		},
		"revoke" => match profile_of(req).and_then(|(_, p)| settings::revoke(&p, s(req, "id").unwrap_or_default())) {
			Ok(()) => json!({}),
			Err(e) => err(e),
		},
		"protect" => {
			let want: devicekey::Want = match s(req, "want").unwrap_or("auto").parse() {
				Ok(w) => w,
				Err(e) => return err(e),
			};
			match profile_of(req).and_then(|(path, mut p)| session::protect(&path, &mut p, want, &Default::default(), None)) {
				Ok(label) => json!({ "protection": label }),
				Err(e) => err(e),
			}
		}
		"cases" => match profile_of(req).and_then(|(_, p)| session::unlock_device(&p).and_then(|sess| settings::cases(&p, &sess))) {
			Ok(c) => json!({ "cases": c }),
			Err(e) => err(e),
		},
		other => err(format!("no app request “{other}”")),
	}
}

fn status(req: &Value) -> Value {
	let Some(path) = s(req, "profile") else { return err("no profile path") };
	match session::load_profile(Path::new(path)) {
		Ok(p) if session::has_device_copy(&p) => json!({
			"enrolled": true,
			"server": p.server,
			"member": p.member,
			"deviceName": p.app.device_name.clone().unwrap_or_else(|| p.device_id.clone()),
			"protection": settings::protection(&p),
			"signedIn": SignIn::of(&p).signed_in(),
			"accessTokenCmd": p.access_token_cmd,
			"accessId": p.access_id,
			"hasAccessSecret": p.access_secret.is_some(),
			"app": p.app,
		}),
		_ => json!({ "enrolled": false, "server": gorani_client_core::DEFAULT_SERVER }),
	}
}

fn signin_wait(req: &Value) -> Value {
	let id = s(req, "id").unwrap_or_default().to_string();
	let (listener, cancel) = match lock(pending()).get_mut(&id) {
		Some(p) => (p.listener.take(), p.cancel.clone()),
		None => return err("no such sign-in — press Sign in again"),
	};
	let Some(listener) = listener else { return err("this sign-in is already being waited for") };
	// (The lock is not held while waiting: Cancel takes it.)
	let r = listener.wait(Duration::from_secs(300), Some(&cancel));
	lock(pending()).remove(&id);
	let token = match r {
		Ok(t) => t,
		Err(e) => return err(e),
	};
	if let Some(path) = s(req, "profile").filter(|p| session::load_profile(Path::new(p)).is_ok_and(|p| session::has_device_copy(&p))) {
		// Enrolled: signed in again, kept in the profile; the extension
		// picks it up when its own token runs out (api.rs › stored_token).
		return match settings::save_access_token(Path::new(path), &token) {
			Ok(_) => json!({ "saved": true }),
			Err(e) => err(e),
		};
	}
	lock(tokens()).insert(id, token);
	json!({ "saved": false })
}

/// The sign-in a request names: an enrolled profile's, or a server with
/// the token of a finished browser sign-in.
fn sign_in_of(req: &Value) -> Result<SignIn, Error> {
	if let Ok((_, p)) = profile_of(req) {
		if session::has_device_copy(&p) {
			return Ok(SignIn::of(&p));
		}
	}
	let server = settings::normalize_server(s(req, "server").unwrap_or_default())?;
	let token = s(req, "signin").and_then(|id| lock(tokens()).get(id).map(|t| t.to_string()));
	Ok(SignIn { server, access_token: token, dev_email: s(req, "devEmail").map(str::to_string), ..Default::default() })
}

fn enrol(req: &Value) -> Value {
	let Some(path) = s(req, "profile") else { return err("no profile path") };
	let si = match sign_in_of(&json!({ "server": req.get("server"), "signin": req.get("signin"), "devEmail": req.get("devEmail") })) {
		Ok(si) => si,
		Err(e) => return err(e),
	};
	let want: devicekey::Want = match s(req, "protect").unwrap_or("auto").parse() {
		Ok(w) => w,
		Err(e) => return err(e),
	};
	let secret = Zeroizing::new(s(req, "secret").unwrap_or_default().to_string());
	if secret.is_empty() {
		return err("type your vault password or recovery code: it opens your key once, on this Mac");
	}
	let e = settings::Enrolment {
		sign_in: si,
		member: None,
		device_name: s(req, "deviceName").unwrap_or("this Mac").to_string(),
		secret: &secret,
		protect: want,
		tpm_options: Default::default(),
		device_secret: s(req, "deviceSecret").map(str::to_string),
		app: AppSettings::default(),
	};
	match settings::enrol(Path::new(path), e) {
		Ok(p) => {
			if let Some(id) = s(req, "signin") {
				lock(tokens()).remove(id);
			}
			json!({ "enrolled": true, "member": p.member, "protection": settings::protection(&p) })
		}
		Err(e) => err(e),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_app_asks_and_the_core_answers() {
		let d = call(&json!({ "op": "defaults" }));
		assert_eq!(d["server"], gorani_client_core::DEFAULT_SERVER);
		assert_eq!(d["protections"][0]["value"], "auto");
		assert_eq!(call(&json!({ "op": "normalize", "server": "Gorani.Example/" }))["server"], "https://gorani.example");
		assert!(call(&json!({ "op": "normalize", "server": "http://gorani.example" }))["error"].as_str().unwrap().contains("in the clear"));
		let missing = std::env::temp_dir().join(format!("gorani-app-{}.json", std::process::id()));
		assert_eq!(call(&json!({ "op": "status", "profile": missing }))["enrolled"], false);
		assert!(call(&json!({ "op": "nope" }))["error"].as_str().unwrap().contains("no app request"));
		assert!(call(&json!({ "op": "enrol", "profile": missing, "server": "https://h.example" }))["error"].as_str().unwrap().contains("vault password"));
	}

	#[test]
	fn a_sign_in_can_be_cancelled_and_its_id_is_then_gone() {
		let started = call(&json!({ "op": "signin.start", "server": "https://gorani.at.day" }));
		let id = started["id"].as_str().unwrap().to_string();
		assert!(started["url"].as_str().unwrap().starts_with("https://gorani.at.day/api/v1/desktop/sign-in?port="));
		call(&json!({ "op": "signin.cancel", "id": id }));
		assert!(call(&json!({ "op": "signin.wait", "id": id }))["error"].as_str().unwrap().contains("cancelled"));
		assert!(call(&json!({ "op": "signin.wait", "id": id }))["error"].as_str().unwrap().contains("no such sign-in"));
	}
}
