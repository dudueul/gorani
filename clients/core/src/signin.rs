// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Signing in through the person's own browser (commit 40c,
//! docs/DESKTOP.md › 40c), the app's half; worker/src/desktop.rs is the
//! server's. The same on Windows, macOS and the command line:
//!
//! ```text
//! BrowserSignIn::start(server)   listen on 127.0.0.1:<random port>, make a random state;
//!                                .url is the server's page that asks the person
//! (the app opens .url in the system browser)
//! .wait(timeout, cancel)         the one POST of {state, token} from that page: its
//!                                Origin must be the server, its state ours; the token
//!                                is the person's Access session, kept in the profile
//! ```
//!
//! The listener answers only on the loopback interface. It takes one sign-in,
//! refuses anything else (another path, a wrong state, a stranger's
//! Origin) without stopping, and gives up at the deadline or when told to.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::{settings, Error};

/// The longest request the listener reads: a form with a JWT fits in far less.
const MAX_REQUEST: usize = 32 * 1024;

pub struct BrowserSignIn {
	listener: TcpListener,
	state: String,
	origin: String,
	/// The page to open in the browser.
	pub url: String,
}

impl BrowserSignIn {
	/// Listen, and say where the browser should go.
	pub fn start(server: &str) -> Result<Self, Error> {
		let server = settings::normalize_server(server)?;
		let listener = TcpListener::bind(("127.0.0.1", 0))?;
		listener.set_nonblocking(true)?;
		let port = listener.local_addr()?.port();
		let state = crate::new_item_id() + &crate::new_item_id();
		let url = format!("{server}/api/v1/desktop/sign-in?port={port}&state={state}");
		Ok(Self { listener, state, origin: server, url })
	}

	/// Wait for the browser's hand-off. `cancel`: the window's Cancel.
	pub fn wait(self, timeout: Duration, cancel: Option<&AtomicBool>) -> Result<Zeroizing<String>, Error> {
		let deadline = Instant::now() + timeout;
		loop {
			if cancel.is_some_and(|c| c.load(Ordering::SeqCst)) {
				return Err(Error::Config("signing in was cancelled".into()));
			}
			if Instant::now() >= deadline {
				return Err(Error::Config("signing in took too long — press Sign in again".into()));
			}
			match self.listener.accept() {
				Ok((stream, peer)) if peer.ip().is_loopback() => {
					if let Some(token) = self.answer(stream) {
						return Ok(token);
					}
				}
				Ok(_) => {}
				Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(100)),
				Err(e) => return Err(e.into()),
			}
		}
	}

	/// One connection: the token if it is the hand-off, else None (answered
	/// with a refusal).
	fn answer(&self, mut stream: TcpStream) -> Option<Zeroizing<String>> {
		let _ = stream.set_nonblocking(false);
		let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
		let request = read_request(&mut stream);
		let outcome = request.as_ref().ok_or("an unreadable request").and_then(|r| judge(r, &self.state, &self.origin));
		match outcome {
			Ok(token) => {
				respond(&mut stream, 200, "Signed in", "Gorani on this computer is signed in. You can close this tab.");
				Some(token)
			}
			Err(why) => {
				let (status, title) = if request.as_ref().is_some_and(|r| r.path != "/gorani-sign-in") { (404, "Not here") } else { (400, "Not signed in") };
				respond(&mut stream, status, title, why);
				None
			}
		}
	}
}

/// What the listener read.
pub struct Request {
	pub method: String,
	pub path: String,
	pub origin: Option<String>,
	pub content_type: Option<String>,
	pub body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
	let mut buf = Vec::new();
	let mut chunk = [0u8; 4096];
	let head_end = loop {
		let n = stream.read(&mut chunk).ok()?;
		if n == 0 {
			return None;
		}
		buf.extend_from_slice(&chunk[..n]);
		if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
			break i + 4;
		}
		if buf.len() > MAX_REQUEST {
			return None;
		}
	};
	let head = std::str::from_utf8(&buf[..head_end]).ok()?;
	let mut lines = head.split("\r\n");
	let mut first = lines.next()?.split(' ');
	let (method, path) = (first.next()?.to_string(), first.next()?.to_string());
	let mut length = 0usize;
	let (mut origin, mut content_type) = (None, None);
	for line in lines {
		let Some((k, v)) = line.split_once(':') else { continue };
		match k.trim().to_ascii_lowercase().as_str() {
			"content-length" => length = v.trim().parse().ok()?,
			"origin" => origin = Some(v.trim().to_string()),
			"content-type" => content_type = Some(v.trim().to_ascii_lowercase()),
			_ => {}
		}
	}
	if length > MAX_REQUEST {
		return None;
	}
	let mut body = buf[head_end..].to_vec();
	while body.len() < length {
		let n = stream.read(&mut chunk).ok()?;
		if n == 0 {
			break;
		}
		body.extend_from_slice(&chunk[..n]);
	}
	body.truncate(length);
	Some(Request { method, path, origin, content_type, body })
}

/// Is this the server's page handing over our sign-in? The token, or why not.
pub fn judge(r: &Request, state: &str, origin: &str) -> Result<Zeroizing<String>, &'static str> {
	if r.path != "/gorani-sign-in" || r.method != "POST" {
		return Err("this address only takes Gorani's sign-in");
	}
	// The page is the server's: a browser names the page's origin on a
	// cross-origin form POST. Another site cannot hand this app a token.
	if r.origin.as_deref().map(|o| o.trim_end_matches('/')) != Some(origin) {
		return Err("this sign-in did not come from your team's server");
	}
	if !r.content_type.as_deref().is_some_and(|t| t.starts_with("application/x-www-form-urlencoded")) {
		return Err("not a sign-in form");
	}
	let form = form_fields(&r.body);
	let got = form.iter().find(|(k, _)| k == "state").map(|(_, v)| v.as_str()).unwrap_or_default();
	if !same(got.as_bytes(), state.as_bytes()) {
		return Err("this sign-in is not the one Gorani asked for — press Sign in in Gorani again");
	}
	let token = form.into_iter().find(|(k, _)| k == "token").map(|(_, v)| Zeroizing::new(v)).ok_or("the sign-in carried no token")?;
	if token.is_empty() || token.len() > 8192 || token.contains(char::is_whitespace) {
		return Err("the sign-in carried no usable token");
	}
	if crate::api::jwt_exp(&token).is_some_and(|exp| exp <= now_secs()) {
		return Err("that sign-in has expired — sign in again in the browser");
	}
	Ok(token)
}

fn now_secs() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Equal, in time that does not depend on where they differ.
fn same(a: &[u8], b: &[u8]) -> bool {
	a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `application/x-www-form-urlencoded`, decoded.
pub fn form_fields(body: &[u8]) -> Vec<(String, String)> {
	let text = String::from_utf8_lossy(body);
	text.split('&')
		.filter(|p| !p.is_empty())
		.map(|p| {
			let (k, v) = p.split_once('=').unwrap_or((p, ""));
			(decode(k), decode(v))
		})
		.collect()
}

fn decode(s: &str) -> String {
	let bytes = s.as_bytes();
	let mut out = Vec::with_capacity(bytes.len());
	let mut i = 0;
	while i < bytes.len() {
		match bytes[i] {
			b'+' => out.push(b' '),
			b'%' => {
				// Exactly two hex digits (from_str_radix alone would take "+1").
				let hex = bytes.get(i + 1..i + 3).filter(|h| h.iter().all(u8::is_ascii_hexdigit)).and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok());
				match hex {
					Some(b) => {
						out.push(b);
						i += 2;
					}
					None => out.push(b'%'),
				}
			}
			b => out.push(b),
		}
		i += 1;
	}
	String::from_utf8_lossy(&out).into_owned()
}

fn respond(stream: &mut TcpStream, status: u16, title: &str, text: &str) {
	let body = format!(
		"<!doctype html><meta charset=\"utf-8\"><title>{title} — Gorani</title><body style=\"font:15px/1.5 system-ui,sans-serif;max-width:34em;margin:4em auto;padding:0 1em\"><h1 style=\"font-size:1.3em\">{title}</h1><p>{text}</p></body>"
	);
	let reason = match status {
		200 => "OK",
		404 => "Not Found",
		_ => "Bad Request",
	};
	let head = format!(
		"HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
		body.len()
	);
	let _ = stream.write_all(head.as_bytes());
	let _ = stream.write_all(body.as_bytes());
	let _ = stream.flush();
}

/// Open `url` in the system browser (the command line's way; the apps
/// open it themselves).
pub fn open_browser(url: &str) -> Result<(), Error> {
	let mut c = if cfg!(windows) {
		let mut c = std::process::Command::new("rundll32");
		c.args(["url.dll,FileProtocolHandler", url]);
		c
	} else if cfg!(target_os = "macos") {
		let mut c = std::process::Command::new("open");
		c.arg(url);
		c
	} else {
		let mut c = std::process::Command::new("xdg-open");
		c.arg(url);
		c
	};
	crate::api::hide_console(&mut c);
	c.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
	c.spawn().map(|_| ()).map_err(|e| Error::Config(format!("the browser did not open ({e}) — open this address yourself: {url}")))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn post(origin: Option<&str>, body: &str) -> Request {
		Request { method: "POST".into(), path: "/gorani-sign-in".into(), origin: origin.map(str::to_string), content_type: Some("application/x-www-form-urlencoded".into()), body: body.as_bytes().to_vec() }
	}

	#[test]
	fn only_our_state_from_our_server_is_taken() {
		let state = "s".repeat(44);
		let ok = post(Some("https://gorani.at.day"), &format!("state={state}&token=ey.tok.sig"));
		assert_eq!(judge(&ok, &state, "https://gorani.at.day").unwrap().as_str(), "ey.tok.sig");
		assert!(judge(&post(Some("https://evil.example"), &format!("state={state}&token=t")), &state, "https://gorani.at.day").unwrap_err().contains("did not come from"));
		assert!(judge(&post(None, &format!("state={state}&token=t")), &state, "https://gorani.at.day").is_err(), "no Origin: refused");
		assert!(judge(&post(Some("https://gorani.at.day"), "state=wrong&token=t"), &state, "https://gorani.at.day").unwrap_err().contains("not the one"));
		assert!(judge(&post(Some("https://gorani.at.day"), &format!("state={state}")), &state, "https://gorani.at.day").is_err());
		let mut get = ok;
		get.method = "GET".into();
		assert!(judge(&get, &state, "https://gorani.at.day").is_err(), "a GET (a URL in the history) is never taken");
	}

	#[test]
	fn an_expired_sign_in_is_refused() {
		use base64::Engine;
		let b64 = |v: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
		let old = format!("{}.{}.sig", b64("{}"), b64(r#"{"exp":1000}"#));
		let state = "s".repeat(44);
		assert!(judge(&post(Some("https://h.example"), &format!("state={state}&token={old}")), &state, "https://h.example").unwrap_err().contains("expired"));
	}

	#[test]
	fn forms_decode_as_browsers_encode_them() {
		assert_eq!(form_fields(b"a=1&b=x%2By+z&c="), vec![("a".into(), "1".into()), ("b".into(), "x+y z".into()), ("c".into(), "".into())]);
		assert_eq!(form_fields(b"bad=%zz%"), vec![("bad".into(), "%zz%".into())]);
	}

	#[test]
	fn the_listener_takes_one_sign_in_over_real_sockets() {
		let s = BrowserSignIn::start("http://localhost:9").unwrap();
		let port: u16 = s.url.split("port=").nth(1).unwrap().split('&').next().unwrap().parse().unwrap();
		let state = s.url.split("state=").nth(1).unwrap().to_string();
		let send = |body: String, origin: &str| {
			let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
			write!(c, "POST /gorani-sign-in HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: {origin}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
			let mut answer = String::new();
			let _ = c.read_to_string(&mut answer);
			answer
		};
		let t = std::thread::spawn(move || s.wait(Duration::from_secs(10), None));
		// A stranger first: refused, and the listener keeps waiting.
		assert!(send(format!("state={state}&token=planted"), "https://evil.example").starts_with("HTTP/1.1 400"));
		assert!(send(format!("state={state}&token=ey.real.sig"), "http://localhost:9").starts_with("HTTP/1.1 200"));
		assert_eq!(t.join().unwrap().unwrap().as_str(), "ey.real.sig");
	}

	#[test]
	fn waiting_ends_when_cancelled() {
		let s = BrowserSignIn::start("https://gorani.at.day").unwrap();
		let stop = AtomicBool::new(true);
		assert!(s.wait(Duration::from_secs(5), Some(&stop)).unwrap_err().to_string().contains("cancelled"));
	}
}
