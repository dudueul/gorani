// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Signing a desktop app in through the person's own browser (commit 40c,
//! docs/DESKTOP.md › 40c).
//!
//! ```text
//! the app      listens on 127.0.0.1:<port> (a random port), makes a random state,
//!              opens the system browser at /api/v1/desktop/sign-in?port=…&state=…
//! Access       signs the person in, as for the web app; usually they already are
//! this page    "Sign Gorani in on this computer as jinu@…?": one button, no script
//! the button   a form POST of {state, token} to http://127.0.0.1:<port>/gorani-sign-in,
//!              the person's Access token being the one this request carried
//! the app      checks the state and the Origin, keeps the token, says "you can close
//!              this tab"
//! ```
//!
//! Why the browser and not a sign-in sheet in the app: identity providers
//! refuse sign-in inside an embedded web view (Google outright), and the
//! person's browser usually holds the session already, often a passkey too.
//! Why not cloudflared: nothing to install, and a sandboxed Mac app could
//! not read its token file anyway. One flow, the same on Windows, macOS and
//! the command line (clients/core/src/signin.rs).
//!
//! What protects it:
//! - **The button.** Nothing is sent without a click, so a website that
//!   opens this page in the person's browser hands nothing to anything
//!   listening on the port it named.
//! - **The state.** The app accepts only the state it made, so a token
//!   planted by someone else is refused.
//! - **POST, not a URL.** The token never sits in the address bar, the
//!   history, or a synced history.
//! - **Loopback only.** The form posts to `http://127.0.0.1`, which
//!   browsers treat as a secure context, and only to the port given.
//! - **The page.** `no-store`, `no-referrer`, no frames, no script.
//!   `form-action` names that one loopback address.
//!
//! The token handed over is the person's own Access session for this
//! application. The app holds it in its profile, as cloudflared holds its
//! own in a file, until it expires; then the app asks for a new sign-in.

use worker::{Headers, Request, Response, Result};

/// The page's port: an unprivileged one, as the app binds.
pub fn port_of(v: &str) -> Option<u16> {
	let n: u16 = v.parse().ok()?;
	(n >= 1024 && v.len() <= 5 && v.bytes().all(|b| b.is_ascii_digit())).then_some(n)
}

/// The app's state: 32–64 base64url characters, so it can sit in the page
/// unescaped.
pub fn state_of(v: &str) -> Option<&str> {
	(v.len() >= 32 && v.len() <= 64 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')).then_some(v)
}

/// A JWT's characters (or dev mode's stand-in), so the token, too, needs no escaping.
pub fn token_ok(t: &str) -> bool {
	!t.is_empty() && t.len() <= 8192 && t.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'='))
}

pub fn escape(s: &str) -> String {
	s.chars()
		.map(|c| match c {
			'&' => "&amp;".to_string(),
			'<' => "&lt;".to_string(),
			'>' => "&gt;".to_string(),
			'"' => "&quot;".to_string(),
			'\'' => "&#39;".to_string(),
			c => c.to_string(),
		})
		.collect()
}

const STYLE: &str = "body{font:15px/1.5 system-ui,sans-serif;max-width:34em;margin:4em auto;padding:0 1em;color:#1d1d1f}h1{font-size:1.3em}button{font:inherit;padding:.6em 1.4em;border-radius:8px;border:0;background:#1a73e8;color:#fff;cursor:pointer}p.small{color:#666;font-size:.9em}";

/// The page and its Content-Security-Policy.
pub fn page(email: &str, port: u16, state: &str, token: &str) -> (String, String) {
	use sha2::{Digest, Sha256};
	use base64::Engine;
	let style_hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(STYLE.as_bytes()));
	let target = format!("http://127.0.0.1:{port}/gorani-sign-in");
	let csp = format!("default-src 'none'; style-src 'sha256-{style_hash}'; form-action {target}; frame-ancestors 'none'; base-uri 'none'; object-src 'none'");
	let html = format!(
		"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Sign Gorani in on this computer</title><style>{STYLE}</style></head><body>\
<h1>Sign Gorani in on this computer?</h1>\
<p>The Gorani app on this computer asked to sign in as <b>{who}</b>.</p>\
<form method=\"post\" action=\"{target}\"><input type=\"hidden\" name=\"state\" value=\"{state}\"><input type=\"hidden\" name=\"token\" value=\"{token}\"><button type=\"submit\">Sign in Gorani</button></form>\
<p class=\"small\">If you did not just press <i>Sign in</i> in Gorani, close this tab. The sign-in goes only to the app on this computer, and lasts as long as your browser's.</p>\
</body></html>",
		who = escape(email),
	);
	(html, csp)
}

/// `GET /api/v1/desktop/sign-in?port=…&state=…`, Access already passed.
pub async fn sign_in(req: &Request, email: &str, dev_mode: bool) -> Result<Response> {
	let q = crate::files_store::urlquery(req.url()?.query().unwrap_or(""));
	let (Some(port), Some(state)) = (q.get("port").and_then(|p| port_of(p)), q.get("state").and_then(|s| state_of(s))) else {
		return crate::family::json_error(400, "port (1024–65535) and state (32–64 base64url characters): what the Gorani app opens this page with");
	};
	// The person's Access token: the one this very request carried, which
	// Access just checked and the Worker verified (auth.rs). In dev mode
	// (no Access) a stand-in the dev server ignores.
	let token = if dev_mode { format!("dev:{}", email.len()) } else { req.headers().get("CF-Access-JWT-Assertion")?.unwrap_or_default() };
	if !token_ok(&token) {
		return crate::family::json_error(401, "no Access sign-in on this request to hand to the app");
	}
	let (html, csp) = page(email, port, state, &token);
	let headers = Headers::new();
	headers.set("Content-Type", "text/html; charset=utf-8")?;
	headers.set("Content-Security-Policy", &csp)?;
	headers.set("Cache-Control", "no-store")?;
	headers.set("Referrer-Policy", "no-referrer")?;
	headers.set("X-Content-Type-Options", "nosniff")?;
	headers.set("X-Frame-Options", "DENY")?;
	Ok(Response::ok(html)?.with_headers(headers))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn only_what_the_app_sends_is_taken() {
		assert_eq!(port_of("54321"), Some(54321));
		assert_eq!(port_of("80"), None, "a privileged port is no app's");
		assert_eq!(port_of("65536"), None);
		assert_eq!(port_of("+5432"), None);
		assert_eq!(port_of("05432"), Some(5432));
		let s = "a".repeat(43);
		assert_eq!(state_of(&s), Some(s.as_str()));
		assert_eq!(state_of("short"), None);
		assert_eq!(state_of(&format!("{}\"><script>", "a".repeat(40))), None, "nothing that could leave the attribute");
		assert!(token_ok("eyJhbGciOiJSUzI1NiJ9.eyJlbWFpbCI6ImEifQ.c2ln"));
		assert!(!token_ok("a\"b"));
		assert!(!token_ok(""));
	}

	#[test]
	fn the_page_asks_first_and_posts_only_to_the_apps_port() {
		let (html, csp) = page("<jinu>@family.test", 54321, &"s".repeat(43), "ey.tok.sig");
		assert!(html.contains("action=\"http://127.0.0.1:54321/gorani-sign-in\""));
		assert!(html.contains("method=\"post\""), "the token in the body, never in a URL");
		assert!(html.contains("&lt;jinu&gt;@family.test") && !html.contains("<jinu>"), "the email escaped");
		assert!(!html.contains("<script"), "no script: the person presses the button");
		assert!(csp.contains("form-action http://127.0.0.1:54321/gorani-sign-in"));
		assert!(csp.contains("frame-ancestors 'none'") && csp.contains("default-src 'none'"));
		assert!(!csp.contains("unsafe-inline"), "the style by its hash");
	}
}
