// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The macOS shell's bridge (commit 39c, docs/DESKTOP.md › 39c): the client
//! core's replica (clients/core/src/replica.rs) behind five C functions, for
//! the Swift File Provider extension — the same JSON protocol the CLI's
//! `replica` command speaks, so the Swift side has one thing to learn:
//!
//! ```c
//! GoraniSession *gorani_open(profile, case_id, dev_email, accept_unverified, &error);
//! GoraniSession *gorani_open_memory(area);          // tests: the in-memory twin
//! char *gorani_call(session, request_json);         // one request, one JSON answer
//! void gorani_free(char *);                         // every string this library returns
//! void gorani_close(session);
//! ```
//!
//! A session is safe to call from any thread (the extension's queues): one
//! call at a time, behind a mutex. Nothing here panics across the C
//! boundary — a panic inside a call is caught and answered as an error.
//!
//! A memory session also answers `mem.*` requests, so a test can play the
//! server: `mem.put`, `mem.dir`, `mem.edit`, `mem.move`, `mem.remove`,
//! `mem.sample`, `mem.readOnly`.

use std::ffi::{c_char, CStr, CString};
use std::path::Path;
use std::sync::Mutex;

use base64::Engine as _;
use gorani_client_core::replica::{self, HttpRemote, MemRemote};
use serde_json::{json, Value};

enum Inner {
	Http(HttpRemote),
	Mem(MemRemote),
}

pub struct GoraniSession {
	inner: Mutex<Inner>,
}

fn text(p: *const c_char) -> Option<String> {
	if p.is_null() {
		return None;
	}
	// SAFETY: the caller passes a NUL-terminated string (or NULL).
	unsafe { CStr::from_ptr(p) }.to_str().ok().map(str::to_string).filter(|s| !s.is_empty())
}

fn out(s: String) -> *mut c_char {
	// (A NUL inside a JSON answer cannot happen — serde escapes it — but if
	// it ever did, an error is answered rather than a truncated string.)
	CString::new(s).unwrap_or_else(|_| CString::new(r#"{"error":"an answer held a NUL","code":"io"}"#).expect("no NUL")).into_raw()
}

/// Open the area the profile names (`case_id` NULL: the member's own),
/// unlocked with this computer's enrolled copy. NULL on failure, with
/// `*error` set to a message the caller frees with `gorani_free`.
///
/// # Safety
/// The strings are NUL-terminated or NULL; `error` is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn gorani_open(profile: *const c_char, case_id: *const c_char, dev_email: *const c_char, accept_unverified: bool, error: *mut *mut c_char) -> *mut GoraniSession {
	let fail = |msg: String| {
		if !error.is_null() {
			// SAFETY: the caller's out-pointer.
			unsafe { *error = out(msg) };
		}
		std::ptr::null_mut()
	};
	let Some(profile) = text(profile) else { return fail("no profile path".into()) };
	let r = std::panic::catch_unwind(|| replica::connect(Path::new(&profile), text(case_id).as_deref(), None, text(dev_email).as_deref(), accept_unverified));
	match r {
		Ok(Ok(remote)) => Box::into_raw(Box::new(GoraniSession { inner: Mutex::new(Inner::Http(remote)) })),
		Ok(Err(e)) => fail(e.to_string()),
		Err(_) => fail("the client core panicked while opening".into()),
	}
}

/// A session over the in-memory twin (tests, and a demo without a server).
///
/// # Safety
/// `area` is NUL-terminated or NULL.
#[no_mangle]
pub unsafe extern "C" fn gorani_open_memory(area: *const c_char) -> *mut GoraniSession {
	let area = text(area).unwrap_or_else(|| "demo".into());
	Box::into_raw(Box::new(GoraniSession { inner: Mutex::new(Inner::Mem(MemRemote::new(&area))) }))
}

/// One request (JSON), one answer (JSON, freed with `gorani_free`).
///
/// # Safety
/// `session` came from `gorani_open*` and is not closed; `request` is NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn gorani_call(session: *mut GoraniSession, request: *const c_char) -> *mut c_char {
	if session.is_null() {
		return out(json!({ "error": "no session", "code": "io" }).to_string());
	}
	// SAFETY: a live session (the caller's promise).
	let s = unsafe { &*session };
	let req: Value = match text(request).map(|r| serde_json::from_str(&r)) {
		Some(Ok(v)) => v,
		_ => return out(json!({ "error": "the request is not JSON", "code": "denied" }).to_string()),
	};
	let answer = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
		let mut inner = match s.inner.lock() {
			Ok(g) => g,
			Err(p) => p.into_inner(),
		};
		match &mut *inner {
			Inner::Http(r) => replica::dispatch(r, &req),
			Inner::Mem(m) => mem_op(m, &req).unwrap_or_else(|| replica::dispatch(m, &req)),
		}
	}));
	out(answer.unwrap_or_else(|_| json!({ "error": "the client core panicked", "code": "io" })).to_string())
}

/// # Safety
/// `p` came from this library (or is NULL), and is freed once.
#[no_mangle]
pub unsafe extern "C" fn gorani_free(p: *mut c_char) {
	if !p.is_null() {
		// SAFETY: a CString this library made.
		drop(unsafe { CString::from_raw(p) });
	}
}

/// # Safety
/// `session` came from `gorani_open*` (or is NULL), and is closed once.
#[no_mangle]
pub unsafe extern "C" fn gorani_close(session: *mut GoraniSession) {
	if !session.is_null() {
		// SAFETY: a session this library made.
		drop(unsafe { Box::from_raw(session) });
	}
}

/// The test-only requests of a memory session: the server's side of a story.
fn mem_op(m: &mut MemRemote, req: &Value) -> Option<Value> {
	let s = |k: &str| req.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
	let data = || base64::engine::general_purpose::STANDARD.decode(s("data")).unwrap_or_default();
	let item = |i: Option<replica::Item>| i.map(|i| json!({ "item": i })).unwrap_or_else(|| json!({ "error": "no such item", "code": "not_found" }));
	Some(match s("op").as_str() {
		"mem.put" => item(Some(m.put(&s("parent"), &s("name"), &data()))),
		"mem.dir" => item(Some(m.put_dir(&s("parent"), &s("name")))),
		"mem.edit" => item(m.edit(&s("id"), &data())),
		"mem.move" => {
			m.move_to(&s("id"), &s("parent"), &s("name"));
			json!({})
		}
		"mem.remove" => {
			m.remove(&s("id"));
			json!({})
		}
		"mem.sample" => {
			m.mark_sample(&s("id"));
			json!({})
		}
		"mem.readOnly" => {
			m.read_only = req.get("why").and_then(|v| v.as_str()).map(str::to_string);
			json!({})
		}
		"mem.content" => match m.content(&s("id")) {
			Some(b) => json!({ "data": base64::engine::general_purpose::STANDARD.encode(b) }),
			None => json!({ "error": "no such item", "code": "not_found" }),
		},
		_ => return None,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	fn call(s: *mut GoraniSession, req: Value) -> Value {
		let r = CString::new(req.to_string()).unwrap();
		// SAFETY: a live session, a NUL-terminated request; the answer freed once.
		unsafe {
			let a = gorani_call(s, r.as_ptr());
			let v = serde_json::from_str(CStr::from_ptr(a).to_str().unwrap()).unwrap();
			gorani_free(a);
			v
		}
	}

	#[test]
	fn the_c_interface_speaks_the_replica_protocol() {
		let area = CString::new("ana").unwrap();
		// SAFETY: a NUL-terminated area name.
		let s = unsafe { gorani_open_memory(area.as_ptr()) };
		let d = call(s, json!({ "op": "mem.dir", "parent": "", "name": "docs" }));
		let id = d["item"]["id"].as_str().unwrap().to_string();
		let f = call(s, json!({ "op": "mem.put", "parent": id, "name": "a.txt", "data": "aGVsbG8=" }));
		let items = call(s, json!({ "op": "items" }));
		assert_eq!(items["items"].as_array().unwrap().len(), 2);
		assert_eq!(items["area"], "ana");
		let r = call(s, json!({ "op": "read", "id": f["item"]["id"], "version": 1, "offset": 0, "len": 5 }));
		assert_eq!(r["data"], "aGVsbG8=");
		assert_eq!(call(s, json!({ "op": "trash", "id": "nope" }))["code"], "not_found");
		// SAFETY: closed once.
		unsafe { gorani_close(s) };
	}

	#[test]
	fn a_bad_profile_is_an_error_not_a_crash() {
		let p = CString::new("/nonexistent/gorani.json").unwrap();
		let mut err: *mut c_char = std::ptr::null_mut();
		// SAFETY: NUL-terminated strings, a writable error pointer.
		let s = unsafe { gorani_open(p.as_ptr(), std::ptr::null(), std::ptr::null(), false, &mut err) };
		assert!(s.is_null());
		assert!(!err.is_null());
		// SAFETY: the error string this library made, freed once.
		unsafe { gorani_free(err) };
	}
}
