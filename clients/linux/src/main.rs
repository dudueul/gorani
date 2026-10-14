// Copyright 2026- Seongwoo Hong. All rights reserved.

//! `gorani-mount` — the Linux shell (commit 33d, docs/DESKTOP.md): the
//! client core's sync engine (clients/core/src/engine.rs) behind FUSE.
//!
//! ```text
//! gorani-mount <dir> [--case C] [--profile P] [--accept-unverified]   mount until Ctrl-C / umount
//! gorani-mount script [--case C] …                                    the same engine, driven by
//!                                                                     JSON lines on stdin (tests,
//!                                                                     and machines without FUSE)
//! ```
//!
//! It unlocks with THIS computer's enrolled copy of the root (the profile
//! `gorani-sync setup` wrote): the server releases the wrapped copy only to
//! the device's token, and only the device secret opens it. `--secret`
//! types a password or recovery code instead.
//!
//! The adapter is thin on purpose: every decision (what a name is, whether
//! evidence may be read, what a write becomes) is the engine's, so the
//! Windows and macOS shells inherit them by calling the same methods.

mod fuse;

use std::io::{BufRead, Write};
use std::path::PathBuf;

use base64::Engine as _;
use gorani_client_core::engine::{Engine, FsError, Kind, ROOT};
use gorani_client_core::{api, area, session, Error};

fn main() {
	let args: Vec<String> = std::env::args().skip(1).collect();
	if let Err(e) = run(&args) {
		eprintln!("error: {e}");
		std::process::exit(1);
	}
}

const SWITCHES: &[&str] = &["accept-unverified"];

fn run(args: &[String]) -> Result<(), Error> {
	let mut flags = std::collections::BTreeMap::new();
	let mut pos = Vec::new();
	let mut i = 0;
	while i < args.len() {
		if let Some(name) = args[i].strip_prefix("--") {
			if SWITCHES.contains(&name) {
				flags.insert(name.to_string(), "1".to_string());
				i += 1;
				continue;
			}
			if let Some(v) = args.get(i + 1) {
				flags.insert(name.to_string(), v.clone());
				i += 2;
				continue;
			}
		}
		pos.push(args[i].clone());
		i += 1;
	}
	let flag = |k: &str| flags.get(k).cloned();
	let Some(target) = pos.first().cloned() else {
		eprintln!("usage: gorani-mount <dir|script> [--case C] [--profile P] [--secret S] [--dev-email E] [--accept-unverified]");
		std::process::exit(2);
	};

	let path = flag("profile").map(PathBuf::from).unwrap_or_else(|| {
		let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
		PathBuf::from(home).join(".gorani-sync.json")
	});
	let mut profile = session::load_profile(&path)?;
	if let Some(e) = flag("dev-email") {
		profile.dev_email = Some(e);
	}
	let sess = match flag("secret") {
		Some(s) => session::unlock(&profile, &s)?,
		None if session::has_device_copy(&profile) => session::unlock_device(&profile)?,
		None => return Err(Error::Config("this profile has no enrolled device copy — run gorani-sync setup, or pass --secret".into())),
	};
	let member = profile.member.clone();
	let client = api::Client::new(profile.clone());
	let opened = area::open_area(&client, &sess, &member, flag("case").as_deref())?;
	let name = opened.name.clone();
	drop(sess); // the root leaves memory: only the area's store key is needed from here
	let mut engine = Engine::new(api::Client::new(profile).in_area(&name), opened, flag("accept-unverified").is_some());
	engine.refresh()?;

	if target == "script" {
		return script(&mut engine);
	}
	fuse::mount(engine, &target, &name)
}

/// The engine over JSON lines: one request per line on stdin, one answer
/// per line on stdout — `{"op":"ls","path":"/"}` → `{"entries":[…]}`, and
/// any refusal as `{"error":"…","errno":N}`. Paths are `/`-separated from
/// the area's top.
fn script(engine: &mut Engine) -> Result<(), Error> {
	println!("{}", serde_json::json!({ "ready": engine.area().name, "readOnly": engine.read_only() }));
	let stdin = std::io::stdin();
	for line in stdin.lock().lines() {
		let line = line?;
		if line.trim().is_empty() {
			continue;
		}
		let answer = match serde_json::from_str::<serde_json::Value>(&line) {
			Ok(req) => step(engine, &req).unwrap_or_else(|e| serde_json::json!({ "error": e.to_string(), "errno": e.errno() })),
			Err(e) => serde_json::json!({ "error": format!("not JSON: {e}"), "errno": 22 }),
		};
		println!("{answer}");
		std::io::stdout().flush().ok();
	}
	Ok(())
}

fn split(path: &str) -> (&str, &str) {
	let p = path.trim_end_matches('/');
	match p.rfind('/') {
		Some(i) => (&p[..i], &p[i + 1..]),
		None => ("", p),
	}
}

fn step(e: &mut Engine, req: &serde_json::Value) -> Result<serde_json::Value, FsError> {
	let s = |k: &str| req[k].as_str().unwrap_or_default().to_string();
	let ino_of = |e: &Engine, p: &str| e.resolve(p).map(|n| n.ino).ok_or(FsError::NotFound);
	let b64 = base64::engine::general_purpose::STANDARD;
	Ok(match req["op"].as_str().unwrap_or_default() {
		"refresh" => serde_json::json!({ "changed": e.refresh()? }),
		"ls" => {
			let at = ino_of(e, &s("path"))?;
			let entries: Vec<serde_json::Value> = e.children(at)?.into_iter().map(|n| serde_json::json!({ "name": n.name, "kind": if n.kind == Kind::Dir { "dir" } else { "file" }, "size": n.size, "version": n.version })).collect();
			serde_json::json!({ "entries": entries })
		}
		"stat" => {
			let n = e.resolve(&s("path")).ok_or(FsError::NotFound)?;
			serde_json::json!({ "name": n.name, "kind": if n.kind == Kind::Dir { "dir" } else { "file" }, "size": n.size, "version": n.version, "id": n.id, "modified": n.modified })
		}
		"cat" => {
			let ino = ino_of(e, &s("path"))?;
			let fh = e.open(ino, false, false)?;
			let mut out = Vec::new();
			let r = (|| loop {
				let piece = e.read(fh, out.len() as u64, 1 << 20)?;
				if piece.is_empty() {
					return Ok::<(), FsError>(());
				}
				out.extend_from_slice(&piece);
			})();
			e.release(fh);
			r?;
			serde_json::json!({ "b64": b64.encode(&out), "size": out.len() })
		}
		"read" => {
			let ino = ino_of(e, &s("path"))?;
			let fh = e.open(ino, false, false)?;
			let r = e.read(fh, req["offset"].as_u64().unwrap_or(0), req["len"].as_u64().unwrap_or(0) as u32);
			e.release(fh);
			serde_json::json!({ "b64": b64.encode(r?) })
		}
		"put" => {
			// create or truncate, write, close — what `cp` does.
			let path = s("path");
			let data = b64.decode(s("b64")).map_err(|_| FsError::Denied("bad base64".into()))?;
			let fh = match e.resolve(&path).map(|n| n.ino) {
				Some(ino) => e.open(ino, true, true)?,
				None => {
					let (dir, name) = split(&path);
					let parent = ino_of(e, dir)?;
					e.create(parent, name)?.1
				}
			};
			let r = e.write(fh, 0, &data).and_then(|_| e.flush(fh));
			e.release(fh);
			r?;
			serde_json::json!({ "ok": true })
		}
		"open" => {
			let ino = ino_of(e, &s("path"))?;
			serde_json::json!({ "fh": e.open(ino, req["write"].as_bool().unwrap_or(false), req["truncate"].as_bool().unwrap_or(false))? })
		}
		"write" => {
			let data = b64.decode(s("b64")).map_err(|_| FsError::Denied("bad base64".into()))?;
			serde_json::json!({ "n": e.write(req["fh"].as_u64().unwrap_or(0), req["offset"].as_u64().unwrap_or(0), &data)? })
		}
		"close" => {
			let fh = req["fh"].as_u64().unwrap_or(0);
			let r = e.flush(fh);
			e.release(fh);
			r?;
			serde_json::json!({ "ok": true })
		}
		"truncate" => {
			let ino = ino_of(e, &s("path"))?;
			e.set_size(ino, None, req["size"].as_u64().unwrap_or(0))?;
			serde_json::json!({ "ok": true })
		}
		"mkdir" => {
			let path = s("path");
			let (dir, name) = split(&path);
			let parent = ino_of(e, dir)?;
			e.mkdir(parent, name)?;
			serde_json::json!({ "ok": true })
		}
		"rm" | "rmdir" => {
			let path = s("path");
			let (dir, name) = split(&path);
			let parent = ino_of(e, dir)?;
			if req["op"] == "rm" {
				e.unlink(parent, name)?;
			} else {
				e.rmdir(parent, name)?;
			}
			serde_json::json!({ "ok": true })
		}
		"mv" => {
			let (from, to) = (s("from"), s("to"));
			let ((fd, fname), (td, tname)) = (split(&from), split(&to));
			let (fp, tp) = (ino_of(e, fd)?, ino_of(e, td)?);
			e.rename(fp, fname, tp, tname)?;
			serde_json::json!({ "ok": true })
		}
		other => serde_json::json!({ "error": format!("no op {other:?}"), "errno": 22, "root": ROOT }),
	})
}
