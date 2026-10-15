// Copyright 2026- Seongwoo Hong. All rights reserved.

//! `gorani-cloud` — the Windows shell (commit 39b, docs/DESKTOP.md › 39b).
//!
//! ```text
//! gorani-cloud <folder> [--case C] [--profile P] [--accept-unverified] [--keep-local] [--verbose]
//!                                    the area as a Cloud Files folder, until Ctrl-C
//! gorani-cloud free <file>           drop one file's local bytes (it stays listed)
//! gorani-cloud unregister <folder>   the folder stops being a sync root
//! ```
//!
//! It unlocks with THIS computer's enrolled copy (the profile `gorani-sync
//! setup` wrote). Explorer shows every file at once; a file's bytes are
//! fetched and decrypted when something reads it, and dropped again when
//! the shell stops — the plaintext lives on this disk only while it runs
//! (`--keep-local` keeps it: then the disk's own encryption, BitLocker, is
//! what protects it).

#[cfg(not(windows))]
fn main() {
	eprintln!("gorani-cloud is the Windows shell — on Linux, gorani-mount; on macOS, the Gorani app");
	std::process::exit(2);
}

#[cfg(windows)]
fn main() {
	if let Err(e) = run() {
		eprintln!("error: {e}");
		std::process::exit(1);
	}
}

#[cfg(windows)]
fn run() -> Result<(), String> {
	use std::path::PathBuf;
	use std::sync::{Arc, Mutex};
	use gorani_windows::{cf, provider};

	let args: Vec<String> = std::env::args().skip(1).collect();
	const SWITCHES: &[&str] = &["accept-unverified", "keep-local", "verbose"];
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
	match pos.first().map(String::as_str) {
		Some("free") => {
			let file = pos.get(1).ok_or("gorani-cloud free <file>")?;
			cf::dehydrate(std::path::Path::new(file)).map_err(|e| e.to_string())?;
			println!("{file}: its local bytes are gone; it stays listed");
			Ok(())
		}
		Some("unregister") => {
			let dir = pos.get(1).ok_or("gorani-cloud unregister <folder>")?;
			gorani_windows::shell::unregister(std::path::Path::new(dir))?;
			println!("{dir} is no longer a Gorani folder");
			Ok(())
		}
		Some(folder) => {
			let profile = flag("profile").map(PathBuf::from).unwrap_or_else(|| {
				let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_else(|_| ".".into());
				PathBuf::from(home).join(".gorani-sync.json")
			});
			let remote = gorani_client_core::replica::connect(&profile, flag("case").as_deref(), None, flag("dev-email").as_deref(), flag("accept-unverified").is_some()).map_err(|e| e.to_string())?;
			let remote: Arc<Mutex<dyn gorani_client_core::replica::Remote + Send>> = Arc::new(Mutex::new(remote));
			let running = provider::start(std::path::Path::new(folder), remote, provider::Options { poll: Some(std::time::Duration::from_secs(3)), keep_local: flag("keep-local").is_some(), verbose: flag("verbose").is_some() })?;
			println!("serving {} — Ctrl-C to stop", running.root().display());
			let (tx, rx) = std::sync::mpsc::channel();
			ctrlc_wait(tx);
			let _ = rx.recv();
			println!("stopping: sending what is left{}", if flag("keep-local").is_some() { "" } else { ", dropping local bytes" });
			running.stop();
			Ok(())
		}
		None => Err("usage: gorani-cloud <folder> [--case C] [--profile P] [--accept-unverified] [--keep-local] [--verbose] | free <file> | unregister <folder>".into()),
	}
}

/// Ctrl-C (or the console closing) → one message on `tx`.
#[cfg(windows)]
fn ctrlc_wait(tx: std::sync::mpsc::Sender<()>) {
	use std::sync::OnceLock;
	use windows::Win32::System::Console::SetConsoleCtrlHandler;
	static TX: OnceLock<std::sync::Mutex<std::sync::mpsc::Sender<()>>> = OnceLock::new();
	let _ = TX.set(std::sync::Mutex::new(tx));
	unsafe extern "system" fn handler(_: u32) -> windows::core::BOOL {
		if let Some(t) = TX.get() {
			let _ = t.lock().map(|t| t.send(()));
		}
		true.into()
	}
	// SAFETY: a handler with the signature the system expects, for the process's life.
	let _ = unsafe { SetConsoleCtrlHandler(Some(handler), true) };
}
