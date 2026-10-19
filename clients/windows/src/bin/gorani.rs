// Copyright 2026- Seongwoo Hong. All rights reserved.

//! `gorani.exe`: the Windows app — the tray icon and Settings (commit 40b,
//! src/app/). A window program: it opens no console of its own.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
	eprintln!("usage: gorani — the Windows app (tray icon and Settings); on Linux, gorani-sync and gorani-mount");
	std::process::exit(2);
}

#[cfg(windows)]
fn main() {
	std::process::exit(gorani_windows::app::run(std::env::args().skip(1).collect()));
}
