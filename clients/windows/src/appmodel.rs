// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The Windows app's words and choices (commit 40b), apart from any
//! window. They have no Win32 in them, so they are tested on every system.
//! The window code (app/) only draws what this decides.

use std::path::{Path, PathBuf};

/// Where the app's sync stands, as the tray icon and the Settings window
/// say it.
#[derive(Clone, Debug, PartialEq)]
pub enum Status {
	/// No enrolled profile: Settings › Account enrols this computer.
	NotEnrolled,
	/// Enrolled, but no folder chosen yet: Settings › Sync.
	NoFolder,
	/// Paused from the tray.
	Paused,
	/// Unlocking and registering the folder.
	Connecting,
	/// The folder is live in Explorer.
	Running { folder: String },
	/// Stopped (Quit, or before a restart).
	Stopped,
	/// It could not start, in the core's words.
	Failed(String),
}

impl Status {
	/// The first line of the tray menu and the Settings window's foot.
	pub fn line(&self) -> String {
		match self {
			Status::NotEnrolled => "Not set up — open Settings to enrol this computer".into(),
			Status::NoFolder => "Choose a folder in Settings › Sync".into(),
			Status::Paused => "Paused".into(),
			Status::Connecting => "Starting…".into(),
			Status::Running { folder } => format!("Up to date in {folder}"),
			Status::Stopped => "Stopped".into(),
			Status::Failed(why) => format!("Not syncing: {why}"),
		}
	}

	/// The tray icon's tooltip: at most 127 characters (the shell's limit),
	/// cut on a character boundary.
	pub fn tip(&self) -> String {
		clip(&format!("Gorani — {}", self.line()), 127)
	}

	/// Whether the tray's Open folder has a folder to open.
	pub fn folder(&self) -> Option<&str> {
		match self {
			Status::Running { folder } => Some(folder),
			_ => None,
		}
	}
}

/// `text` cut to at most `max` UTF-16 units, an ellipsis at the end when cut.
pub fn clip(text: &str, max: usize) -> String {
	if text.encode_utf16().count() <= max {
		return text.to_string();
	}
	let mut out = String::new();
	let mut used = 0;
	for c in text.chars() {
		if used + c.len_utf16() + 1 > max {
			break;
		}
		out.push(c);
		used += c.len_utf16();
	}
	out.push('…');
	out
}

/// The folder Settings suggests: `<home>\Gorani` for your own files, or
/// `<home>\Gorani — <case>` for a case, its title made safe for a folder
/// name (Windows refuses `\ / : * ? " < > |` and a trailing dot or space).
pub fn default_folder(home: &Path, case_title: Option<&str>) -> PathBuf {
	match case_title.map(folder_safe).filter(|t| !t.is_empty()) {
		Some(t) => home.join(format!("Gorani — {t}")),
		None => home.join("Gorani"),
	}
}

fn folder_safe(name: &str) -> String {
	let cleaned: String = name.chars().map(|c| if matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || c.is_control() { ' ' } else { c }).collect();
	let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
	clip(cleaned.trim_end_matches(['.', ' ']), 60).trim_end_matches(['.', ' ', '…']).to_string()
}

/// A device's "last seen", as the Devices list shows it: the date and the
/// minute, in UTC as the server records it.
pub fn seen(at: Option<&str>) -> String {
	match at {
		Some(t) if t.len() >= 16 => format!("{} {} UTC", &t[..10], &t[11..16]),
		Some(t) => t.to_string(),
		None => "never".into(),
	}
}

/// What the Account tab says about an enrolled computer.
pub fn enrolled_line(name: &str, server: &str, protection: &str) -> String {
	let protection = if protection.is_empty() { "(not recorded)" } else { protection };
	format!("This computer is enrolled as “{name}” on {server}. Its key part is protected by: {protection}.")
}

/// The question asked before a new server URL signs this computer out.
pub fn change_server_question(from: &str, to: &str) -> String {
	format!(
		"Use {to} instead of {from}?\n\nA computer is enrolled on one server. Gorani will sign this computer out of {from} (its copy of your key there is deleted, and the folder is removed from this computer — your files stay on the server), then you enrol it on {to} with your vault password."
	)
}

/// The question asked before signing out.
pub fn sign_out_question(server: &str, folder: Option<&str>) -> String {
	let folder = match folder {
		Some(f) => format!(" The folder {f} is removed from this computer; your files stay on the server."),
		None => String::new(),
	};
	format!("Sign this computer out of {server}?\n\nIts copy of your key on the server is deleted, and its key parts here are forgotten.{folder} To use Gorani here again, enrol it with your vault password.")
}

/// One image of an .ico file, the one nearest `want` pixels (a larger one
/// before a smaller): `(offset, length, size)`. None for a file that is
/// not an icon, or an entry that runs past its end.
pub fn ico_entry(ico: &[u8], want: u32) -> Option<(usize, usize, u32)> {
	let u16le = |at: usize| ico.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
	let u32le = |at: usize| ico.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
	if u16le(0)? != 0 || u16le(2)? != 1 {
		return None;
	}
	let count = u16le(4)? as usize;
	let mut best: Option<(usize, usize, u32)> = None;
	for i in 0..count {
		let e = 6 + i * 16;
		let size = match *ico.get(e)? {
			0 => 256,
			n => n as u32,
		};
		let (len, off) = (u32le(e + 8)? as usize, u32le(e + 12)? as usize);
		if off.checked_add(len).is_none_or(|end| end > ico.len()) {
			continue;
		}
		let better = match best {
			None => true,
			Some((_, _, b)) => {
				let fits = |s: u32| s >= want;
				match (fits(size), fits(b)) {
					(true, false) => true,
					(false, true) => false,
					(true, true) => size < b,
					(false, false) => size > b,
				}
			}
		};
		if better {
			best = Some((off, len, size));
		}
	}
	best
}

/// Whether `folder` may become Gorani's folder: one that does not exist
/// yet, an empty one, or the one already in use. Never a folder already
/// holding files: signing out removes what Gorani put there, and it must
/// never be anyone's own files.
pub fn folder_ok(folder: &Path, current: Option<&Path>) -> Result<(), String> {
	if !folder.is_absolute() {
		return Err(format!("the folder must be a full path (“{}” is not)", folder.display()));
	}
	if current.is_some_and(|c| c == folder) {
		return Ok(());
	}
	match std::fs::read_dir(folder) {
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
		Err(e) => Err(format!("{}: {e}", folder.display())),
		Ok(mut entries) => match entries.next() {
			None => Ok(()),
			Some(_) => Err(format!("{} already holds files — choose a new or empty folder (Gorani removes its folder when this computer signs out)", folder.display())),
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_tip_fits_the_shells_limit() {
		let long = Status::Failed("x".repeat(400));
		let tip = long.tip();
		assert!(tip.encode_utf16().count() <= 127, "{}", tip.len());
		assert!(tip.ends_with('…'));
		assert_eq!(Status::Paused.tip(), "Gorani — Paused");
		// A character outside the BMP counts two units, and is never split.
		let emoji = Status::Failed("😀".repeat(100)).tip();
		assert!(emoji.encode_utf16().count() <= 127);
	}

	#[test]
	fn a_case_gets_a_folder_named_for_it() {
		let home = Path::new("C:/Users/jinu");
		assert_eq!(default_folder(home, None), home.join("Gorani"));
		assert_eq!(default_folder(home, Some("Operation: Blue/Green?")), home.join("Gorani — Operation Blue Green"));
		assert_eq!(default_folder(home, Some("ends with a dot.")), home.join("Gorani — ends with a dot"));
		assert_eq!(default_folder(home, Some("***")), home.join("Gorani"), "nothing left: the plain name");
	}

	#[test]
	fn the_tray_takes_the_icon_nearest_its_size() {
		let ico = include_bytes!("../packaging/gorani.ico");
		let (off, len, size) = ico_entry(ico, 16).expect("gorani.ico has images");
		assert!(size >= 16 && off + len <= ico.len());
		let (_, _, big) = ico_entry(ico, 32).unwrap();
		assert!(big >= 32);
		assert_eq!(ico_entry(b"not an icon", 16), None);
		// An entry claiming bytes past the end is skipped, never read.
		let mut bad = vec![0, 0, 1, 0, 1, 0];
		bad.extend([16, 16, 0, 0, 1, 0, 32, 0]);
		bad.extend(1000u32.to_le_bytes());
		bad.extend(22u32.to_le_bytes());
		assert_eq!(ico_entry(&bad, 16), None);
	}

	#[test]
	fn gorani_never_takes_a_folder_that_holds_files() {
		let base = std::env::temp_dir().join(format!("gorani-folder-{}", std::process::id()));
		let full = base.join("full");
		std::fs::create_dir_all(&full).unwrap();
		std::fs::write(full.join("mine.txt"), "someone's own file").unwrap();
		assert!(folder_ok(&base.join("new"), None).is_ok(), "a new folder");
		std::fs::create_dir_all(base.join("empty")).unwrap();
		assert!(folder_ok(&base.join("empty"), None).is_ok(), "an empty one");
		assert!(folder_ok(&full, None).unwrap_err().contains("already holds files"));
		assert!(folder_ok(&full, Some(&full)).is_ok(), "the folder already in use");
		assert!(folder_ok(Path::new("relative"), None).is_err());
		std::fs::remove_dir_all(&base).unwrap();
	}

	#[test]
	fn the_words_name_what_happens() {
		assert_eq!(seen(Some("2026-10-19T08:30:12.345Z")), "2026-10-19 08:30 UTC");
		assert_eq!(seen(None), "never");
		assert!(change_server_question("https://a.example", "https://b.example").contains("sign this computer out of https://a.example"));
		assert!(sign_out_question("https://a.example", Some("C:\\Users\\jinu\\Gorani")).contains("files stay on the server"));
		assert_eq!(Status::Running { folder: "C:\\G".into() }.folder(), Some("C:\\G"));
		assert_eq!(Status::Paused.folder(), None);
	}
}
