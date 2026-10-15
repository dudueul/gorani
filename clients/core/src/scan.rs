// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The local scanner hook (commit 38c, docs/REQUESTS.md › Scanning):
//! `gorani-sync accept --scan "<command>"` puts an item's DECRYPTED bytes in
//! a private temporary file, runs the command on it, and refuses to file
//! the item when the command exits non-zero.
//!
//! Why here and not on a server: the server holds ciphertext only. The one
//! place plaintext exists is the accepting member's machine — so the only
//! scanner that can look at the bytes is one that runs there.
//!
//! ```text
//! the file   <temp>/gorani-scan-<random>/<item>-<name, sanitised>; the directory 0700, the
//!            file 0600 (Unix) — created fresh, never an existing path; removed when the
//!            scan ends, whatever the outcome (a scanner that deletes or quarantines it is fine)
//! the command split into words (quotes group, no other shell syntax), run WITHOUT a shell:
//!            no globbing, no pipes, no `$(…)` — nothing in an item's name can become code.
//!            `{}` in a word is replaced by the file's path; with no `{}`, the path is the
//!            last argument. ClamAV: --scan "clamscan --no-summary"
//! the verdict exit 0 → clean; anything else (ClamAV: 1 found, 2 an error) → refused: an
//!            error is not a pass
//! ```
//!
//! The honest limit: the plaintext touches this machine's disk for the
//! length of the scan. That is what a scanner needs — and why the hook is
//! asked for, never on by default.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Error;

/// Split a command line into words: whitespace separates, single or double
/// quotes group (no escapes, no variables — not a shell, on purpose).
pub fn split_words(cmd: &str) -> Result<Vec<String>, Error> {
	let mut out = Vec::new();
	let mut cur = String::new();
	let mut quote: Option<char> = None;
	let mut any = false;
	for c in cmd.chars() {
		match (quote, c) {
			(Some(q), c) if c == q => quote = None,
			(Some(_), c) => cur.push(c),
			(None, '"' | '\'') => {
				quote = Some(c);
				any = true;
			}
			(None, c) if c.is_whitespace() => {
				if any || !cur.is_empty() {
					out.push(std::mem::take(&mut cur));
				}
				any = false;
			}
			(None, c) => cur.push(c),
		}
	}
	if quote.is_some() {
		return Err(Error::Config("--scan: an unclosed quote".into()));
	}
	if any || !cur.is_empty() {
		out.push(cur);
	}
	if out.is_empty() {
		return Err(Error::Config("--scan: a command to run, e.g. \"clamscan --no-summary\"".into()));
	}
	Ok(out)
}

/// The words with the file's path put in: every `{}` replaced, or appended.
pub fn with_path(words: &[String], path: &Path) -> Vec<String> {
	let p = path.to_string_lossy();
	if words.iter().any(|w| w.contains("{}")) {
		words.iter().map(|w| w.replace("{}", &p)).collect()
	} else {
		words.iter().cloned().chain(std::iter::once(p.to_string())).collect()
	}
}

/// A file name that is safe on every platform and says what it was.
fn sanitised(name: &str) -> String {
	let s: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' }).collect();
	let s = s.trim_start_matches('.');
	s.chars().take(80).collect::<String>()
}

/// A private directory holding one file, removed when dropped.
pub struct PrivateFile {
	dir: PathBuf,
	pub path: PathBuf,
	file: Option<std::fs::File>,
}

impl PrivateFile {
	pub fn create(item: &str, name: &str) -> Result<Self, Error> {
		let dir = std::env::temp_dir().join(format!("gorani-scan-{}", crate::new_item_id()));
		#[cfg(unix)]
		{
			use std::os::unix::fs::DirBuilderExt;
			std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
		}
		#[cfg(not(unix))]
		std::fs::create_dir(&dir)?;
		let path = dir.join(format!("{item}-{}", sanitised(name)));
		let mut opts = std::fs::OpenOptions::new();
		opts.write(true).create_new(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			opts.mode(0o600);
		}
		let file = match opts.open(&path) {
			Ok(f) => f,
			Err(e) => {
				let _ = std::fs::remove_dir_all(&dir);
				return Err(e.into());
			}
		};
		Ok(Self { dir, path, file: Some(file) })
	}

	pub fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
		self.file.as_mut().ok_or(Error::Config("the scan file is closed".into()))?.write_all(bytes)?;
		Ok(())
	}

	/// Flush and close the file (the scanner opens it by path).
	pub fn finish(&mut self) -> Result<(), Error> {
		if let Some(mut f) = self.file.take() {
			f.flush()?;
			f.sync_all()?;
		}
		Ok(())
	}
}

impl Drop for PrivateFile {
	fn drop(&mut self) {
		self.file = None;
		let _ = std::fs::remove_dir_all(&self.dir);
	}
}

/// What the scanner said: clean or not, its exit code, and its output (shown to the person).
pub struct Verdict {
	pub clean: bool,
	pub code: Option<i32>,
	pub output: String,
}

/// Run `cmd` on the file — no shell.
pub fn run(cmd: &str, path: &Path) -> Result<Verdict, Error> {
	let words = with_path(&split_words(cmd)?, path);
	let out = Command::new(&words[0]).args(&words[1..]).output().map_err(|e| Error::Config(format!("--scan: could not run {}: {e}", words[0])))?;
	let output = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)).trim().to_string();
	Ok(Verdict { clean: out.status.success(), code: out.status.code(), output })
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn words_split_like_a_command_line_and_nothing_more() {
		assert_eq!(split_words("clamscan --no-summary").unwrap(), ["clamscan", "--no-summary"]);
		assert_eq!(split_words(r#"sh -c "exit 1""#).unwrap(), ["sh", "-c", "exit 1"]);
		assert_eq!(split_words("a '' b").unwrap(), ["a", "", "b"]);
		assert_eq!(split_words("echo $(rm -rf ~) | x").unwrap(), ["echo", "$(rm", "-rf", "~)", "|", "x"], "no shell syntax means anything");
		assert!(split_words("  ").is_err());
		assert!(split_words("a \"b").is_err());
	}

	#[test]
	fn the_path_goes_where_asked_or_last() {
		let p = Path::new("/t/f");
		assert_eq!(with_path(&["scan".into(), "--file={}".into()], p), ["scan", "--file=/t/f"]);
		assert_eq!(with_path(&["clamscan".into()], p), ["clamscan", "/t/f"]);
	}

	#[test]
	fn names_are_tamed() {
		assert_eq!(sanitised("../../etc/passwd"), "_.._etc_passwd");
		assert_eq!(sanitised("invoice $(x).pdf"), "invoice___x_.pdf");
	}

	#[cfg(unix)]
	#[test]
	fn the_file_is_private_and_goes_away() {
		use std::os::unix::fs::PermissionsExt;
		let mut f = PrivateFile::create("item1", "a b.exe").unwrap();
		f.write(b"MZ").unwrap();
		f.finish().unwrap();
		let path = f.path.clone();
		assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
		assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
		assert!(run("true", &path).unwrap().clean);
		let v = run("sh -c 'echo FOUND: $0; exit 1'", &path).unwrap();
		assert!(!v.clean && v.code == Some(1) && v.output.contains("FOUND"));
		drop(f);
		assert!(!path.exists() && !path.parent().unwrap().exists());
	}
}
