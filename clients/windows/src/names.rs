// Copyright 2026- Seongwoo Hong. All rights reserved.

//! What the Windows shell decides without Windows (commit 39b) — so it is
//! unit-tested on any machine: how a server name becomes an NTFS name, how
//! a folder's names are made unique the way NTFS compares them, what a
//! placeholder's identity blob holds, and which local files are not ours
//! to upload.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use gorani_client_core::engine::Kind;
use gorani_client_core::replica::Item;

/// The names Windows reserves for devices, whatever their extension.
const RESERVED: &[&str] = &["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"];

/// A server name as an NTFS name. The characters Windows refuses become
/// look-alikes (full-width forms), a trailing dot or space is kept visible
/// (`.` → `․`, ` ` → U+2002), and a device name gets an underscore — the
/// name still reads as itself, and nothing in it can address a device or a
/// path. (The engine already turned `/` into `∕`.)
pub fn local_name(name: &str) -> String {
	let mut out: String = name
		.chars()
		.map(|c| match c {
			'<' => '＜',
			'>' => '＞',
			':' => '：',
			'"' => '＂',
			'/' => '∕',
			'\\' => '＼',
			'|' => '｜',
			'?' => '？',
			'*' => '＊',
			c if (c as u32) < 0x20 => '\u{FFFD}',
			c => c,
		})
		.collect();
	if out.ends_with('.') || out.ends_with(' ') {
		let last = out.pop().expect("non-empty");
		out.push(if last == '.' { '․' } else { '\u{2002}' });
	}
	let stem = out.split('.').next().unwrap_or_default().trim_end().to_ascii_uppercase();
	if RESERVED.contains(&stem.as_str()) {
		out.insert(stem.len(), '_');
	}
	if out.is_empty() {
		out.push('_');
	}
	out
}

/// NTFS compares names without case (the volume's upcase table — for the
/// names that matter here, Unicode's simple upper case).
pub fn fold(name: &str) -> String {
	name.chars().flat_map(char::to_uppercase).collect()
}

/// Every item's path relative to the sync root: its folder's path and its
/// local name, unique within the folder the way NTFS compares names — the
/// first by id keeps a name, a later namesake gets " (id)" before its
/// extension. Items whose folder is not in the list sit at the top.
pub fn layout(items: &[Item]) -> HashMap<String, PathBuf> {
	let by_id: HashMap<&str, &Item> = items.iter().map(|i| (i.id.as_str(), i)).collect();
	let mut names: HashMap<&str, String> = HashMap::new();
	let mut by_folder: HashMap<&str, Vec<&Item>> = HashMap::new();
	for i in items {
		let parent = if by_id.get(i.parent.as_str()).is_some_and(|p| p.kind == Kind::Dir) { i.parent.as_str() } else { "" };
		by_folder.entry(parent).or_default().push(i);
	}
	for (_, mut kids) in by_folder {
		kids.sort_by(|a, b| a.id.cmp(&b.id));
		let mut taken: HashMap<String, ()> = HashMap::new();
		for k in kids {
			let mut n = local_name(&k.name);
			if taken.contains_key(&fold(&n)) {
				n = with_suffix(&n, &k.id[..k.id.len().min(8)], k.kind);
			}
			taken.insert(fold(&n), ());
			names.insert(k.id.as_str(), n);
		}
	}
	let mut out = HashMap::new();
	for i in items {
		let mut parts = vec![names[i.id.as_str()].clone()];
		let mut at = i.parent.as_str();
		let mut hops = 0;
		while let Some(p) = by_id.get(at).filter(|p| p.kind == Kind::Dir) {
			if hops > 4096 || p.id == i.id {
				parts.truncate(1); // a loop: the item sits at the top
				break;
			}
			parts.push(names[p.id.as_str()].clone());
			at = p.parent.as_str();
			hops += 1;
		}
		parts.reverse();
		out.insert(i.id.clone(), parts.iter().collect::<PathBuf>());
	}
	out
}

fn with_suffix(name: &str, tag: &str, kind: Kind) -> String {
	match name.rfind('.').filter(|i| *i > 0 && kind == Kind::File) {
		Some(i) => format!("{} ({tag}){}", &name[..i], &name[i..]),
		None => format!("{name} ({tag})"),
	}
}

/// A placeholder's identity blob: which item, which version. Small (the
/// platform keeps it per file; at most 4 KiB) and versioned by its prefix.
pub fn identity(id: &str, version: i64) -> Vec<u8> {
	format!("gorani1:{version}:{id}").into_bytes()
}

/// (id, version) from an identity blob, or None for one that is not ours.
pub fn parse_identity(blob: &[u8]) -> Option<(String, i64)> {
	let s = std::str::from_utf8(blob).ok()?;
	let rest = s.strip_prefix("gorani1:")?;
	let (v, id) = rest.split_once(':')?;
	let version = v.parse().ok()?;
	(!id.is_empty() || version == 0).then(|| (id.to_string(), version))
}

/// Seconds since 1970 as a FILETIME (100 ns since 1601).
pub fn filetime(secs: u64) -> i64 {
	((secs as i64) + 11_644_473_600) * 10_000_000
}

/// Files that are not the member's to upload: the shell's own, Explorer's,
/// and the lock and scratch files editors leave beside a document.
pub fn ignored(name: &str) -> bool {
	let lower = name.to_ascii_lowercase();
	lower == "desktop.ini" || lower == "thumbs.db" || lower.starts_with("~$") || lower.starts_with(".~lock.") || lower.starts_with(".gorani") || lower.ends_with(".tmp") || lower.ends_with(".crdownload") || lower.ends_with(".partial")
}

/// The path, folded for lookups (NTFS: case-insensitive).
pub fn key(rel: &Path) -> String {
	fold(&rel.to_string_lossy().replace('/', "\\"))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn item(id: &str, parent: &str, name: &str, kind: Kind) -> Item {
		Item { id: id.into(), parent: parent.into(), name: name.into(), kind, size: 0, version: 1, modified: 0, sample: false, name_verified: true }
	}

	#[test]
	fn a_server_name_becomes_a_name_ntfs_takes_and_reads_the_same() {
		assert_eq!(local_name("report.docx"), "report.docx");
		assert_eq!(local_name("Q3: what?.txt"), "Q3： what？.txt");
		assert_eq!(local_name(r#"a<b>c"d|e*f\g"#), "a＜b＞c＂d｜e＊f＼g");
		assert_eq!(local_name("notes."), "notes․", "a trailing dot is kept, visibly");
		assert_eq!(local_name("con.txt"), "con_.txt");
		assert_eq!(local_name("LPT1"), "LPT1_");
		assert_eq!(local_name("console.txt"), "console.txt");
		assert_eq!(local_name("bell\u{7}"), "bell\u{FFFD}");
	}

	#[test]
	fn names_are_unique_as_ntfs_compares_them_and_paths_follow_folders() {
		let items = vec![item("b2", "", "Report.txt", Kind::File), item("a1", "", "report.txt", Kind::File), item("d1", "", "Cases", Kind::Dir), item("f9", "d1", "x", Kind::File), item("f8", "gone", "orphan", Kind::File)];
		let l = layout(&items);
		assert_eq!(l["a1"], PathBuf::from("report.txt"), "the first by id keeps the name");
		assert_eq!(l["b2"], PathBuf::from("Report (b2).txt"));
		assert_eq!(l["f9"], PathBuf::from("Cases").join("x"));
		assert_eq!(l["f8"], PathBuf::from("orphan"), "a missing folder puts the item at the top");
	}

	#[test]
	fn identities_round_trip_and_strangers_are_refused() {
		assert_eq!(parse_identity(&identity("abc", 7)), Some(("abc".into(), 7)));
		assert_eq!(parse_identity(b"onedrive:123"), None);
		assert_eq!(parse_identity(b"gorani1:x:abc"), None);
		assert_eq!(filetime(0), 116_444_736_000_000_000);
		assert!(ignored("~$report.docx") && ignored("Thumbs.db") && ignored("x.tmp") && !ignored("report.docx"));
		assert_eq!(key(Path::new("Cases/x")), key(Path::new("cases\\X")));
	}
}
