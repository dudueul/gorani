// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The Windows shell's smoke test (commit 39b), on a real Cloud Files sync
//! root (the hosted Windows runner: .github/workflows/clients.yml) over the
//! in-memory replica — the server's half is api:replica's, on Linux. What
//! it proves, through what any program on the machine does — reads and
//! writes from this process, renames and deletes from ANOTHER (found in CI:
//! the platform sends no rename/delete notification for the provider's own
//! process, and here the provider runs in the test's):
//!
//!   1. every item is listed with its size before a byte of it is fetched;
//!   2. a read fetches it (a whole small file; a range of a large one), a
//!      sample's read is refused;
//!   3. a new file, a new folder with a file in it, and an edit reach the
//!      server once written; a rename and a delete are the server's first
//!      (and a rename is not mistaken for an edit);
//!   4. the server's changes reach the folder: a new file, new bytes for
//!      a file (read afresh), a move, a removal (of the moved file: gone,
//!      not kept as the member's);
//!   5. a save the server refuses as stale becomes a conflict copy — both
//!      versions on both sides;
//!   6. a read-only area refuses deletes and keeps new files local;
//!   7. after stop, the bytes are gone from the disk — the evidence's too,
//!      read-only as it is: the placeholder stays listed, and a read without
//!      the shell running cannot fill it.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gorani_client_core::replica::{MemRemote, Remote};
use gorani_windows::{cf, provider, shell};

fn wait(what: &str, run: &provider::Running, mut done: impl FnMut() -> bool) {
	let t = Instant::now();
	while t.elapsed() < Duration::from_secs(30) {
		run.sync_local();
		if done() {
			return;
		}
		std::thread::sleep(Duration::from_millis(200));
	}
	panic!("timed out waiting for: {what}");
}

/// A rename or delete as another program does it (PowerShell: its exit
/// code says whether the operation was refused).
fn elsewhere(command: &str) -> bool {
	std::process::Command::new("powershell")
		.args(["-NoProfile", "-NonInteractive", "-Command", &format!("$ErrorActionPreference='Stop'; {command}")])
		.status()
		.map(|s| s.success())
		.unwrap_or(false)
}

fn ps(p: &Path) -> String {
	format!("'{}'", p.display().to_string().replace('\'', "''"))
}

fn pattern(n: usize) -> Vec<u8> {
	(0..n).map(|i| (i % 251) as u8).collect()
}

fn fresh_root(tag: &str) -> PathBuf {
	let root = std::env::temp_dir().join(format!("gorani-cloud-{tag}-{}", gorani_client_core::new_item_id()));
	std::fs::create_dir_all(&root).unwrap();
	root
}

fn cleanup(root: &Path) {
	let _ = shell::unregister(root);
	let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_cloud_files_folder_over_the_replica() {
	let mem = Arc::new(Mutex::new(MemRemote::new("ana")));
	let (docs, a, big, bad) = {
		let mut m = mem.lock().unwrap();
		let docs = m.put_dir("", "docs");
		let a = m.put(&docs.id, "a.txt", b"hello");
		let big = m.put("", "big.bin", &pattern(5 * 1024 * 1024 + 123));
		let bad = m.put("", "bad.exe", b"MZ");
		m.mark_sample(&bad.id);
		(docs, a, big, bad)
	};
	let remote: Arc<Mutex<dyn Remote + Send>> = mem.clone();
	let run = provider::start(&fresh_root("main"), remote, provider::Options { poll: None, keep_local: false, verbose: true }).expect("start the sync root");
	let root = run.root().to_path_buf();

	// 0. Explorer's registration where the shell gives one (39e), said
	// either way: a Server runner may give only cldapi's.
	let id = shell::sync_root_id("ana").expect("this user's SID");
	match shell::registered_path(&id) {
		Ok(Some(path)) => {
			eprintln!("Explorer knows the folder as {id} ({path})");
			assert!(shell::same_folder(&path, &root), "the shell's root {path} is this folder");
		}
		Ok(None) => {
			// (Only a Windows without the shell's support may fall back.)
			// (What the registry holds, for the reader of a failure.)
			let reg = std::process::Command::new("reg").args(["query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager", "/s"]).output().map(|o| String::from_utf8_lossy(&o.stdout).chars().take(4000).collect::<String>()).unwrap_or_default();
			assert!(!shell::supported(), "the shell supports sync roots here, yet holds nothing under {id} — by folder: {:?}, among its roots: {:?}; the registry: {reg}", shell::registered_id(&root), shell::roots());
			eprintln!("this Windows has no shell sync-root support — cldapi's sync root only");
		}
		Err(e) => panic!("the shell, asked for {id}: {e} — by folder: {:?}, among its roots: {:?}", shell::registered_id(&root), shell::roots()),
	}

	// 1. Listed, sized, identified — nothing fetched yet.
	assert_eq!(std::fs::metadata(root.join("big.bin")).unwrap().len(), 5 * 1024 * 1024 + 123);
	assert!(root.join("docs").is_dir());
	let info = cf::info(&root.join("docs").join("a.txt")).expect("a placeholder");
	assert!(info.in_sync);
	assert_eq!(gorani_windows::names::parse_identity(&info.identity), Some((a.id.clone(), 1)));

	// 2. Reads fetch; a sample does not.
	assert_eq!(std::fs::read_to_string(root.join("docs").join("a.txt")).unwrap(), "hello");
	{
		use std::io::{Read, Seek, SeekFrom};
		let mut f = std::fs::File::open(root.join("big.bin")).unwrap();
		f.seek(SeekFrom::Start(3 * 1024 * 1024 + 7)).unwrap();
		let mut b = vec![0u8; 100_000];
		f.read_exact(&mut b).unwrap();
		assert_eq!(b, pattern(5 * 1024 * 1024 + 123)[3 * 1024 * 1024 + 7..3 * 1024 * 1024 + 7 + 100_000]);
	}
	assert!(std::fs::read(root.join("bad.exe")).is_err(), "a malware sample is never served raw");
	assert!(cf::info(&root.join("bad.exe")).is_some_and(|i| i.in_sync), "its state shown, it is still in sync — nothing to send");
	let _ = (&big, &bad);

	// 3. The member's own changes reach the server.
	std::fs::write(root.join("docs").join("new.txt"), "made here").unwrap();
	wait("new.txt on the server", &run, || mem.lock().unwrap().find(&docs.id, "new.txt").is_some());
	let made = mem.lock().unwrap().find(&docs.id, "new.txt").unwrap();
	assert_eq!(mem.lock().unwrap().content(&made.id).unwrap(), b"made here");
	assert!(cf::info(&root.join("docs").join("new.txt")).is_some_and(|i| i.in_sync), "sent, and a placeholder in sync now");
	std::fs::create_dir(root.join("out")).unwrap();
	std::fs::write(root.join("out").join("x.txt"), "inside").unwrap();
	wait("out/x.txt on the server", &run, || {
		let m = mem.lock().unwrap();
		m.find("", "out").is_some_and(|o| m.find(&o.id, "x.txt").is_some())
	});
	std::fs::write(root.join("docs").join("a.txt"), "hello again").unwrap();
	wait("a.txt version 2", &run, || mem.lock().unwrap().content(&a.id).as_deref() == Some(&b"hello again"[..]));
	assert!(elsewhere(&format!("Move-Item -LiteralPath {} -Destination {}", ps(&root.join("docs").join("new.txt")), ps(&root.join("renamed.txt")))), "the rename went through");
	assert!(mem.lock().unwrap().find("", "renamed.txt").is_some(), "the rename is the server's before it is the folder's");
	// (A rename clears the platform's in-sync state; the shell must see it
	// was only renamed, not send the same bytes again as version 2.)
	wait("renamed.txt in sync again", &run, || cf::info(&root.join("renamed.txt")).is_some_and(|i| i.in_sync));
	assert_eq!(mem.lock().unwrap().find("", "renamed.txt").map(|i| i.version), Some(1), "only renamed: no new version");
	assert!(elsewhere(&format!("Remove-Item -LiteralPath {}", ps(&root.join("renamed.txt")))), "the delete went through");
	assert!(mem.lock().unwrap().find("", "renamed.txt").is_none(), "…and so is the delete");

	// 4. The server's changes reach the folder.
	let remote_file = mem.lock().unwrap().put("", "remote.txt", b"from elsewhere");
	run.sync_remote().unwrap();
	assert_eq!(std::fs::read_to_string(root.join("remote.txt")).unwrap(), "from elsewhere");
	mem.lock().unwrap().edit(&remote_file.id, b"edited elsewhere");
	run.sync_remote().unwrap();
	assert_eq!(std::fs::read_to_string(root.join("remote.txt")).unwrap(), "edited elsewhere", "new bytes, read afresh");
	mem.lock().unwrap().move_to(&remote_file.id, &docs.id, "moved.txt");
	run.sync_remote().unwrap();
	assert!(!root.join("remote.txt").exists() && root.join("docs").join("moved.txt").exists());
	mem.lock().unwrap().remove(&remote_file.id);
	run.sync_remote().unwrap();
	assert!(!root.join("docs").join("moved.txt").exists());
	// (Found in CI: the move had cleared the in-sync state, and the removal
	// then took the file for the member's unsent change — kept and sent
	// back as "moved.txt (removed elsewhere)".)
	let leftovers: Vec<String> = std::fs::read_dir(root.join("docs")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| n.starts_with("moved.txt")).collect();
	assert!(leftovers.is_empty(), "removed on the server, removed here: {leftovers:?}");

	// 5. A stale save: both versions kept, on both sides.
	mem.lock().unwrap().edit(&a.id, b"theirs");
	std::fs::write(root.join("docs").join("a.txt"), "mine").unwrap();
	wait("a conflict copy", &run, || std::fs::read_dir(root.join("docs")).unwrap().flatten().any(|e| e.file_name().to_string_lossy().starts_with("a (conflict ")));
	run.sync_remote().unwrap();
	assert_eq!(std::fs::read_to_string(root.join("docs").join("a.txt")).unwrap(), "theirs", "their version stands at the name");
	let copy = std::fs::read_dir(root.join("docs")).unwrap().flatten().find(|e| e.file_name().to_string_lossy().starts_with("a (conflict ")).unwrap();
	assert_eq!(std::fs::read_to_string(copy.path()).unwrap(), "mine", "and mine beside it");

	// 7. Stop: the plaintext leaves with the shell.
	run.stop();
	assert!(root.join("docs").join("a.txt").exists(), "still listed");
	assert!(std::fs::read(root.join("docs").join("a.txt")).is_err(), "its bytes are gone: nothing serves them now");
	assert!(mem.lock().unwrap().find(&docs.id, "moved.txt (removed elsewhere)").is_none(), "nothing came back from the dead");
	cleanup(&root);
	// (Unregistering removes the shell's record too — no stale entry left in
	// Explorer's navigation pane.)
	if shell::supported() {
		assert_eq!(shell::registered_path(&id), Ok(None), "the shell still holds {id} after unregister");
	}
}

/// Explorer's two context-menu choices, as another program makes them:
/// "Always keep on this device" and "Free up space" are only the pin
/// attribute (attrib's +P and +U set the same one Explorer does), and the
/// shell must do the rest (provider.rs › pins). Files of 200 KB and more:
/// a tiny one can live inside its MFT record, where "on disk" means little.
#[test]
fn explorer_always_keep_and_free_up_space() {
	use cf::Pin;
	let mem = Arc::new(Mutex::new(MemRemote::new("pins")));
	let (keep_dir, k1, top, free_dir, f1, f2, bad) = {
		let mut m = mem.lock().unwrap();
		let keep_dir = m.put_dir("", "keep");
		let k1 = m.put(&keep_dir.id, "k1.bin", &pattern(6 * 1024 * 1024 + 5));
		let top = m.put("", "top.bin", &pattern(200_000));
		let free_dir = m.put_dir("", "free");
		let f1 = m.put(&free_dir.id, "f1.bin", &pattern(300_000));
		let f2 = m.put(&free_dir.id, "f2.bin", &pattern(250_000));
		let bad = m.put("", "bad.exe", &pattern(200_000));
		m.mark_sample(&bad.id);
		(keep_dir, k1, top, free_dir, f1, f2, bad)
	};
	let remote: Arc<Mutex<dyn Remote + Send>> = mem.clone();
	let run = provider::start(&fresh_root("pins"), remote, provider::Options { poll: None, keep_local: false, verbose: true }).expect("start");
	let root = run.root().to_path_buf();
	let at = |rel: &str| root.join(rel);
	let size = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
	let on_disk = |p: &Path| cf::info(p).map(|i| i.on_disk).unwrap_or(u64::MAX);
	let pin = |p: &Path| cf::info(p).map(|i| i.pin);
	let whole = |p: &Path| size(p) > 0 && on_disk(p) >= size(p);
	// (attrib.exe: another program, as Explorer is — and the same attribute.)
	let attrib = |flags: &[&str], p: &Path| {
		let ok = std::process::Command::new("attrib").args(flags).arg(p).status().map(|s| s.success()).unwrap_or(false);
		assert!(ok, "attrib {flags:?} {}", p.display());
	};
	let reads = || mem.lock().unwrap().reads;
	let _ = (&keep_dir, &k1, &free_dir, &f2);

	// 1. "Always keep on this device" on a file: fetched whole, at once,
	// without anything reading it — and read from the disk after.
	assert_eq!(on_disk(&at("top.bin")), 0, "nothing fetched before it is asked for");
	attrib(&["+P"], &at("top.bin"));
	wait("top.bin kept on this device", &run, || whole(&at("top.bin")));
	let before = reads();
	assert_eq!(std::fs::read(at("top.bin")).unwrap(), pattern(200_000));
	assert_eq!(reads(), before, "a kept file is read from this disk, not fetched");

	// 2. On a folder (the folder alone): what is in it is kept too, and so
	// is what arrives in it later.
	attrib(&["+P"], &at("keep"));
	wait("keep\\k1.bin kept", &run, || whole(&at("keep\\k1.bin")));
	assert_eq!(pin(&at("keep\\k1.bin")), Some(Pin::Pinned), "marked kept, as Explorer then shows it");
	let later = mem.lock().unwrap().put(&keep_dir.id, "later.bin", &pattern(220_000));
	run.sync_remote().unwrap();
	wait("keep\\later.bin, arrived later, kept", &run, || whole(&at("keep\\later.bin")));
	let _ = later;
	// Freeing one of them: that one freed, the folder kept as a whole no
	// more (or its next look would keep the file again), the rest still
	// kept — and what arrives now is not.
	attrib(&["-P", "+U"], &at("keep\\later.bin"));
	wait("keep\\later.bin freed", &run, || on_disk(&at("keep\\later.bin")) == 0 && pin(&at("keep")) == Some(Pin::Unspecified));
	assert!(whole(&at("keep\\k1.bin")) && pin(&at("keep\\k1.bin")) == Some(Pin::Pinned), "the other file stays kept");
	mem.lock().unwrap().put(&keep_dir.id, "after.bin", &pattern(210_000));
	run.sync_remote().unwrap();
	run.sync_local();
	std::thread::sleep(Duration::from_secs(2));
	run.sync_local();
	assert_eq!(on_disk(&at("keep\\after.bin")), 0, "arrived after the folder was freed: not kept");
	assert!(on_disk(&at("keep\\later.bin")) == 0, "and the freed file was not kept again");

	// 3. A new version of a kept file: its old bytes dropped (the platform
	// refuses that while it is pinned — the shell lifts the pin for it),
	// the new ones fetched at once, still kept.
	mem.lock().unwrap().edit(&top.id, &pattern(260_000));
	run.sync_remote().unwrap();
	wait("top.bin's new version kept", &run, || size(&at("top.bin")) == 260_000 && whole(&at("top.bin")) && pin(&at("top.bin")) == Some(Pin::Pinned));
	let before = reads();
	assert_eq!(std::fs::read(at("top.bin")).unwrap(), pattern(260_000), "the new version's bytes");
	assert_eq!(reads(), before, "…from this disk");

	// 4. "Free up space" on a file: its bytes dropped, still listed, and the
	// request done (back to neither) — so a later read fetches it as any
	// read does, and it is not dropped again under the reader.
	assert_eq!(std::fs::read(at("free\\f1.bin")).unwrap(), pattern(300_000));
	assert!(on_disk(&at("free\\f1.bin")) > 0, "read, so on disk");
	attrib(&["+U"], &at("free\\f1.bin"));
	wait("free\\f1.bin freed", &run, || on_disk(&at("free\\f1.bin")) == 0 && pin(&at("free\\f1.bin")) == Some(Pin::Unspecified));
	assert!(at("free\\f1.bin").exists(), "still listed");
	let before = reads();
	assert_eq!(std::fs::read(at("free\\f1.bin")).unwrap(), pattern(300_000), "read again…");
	assert!(reads() > before, "…fetched again: its bytes had left the disk");
	std::thread::sleep(Duration::from_secs(2));
	run.sync_local();
	assert!(on_disk(&at("free\\f1.bin")) > 0, "…and left there: the request was done once");

	// 5. A change not sent yet is sent first, freed after — never lost.
	let edited: Vec<u8> = pattern(230_000).iter().map(|b| b ^ 0x5a).collect();
	std::fs::write(at("free\\f1.bin"), &edited).unwrap();
	attrib(&["+U"], &at("free\\f1.bin"));
	wait("the change sent, then freed", &run, || mem.lock().unwrap().content(&f1.id).as_deref() == Some(&edited[..]) && on_disk(&at("free\\f1.bin")) == 0 && pin(&at("free\\f1.bin")) == Some(Pin::Unspecified));
	let before = reads();
	assert_eq!(std::fs::read(at("free\\f1.bin")).unwrap(), edited, "the change, from the server");
	assert!(reads() > before);

	// 6. On a folder: everything in it.
	assert_eq!(std::fs::read(at("free\\f2.bin")).unwrap(), pattern(250_000));
	attrib(&["+U"], &at("free"));
	wait("free\\ freed", &run, || on_disk(&at("free\\f2.bin")) == 0 && pin(&at("free")) == Some(Pin::Unspecified));

	// 7. "Free up space" on a kept file: kept no more.
	attrib(&["-P", "+U"], &at("top.bin"));
	wait("top.bin freed", &run, || on_disk(&at("top.bin")) == 0 && pin(&at("top.bin")) == Some(Pin::Unspecified));

	// 8. A malware sample is never kept: its bytes never on this disk raw,
	// and the mark undone so Explorer does not claim it.
	attrib(&["+P"], &at("bad.exe"));
	wait("the sample's mark undone", &run, || pin(&at("bad.exe")) == Some(Pin::Unspecified));
	assert_eq!(on_disk(&at("bad.exe")), 0);
	let _ = &bad;

	// 9. Stop: the kept files' plaintext leaves with the shell too — still
	// marked kept, and fetched again when it next starts.
	run.stop();
	assert_eq!(on_disk(&at("keep\\k1.bin")), 0, "no plaintext left while no shell runs");
	assert_eq!(pin(&at("keep\\k1.bin")), Some(Pin::Pinned), "the choice kept");
	let remote: Arc<Mutex<dyn Remote + Send>> = mem.clone();
	let run = provider::start(&root, remote, provider::Options { poll: None, keep_local: false, verbose: true }).expect("start again");
	wait("keep\\k1.bin fetched again at start", &run, || whole(&at("keep\\k1.bin")));
	run.stop();
	cleanup(&root);
}

#[test]
fn a_read_only_area_refuses_deletes_and_keeps_new_files_local() {
	let mem = Arc::new(Mutex::new(MemRemote::new("case:ir-1")));
	let kept = {
		let mut m = mem.lock().unwrap();
		m.read_only = Some("an evidence case is read-only through the shell".into());
		m.put("", "memory.raw", b"evidence")
	};
	let remote: Arc<Mutex<dyn Remote + Send>> = mem.clone();
	let run = provider::start(&fresh_root("ro"), remote, provider::Options { poll: None, keep_local: false, verbose: true }).expect("start");
	let root = run.root().to_path_buf();
	assert_eq!(std::fs::read_to_string(root.join("memory.raw")).unwrap(), "evidence");
	assert!(!elsewhere(&format!("Remove-Item -LiteralPath {}", ps(&root.join("memory.raw")))), "the delete is refused");
	assert!(root.join("memory.raw").exists());
	assert!(mem.lock().unwrap().find("", "memory.raw").is_some_and(|i| i.id == kept.id));
	std::fs::write(root.join("notes.txt"), "local only").unwrap();
	run.sync_local();
	std::thread::sleep(Duration::from_millis(500));
	run.sync_local();
	assert!(mem.lock().unwrap().find("", "notes.txt").is_none(), "nothing is sent into a read-only area");
	run.stop();
	// (Found in CI: a read-only placeholder refused the write open that
	// dehydrating takes, and the evidence stayed on the disk in the clear.)
	assert!(std::fs::read(root.join("memory.raw")).is_err(), "the evidence's bytes left with the shell");
	assert_eq!(std::fs::read_to_string(root.join("notes.txt")).unwrap(), "local only", "the member's own file stays");
	cleanup(&root);
}
