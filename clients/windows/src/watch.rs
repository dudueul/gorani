// Copyright 2026- Seongwoo Hong. All rights reserved.

//! What the member does in the folder (commit 39b). The Cloud Files API
//! tells a provider about deletes and renames of placeholders — not about
//! new files, new folders or edits; those come from ReadDirectoryChangesW
//! on the whole tree. Each event is only a path to look at again: the
//! provider decides what it is (provider.rs › local), so a lost or
//! repeated event costs a look, never a wrong upload.

use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use windows::core::HSTRING;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::IO::CancelSynchronousIo;

pub struct Watcher {
	stop: Arc<AtomicBool>,
	thread: Option<JoinHandle<()>>,
}

impl Watcher {
	/// Watch `root`; `seen` gets every path (relative to the root) that changed.
	pub fn start(root: &Path, seen: impl Fn(PathBuf) + Send + 'static) -> windows::core::Result<Self> {
		// SAFETY: a path string that outlives the call; the handle is closed by the thread.
		let dir = unsafe {
			CreateFileW(
				&HSTRING::from(root),
				FILE_LIST_DIRECTORY.0,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				None,
				OPEN_EXISTING,
				FILE_FLAG_BACKUP_SEMANTICS,
				None,
			)
		}?;
		let stop = Arc::new(AtomicBool::new(false));
		let flag = stop.clone();
		let raw = dir.0 as usize;
		let thread = std::thread::spawn(move || {
			let dir = HANDLE(raw as *mut _);
			// (u32-aligned, as FILE_NOTIFY_INFORMATION records are.)
			let mut buf = vec![0u32; 16 * 1024];
			while !flag.load(Ordering::SeqCst) {
				let mut got = 0u32;
				// SAFETY: our buffer and handle; synchronous, cancelled by `stop`.
				let r = unsafe {
					ReadDirectoryChangesW(
						dir,
						buf.as_mut_ptr() as *mut _,
						(buf.len() * 4) as u32,
						true,
						FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
						Some(&mut got),
						None,
						None,
					)
				};
				if r.is_err() || flag.load(Ordering::SeqCst) {
					break;
				}
				if got == 0 {
					// The buffer overflowed: the provider looks at everything again.
					seen(PathBuf::new());
					continue;
				}
				let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, got as usize) };
				let mut at = 0usize;
				loop {
					// SAFETY: records the system wrote, each within `got` bytes.
					let rec = unsafe { &*(bytes.as_ptr().add(at) as *const FILE_NOTIFY_INFORMATION) };
					let len = rec.FileNameLength as usize / 2;
					let name = unsafe { std::slice::from_raw_parts(rec.FileName.as_ptr(), len) };
					if rec.Action != FILE_ACTION_REMOVED && rec.Action != FILE_ACTION_RENAMED_OLD_NAME {
						seen(PathBuf::from(String::from_utf16_lossy(name)));
					}
					if rec.NextEntryOffset == 0 {
						break;
					}
					at += rec.NextEntryOffset as usize;
				}
			}
			// SAFETY: the handle this thread owns.
			let _ = unsafe { CloseHandle(dir) };
		});
		Ok(Self { stop, thread: Some(thread) })
	}

	pub fn stop(mut self) {
		self.stop.store(true, Ordering::SeqCst);
		if let Some(t) = self.thread.take() {
			// (Cancelled again until it ends: a cancel that lands just before
			// the thread enters its wait would be lost.)
			for _ in 0..200 {
				if t.is_finished() {
					break;
				}
				// SAFETY: the thread's own handle, alive until joined.
				let _ = unsafe { CancelSynchronousIo(HANDLE(t.as_raw_handle())) };
				std::thread::sleep(std::time::Duration::from_millis(25));
			}
			let _ = t.join();
		}
	}
}
