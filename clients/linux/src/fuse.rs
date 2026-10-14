// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The FUSE adapter: each kernel request becomes one engine call, each
//! FsError its errno. The kernel serialises nothing for us — `fuser` calls
//! these on one thread, so the engine needs no locks.
//!
//! Freshness: the tree is refreshed (the change feed asked, the listing
//! read again if it moved) when a directory is listed or a name looked up,
//! at most every few seconds — "changes elsewhere appear within seconds"
//! without a request per `stat`.

use std::ffi::OsStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fuser::{FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow};
use gorani_client_core::engine::{Engine, FsError, Kind, Node};
use gorani_client_core::Error;

/// How long the kernel may cache an answer (and how stale a listing may be).
const TTL: Duration = Duration::from_secs(1);
const REFRESH_EVERY: Duration = Duration::from_secs(3);

struct Fs {
	engine: Engine,
	last_refresh: Instant,
	uid: u32,
	gid: u32,
	read_only: bool,
}

impl Fs {
	fn fresh(&mut self) {
		if self.last_refresh.elapsed() >= REFRESH_EVERY {
			if let Err(e) = self.engine.refresh() {
				eprintln!("gorani-mount: refresh failed (serving what is known): {e}");
			}
			self.last_refresh = Instant::now();
		}
	}

	fn attr(&self, n: &Node) -> FileAttr {
		let t = UNIX_EPOCH + Duration::from_secs(n.modified);
		let (kind, perm) = match n.kind {
			Kind::Dir => (FileType::Directory, if self.read_only { 0o550 } else { 0o750 }),
			// A sample shows, but no one may open it (the engine refuses too).
			Kind::File if n.sample => (FileType::RegularFile, 0o000),
			Kind::File => (FileType::RegularFile, if self.read_only { 0o440 } else { 0o640 }),
		};
		FileAttr { ino: n.ino, size: n.size, blocks: n.size.div_ceil(512), atime: t, mtime: t, ctime: t, crtime: t, kind, perm, nlink: if n.kind == Kind::Dir { 2 } else { 1 }, uid: self.uid, gid: self.gid, rdev: 0, blksize: 4096, flags: 0 }
	}
}

fn errno(e: &FsError) -> i32 {
	if let FsError::Denied(why) | FsError::ReadOnly(why) | FsError::Io(why) = e {
		eprintln!("gorani-mount: {why}");
	}
	e.errno()
}

fn name_of(name: &OsStr) -> Option<&str> {
	name.to_str()
}

impl Filesystem for Fs {
	fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
		self.fresh();
		match name_of(name).and_then(|n| self.engine.lookup(parent, n)) {
			Some(n) => reply.entry(&TTL, &self.attr(n), 0),
			None => reply.error(libc::ENOENT),
		}
	}

	fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
		match self.engine.node(ino) {
			Some(n) => reply.attr(&TTL, &self.attr(n)),
			None => reply.error(libc::ENOENT),
		}
	}

	#[allow(clippy::too_many_arguments)]
	fn setattr(&mut self, _req: &Request<'_>, ino: u64, _mode: Option<u32>, _uid: Option<u32>, _gid: Option<u32>, size: Option<u64>, _atime: Option<TimeOrNow>, _mtime: Option<TimeOrNow>, _ctime: Option<SystemTime>, fh: Option<u64>, _crtime: Option<SystemTime>, _chgtime: Option<SystemTime>, _bkuptime: Option<SystemTime>, _flags: Option<u32>, reply: ReplyAttr) {
		// Only the size means anything here (modes and times are the vault's).
		if let Some(size) = size {
			if let Err(e) = self.engine.set_size(ino, fh, size) {
				return reply.error(errno(&e));
			}
		}
		match self.engine.node(ino) {
			Some(n) => reply.attr(&TTL, &self.attr(n)),
			None => reply.error(libc::ENOENT),
		}
	}

	fn readdir(&mut self, _req: &Request<'_>, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
		if offset == 0 {
			self.fresh();
		}
		let parent = self.engine.node(ino).map(|n| n.parent).unwrap_or(ino);
		let children = match self.engine.children(ino) {
			Ok(c) => c,
			Err(e) => return reply.error(errno(&e)),
		};
		let mut all: Vec<(u64, FileType, String)> = vec![(ino, FileType::Directory, ".".into()), (parent, FileType::Directory, "..".into())];
		all.extend(children.into_iter().map(|n| (n.ino, if n.kind == Kind::Dir { FileType::Directory } else { FileType::RegularFile }, n.name.clone())));
		for (i, (ino, kind, name)) in all.into_iter().enumerate().skip(offset as usize) {
			if reply.add(ino, (i + 1) as i64, kind, name) {
				break;
			}
		}
		reply.ok();
	}

	fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
		let write = flags & libc::O_ACCMODE != libc::O_RDONLY;
		match self.engine.open(ino, write, flags & libc::O_TRUNC != 0) {
			Ok(fh) => reply.opened(fh, 0),
			Err(e) => reply.error(errno(&e)),
		}
	}

	#[allow(clippy::too_many_arguments)]
	fn read(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, offset: i64, size: u32, _flags: i32, _lock: Option<u64>, reply: ReplyData) {
		match self.engine.read(fh, offset.max(0) as u64, size) {
			Ok(bytes) => reply.data(&bytes),
			Err(e) => reply.error(errno(&e)),
		}
	}

	#[allow(clippy::too_many_arguments)]
	fn write(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, offset: i64, data: &[u8], _wflags: u32, _flags: i32, _lock: Option<u64>, reply: ReplyWrite) {
		match self.engine.write(fh, offset.max(0) as u64, data) {
			Ok(n) => reply.written(n),
			Err(e) => reply.error(errno(&e)),
		}
	}

	/// close(2) sees THIS answer: the upload happens here, so a refusal
	/// (a read grant, a full quota) reaches the program that saved.
	fn flush(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _lock: u64, reply: ReplyEmpty) {
		match self.engine.flush(fh) {
			Ok(()) => reply.ok(),
			Err(e) => reply.error(errno(&e)),
		}
	}

	fn fsync(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _datasync: bool, reply: ReplyEmpty) {
		match self.engine.flush(fh) {
			Ok(()) => reply.ok(),
			Err(e) => reply.error(errno(&e)),
		}
	}

	fn release(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _flags: i32, _lock: Option<u64>, _flush: bool, reply: ReplyEmpty) {
		if let Err(e) = self.engine.flush(fh) {
			errno(&e);
		}
		self.engine.release(fh);
		reply.ok();
	}

	fn create(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, _mode: u32, _umask: u32, _flags: i32, reply: ReplyCreate) {
		let Some(name) = name_of(name) else { return reply.error(libc::EINVAL) };
		match self.engine.create(parent, name) {
			Ok((ino, fh)) => {
				let attr = self.attr(self.engine.node(ino).expect("created"));
				reply.created(&TTL, &attr, 0, fh, 0)
			}
			Err(e) => reply.error(errno(&e)),
		}
	}

	fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
		let Some(name) = name_of(name) else { return reply.error(libc::ENOENT) };
		match self.engine.unlink(parent, name) {
			Ok(()) => reply.ok(),
			Err(e) => reply.error(errno(&e)),
		}
	}

	fn mkdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
		let Some(name) = name_of(name) else { return reply.error(libc::EINVAL) };
		match self.engine.mkdir(parent, name) {
			Ok(ino) => {
				let attr = self.attr(self.engine.node(ino).expect("made"));
				reply.entry(&TTL, &attr, 0)
			}
			Err(e) => reply.error(errno(&e)),
		}
	}

	fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
		let Some(name) = name_of(name) else { return reply.error(libc::ENOENT) };
		match self.engine.rmdir(parent, name) {
			Ok(()) => reply.ok(),
			Err(e) => reply.error(errno(&e)),
		}
	}

	fn rename(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, _flags: u32, reply: ReplyEmpty) {
		let (Some(name), Some(newname)) = (name_of(name), name_of(newname)) else { return reply.error(libc::EINVAL) };
		match self.engine.rename(parent, name, newparent, newname) {
			Ok(()) => reply.ok(),
			Err(e) => reply.error(errno(&e)),
		}
	}
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
	STOP.store(true, Ordering::SeqCst);
}

/// Mount and serve until SIGINT/SIGTERM (or an external umount).
pub fn mount(engine: Engine, dir: &str, area: &str) -> Result<(), Error> {
	let read_only = engine.read_only().is_some();
	// SAFETY: getuid/getgid cannot fail; the handler only stores an atomic.
	let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
	unsafe {
		libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
		libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
	}
	let mut options = vec![MountOption::FSName("gorani".into()), MountOption::Subtype("gorani".into()), MountOption::NoAtime, MountOption::NoDev, MountOption::NoSuid];
	// No exec from a vault: what is stored there is data (often hostile).
	options.push(MountOption::NoExec);
	if read_only {
		options.push(MountOption::RO);
	}
	let fs = Fs { engine, last_refresh: Instant::now(), uid, gid, read_only };
	let session = fuser::spawn_mount2(fs, dir, &options).map_err(|e| Error::Config(format!("mount {dir}: {e} (FUSE needs /dev/fuse, and root or fusermount3)")))?;
	println!("mounted {area} at {dir}{}", if read_only { " (read-only)" } else { "" });
	use std::io::Write;
	std::io::stdout().flush().ok();
	while !STOP.load(Ordering::SeqCst) && !session.guard.is_finished() {
		std::thread::sleep(Duration::from_millis(200));
	}
	drop(session); // unmounts
	println!("unmounted {dir}");
	Ok(())
}
