// Copyright 2026- Seongwoo Hong. All rights reserved.

//! `gorani.exe`, the Windows app (commit 40b, docs/DESKTOP.md › 40b).
//!
//! ```text
//! the tray icon     where the sync stands; Open the folder, Open in the browser,
//!                   Pause, Settings…, Quit
//! Settings          Account, Sync, This computer & devices, Advanced (window.rs)
//! the sync          the Cloud Files folder gorani-cloud serves, run here on its
//!                   own thread (provider.rs), started and stopped by the settings
//! ```
//!
//! **One app per sign-in.** A named mutex keeps it single. Starting it
//! again (the Start menu, a double-click) opens the running one's Settings.
//!
//! **Threads.** The window thread draws and decides. The sync thread owns
//! the running folder: it starts, stops and signs out on that thread, and
//! posts what happened back as messages. Short jobs (signing in, enrolling,
//! listing devices) each get a thread of their own and post their result
//! the same way, so the window never waits on the network.
//!
//! **State** lives in thread-locals on the window thread, borrowed only
//! for a moment and never across a call that runs a message loop (a
//! message box, a menu). Such a call can re-enter the window procedure,
//! and a held borrow would then panic, which a release build turns into an
//! abort.

mod startup;
mod tray;
mod ui;
mod window;

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS, HANDLE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::Controls::{InitCommonControlsEx, ICC_LISTVIEW_CLASSES, ICC_STANDARD_CLASSES, ICC_TAB_CLASSES, INITCOMMONCONTROLSEX};
use windows::Win32::UI::WindowsAndMessaging::*;

use gorani_client_core::{session, DeviceProfile};

use crate::appmodel::Status;
use ui::Target;

/// The tray icon's callback.
const WM_APP_TRAY: u32 = WM_APP + 1;
/// A boxed `Event` from another thread.
const WM_APP_EVENT: u32 = WM_APP + 2;
/// "Open Settings": a second start of the app asks the first.
const WM_APP_SHOW: u32 = WM_APP + 3;

const HIDDEN_CLASS: PCWSTR = w!("Gorani.App");

/// What other threads tell the window thread.
pub(crate) enum Event {
	Status(Status),
	Done(window::Done),
}

/// What the sync thread is asked to do.
pub(crate) enum SyncCmd {
	Start(Spec),
	/// Pause: stop (sending what is left), keep the folder registered.
	Stop,
	/// Sign out: stop, unregister the folder and remove what Gorani put
	/// there, then settings::sign_out. Answers with `Done::SignedOut`.
	SignOut { profile: PathBuf, folder: Option<String> },
	/// A folder given up for another: stop, unregister it, remove what
	/// Gorani put there. (The next Start names the new one.)
	Retire(String),
	Quit,
}

/// What a sync needs, read from the profile when it is started.
pub(crate) struct Spec {
	profile: PathBuf,
	folder: String,
	case: Option<String>,
	keep_local: bool,
	accept_unverified: bool,
	dev_email: Option<String>,
}

pub(crate) struct App {
	profile_path: PathBuf,
	hidden: HWND,
	settings: Option<HWND>,
	status: Status,
	sync: mpsc::Sender<SyncCmd>,
	icon: HICON,
	taskbar_created: u32,
}

thread_local! {
	static APP: RefCell<Option<App>> = const { RefCell::new(None) };
}

/// The app's state for a moment (None while another borrow holds it).
pub(crate) fn with_app<R>(f: impl FnOnce(&mut App) -> R) -> Option<R> {
	APP.with(|a| a.try_borrow_mut().ok().and_then(|mut a| a.as_mut().map(f)))
}

/// The profile this app uses: the same file the CLI and gorani-cloud read.
pub(crate) fn profile_path() -> PathBuf {
	let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_else(|_| ".".into());
	PathBuf::from(home).join(".gorani-sync.json")
}

pub(crate) fn home() -> PathBuf {
	profile_path().parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."))
}

pub fn run(args: Vec<String>) -> i32 {
	if args.iter().any(|a| matches!(a.as_str(), "--version" | "--help" | "-h" | "/?")) {
		// (Printed where the caller can read it: a pipe, as the package's
		// checks use. Started from the Start menu there is nowhere, and
		// nothing is printed.)
		println!("usage: gorani [--background] — the Windows app: Gorani's tray icon and Settings (version {})", env!("CARGO_PKG_VERSION"));
		return 0;
	}
	if args.iter().any(|a| a == "--self-test") {
		// SAFETY: as below, for the window alone.
		unsafe {
			let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
			let icc = INITCOMMONCONTROLSEX { dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32, dwICC: ICC_STANDARD_CLASSES | ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES };
			let _ = InitCommonControlsEx(&icc);
		}
		return match window::self_test() {
			Ok(said) => {
				println!("{said}");
				0
			}
			Err(e) => {
				println!("self-test failed: {e}");
				1
			}
		};
	}
	let background = args.iter().any(|a| a == "--background") || startup::started_at_login();
	// SAFETY: once, on the window thread, before any window or COM object.
	unsafe {
		let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
		let icc = INITCOMMONCONTROLSEX { dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32, dwICC: ICC_STANDARD_CLASSES | ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES };
		let _ = InitCommonControlsEx(&icc);
	}
	let Some(_single) = single_instance() else {
		// Already running: its Settings, and done.
		// SAFETY: finding and posting to the first instance's window.
		unsafe {
			if let Ok(h) = FindWindowW(HIDDEN_CLASS, PCWSTR::null()) {
				let _ = PostMessageW(Some(h), WM_APP_SHOW, WPARAM(0), LPARAM(0));
			}
		}
		return 0;
	};
	let Some(hidden) = hidden_window() else { return 1 };
	window::register();
	let icon = tray::load_icon();
	// SAFETY: a registered message name; no preconditions.
	let taskbar_created = unsafe { RegisterWindowMessageW(w!("TaskbarCreated")) };
	let (tx, rx) = mpsc::channel();
	let to = Target::of(hidden);
	let sync_thread = std::thread::Builder::new().name("gorani-sync".into()).spawn(move || sync_loop(rx, to)).ok();
	APP.with(|a| *a.borrow_mut() = Some(App { profile_path: profile_path(), hidden, settings: None, status: Status::Stopped, sync: tx, icon, taskbar_created }));
	tray::add(hidden, icon, &Status::Stopped);
	first_steps(background);

	let mut msg = MSG::default();
	// SAFETY: the standard message loop; the Settings window takes its own
	// keys (Tab, Enter, Escape) first.
	unsafe {
		while GetMessageW(&mut msg, None, 0, 0).as_bool() {
			if let Some(Some(dialog)) = with_app(|a| a.settings) {
				if IsDialogMessageW(dialog, &msg).as_bool() {
					continue;
				}
			}
			let _ = TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}
	}
	// Quit: the folder stops (sending what is left; dropping the local
	// bytes unless they are kept), then the icon goes.
	with_app(|a| {
		let _ = a.sync.send(SyncCmd::Quit);
	});
	if let Some(t) = sync_thread {
		let _ = t.join();
	}
	tray::remove(hidden);
	0
}

/// The mutex that makes the app one per sign-in session. None: another
/// instance holds it.
fn single_instance() -> Option<HANDLE> {
	// SAFETY: a named mutex in this session's namespace, held for the
	// process's life (the handle is never closed: the system frees it).
	unsafe {
		let h = CreateMutexW(None, true, w!("Local\\Gorani.App.Single")).ok()?;
		(GetLastError() != ERROR_ALREADY_EXISTS).then_some(h)
	}
}

fn hidden_window() -> Option<HWND> {
	let class = WNDCLASSEXW { cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32, lpfnWndProc: Some(hidden_proc), hInstance: ui::hinstance(), lpszClassName: HIDDEN_CLASS, ..Default::default() };
	// SAFETY: registering our class and making its one window: a hidden
	// top-level window (a message-only one would miss TaskbarCreated).
	unsafe {
		RegisterClassExW(&class);
		CreateWindowExW(WINDOW_EX_STYLE(0), HIDDEN_CLASS, w!("Gorani"), WS_OVERLAPPED, 0, 0, 0, 0, None, None, Some(ui::hinstance()), None).ok()
	}
}

/// What happens at start: an enrolled computer with a folder syncs; one
/// that is not enrolled, or has no folder, gets its Settings.
fn first_steps(background: bool) {
	let path = profile_path();
	match session::load_profile(&path) {
		Ok(p) if session::has_device_copy(&p) => {
			if p.app.paused {
				set_status(Status::Paused);
			} else if p.app.folder.is_none() {
				set_status(Status::NoFolder);
				window::open(window::Tab::Sync);
			} else {
				start_sync(&path, &p);
				if !background {
					with_app(|a| tray::notify(a.hidden, "Gorani is running", "It syncs from the notification area. Right-click the water deer for Settings.", false));
				}
			}
		}
		_ => {
			set_status(Status::NotEnrolled);
			window::open(window::Tab::Account);
		}
	}
}

/// Start (or restart) syncing as the profile says.
pub(crate) fn start_sync(path: &Path, p: &DeviceProfile) {
	let Some(folder) = p.app.folder.clone() else {
		set_status(Status::NoFolder);
		return;
	};
	let spec = Spec { profile: path.to_path_buf(), folder, case: p.app.case.clone(), keep_local: p.app.keep_local, accept_unverified: p.app.accept_unverified, dev_email: p.dev_email.clone() };
	with_app(|a| {
		let _ = a.sync.send(SyncCmd::Start(spec));
	});
}

pub(crate) fn stop_sync() {
	with_app(|a| {
		let _ = a.sync.send(SyncCmd::Stop);
	});
}

pub(crate) fn retire(folder: String) {
	with_app(|a| {
		let _ = a.sync.send(SyncCmd::Retire(folder));
	});
}

pub(crate) fn sign_out(folder: Option<String>) {
	with_app(|a| {
		let _ = a.sync.send(SyncCmd::SignOut { profile: a.profile_path.clone(), folder });
	});
}

pub(crate) fn set_status(status: Status) {
	let shown = with_app(|a| {
		a.status = status.clone();
		tray::update(a.hidden, &status);
		a.settings
	});
	if let Some(Some(_)) = shown {
		window::status_changed(&status);
	}
}

pub(crate) fn status() -> Status {
	with_app(|a| a.status.clone()).unwrap_or(Status::Stopped)
}

/// The hidden window: the tray icon's owner, and where other threads post.
unsafe extern "system" fn hidden_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
	match msg {
		WM_APP_TRAY => {
			match lparam.0 as u32 {
				WM_RBUTTONUP | WM_CONTEXTMENU => tray_menu(hwnd),
				WM_LBUTTONDBLCLK => match status().folder() {
					Some(folder) => ui::open(folder),
					None => window::open(window::Tab::Account),
				},
				_ => {}
			}
			LRESULT(0)
		}
		WM_COMMAND => {
			menu_command((wparam.0 & 0xffff) as u16);
			LRESULT(0)
		}
		WM_APP_EVENT => {
			// SAFETY: every WM_APP_EVENT is posted by Target::post::<Event>.
			let event = unsafe { ui::taken::<Event>(lparam) };
			match *event {
				Event::Status(s) => set_status(s),
				Event::Done(done) => window::done(done),
			}
			LRESULT(0)
		}
		WM_APP_SHOW => {
			window::open(window::Tab::Account);
			LRESULT(0)
		}
		WM_DESTROY => {
			// SAFETY: ends the message loop.
			unsafe { PostQuitMessage(0) };
			LRESULT(0)
		}
		_ => {
			if with_app(|a| a.taskbar_created).is_some_and(|m| m != 0 && m == msg) {
				// Explorer restarted: the icon again.
				with_app(|a| tray::add(a.hidden, a.icon, &a.status));
			}
			// SAFETY: the default for everything else.
			unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
		}
	}
}

fn tray_menu(hwnd: HWND) {
	let status = status();
	let profile = session::load_profile(&profile_path()).ok();
	let enrolled = profile.as_ref().is_some_and(session::has_device_copy);
	let paused = profile.as_ref().is_some_and(|p| p.app.paused);
	// (No borrow held: the menu runs a message loop of its own.)
	tray::menu(hwnd, &status, enrolled, paused);
}

fn menu_command(id: u16) {
	let path = profile_path();
	match id {
		tray::OPEN_FOLDER => {
			if let Some(f) = status().folder() {
				ui::open(f);
			}
		}
		tray::OPEN_WEB => {
			let server = session::load_profile(&path).map(|p| p.server).unwrap_or_else(|_| gorani_client_core::DEFAULT_SERVER.into());
			ui::open(&server);
		}
		tray::PAUSE => toggle_pause(),
		tray::SETTINGS => window::open(window::Tab::Account),
		tray::QUIT => {
			window::close();
			// (The handle first, the borrow let go: destroying runs the
			// window procedure again.)
			if let Some(hidden) = with_app(|a| a.hidden) {
				// SAFETY: destroying our own hidden window ends the loop.
				unsafe {
					let _ = DestroyWindow(hidden);
				}
			}
		}
		_ => {}
	}
}

/// Pause or resume, saved in the profile (the next start remembers).
pub(crate) fn toggle_pause() {
	let path = profile_path();
	let Ok(mut p) = session::load_profile(&path) else { return };
	p.app.paused = !p.app.paused;
	if gorani_client_core::settings::save(&path, &p.app).is_err() {
		return;
	}
	if p.app.paused {
		stop_sync();
		set_status(Status::Paused);
	} else {
		start_sync(&path, &p);
	}
	window::profile_changed();
}

// ── the sync thread ─────────────────────────────────────────────────

fn sync_loop(rx: mpsc::Receiver<SyncCmd>, to: Target) {
	use crate::provider;
	let mut running: Option<provider::Running> = None;
	let post = |s: Status| to.post(WM_APP_EVENT, Event::Status(s));
	while let Ok(cmd) = rx.recv() {
		match cmd {
			SyncCmd::Start(spec) => {
				if let Some(r) = running.take() {
					r.stop();
				}
				post(Status::Connecting);
				match start(&spec) {
					Ok(r) => {
						post(Status::Running { folder: r.root().display().to_string() });
						running = Some(r);
					}
					Err(e) => post(Status::Failed(e)),
				}
			}
			SyncCmd::Stop => {
				if let Some(r) = running.take() {
					r.stop();
				}
			}
			SyncCmd::SignOut { profile, folder } => {
				if let Some(r) = running.take() {
					r.stop();
				}
				let left = folder.as_deref().map(|f| remove_folder(Path::new(f))).unwrap_or_default();
				let out = gorani_client_core::settings::sign_out(&profile).map_err(|e| e.to_string()).map(|mut o| {
					if left > 0 {
						let note = format!("{left} file(s) kept on this computer stay in {}", folder.as_deref().unwrap_or_default());
						o.warning = Some(match o.warning.take() {
							Some(w) => format!("{w}. {note}"),
							None => note,
						});
					}
					o
				});
				post(Status::NotEnrolled);
				to.post(WM_APP_EVENT, Event::Done(window::Done::SignedOut(out)));
			}
			SyncCmd::Retire(folder) => {
				if let Some(r) = running.take() {
					r.stop();
				}
				remove_folder(Path::new(&folder));
			}
			SyncCmd::Quit => {
				if let Some(r) = running.take() {
					r.stop();
				}
				break;
			}
		}
	}
}

fn start(spec: &Spec) -> Result<crate::provider::Running, String> {
	use gorani_client_core::replica::{self, Remote};
	let remote = replica::connect(&spec.profile, spec.case.as_deref(), None, spec.dev_email.as_deref(), spec.accept_unverified).map_err(|e| e.to_string())?;
	let remote: Arc<Mutex<dyn Remote + Send>> = Arc::new(Mutex::new(remote));
	crate::provider::start(Path::new(&spec.folder), remote, crate::provider::Options { poll: Some(std::time::Duration::from_secs(3)), keep_local: spec.keep_local, verbose: false })
}

/// After a sign-out: the folder stops being a sync root, and what Gorani
/// put there goes — placeholders (no bytes here) and the folders left
/// empty. Whole files stay: they are copies the person chose to keep
/// (Keep downloaded files), and deleting a file is never a guess. Returns
/// how many files stayed.
fn remove_folder(root: &Path) -> usize {
	use std::os::windows::fs::MetadataExt;
	const PLACEHOLDER: u32 = 0x0040_0000 /* RECALL_ON_DATA_ACCESS */ | 0x0004_0000 /* RECALL_ON_OPEN */ | 0x0000_1000 /* OFFLINE */;
	let _ = crate::shell::unregister(root);
	fn walk(dir: &Path, kept: &mut usize) {
		let Ok(entries) = std::fs::read_dir(dir) else { return };
		for e in entries.flatten() {
			let p = e.path();
			let Ok(m) = std::fs::symlink_metadata(&p) else { continue };
			if m.is_dir() {
				walk(&p, kept);
				let _ = std::fs::remove_dir(&p);
			} else if m.file_attributes() & PLACEHOLDER != 0 {
				let _ = std::fs::remove_file(&p);
			} else {
				*kept += 1;
			}
		}
	}
	let mut kept = 0;
	walk(root, &mut kept);
	let _ = std::fs::remove_dir(root);
	kept
}
