// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The Settings window (commit 40b, docs/DESKTOP.md › 40b): four tabs, each
//! a set of plain Win32 controls, every decision made by the core
//! (gorani_client_core::settings) or by appmodel.rs.
//!
//! ```text
//! Account     Server · Sign in with your browser (40c) · signed in as …
//!             not enrolled: this computer's name, its protection, the vault
//!               password, Enrol
//!             enrolled: where and how it is enrolled, Change server…, Sign out…
//! Sync        Folder (Browse…) · Show: my files or a case (Refresh) · start at
//!             sign-in · keep downloaded files · Pause · Save
//! Devices     this computer's protection, and changing it · your computers
//!             (Refresh, Revoke selected…)
//! Advanced    the sign-in command · an Access service token · accept unverified
//!             files · the scanner · Save
//! ```
//!
//! Work that waits on the network or a person (the browser sign-in, an
//! enrolment, a list of devices) runs on a thread of its own and comes
//! back as `Done`, so the window stays responsive. The vault password is
//! read once, out of its box (which is emptied), into memory that is
//! wiped when the enrolment ends.

use std::cell::RefCell;
use std::path::Path;

use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{GetSysColor, GetSysColorBrush, SetBkColor, COLOR_WINDOW, HDC, HFONT};
use windows::Win32::UI::Controls::{NMHDR, TCN_SELCHANGE, WC_LISTVIEWW, WC_TABCONTROLW, LVS_REPORT, LVS_SINGLESEL, LVS_SHOWSELALWAYS, LVS_NOSORTHEADER};
use windows::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForSystem, GetDpiForWindow};
use windows::Win32::UI::WindowsAndMessaging::*;

use gorani_client_core::settings::{self, AppSettings, CaseChoice, Device, Me, SignIn};
use gorani_client_core::{devicekey, session, DeviceProfile};

use super::ui::{self, Target};
use super::{with_app, Event, WM_APP_EVENT};
use crate::appmodel::{self, Status};

const CLASS: PCWSTR = w!("Gorani.Settings");
const TITLE: &str = "Gorani Settings";
/// The client area, in 96-dpi units.
const WIDTH: i32 = 580;
const HEIGHT: i32 = 500;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Tab {
	Account = 0,
	Sync = 1,
	Devices = 2,
	Advanced = 3,
}

/// A finished job, back on the window thread.
pub(crate) enum Done {
	/// The sign-in command, proven to print a token.
	SignedIn(Result<String, String>),
	Me(Result<Me, String>),
	Enrolled(Result<Box<DeviceProfile>, String>),
	SignedOut(Result<settings::SignedOut, String>),
	Devices(Result<Vec<Device>, String>),
	Revoked(Result<String, String>),
	/// The new protection label.
	Protected(Result<String, String>),
	Cases(Result<Vec<CaseChoice>, String>),
}

// Control ids (WM_COMMAND).
const ID_TAB: u16 = 200;
const ID_SIGN_IN: u16 = 201;
const ID_ENROL: u16 = 202;
const ID_SIGN_OUT: u16 = 203;
const ID_CHANGE_SERVER: u16 = 204;
const ID_PROTECT: u16 = 205;
const ID_BROWSE: u16 = 210;
const ID_AREA_REFRESH: u16 = 211;
const ID_PAUSE: u16 = 212;
const ID_SYNC_SAVE: u16 = 213;
const ID_PROT_COMBO: u16 = 220;
const ID_PROT_CHANGE: u16 = 221;
const ID_DEV_REFRESH: u16 = 222;
const ID_DEV_REVOKE: u16 = 223;
const ID_ADV_SAVE: u16 = 230;
const ID_CLOSE: u16 = 240;
/// What IsDialogMessage sends for Escape.
const IDCANCEL_ID: u16 = 2;

/// When a control shows.
#[derive(Clone, Copy, PartialEq)]
enum Show {
	Always,
	Enrolled,
	NotEnrolled,
}

struct Placed {
	h: HWND,
	/// None: under every tab (the status line, Close).
	page: Option<usize>,
	show: Show,
	r: [i32; 4],
}

#[derive(Default)]
struct C {
	tab: HWND,
	server: HWND,
	sign_in: HWND,
	signed_as: HWND,
	name: HWND,
	protect: HWND,
	protect_detail: HWND,
	password: HWND,
	enrolled: HWND,
	folder: HWND,
	area: HWND,
	start_login: HWND,
	keep_local: HWND,
	pause: HWND,
	prot_now: HWND,
	prot_combo: HWND,
	prot_detail: HWND,
	devices: HWND,
	cmd: HWND,
	access_id: HWND,
	access_secret: HWND,
	accept: HWND,
	scan: HWND,
	status: HWND,
}

struct Win {
	hwnd: HWND,
	dpi: u32,
	font: HFONT,
	placed: Vec<Placed>,
	c: C,
	/// The enrolled profile (None: not enrolled).
	profile: Option<DeviceProfile>,
	/// Before enrolment: the sign-in the browser handed over (40c).
	token: Option<zeroize::Zeroizing<String>>,
	/// A browser sign-in waiting: set to cancel it (Sign in pressed
	/// again, or the window closed).
	signing: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
	devices: Vec<Device>,
	/// The area menu's entries after "My files": case ids, with titles.
	cases: Vec<(String, String)>,
	/// A new server waiting for the sign-out that makes room for it.
	next_server: Option<String>,
	busy: bool,
}

thread_local! {
	static WIN: RefCell<Option<Win>> = const { RefCell::new(None) };
}

fn with_win<R>(f: impl FnOnce(&mut Win) -> R) -> Option<R> {
	WIN.with(|w| w.try_borrow_mut().ok().and_then(|mut w| w.as_mut().map(f)))
}

pub(crate) fn register() {
	let class = WNDCLASSEXW {
		cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
		lpfnWndProc: Some(proc_),
		hInstance: ui::hinstance(),
		lpszClassName: CLASS,
		// SAFETY: a system brush and the system's arrow, no preconditions.
		hbrBackground: unsafe { GetSysColorBrush(COLOR_WINDOW) },
		hCursor: unsafe { LoadCursorW(None, IDC_ARROW).unwrap_or_default() },
		..Default::default()
	};
	// SAFETY: registering our own class once.
	unsafe {
		RegisterClassExW(&class);
	}
}

/// Show Settings at `tab` (made the first time, brought forward after).
pub(crate) fn open(tab: Tab) {
	if let Some(Some(h)) = with_app(|a| a.settings) {
		select(tab);
		// SAFETY: our own window.
		unsafe {
			let _ = ShowWindow(h, SW_SHOWNORMAL);
			let _ = SetForegroundWindow(h);
		}
		return;
	}
	let Some(hwnd) = create() else { return };
	with_app(|a| {
		a.settings = Some(hwnd);
		// SAFETY: the app's icon on our window.
		unsafe {
			SendMessageW(hwnd, WM_SETICON, Some(WPARAM(ICON_SMALL as usize)), Some(LPARAM(a.icon.0 as isize)));
			SendMessageW(hwnd, WM_SETICON, Some(WPARAM(ICON_BIG as usize)), Some(LPARAM(a.icon.0 as isize)));
		}
	});
	refresh();
	select(tab);
	status_changed(&super::status());
	// SAFETY: our own window.
	unsafe {
		let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
		let _ = SetForegroundWindow(hwnd);
	}
}

/// The window and its controls, not shown yet.
fn create() -> Option<HWND> {
	// SAFETY: making our window at the system DPI, then the controls.
	let dpi = unsafe { GetDpiForSystem() };
	let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
	let ex = WS_EX_CONTROLPARENT;
	let mut r = RECT { left: 0, top: 0, right: ui::scale(WIDTH, dpi), bottom: ui::scale(HEIGHT, dpi) };
	// SAFETY: as above.
	let hwnd = unsafe {
		let _ = AdjustWindowRectExForDpi(&mut r, style, false, ex, dpi);
		CreateWindowExW(ex, CLASS, &HSTRING::from(TITLE), style, CW_USEDEFAULT, CW_USEDEFAULT, r.right - r.left, r.bottom - r.top, None, None, Some(ui::hinstance()), None)
	}
	.ok()?;
	// SAFETY: the window exists now; its own DPI. A window that opened on a
	// screen of another DPI than the system's is sized again for it.
	let dpi = unsafe { GetDpiForWindow(hwnd) }.max(96);
	if dpi != unsafe { GetDpiForSystem() } {
		let mut r = RECT { left: 0, top: 0, right: ui::scale(WIDTH, dpi), bottom: ui::scale(HEIGHT, dpi) };
		// SAFETY: sizing our own window.
		unsafe {
			let _ = AdjustWindowRectExForDpi(&mut r, style, false, ex, dpi);
			let _ = SetWindowPos(hwnd, None, 0, 0, r.right - r.left, r.bottom - r.top, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
		}
	}
	let win = build(hwnd, dpi);
	WIN.with(|w| *w.borrow_mut() = Some(win));
	Some(hwnd)
}

/// `gorani --self-test` (CI, commit 40b): the real window, made but never
/// shown. Every control must exist, every tab must arrange, the layout
/// must survive a DPI change, and the window must go cleanly. It needs no
/// profile, no network and no person, so a build machine can run it.
pub(crate) fn self_test() -> Result<String, String> {
	register();
	let hwnd = create().ok_or("the Settings window could not be made")?;
	let missing = with_win(|w| w.placed.iter().filter(|p| p.h.is_invalid()).count()).unwrap_or(usize::MAX);
	if missing != 0 {
		return Err(format!("{missing} control(s) could not be made"));
	}
	let controls = with_win(|w| w.placed.len()).unwrap_or(0);
	refresh();
	for tab in [Tab::Account, Tab::Sync, Tab::Devices, Tab::Advanced] {
		select(tab);
		if with_win(|w| ui::tab_selected(w.c.tab)) != Some(tab as usize) {
			return Err(format!("the tab {} did not open", tab as usize));
		}
	}
	let choices = with_win(|w| (ui::combo_selected(w.c.protect), ui::text(w.c.protect_detail))).unwrap_or_default();
	if choices.0 != Some(0) || choices.1.is_empty() {
		return Err("the protection menu is empty".into());
	}
	with_win(|w| {
		ui::drop_font(w.font);
		w.dpi = 144;
		w.font = ui::message_font(144);
		relayout(w);
	});
	if with_win(|w| w.font.is_invalid()) != Some(false) {
		return Err("no message font at 144 dpi".into());
	}
	// SAFETY: our own window; WM_DESTROY clears the state.
	unsafe {
		DestroyWindow(hwnd).map_err(|e| e.message().to_string())?;
	}
	if with_win(|_| ()).is_some() {
		return Err("the window's state outlived it".into());
	}
	Ok(format!("self-test ok: {controls} controls, 4 tabs, re-laid out at 144 dpi"))
}

pub(crate) fn close() {
	if let Some(Some(h)) = with_app(|a| a.settings) {
		// SAFETY: destroying our own window (WM_DESTROY clears the state).
		unsafe {
			let _ = DestroyWindow(h);
		}
	}
}

fn build(hwnd: HWND, dpi: u32) -> Win {
	let mut placed: Vec<Placed> = Vec::new();
	let mut add = |page: Option<usize>, show: Show, class: PCWSTR, text: &str, style: WINDOW_STYLE, ex: WINDOW_EX_STYLE, id: u16, r: [i32; 4]| -> HWND {
		let h = ui::control(hwnd, class, text, style, ex, id);
		placed.push(Placed { h, page, show, r });
		h
	};
	let none = WINDOW_EX_STYLE(0);
	let edge = WS_EX_CLIENTEDGE;
	let label = WINDOW_STYLE(0);
	let edit = WS_TABSTOP | ui::ws(ES_AUTOHSCROLL);
	let button = WS_TABSTOP | ui::ws(BS_PUSHBUTTON);
	let check = WS_TABSTOP | ui::ws(BS_AUTOCHECKBOX);
	let combo = WS_TABSTOP | WS_VSCROLL | ui::ws(CBS_DROPDOWNLIST);
	let mut c = C { tab: add(None, Show::Always, WC_TABCONTROLW, "", WS_TABSTOP, none, ID_TAB, [8, 8, 564, 432]), ..Default::default() };
	for (i, title) in ["Account", "Sync", "This computer & devices", "Advanced"].iter().enumerate() {
		ui::tab_add(c.tab, i, title);
	}
	let (a, s, d, v) = (Some(0), Some(1), Some(2), Some(3));
	use Show::{Always, Enrolled, NotEnrolled};

	// Account.
	add(a, Always, ui::STATIC, "Server", label, none, 0, [24, 51, 160, 20]);
	c.server = add(a, Always, ui::EDIT, gorani_client_core::DEFAULT_SERVER, edit, edge, 0, [192, 48, 250, 24]);
	add(a, Enrolled, ui::BUTTON, "Change server…", button, none, ID_CHANGE_SERVER, [450, 47, 102, 26]);
	c.sign_in = add(a, Always, ui::BUTTON, SIGN_IN, button, none, ID_SIGN_IN, [192, 82, 230, 28]);
	c.signed_as = add(a, Always, ui::STATIC, "Not signed in yet.", label, none, 0, [192, 116, 360, 36]);
	add(a, NotEnrolled, ui::STATIC, "This computer's name", label, none, 0, [24, 165, 160, 20]);
	c.name = add(a, NotEnrolled, ui::EDIT, "", edit, edge, 0, [192, 162, 360, 24]);
	add(a, NotEnrolled, ui::STATIC, "Protect its key with", label, none, 0, [24, 199, 160, 20]);
	c.protect = add(a, NotEnrolled, ui::COMBOBOX, "", combo, none, ID_PROTECT, [192, 196, 360, 200]);
	c.protect_detail = add(a, NotEnrolled, ui::STATIC, "", label, none, 0, [192, 226, 360, 36]);
	add(a, NotEnrolled, ui::STATIC, "Vault password or recovery code", label, none, 0, [24, 268, 160, 36]);
	c.password = add(a, NotEnrolled, ui::EDIT, "", edit | ui::ws(ES_PASSWORD), edge, 0, [192, 270, 360, 24]);
	add(a, NotEnrolled, ui::BUTTON, "Enrol this computer", button, none, ID_ENROL, [192, 306, 200, 30]);
	c.enrolled = add(a, Enrolled, ui::STATIC, "", label, none, 0, [24, 166, 528, 56]);
	add(a, Enrolled, ui::BUTTON, "Sign out of this computer…", button, none, ID_SIGN_OUT, [24, 230, 240, 30]);

	// Sync, This computer & devices, Advanced: each says "enrol first" until it is.
	for p in [s, d, v] {
		add(p, NotEnrolled, ui::STATIC, "Enrol this computer first, on the Account tab.", label, none, 0, [24, 52, 528, 40]);
	}
	add(s, Enrolled, ui::STATIC, "Folder", label, none, 0, [24, 51, 160, 20]);
	c.folder = add(s, Enrolled, ui::EDIT, "", edit, edge, 0, [192, 48, 260, 24]);
	add(s, Enrolled, ui::BUTTON, "Browse…", button, none, ID_BROWSE, [460, 47, 92, 26]);
	add(s, Enrolled, ui::STATIC, "Show", label, none, 0, [24, 87, 160, 20]);
	c.area = add(s, Enrolled, ui::COMBOBOX, "", combo, none, 0, [192, 84, 260, 200]);
	add(s, Enrolled, ui::BUTTON, "Refresh", button, none, ID_AREA_REFRESH, [460, 83, 92, 26]);
	c.start_login = add(s, Enrolled, ui::BUTTON, "Start Gorani when I sign in to Windows", check, none, 0, [24, 124, 528, 22]);
	c.keep_local = add(s, Enrolled, ui::BUTTON, "Keep downloaded files on this computer when Gorani stops", check, none, 0, [24, 152, 528, 22]);
	add(s, Enrolled, ui::STATIC, "Off: a file's bytes are on this disk only while Gorani runs. On: the disk's own encryption (BitLocker) is what protects them.", label, none, 0, [44, 176, 508, 36]);
	c.pause = add(s, Enrolled, ui::BUTTON, "Pause syncing", button, none, ID_PAUSE, [24, 226, 160, 30]);
	add(s, Enrolled, ui::BUTTON, "Save", button, none, ID_SYNC_SAVE, [452, 226, 100, 30]);

	c.prot_now = add(d, Enrolled, ui::STATIC, "", label, none, 0, [24, 50, 528, 22]);
	add(d, Enrolled, ui::STATIC, "Change it to", label, none, 0, [24, 83, 160, 20]);
	c.prot_combo = add(d, Enrolled, ui::COMBOBOX, "", combo, none, ID_PROT_COMBO, [192, 80, 250, 200]);
	add(d, Enrolled, ui::BUTTON, "Change", button, none, ID_PROT_CHANGE, [452, 79, 100, 28]);
	c.prot_detail = add(d, Enrolled, ui::STATIC, "", label, none, 0, [192, 110, 360, 36]);
	add(d, Enrolled, ui::STATIC, "Your computers", label, none, 0, [24, 154, 528, 20]);
	c.devices = add(d, Enrolled, WC_LISTVIEWW, "", WS_TABSTOP | WINDOW_STYLE(LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER), edge, 0, [24, 176, 528, 200]);
	add(d, Enrolled, ui::BUTTON, "Refresh", button, none, ID_DEV_REFRESH, [24, 384, 100, 28]);
	add(d, Enrolled, ui::BUTTON, "Revoke selected…", button, none, ID_DEV_REVOKE, [132, 384, 160, 28]);

	add(v, Enrolled, ui::STATIC, "Sign-in command", label, none, 0, [24, 51, 160, 20]);
	c.cmd = add(v, Enrolled, ui::EDIT, "", edit, edge, 0, [192, 48, 360, 24]);
	add(v, Enrolled, ui::STATIC, "Access service token ID", label, none, 0, [24, 85, 160, 20]);
	c.access_id = add(v, Enrolled, ui::EDIT, "", edit, edge, 0, [192, 82, 360, 24]);
	add(v, Enrolled, ui::STATIC, "…and its secret", label, none, 0, [24, 119, 160, 20]);
	c.access_secret = add(v, Enrolled, ui::EDIT, "", edit | ui::ws(ES_PASSWORD), edge, 0, [192, 116, 360, 24]);
	c.accept = add(v, Enrolled, ui::BUTTON, "Accept files whose uploader's signature cannot be checked", check, none, 0, [24, 152, 528, 22]);
	add(v, Enrolled, ui::STATIC, "Scanner for upload-link items", label, none, 0, [24, 186, 160, 36]);
	c.scan = add(v, Enrolled, ui::EDIT, "", edit, edge, 0, [192, 188, 360, 24]);
	add(v, Enrolled, ui::STATIC, "Used by gorani-sync accept. {} is the file's path; run without a shell. Empty: none.", label, none, 0, [192, 216, 360, 36]);
	add(v, Enrolled, ui::BUTTON, "Save", button, none, ID_ADV_SAVE, [452, 262, 100, 30]);

	c.status = add(None, Always, ui::STATIC, "", label, none, 0, [12, 448, 440, 44]);
	add(None, Always, ui::BUTTON, "Close", button, none, ID_CLOSE, [468, 452, 100, 30]);

	ui::cue(c.cmd, "cloudflared access token -app=https://…");
	ui::cue(c.scan, "clamscan --no-summary");
	ui::cue(c.name, "e.g. Jinu's ThinkPad");
	ui::list_columns(c.devices, &[("Name", 170), ("System", 70), ("Protection", 130), ("Last seen", 150)], dpi);
	let font = ui::message_font(dpi);
	let win = Win { hwnd, dpi, font, placed, c, profile: None, token: None, signing: None, devices: Vec::new(), cases: Vec::new(), next_server: None, busy: false };
	relayout(&win);
	win
}

fn relayout(win: &Win) {
	for p in &win.placed {
		ui::place(p.h, p.r[0], p.r[1], p.r[2], p.r[3], win.dpi);
		ui::set_font(p.h, win.font);
	}
}

/// Show what belongs to the chosen tab and the enrolment state.
fn arrange(win: &Win) {
	let tab = ui::tab_selected(win.c.tab);
	let enrolled = win.profile.is_some();
	for p in &win.placed {
		let page = p.page.is_none_or(|pg| pg == tab);
		let state = match p.show {
			Show::Always => true,
			Show::Enrolled => enrolled,
			Show::NotEnrolled => !enrolled,
		};
		ui::show(p.h, page && state);
	}
}

fn select(tab: Tab) {
	let load_devices_now = with_win(|w| {
		ui::tab_select(w.c.tab, tab as usize);
		arrange(w);
		tab == Tab::Devices && w.devices.is_empty() && w.profile.is_some()
	});
	if load_devices_now == Some(true) {
		load_devices();
	}
}

fn say(text: &str) {
	with_win(|w| ui::set_text(w.c.status, text));
}

/// The sync's state, at the foot of the window.
pub(crate) fn status_changed(status: &Status) {
	with_win(|w| {
		if !w.busy {
			ui::set_text(w.c.status, &status.line());
		}
		ui::set_text(w.c.pause, if matches!(status, Status::Paused) { "Resume syncing" } else { "Pause syncing" });
	});
}

/// The profile changed elsewhere (Pause from the tray): show it again.
pub(crate) fn profile_changed() {
	if with_win(|_| ()).is_some() {
		refresh();
	}
}

/// Fill every tab from the profile.
fn refresh() {
	let path = super::profile_path();
	let profile = session::load_profile(&path).ok().filter(session::has_device_copy);
	let start_login = super::startup::enabled();
	let first_whoami = with_win(|w| {
		w.profile = profile.clone();
		let c = &w.c;
		let server = w.next_server.clone().or_else(|| profile.as_ref().map(|p| p.server.clone())).unwrap_or_else(|| gorani_client_core::DEFAULT_SERVER.into());
		ui::set_text(c.server, &server);
		ui::combo_clear(c.protect);
		ui::combo_clear(c.prot_combo);
		for choice in settings::protection_choices() {
			ui::combo_add(c.protect, choice.label);
			ui::combo_add(c.prot_combo, choice.label);
		}
		ui::combo_select(c.protect, 0);
		ui::combo_select(c.prot_combo, 0);
		describe_choice(c.protect, c.protect_detail);
		describe_choice(c.prot_combo, c.prot_detail);
		match &profile {
			None => {
				if ui::text(c.name).is_empty() {
					ui::set_text(c.name, &std::env::var("COMPUTERNAME").unwrap_or_else(|_| "this computer".into()));
				}
			}
			Some(p) => {
				let name = p.app.device_name.clone().unwrap_or_else(|| p.device_id.clone());
				ui::set_text(c.enrolled, &appmodel::enrolled_line(&name, &p.server, &settings::protection(p)));
				ui::set_text(c.prot_now, &format!("This computer's key part is protected by: {}", settings::protection(p)));
				ui::set_text(c.folder, &p.app.folder.clone().unwrap_or_else(|| appmodel::default_folder(&super::home(), None).display().to_string()));
				ui::combo_clear(c.area);
				ui::combo_add(c.area, "My files");
				if w.cases.is_empty() {
					if let Some(case) = &p.app.case {
						w.cases = vec![(case.clone(), format!("Case {case}"))];
					}
				}
				for (_, title) in &w.cases {
					ui::combo_add(c.area, title);
				}
				let at = p.app.case.as_ref().and_then(|id| w.cases.iter().position(|(c, _)| c == id)).map(|i| i + 1).unwrap_or(0);
				ui::combo_select(c.area, at);
				ui::set_checked(c.start_login, start_login);
				ui::set_checked(c.keep_local, p.app.keep_local);
				ui::set_checked(c.accept, p.app.accept_unverified);
				ui::set_text(c.cmd, p.access_token_cmd.as_deref().unwrap_or_default());
				ui::set_text(c.access_id, p.access_id.as_deref().unwrap_or_default());
				ui::cue(c.access_secret, if p.access_secret.is_some() { "(unchanged)" } else { "" });
				ui::set_text(c.scan, p.app.scan_command.as_deref().unwrap_or_default());
				ui::set_text(c.pause, if p.app.paused { "Resume syncing" } else { "Pause syncing" });
			}
		}
		arrange(w);
		profile.clone()
	});
	// Who is signed in, said as soon as it is known.
	if let Some(Some(p)) = first_whoami {
		let sign_in = SignIn::of(&p);
		job(move || Done::Me(settings::whoami(&sign_in).map_err(|e| e.to_string())));
	}
}

fn describe_choice(combo: HWND, detail: HWND) {
	let choices = settings::protection_choices();
	let i = ui::combo_selected(combo).unwrap_or(0).min(choices.len() - 1);
	ui::set_text(detail, choices[i].detail);
}

fn chosen_protection(combo: HWND) -> Result<devicekey::Want, String> {
	let choices = settings::protection_choices();
	let i = ui::combo_selected(combo).unwrap_or(0).min(choices.len() - 1);
	choices[i].value.parse().map_err(|e: gorani_client_core::Error| e.to_string())
}

/// Run `f` on a thread of its own; its result comes back as WM_APP_EVENT.
fn job(f: impl FnOnce() -> Done + Send + 'static) {
	let Some(to) = with_app(|a| Target::of(a.hidden)) else { return };
	std::thread::spawn(move || to.post(WM_APP_EVENT, Event::Done(f())));
}

/// Mark the window busy with `what` (one job at a time). False: it was busy.
fn begin(what: &str) -> bool {
	with_win(|w| {
		if w.busy {
			return false;
		}
		w.busy = true;
		ui::set_text(w.c.status, what);
		true
	})
	.unwrap_or(false)
}

fn end(what: &str) {
	with_win(|w| {
		w.busy = false;
		ui::set_text(w.c.status, what);
	});
}

fn owner() -> HWND {
	with_win(|w| w.hwnd).unwrap_or_default()
}

// ── the actions ─────────────────────────────────────────────────────

const SIGN_IN: &str = "Sign in with your browser";

/// Sign in through the person's own browser (40c, signin.rs): the app
/// listens on this computer, the browser opens the team's page, the page
/// asks, and the browser hands the sign-in back. Pressed again while it
/// waits, the button cancels.
fn sign_in() {
	let waiting = with_win(|w| w.signing.take()).flatten();
	if let Some(cancel) = waiting {
		cancel.store(true, std::sync::atomic::Ordering::SeqCst);
		return;
	}
	let Some((typed, profile)) = with_win(|w| (ui::text(w.c.server), w.profile.clone())) else { return };
	let server = match &profile {
		Some(p) => p.server.clone(),
		None => match settings::normalize_server(&typed) {
			Ok(s) => s,
			Err(e) => return say(&e.to_string()),
		},
	};
	let pending = match gorani_client_core::signin::BrowserSignIn::start(&server) {
		Ok(p) => p,
		Err(e) => return say(&e.to_string()),
	};
	if !begin("Finish signing in in your browser — press the button on the page it opened.") {
		return;
	}
	let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
	with_win(|w| {
		w.signing = Some(cancel.clone());
		ui::set_text(w.c.sign_in, "Cancel signing in");
	});
	ui::open(&pending.url);
	job(move || Done::SignedIn(pending.wait(std::time::Duration::from_secs(300), Some(&cancel)).map(|t| t.to_string()).map_err(|e| e.to_string())));
}

fn enrol() {
	let Some((typed, name, password, want)) = with_win(|w| (ui::text(w.c.server), ui::text(w.c.name), ui::take_secret(w.c.password), chosen_protection(w.c.protect))) else { return };
	let want = match want {
		Ok(w) => w,
		Err(e) => return say(&e),
	};
	if password.is_empty() {
		return say("Type your vault password or recovery code: it opens your key once, on this computer.");
	}
	let server = match settings::normalize_server(&typed) {
		Ok(s) => s,
		Err(e) => return say(&e.to_string()),
	};
	let token = with_win(|w| w.token.as_ref().map(|t| t.to_string())).flatten();
	if !begin("Enrolling this computer…") {
		return;
	}
	let path = super::profile_path();
	let folder = appmodel::default_folder(&super::home(), None).display().to_string();
	job(move || {
		let sign_in = SignIn { server, access_token: token, dev_email: std::env::var("GORANI_DEV_EMAIL").ok(), ..Default::default() };
		let e = settings::Enrolment { sign_in, member: None, device_name: name, secret: &password, protect: want, tpm_options: Default::default(), device_secret: None, app: AppSettings { folder: Some(folder), ..Default::default() } };
		Done::Enrolled(settings::enrol(&path, e).map(Box::new).map_err(|e| e.to_string()))
	});
}

fn sign_out() {
	let Some(Some(p)) = with_win(|w| w.profile.clone()) else { return };
	if !ui::ask(owner(), TITLE, &appmodel::sign_out_question(&p.server, p.app.folder.as_deref())) {
		return;
	}
	if begin("Signing out…") {
		super::sign_out(p.app.folder.clone());
	}
}

fn change_server() {
	let Some((typed, Some(p))) = with_win(|w| (ui::text(w.c.server), w.profile.clone())) else { return };
	let next = match settings::normalize_server(&typed) {
		Ok(s) => s,
		Err(e) => return say(&e.to_string()),
	};
	if next == p.server {
		return say("That is the server this computer uses already.");
	}
	if !ui::ask(owner(), TITLE, &appmodel::change_server_question(&p.server, &next)) {
		with_win(|w| ui::set_text(w.c.server, &p.server));
		return;
	}
	if begin("Signing out, to move to the new server…") {
		with_win(|w| w.next_server = Some(next));
		super::sign_out(p.app.folder.clone());
	}
}

fn browse() {
	let Some(start) = with_win(|w| ui::text(w.c.folder)) else { return };
	// (No borrow held: the picker runs its own message loop.)
	if let Some(chosen) = ui::pick_folder(owner(), Some(&start)) {
		with_win(|w| ui::set_text(w.c.folder, &chosen));
	}
}

fn load_cases() {
	let Some(Some(p)) = with_win(|w| w.profile.clone()) else { return };
	if !begin("Opening your key to read the cases' titles…") {
		return;
	}
	job(move || {
		let r = session::unlock_device(&p).and_then(|sess| settings::cases(&p, &sess));
		Done::Cases(r.map_err(|e| e.to_string()))
	});
}

fn save_sync() {
	let path = super::profile_path();
	let Some(read) = with_win(|w| {
		let area = ui::combo_selected(w.c.area).unwrap_or(0);
		let case = if area == 0 { None } else { w.cases.get(area - 1).map(|(id, _)| id.clone()) };
		let title = if area == 0 { None } else { w.cases.get(area - 1).map(|(_, t)| t.clone()) };
		(w.profile.clone(), ui::text(w.c.folder).trim().to_string(), case, title, ui::checked(w.c.keep_local), ui::checked(w.c.start_login))
	}) else {
		return;
	};
	let (Some(p), folder, case, title, keep_local, start_login) = read else { return };
	let old = p.app.clone();
	// Each area has a folder of its own: the old area's placeholders must
	// never be taken for new files of the other one.
	if case != old.case && old.folder.as_deref() == Some(folder.as_str()) {
		let suggestion = appmodel::default_folder(&super::home(), title.as_deref()).display().to_string();
		with_win(|w| ui::set_text(w.c.folder, &suggestion));
		return say("Each area gets a folder of its own — a new one is suggested; press Save again to use it.");
	}
	if let Err(e) = appmodel::folder_ok(Path::new(&folder), old.folder.as_deref().map(Path::new)) {
		return say(&e);
	}
	let mut next = AppSettings { folder: Some(folder.clone()), case, keep_local, start_at_login: start_login, ..old.clone() };
	if start_login != super::startup::enabled() {
		if let Err(e) = super::startup::set(start_login) {
			next.start_at_login = !start_login;
			with_win(|w| ui::set_checked(w.c.start_login, !start_login));
			say(&format!("Start at sign-in: {e}"));
		}
	}
	let saved = match settings::save(&path, &next) {
		Ok(s) => s,
		Err(e) => return say(&e.to_string()),
	};
	with_win(|w| w.profile = Some(saved.clone()));
	if old.restart_needed(&next) && !next.paused {
		if old.folder.as_deref().is_some_and(|f| f != folder) {
			// The old folder goes before the new one starts (sync thread, in order).
			super::retire(old.folder.clone().unwrap_or_default());
		}
		super::start_sync(&path, &saved);
	}
	say("Saved.");
}

fn change_protection() {
	let Some((Some(p), want)) = with_win(|w| (w.profile.clone(), chosen_protection(w.c.prot_combo))) else { return };
	let want = match want {
		Ok(w) => w,
		Err(e) => return say(&e),
	};
	if !begin("Moving this computer's key part…") {
		return;
	}
	let path = super::profile_path();
	job(move || {
		let mut p = p;
		Done::Protected(session::protect(&path, &mut p, want, &Default::default(), None).map_err(|e| e.to_string()))
	});
}

fn load_devices() {
	let Some(Some(p)) = with_win(|w| w.profile.clone()) else { return };
	if !begin("Listing your computers…") {
		return;
	}
	job(move || Done::Devices(settings::devices(&p).map_err(|e| e.to_string())));
}

fn revoke() {
	let Some((Some(p), chosen)) = with_win(|w| (w.profile.clone(), ui::list_selected(w.c.devices).and_then(|i| w.devices.get(i).cloned()))) else { return };
	let Some(device) = chosen else { return say("Choose a computer in the list first.") };
	if device.this {
		return say("That is this computer — sign it out on the Account tab instead, which also forgets its key here.");
	}
	if !ui::ask(owner(), TITLE, &format!("Revoke “{}”?\n\nIts copy of your key is deleted from the server: it can never open your files again, until it is enrolled anew.", device.name)) {
		return;
	}
	if !begin("Revoking…") {
		return;
	}
	job(move || Done::Revoked(settings::revoke(&p, &device.id).map(|_| device.name.clone()).map_err(|e| e.to_string())));
}

fn save_advanced() {
	let path = super::profile_path();
	let Some((Some(p), cmd, id, secret, accept, scan)) = with_win(|w| (w.profile.clone(), ui::text(w.c.cmd), ui::text(w.c.access_id), ui::take_secret(w.c.access_secret), ui::checked(w.c.accept), ui::text(w.c.scan))) else { return };
	let secret = (!secret.is_empty()).then(|| secret.to_string());
	if let Err(e) = settings::save_sign_in(&path, Some(cmd), Some(id), secret) {
		return say(&e.to_string());
	}
	let old = p.app.clone();
	let next = AppSettings { accept_unverified: accept, scan_command: Some(scan.trim().to_string()).filter(|s| !s.is_empty()), ..old.clone() };
	let saved = match settings::save(&path, &next) {
		Ok(s) => s,
		Err(e) => return say(&e.to_string()),
	};
	with_win(|w| w.profile = Some(saved.clone()));
	if old.restart_needed(&next) && !next.paused {
		super::start_sync(&path, &saved);
	}
	refresh();
	say("Saved.");
}

// ── results ─────────────────────────────────────────────────────────

/// A job finished. Results for a window that was closed meanwhile are
/// dropped, except a sign-out's, which the tray still reports.
pub(crate) fn done(d: Done) {
	if with_win(|_| ()).is_none() {
		if let Done::SignedOut(Ok(o)) = &d {
			if let Some(w) = &o.warning {
				with_app(|a| super::tray::notify(a.hidden, "Signed out", w, true));
			}
		}
		return;
	}
	match d {
		Done::SignedIn(Ok(token)) => {
			let path = super::profile_path();
			let enrolled = with_win(|w| {
				w.signing = None;
				ui::set_text(w.c.sign_in, SIGN_IN);
				w.profile.clone()
			})
			.flatten();
			let sign_in = match enrolled {
				Some(_) => {
					// Signed in again: the profile keeps it, and the sync starts
					// over with it (a sync that stopped for want of it resumes).
					let saved = match settings::save_access_token(&path, &token) {
						Ok(p) => p,
						Err(e) => return end(&e.to_string()),
					};
					with_win(|w| w.profile = Some(saved.clone()));
					if !saved.app.paused {
						super::start_sync(&path, &saved);
					}
					SignIn::of(&saved)
				}
				None => {
					with_win(|w| w.token = Some(zeroize::Zeroizing::new(token.clone())));
					let server = with_win(|w| ui::text(w.c.server)).unwrap_or_default();
					SignIn { server: settings::normalize_server(&server).unwrap_or(server), access_token: Some(token), dev_email: std::env::var("GORANI_DEV_EMAIL").ok(), ..Default::default() }
				}
			};
			end("Signed in.");
			job(move || Done::Me(settings::whoami(&sign_in).map_err(|e| e.to_string())));
		}
		Done::SignedIn(Err(e)) => {
			with_win(|w| {
				w.signing = None;
				ui::set_text(w.c.sign_in, SIGN_IN);
			});
			end(&e);
		}
		Done::Me(Ok(me)) => {
			let line = match &me.member {
				Some(m) if m.active => format!("Signed in as {} — member {} ({}, {}).", me.email, m.id, m.name, m.role),
				Some(m) => format!("Signed in as {} — the account {} is not active; a lead reactivates it.", me.email, m.id),
				None => format!("Signed in as {} — no account on this team; a lead adds the address in Team › People.", me.email),
			};
			with_win(|w| ui::set_text(w.c.signed_as, &line));
		}
		Done::Me(Err(e)) => {
			with_win(|w| ui::set_text(w.c.signed_as, &e));
		}
		Done::Enrolled(Ok(p)) => {
			with_win(|w| {
				w.token = None;
				w.next_server = None;
			});
			refresh();
			end(&format!("Enrolled. Syncing into {} — change it on the Sync tab.", p.app.folder.as_deref().unwrap_or("your folder")));
			super::start_sync(&super::profile_path(), &p);
		}
		Done::SignedOut(Ok(o)) => {
			with_win(|w| {
				w.devices.clear();
				w.cases.clear();
				ui::list_clear(w.c.devices);
			});
			refresh();
			let moving = with_win(|w| w.next_server.is_some()).unwrap_or(false);
			end(if moving { "Signed out. Sign in to the new server, then enrol with your vault password." } else { "Signed out." });
			if let Some(w) = o.warning {
				ui::tell(owner(), TITLE, &w, true);
			}
			select(Tab::Account);
		}
		Done::Devices(Ok(list)) => {
			with_win(|w| {
				ui::list_clear(w.c.devices);
				for (i, d) in list.iter().enumerate() {
					let name = if d.this { format!("{} (this computer)", d.name) } else if d.revoked { format!("{} (revoked)", d.name) } else { d.name.clone() };
					ui::list_add(w.c.devices, i, &[name, d.platform.clone(), d.protection.clone().unwrap_or_default(), appmodel::seen(d.last_seen.as_deref())]);
				}
				w.devices = list;
			});
			end("");
			status_changed(&super::status());
		}
		Done::Revoked(Ok(name)) => {
			end(&format!("Revoked “{name}”."));
			load_devices();
		}
		Done::Protected(Ok(label)) => {
			refresh();
			end(&format!("This computer's key part is now protected by: {label}."));
		}
		Done::Cases(Ok(list)) => {
			with_win(|w| {
				w.cases = list.into_iter().filter(|c| !c.closed).map(|c| (c.id, if c.permission == "read" { format!("{} (read only)", c.title) } else { c.title })).collect();
			});
			refresh();
			end("");
			status_changed(&super::status());
		}
		Done::Enrolled(Err(e)) | Done::SignedOut(Err(e)) | Done::Devices(Err(e)) | Done::Revoked(Err(e)) | Done::Protected(Err(e)) | Done::Cases(Err(e)) => {
			with_win(|w| w.next_server = None);
			end(&e);
		}
	}
}

// ── the window procedure ────────────────────────────────────────────

unsafe extern "system" fn proc_(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
	match msg {
		WM_COMMAND => {
			let (id, code) = ((wparam.0 & 0xffff) as u16, ((wparam.0 >> 16) & 0xffff) as u32);
			match (id, code) {
				(ID_PROTECT, CBN_SELCHANGE) => {
					with_win(|w| describe_choice(w.c.protect, w.c.protect_detail));
				}
				(ID_PROT_COMBO, CBN_SELCHANGE) => {
					with_win(|w| describe_choice(w.c.prot_combo, w.c.prot_detail));
				}
				(_, BN_CLICKED) => click(id),
				_ => {}
			}
			LRESULT(0)
		}
		WM_NOTIFY => {
			// SAFETY: WM_NOTIFY's LPARAM is an NMHDR from one of our controls.
			let hdr = unsafe { &*(lparam.0 as *const NMHDR) };
			if hdr.idFrom == ID_TAB as usize && hdr.code == TCN_SELCHANGE {
				let tab = with_win(|w| ui::tab_selected(w.c.tab)).unwrap_or(0);
				select(match tab {
					1 => Tab::Sync,
					2 => Tab::Devices,
					3 => Tab::Advanced,
					_ => Tab::Account,
				});
			}
			LRESULT(0)
		}
		WM_CTLCOLORSTATIC => {
			// Labels and check boxes on the window's own background.
			// SAFETY: the DC the control hands us, for this paint only.
			unsafe {
				SetBkColor(HDC(wparam.0 as *mut _), COLORREF(GetSysColor(COLOR_WINDOW)));
				LRESULT(GetSysColorBrush(COLOR_WINDOW).0 as isize)
			}
		}
		WM_DPICHANGED => {
			let dpi = ((wparam.0 >> 16) & 0xffff) as u32;
			// SAFETY: WM_DPICHANGED's LPARAM is the suggested window RECT.
			let r = unsafe { *(lparam.0 as *const RECT) };
			with_win(|w| {
				ui::drop_font(w.font);
				w.dpi = dpi;
				w.font = ui::message_font(dpi);
			});
			// SAFETY: moving our own window where Windows suggests.
			unsafe {
				let _ = SetWindowPos(hwnd, None, r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOZORDER | SWP_NOACTIVATE);
			}
			with_win(|w| relayout(w));
			LRESULT(0)
		}
		WM_CLOSE => {
			// SAFETY: our own window.
			unsafe {
				let _ = DestroyWindow(hwnd);
			}
			LRESULT(0)
		}
		WM_DESTROY => {
			let gone = WIN.with(|w| w.try_borrow_mut().ok().and_then(|mut w| w.take()));
			if let Some(w) = gone {
				ui::drop_font(w.font);
				// A browser sign-in still waiting stops listening.
				if let Some(cancel) = w.signing {
					cancel.store(true, std::sync::atomic::Ordering::SeqCst);
				}
			}
			with_app(|a| a.settings = None);
			LRESULT(0)
		}
		// SAFETY: the default for everything else.
		_ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
	}
}

fn click(id: u16) {
	match id {
		ID_SIGN_IN => sign_in(),
		ID_ENROL => enrol(),
		ID_SIGN_OUT => sign_out(),
		ID_CHANGE_SERVER => change_server(),
		ID_BROWSE => browse(),
		ID_AREA_REFRESH => load_cases(),
		ID_PAUSE => super::toggle_pause(),
		ID_SYNC_SAVE => save_sync(),
		ID_PROT_CHANGE => change_protection(),
		ID_DEV_REFRESH => load_devices(),
		ID_DEV_REVOKE => revoke(),
		ID_ADV_SAVE => save_advanced(),
		ID_CLOSE | IDCANCEL_ID => close(),
		_ => {}
	}
}

