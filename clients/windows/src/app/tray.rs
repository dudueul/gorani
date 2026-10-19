// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The notification-area icon (commit 40b): the water deer, its tooltip
//! saying where the sync stands, and its menu.

use windows::Win32::Foundation::{HWND, POINT, WPARAM, LPARAM};
use windows::Win32::UI::Shell::{Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIIF_WARNING, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW};
use windows::Win32::UI::WindowsAndMessaging::*;

use crate::appmodel::{ico_entry, Status};

/// The tray icon's id (one per app).
const ICON_ID: u32 = 1;

/// The menu's commands (WM_COMMAND ids on the hidden window).
pub const OPEN_FOLDER: u16 = 101;
pub const OPEN_WEB: u16 = 102;
pub const PAUSE: u16 = 103;
pub const SETTINGS: u16 = 104;
pub const QUIT: u16 = 105;

/// The water deer at the size the tray draws (gorani.ico, built in).
pub fn load_icon() -> HICON {
	static ICO: &[u8] = include_bytes!("../../packaging/gorani.ico");
	// SAFETY: GetSystemMetrics has no preconditions.
	let want = unsafe { GetSystemMetrics(SM_CXSMICON) }.max(16) as u32;
	if let Some((start, len, size)) = ico_entry(ICO, want) {
		// SAFETY: the slice is one image of the icon file, bounds checked.
		if let Ok(icon) = unsafe { CreateIconFromResourceEx(&ICO[start..start + len], true, 0x0003_0000, size as i32, size as i32, LR_DEFAULTCOLOR) } {
			return icon;
		}
	}
	// SAFETY: the system's application icon, always there.
	unsafe { LoadIconW(None, IDI_APPLICATION).unwrap_or_default() }
}

fn data(owner: HWND) -> NOTIFYICONDATAW {
	NOTIFYICONDATAW { cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32, hWnd: owner, uID: ICON_ID, ..Default::default() }
}

fn fill(dst: &mut [u16], s: &str) {
	let units: Vec<u16> = s.encode_utf16().take(dst.len() - 1).collect();
	dst[..units.len()].copy_from_slice(&units);
	dst[units.len()] = 0;
}

/// Add the icon (also after Explorer restarts: "TaskbarCreated").
pub fn add(owner: HWND, icon: HICON, status: &Status) {
	let mut d = data(owner);
	d.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
	d.uCallbackMessage = super::WM_APP_TRAY;
	d.hIcon = icon;
	fill(&mut d.szTip, &status.tip());
	// SAFETY: a filled NOTIFYICONDATAW for a window of ours.
	unsafe {
		let _ = Shell_NotifyIconW(NIM_ADD, &d);
	}
}

/// Say where the sync stands, in the tooltip.
pub fn update(owner: HWND, status: &Status) {
	let mut d = data(owner);
	d.uFlags = NIF_TIP;
	fill(&mut d.szTip, &status.tip());
	// SAFETY: as above.
	unsafe {
		let _ = Shell_NotifyIconW(NIM_MODIFY, &d);
	}
}

/// A notification from the icon (Windows shows it as a toast).
pub fn notify(owner: HWND, title: &str, text: &str, warning: bool) {
	let mut d = data(owner);
	d.uFlags = NIF_INFO;
	fill(&mut d.szInfoTitle, title);
	fill(&mut d.szInfo, text);
	d.dwInfoFlags = if warning { NIIF_WARNING } else { NIIF_INFO };
	// SAFETY: as above.
	unsafe {
		let _ = Shell_NotifyIconW(NIM_MODIFY, &d);
	}
}

pub fn remove(owner: HWND) {
	let d = data(owner);
	// SAFETY: as above.
	unsafe {
		let _ = Shell_NotifyIconW(NIM_DELETE, &d);
	}
}

/// The menu, at the cursor: where it stands, Open, Pause, Settings, Quit.
pub fn menu(owner: HWND, status: &Status, enrolled: bool, paused: bool) {
	use windows::core::HSTRING;
	// SAFETY: a popup menu made, shown and destroyed here; the owner is
	// brought forward first, as TrackPopupMenu requires for the menu to
	// close when the person clicks elsewhere.
	unsafe {
		let Ok(m) = CreatePopupMenu() else { return };
		let item = |flags: MENU_ITEM_FLAGS, id: u16, text: &str| {
			let _ = AppendMenuW(m, flags, id as usize, &HSTRING::from(text));
		};
		item(MF_STRING | MF_GRAYED, 0, &crate::appmodel::clip(&status.line(), 80));
		let _ = AppendMenuW(m, MF_SEPARATOR, 0, None);
		item(if status.folder().is_some() { MF_STRING } else { MF_STRING | MF_GRAYED }, OPEN_FOLDER, "Open the Gorani folder");
		item(MF_STRING, OPEN_WEB, "Open Gorani in the browser");
		item(if enrolled { MF_STRING } else { MF_STRING | MF_GRAYED }, PAUSE, if paused { "Resume syncing" } else { "Pause syncing" });
		item(MF_STRING | MF_DEFAULT, SETTINGS, "Settings…");
		let _ = AppendMenuW(m, MF_SEPARATOR, 0, None);
		item(MF_STRING, QUIT, "Quit Gorani");
		let mut at = POINT::default();
		let _ = GetCursorPos(&mut at);
		let _ = SetForegroundWindow(owner);
		let _ = TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, at.x, at.y, None, owner, None);
		let _ = PostMessageW(Some(owner), WM_NULL, WPARAM(0), LPARAM(0));
		let _ = DestroyMenu(m);
	}
}
