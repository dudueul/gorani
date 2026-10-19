// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Small Win32 helpers for the app's windows (commit 40b): controls and
//! their text, the system's message font at a window's DPI, message boxes,
//! the folder picker, and handing a value from a worker thread to the
//! window thread. No third-party UI code: the `windows` crate only, as
//! decided for a program that holds the vault password for a moment.

use std::ffi::c_void;

use windows::core::{w, HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, WPARAM};
use windows::Win32::Graphics::Gdi::{CreateFontIndirectW, DeleteObject, HFONT, HGDIOBJ};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::*;
use windows::Win32::UI::HiDpi::SystemParametersInfoForDpi;
use windows::Win32::UI::WindowsAndMessaging::*;

pub fn hinstance() -> HINSTANCE {
	// SAFETY: the module handle of this program, always valid.
	unsafe { GetModuleHandleW(PCWSTR::null()).map(|m| HINSTANCE(m.0)).unwrap_or_default() }
}

/// A length in 96-dpi units, at `dpi`.
pub fn scale(v: i32, dpi: u32) -> i32 {
	((v as i64 * dpi as i64 + 48) / 96) as i32
}

/// A child control: `class` is BUTTON, EDIT, STATIC, COMBOBOX or a common
/// control's class. Placed later (`place`), so its size follows the DPI.
pub fn control(parent: HWND, class: PCWSTR, text: &str, style: WINDOW_STYLE, ex: WINDOW_EX_STYLE, id: u16) -> HWND {
	// SAFETY: plain window creation; a failure gives the null handle, which
	// every helper here treats as "no control".
	unsafe { CreateWindowExW(ex, class, &HSTRING::from(text), WS_CHILD | WS_CLIPSIBLINGS | style, 0, 0, 0, 0, Some(parent), Some(HMENU(id as usize as *mut c_void)), Some(hinstance()), None).unwrap_or_default() }
}

pub const BUTTON: PCWSTR = w!("BUTTON");
pub const EDIT: PCWSTR = w!("EDIT");
pub const STATIC: PCWSTR = w!("STATIC");
pub const COMBOBOX: PCWSTR = w!("COMBOBOX");

/// Window style bits from the `i32` control styles the crate defines.
pub fn ws(bits: i32) -> WINDOW_STYLE {
	WINDOW_STYLE(bits as u32)
}

pub fn place(h: HWND, x: i32, y: i32, w: i32, height: i32, dpi: u32) {
	// SAFETY: moving a child window of ours.
	unsafe {
		let _ = MoveWindow(h, scale(x, dpi), scale(y, dpi), scale(w, dpi), scale(height, dpi), true);
	}
}

pub fn text(h: HWND) -> String {
	// SAFETY: the buffer is as long as the length asked for, plus one.
	unsafe {
		let n = GetWindowTextLengthW(h);
		if n <= 0 {
			return String::new();
		}
		let mut buf = vec![0u16; n as usize + 1];
		let got = GetWindowTextW(h, &mut buf).max(0) as usize;
		String::from_utf16_lossy(&buf[..got])
	}
}

/// A password box's text: the UTF-16 copy wiped, the box emptied.
pub fn take_secret(h: HWND) -> zeroize::Zeroizing<String> {
	use zeroize::Zeroize;
	// SAFETY: as `text`.
	unsafe {
		let n = GetWindowTextLengthW(h);
		let mut buf = vec![0u16; n.max(0) as usize + 1];
		let got = GetWindowTextW(h, &mut buf).max(0) as usize;
		let out = zeroize::Zeroizing::new(String::from_utf16_lossy(&buf[..got]));
		buf.zeroize();
		let _ = SetWindowTextW(h, PCWSTR::null());
		out
	}
}

pub fn set_text(h: HWND, s: &str) {
	// SAFETY: a window of ours, a string that lives through the call.
	unsafe {
		let _ = SetWindowTextW(h, &HSTRING::from(s));
	}
}

pub fn show(h: HWND, on: bool) {
	// SAFETY: as above.
	unsafe {
		let _ = ShowWindow(h, if on { SW_SHOW } else { SW_HIDE });
	}
}

pub fn checked(h: HWND) -> bool {
	// SAFETY: BM_GETCHECK on a check box of ours.
	unsafe { SendMessageW(h, BM_GETCHECK, None, None).0 as u32 == BST_CHECKED.0 }
}

pub fn set_checked(h: HWND, on: bool) {
	// SAFETY: BM_SETCHECK on a check box of ours.
	unsafe {
		SendMessageW(h, BM_SETCHECK, Some(WPARAM(if on { BST_CHECKED.0 as usize } else { 0 })), None);
	}
}

pub fn combo_clear(h: HWND) {
	// SAFETY: CB_RESETCONTENT on a combo box of ours.
	unsafe {
		SendMessageW(h, CB_RESETCONTENT, None, None);
	}
}

pub fn combo_add(h: HWND, item: &str) {
	let s = HSTRING::from(item);
	// SAFETY: the string outlives the call; the box copies it.
	unsafe {
		SendMessageW(h, CB_ADDSTRING, None, Some(LPARAM(s.as_ptr() as isize)));
	}
}

pub fn combo_select(h: HWND, i: usize) {
	// SAFETY: CB_SETCURSEL on a combo box of ours.
	unsafe {
		SendMessageW(h, CB_SETCURSEL, Some(WPARAM(i)), None);
	}
}

pub fn combo_selected(h: HWND) -> Option<usize> {
	// SAFETY: CB_GETCURSEL on a combo box of ours (-1: none).
	let i = unsafe { SendMessageW(h, CB_GETCURSEL, None, None).0 };
	(i >= 0).then_some(i as usize)
}

/// A grey hint inside an empty edit box (EM_SETCUEBANNER).
pub fn cue(h: HWND, hint: &str) {
	let s = HSTRING::from(hint);
	// SAFETY: the box copies the string.
	unsafe {
		SendMessageW(h, EM_SETCUEBANNER, Some(WPARAM(0)), Some(LPARAM(s.as_ptr() as isize)));
	}
}

pub fn set_font(h: HWND, font: HFONT) {
	// SAFETY: WM_SETFONT with a font that lives as long as the window.
	unsafe {
		SendMessageW(h, WM_SETFONT, Some(WPARAM(font.0 as usize)), Some(LPARAM(1)));
	}
}

/// The font Windows uses for messages, at `dpi` — what dialogs use.
pub fn message_font(dpi: u32) -> HFONT {
	// SAFETY: a zeroed NONCLIENTMETRICSW with its size set is what the call
	// fills; the font made is deleted by `drop_font`.
	unsafe {
		let mut ncm: NONCLIENTMETRICSW = std::mem::zeroed();
		ncm.cbSize = std::mem::size_of::<NONCLIENTMETRICSW>() as u32;
		if SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS.0, ncm.cbSize, Some(&mut ncm as *mut _ as *mut c_void), 0, dpi).is_err() {
			return HFONT::default();
		}
		CreateFontIndirectW(&ncm.lfMessageFont)
	}
}

pub fn drop_font(font: HFONT) {
	if !font.is_invalid() {
		// SAFETY: a font this module made, no longer selected anywhere.
		unsafe {
			let _ = DeleteObject(HGDIOBJ(font.0));
		}
	}
}

/// OK/Cancel, answered.
pub fn ask(owner: HWND, title: &str, text: &str) -> bool {
	// SAFETY: a modal message box over a window of ours.
	unsafe { MessageBoxW(Some(owner), &HSTRING::from(text), &HSTRING::from(title), MB_OKCANCEL | MB_ICONQUESTION | MB_DEFBUTTON2) == IDOK }
}

pub fn tell(owner: HWND, title: &str, text: &str, warning: bool) {
	// SAFETY: as above.
	unsafe {
		MessageBoxW(Some(owner), &HSTRING::from(text), &HSTRING::from(title), MB_OK | if warning { MB_ICONWARNING } else { MB_ICONINFORMATION });
	}
}

/// Open a folder in Explorer, or a web address in the browser.
pub fn open(target: &str) {
	use windows::Win32::UI::Shell::ShellExecuteW;
	// SAFETY: the shell's own "open" of a path or URL we name.
	unsafe {
		ShellExecuteW(None, w!("open"), &HSTRING::from(target), PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL);
	}
}

/// The system's folder picker, starting at `start`. None: cancelled.
pub fn pick_folder(owner: HWND, start: Option<&str>) -> Option<String> {
	use windows::Win32::System::Com::{CoCreateInstance, CoTaskMemFree, CLSCTX_INPROC_SERVER};
	use windows::Win32::UI::Shell::{FileOpenDialog, IFileOpenDialog, IShellItem, SHCreateItemFromParsingName, FOS_FORCEFILESYSTEM, FOS_PICKFOLDERS, SIGDN_FILESYSPATH};
	// SAFETY: COM is initialised on this thread (app::run); every pointer
	// the dialog returns is released by its wrapper, the path by CoTaskMemFree.
	unsafe {
		let dialog: IFileOpenDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).ok()?;
		let options = dialog.GetOptions().ok()?;
		dialog.SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM).ok()?;
		if let Some(start) = start.filter(|s| std::path::Path::new(s).is_dir()) {
			if let Ok(item) = SHCreateItemFromParsingName::<_, _, IShellItem>(&HSTRING::from(start), None) {
				let _ = dialog.SetFolder(&item);
			}
		}
		dialog.Show(Some(owner)).ok()?;
		let item = dialog.GetResult().ok()?;
		let path: PWSTR = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
		let out = path.to_string().ok();
		CoTaskMemFree(Some(path.0 as *const c_void));
		out
	}
}

// ── a list view in report mode ───────────────────────────────────────

pub fn list_columns(h: HWND, columns: &[(&str, i32)], dpi: u32) {
	// SAFETY: LVM_* on a list view of ours; each text lives through its call.
	unsafe {
		SendMessageW(h, LVM_SETEXTENDEDLISTVIEWSTYLE, Some(WPARAM(LVS_EX_FULLROWSELECT as usize)), Some(LPARAM(LVS_EX_FULLROWSELECT as isize)));
		for (i, (title, width)) in columns.iter().enumerate() {
			let mut text: Vec<u16> = title.encode_utf16().chain(Some(0)).collect();
			let col = LVCOLUMNW { mask: LVCF_TEXT | LVCF_WIDTH, cx: scale(*width, dpi), pszText: PWSTR(text.as_mut_ptr()), ..Default::default() };
			SendMessageW(h, LVM_INSERTCOLUMNW, Some(WPARAM(i)), Some(LPARAM(&col as *const _ as isize)));
		}
	}
}

pub fn list_clear(h: HWND) {
	// SAFETY: as above.
	unsafe {
		SendMessageW(h, LVM_DELETEALLITEMS, None, None);
	}
}

pub fn list_add(h: HWND, row: usize, cells: &[String]) {
	// SAFETY: as above.
	unsafe {
		for (col, cell) in cells.iter().enumerate() {
			let mut text: Vec<u16> = cell.encode_utf16().chain(Some(0)).collect();
			let item = LVITEMW { mask: LVIF_TEXT, iItem: row as i32, iSubItem: col as i32, pszText: PWSTR(text.as_mut_ptr()), ..Default::default() };
			let msg = if col == 0 { LVM_INSERTITEMW } else { LVM_SETITEMTEXTW };
			SendMessageW(h, msg, Some(WPARAM(row)), Some(LPARAM(&item as *const _ as isize)));
		}
	}
}

pub fn list_selected(h: HWND) -> Option<usize> {
	// SAFETY: LVM_GETNEXTITEM from the start (-1) for the selected row.
	let i = unsafe { SendMessageW(h, LVM_GETNEXTITEM, Some(WPARAM(usize::MAX)), Some(LPARAM(LVNI_SELECTED as isize))).0 };
	(i >= 0).then_some(i as usize)
}

// ── a tab control ───────────────────────────────────────────────────

pub fn tab_add(h: HWND, i: usize, title: &str) {
	let mut text: Vec<u16> = title.encode_utf16().chain(Some(0)).collect();
	let item = TCITEMW { mask: TCIF_TEXT, pszText: PWSTR(text.as_mut_ptr()), ..Default::default() };
	// SAFETY: TCM_INSERTITEMW on a tab control of ours.
	unsafe {
		SendMessageW(h, TCM_INSERTITEMW, Some(WPARAM(i)), Some(LPARAM(&item as *const _ as isize)));
	}
}

pub fn tab_selected(h: HWND) -> usize {
	// SAFETY: TCM_GETCURSEL on a tab control of ours.
	unsafe { SendMessageW(h, TCM_GETCURSEL, None, None).0.max(0) as usize }
}

pub fn tab_select(h: HWND, i: usize) {
	// SAFETY: TCM_SETCURSEL on a tab control of ours (sends no notification).
	unsafe {
		SendMessageW(h, TCM_SETCURSEL, Some(WPARAM(i)), None);
	}
}

// ── a value from a worker thread to the window thread ────────────────

/// A window handle a worker thread may carry (it only posts to it).
#[derive(Clone, Copy)]
pub struct Target(isize);

// SAFETY: the handle is only ever used with PostMessageW, which any thread
// may call; the window itself stays on its own thread.
unsafe impl Send for Target {}

impl Target {
	pub fn of(h: HWND) -> Self {
		Self(h.0 as isize)
	}

	/// Post `value` as `msg`'s LPARAM: the window takes it back with
	/// `taken`. A window already gone drops it here.
	pub fn post<T: Send + 'static>(self, msg: u32, value: T) {
		let p = Box::into_raw(Box::new(value));
		// SAFETY: posting to a window handle; the box is reclaimed exactly
		// once — by the window (`taken`), or here when the post fails.
		unsafe {
			if PostMessageW(Some(HWND(self.0 as *mut c_void)), msg, WPARAM(0), LPARAM(p as isize)).is_err() {
				drop(Box::from_raw(p));
			}
		}
	}
}

/// The value a `Target::post` sent.
///
/// # Safety
/// `lparam` must be the LPARAM of a message `Target::post::<T>` posted,
/// taken once.
pub unsafe fn taken<T>(lparam: LPARAM) -> Box<T> {
	// SAFETY: per the contract above.
	unsafe { Box::from_raw(lparam.0 as *mut T) }
}
