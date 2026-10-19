// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Start Gorani when the person signs in to Windows (commit 40b).
//!
//! Installed from the package (MSIX), Windows owns the switch: the
//! manifest declares a startup task, and the person may turn it off in
//! Task Manager › Startup apps, which an app cannot override. From the
//! ZIP, it is the per-user Run key, the classic way.

use windows::core::{w, HSTRING};
use windows::Win32::Foundation::{APPMODEL_ERROR_NO_PACKAGE, ERROR_SUCCESS};
use windows::Win32::Storage::Packaging::Appx::GetCurrentPackageFullName;
use windows::Win32::System::Registry::{RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_SZ};

/// The manifest's startup task (AppxManifest.xml).
const TASK_ID: &str = "GoraniStartup";
const RUN_KEY: windows::core::PCWSTR = w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
const RUN_VALUE: windows::core::PCWSTR = w!("Gorani");

/// Whether this process runs from the package (it has a package identity).
pub fn packaged() -> bool {
	let mut len = 0u32;
	// SAFETY: asking for the length only (no buffer).
	unsafe { GetCurrentPackageFullName(&mut len, None) != APPMODEL_ERROR_NO_PACKAGE }
}

/// Whether Windows started this process for the startup task (then it
/// says nothing at start: no toast at every sign-in).
pub fn started_at_login() -> bool {
	use windows::ApplicationModel::Activation::ActivationKind;
	use windows::ApplicationModel::AppInstance;
	packaged() && AppInstance::GetActivatedEventArgs().and_then(|a| a.Kind()).map(|k| k == ActivationKind::StartupTask).unwrap_or(false)
}

/// Whether Gorani starts at sign-in now.
pub fn enabled() -> bool {
	if packaged() {
		use windows::ApplicationModel::{StartupTask, StartupTaskState};
		return StartupTask::GetAsync(&HSTRING::from(TASK_ID)).and_then(|op| op.get()).and_then(|t| t.State()).map(|s| s == StartupTaskState::Enabled || s == StartupTaskState::EnabledByPolicy).unwrap_or(false);
	}
	let mut size = 0u32;
	// SAFETY: asking whether the value exists (its size only).
	unsafe { RegGetValueW(HKEY_CURRENT_USER, RUN_KEY, RUN_VALUE, RRF_RT_REG_SZ, None, None, Some(&mut size)) == ERROR_SUCCESS }
}

/// Turn it on or off, or say why Windows will not.
pub fn set(on: bool) -> Result<(), String> {
	if packaged() {
		use windows::ApplicationModel::{StartupTask, StartupTaskState};
		let task = StartupTask::GetAsync(&HSTRING::from(TASK_ID)).and_then(|op| op.get()).map_err(|e| e.message().to_string())?;
		if !on {
			return task.Disable().map_err(|e| e.message().to_string());
		}
		return match task.RequestEnableAsync().and_then(|op| op.get()).map_err(|e| e.message().to_string())? {
			StartupTaskState::Enabled | StartupTaskState::EnabledByPolicy => Ok(()),
			StartupTaskState::DisabledByUser => Err("it was turned off in Task Manager › Startup apps — turn Gorani on there".into()),
			StartupTaskState::DisabledByPolicy => Err("your organisation's policy keeps startup apps off".into()),
			_ => Err("Windows did not turn it on".into()),
		};
	}
	if on {
		let exe = std::env::current_exe().map_err(|e| e.to_string())?;
		let line = format!("\"{}\" --background", exe.display());
		let wide: Vec<u16> = line.encode_utf16().chain(Some(0)).collect();
		// SAFETY: a REG_SZ of `wide`'s bytes, NUL included.
		let r = unsafe { RegSetKeyValueW(HKEY_CURRENT_USER, RUN_KEY, RUN_VALUE, REG_SZ.0, Some(wide.as_ptr() as *const _), (wide.len() * 2) as u32) };
		if r != ERROR_SUCCESS {
			return Err(format!("the Run key could not be written ({})", r.0));
		}
	} else {
		// SAFETY: deleting our own value; absent is fine.
		let _ = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, RUN_KEY, RUN_VALUE) };
	}
	Ok(())
}
