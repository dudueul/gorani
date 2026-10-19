// Copyright 2026- Seongwoo Hong. All rights reserved.

// The Mac app (commit 40d, docs/DESKTOP.md › 40d): a menu-bar item and a
// Settings window, over the same core the Windows app uses (AppBridge →
// clients/macos/src/app.rs → gorani_client_core::settings). The files
// themselves are Finder's: the File Provider extension (39c) serves them
// under Locations; this app enrols the Mac, chooses what it shows, and
// pauses or removes it.
//
// ```text
// the menu bar   where it stands; Open in Finder, Open in the browser, Pause,
//                Sign in again (when it ran out), Settings…, Quit
// Settings       Account · Sync · This Mac & devices · Advanced (SettingsView.swift)
// ```
//
// The Settings window is a `Window` scene, not SwiftUI's `Settings`:
// macOS 14 no longer opens that one from code, and the app must open it
// by itself on the first launch (not enrolled yet) and when the sign-in
// ran out.

import AppKit
import SwiftUI

@main
struct GoraniApp: App {
	@StateObject private var model = AppModel.shared

	var body: some Scene {
		MenuBarExtra {
			MenuContent().environmentObject(model)
		} label: {
			MenuLabel().environmentObject(model)
		}
		Window("Gorani Settings", id: "settings") {
			SettingsView().environmentObject(model)
		}
		.windowResizability(.contentSize)
	}
}

/// The menu bar's icon. Drawn at launch, so it is also where the app
/// opens Settings by itself when the Mac needs enrolling or signing in.
struct MenuLabel: View {
	@EnvironmentObject var model: AppModel
	@Environment(\.openWindow) private var openWindow

	var body: some View {
		Image(systemName: model.menuSymbol)
			.onAppear {
				model.refresh()
				if model.needsAttention {
					NSApp.activate(ignoringOtherApps: true)
					openWindow(id: "settings")
				}
			}
	}
}

struct MenuContent: View {
	@EnvironmentObject var model: AppModel
	@Environment(\.openWindow) private var openWindow

	private func settings() {
		NSApp.activate(ignoringOtherApps: true)
		openWindow(id: "settings")
	}

	var body: some View {
		Text(model.statusLine)
		Divider()
		Button("Open in Finder") { model.openInFinder() }
			.disabled(!model.status.enrolled)
		Button("Open Gorani in the browser") { model.openWeb() }
		Button(model.paused ? "Resume syncing" : "Pause syncing") { model.setPaused(!model.paused) }
			.disabled(!model.status.enrolled)
		if model.status.enrolled && model.status.signedIn == false {
			Button("Sign in again…") { settings() }
		}
		Divider()
		Button("Settings…") { settings() }
			.keyboardShortcut(",")
		Button("Quit Gorani") { NSApp.terminate(nil) }
			.keyboardShortcut("q")
	}
}
