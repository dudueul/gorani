// Copyright 2026- Seongwoo Hong. All rights reserved.

// The host app (commit 39c): what puts Gorani in Finder's sidebar. The
// work is the extension's; this window adds or removes the File Provider
// domain and says where the extension looks for this Mac's profile.

import FileProvider
import SwiftUI

@main
struct GoraniApp: App {
	var body: some Scene {
		WindowGroup("Gorani") { StatusView() }
	}
}

struct StatusView: View {
	@State private var message = ""
	private let domain = NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(rawValue: "gorani"), displayName: "Gorani")

	private var profilePath: String {
		guard let group = Bundle.main.object(forInfoDictionaryKey: "GoraniAppGroup") as? String,
			let dir = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)
		else { return "(no app group — is the app signed with its entitlements?)" }
		return dir.appendingPathComponent("gorani-sync.json").path
	}

	/// (The system answers on its own queue; the window is the main thread's.)
	private func say(_ text: String) {
		DispatchQueue.main.async { message = text }
	}

	var body: some View {
		VStack(alignment: .leading, spacing: 12) {
			Text("Gorani").font(.title)
			Text("This Mac's profile (enrol it with gorani-sync setup --profile …):").font(.caption)
			Text(profilePath).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
			Text(FileManager.default.fileExists(atPath: profilePath) ? "Profile found." : "No profile yet.")
			HStack {
				Button("Show in Finder") {
					NSFileProviderManager.add(domain) { error in say(error.map { "Not added: \($0.localizedDescription)" } ?? "Gorani is in Finder's sidebar.") }
				}
				Button("Remove from Finder") {
					NSFileProviderManager.remove(domain) { error in say(error.map { "Not removed: \($0.localizedDescription)" } ?? "Removed. Nothing of it stays on this Mac.") }
				}
			}
			Text(message).font(.caption)
		}
		.padding(20)
		.frame(minWidth: 520)
	}
}
