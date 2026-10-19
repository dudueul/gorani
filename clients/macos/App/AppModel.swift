// Copyright 2026- Seongwoo Hong. All rights reserved.

// What the Mac app's windows show and do (commit 40d). Every decision is
// the core's (AppBridge); this class runs the slow ones off the main
// thread, keeps the answers for the views, and talks to the system:
// Finder's domain (NSFileProviderManager), login items (SMAppService),
// the browser (NSWorkspace).

import AppKit
import FileProvider
import Foundation
import GoraniKit
import ServiceManagement

final class AppModel: ObservableObject {
	static let shared = AppModel()

	@Published var status = AppStatus.unknown
	@Published var protections: [ProtectionChoice] = []
	@Published var defaultServer = "https://gorani.at.day"
	@Published var message = ""
	@Published var busy = false
	@Published var me: Me?
	@Published var devices: [DeviceInfo] = []
	@Published var cases: [CaseInfo] = []
	/// A browser sign-in waiting (its id): the button then cancels it.
	@Published var pendingSignIn: String?
	@Published var finderShown = false
	/// A new server waiting for the sign-out that makes room for it.
	@Published var nextServer: String?
	/// Before enrolment: the finished sign-in's id. The core holds its
	/// token; Swift never sees it.
	var signInId: String?

	let domain = NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(rawValue: "gorani"), displayName: "Gorani")

	/// The profile, in the app group's container the extension reads.
	var profilePath: String {
		guard let group = Bundle.main.object(forInfoDictionaryKey: "GoraniAppGroup") as? String,
			let dir = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)
		else { return FileManager.default.temporaryDirectory.appendingPathComponent("gorani-sync.json").path }
		return dir.appendingPathComponent("gorani-sync.json").path
	}

	var paused: Bool { status.app?.paused ?? false }

	/// Not enrolled, or its sign-in ran out: Settings opens by itself.
	var needsAttention: Bool { !status.enrolled || status.signedIn == false }

	var menuSymbol: String {
		if !status.enrolled { return "icloud.slash" }
		if status.signedIn == false { return "exclamationmark.icloud" }
		return paused ? "pause.circle" : "lock.icloud"
	}

	var statusLine: String {
		if !status.enrolled { return "Not set up — open Settings to enrol this Mac" }
		if status.signedIn == false { return "Signed out — sign in again in Settings" }
		if paused { return "Paused" }
		return finderShown ? "In Finder, under Locations" : "Not shown in Finder"
	}

	var startsAtLogin: Bool { SMAppService.mainApp.status == .enabled }

	// ── reading where it stands ────────────────────────────────────────

	func refresh() {
		if let d = try? AppBridge.defaults() {
			defaultServer = d.server
			protections = d.protections
		}
		status = (try? AppBridge.status(profile: profilePath)) ?? AppStatus(enrolled: false, server: defaultServer)
		NSFileProviderManager.getDomainsWithCompletionHandler { domains, _ in
			let shown = domains.contains { $0.identifier == self.domain.identifier }
			DispatchQueue.main.async { self.finderShown = shown }
		}
		if status.enrolled && me == nil { whoami(server: status.server) }
	}

	/// The core's refusal, as a person reads it.
	static func words(_ error: Error) -> String {
		(error as? GoraniError)?.message ?? error.localizedDescription
	}

	/// `work` off the main thread; `done` (or the error, said) back on it.
	func run<T>(_ what: String, _ work: @escaping () throws -> T, failed: (() -> Void)? = nil, done: @escaping (T) -> Void) {
		busy = true
		message = what
		DispatchQueue.global(qos: .userInitiated).async {
			do {
				let value = try work()
				DispatchQueue.main.async {
					self.busy = false
					done(value)
				}
			} catch {
				DispatchQueue.main.async {
					self.busy = false
					self.message = AppModel.words(error)
					failed?()
				}
			}
		}
	}

	// ── Account ────────────────────────────────────────────────────────

	/// Sign in through the person's own browser (40c): the core listens on
	/// this Mac, the browser opens the team's page, the page asks, and the
	/// browser hands the sign-in back. Pressed again while it waits: cancel.
	func signIn(server typed: String) {
		if let id = pendingSignIn {
			AppBridge.cancelSignIn(id: id)
			return
		}
		let server: String
		do {
			server = try AppBridge.normalize(server: status.enrolled ? status.server : typed)
		} catch {
			message = AppModel.words(error)
			return
		}
		let pending: PendingSignIn
		do {
			pending = try AppBridge.startSignIn(server: server)
		} catch {
			message = AppModel.words(error)
			return
		}
		pendingSignIn = pending.id
		if let url = URL(string: pending.url) { NSWorkspace.shared.open(url) }
		let profile = profilePath
		run("Finish signing in in your browser — press the button on the page it opened.", { try AppBridge.waitSignIn(id: pending.id, profile: profile) }, failed: { self.pendingSignIn = nil }) { saved in
			self.pendingSignIn = nil
			if !saved { self.signInId = pending.id }
			self.message = "Signed in."
			self.me = nil
			self.refresh()
			self.whoami(server: server)
		}
	}

	func whoami(server: String) {
		let id = signInId
		let profile = profilePath
		DispatchQueue.global(qos: .utility).async {
			let me = try? AppBridge.whoami(server: server, signIn: id, profile: profile)
			DispatchQueue.main.async { self.me = me }
		}
	}

	var signedInLine: String {
		guard let me else { return status.enrolled || signInId != nil ? "Asking who is signed in…" : "Not signed in yet." }
		guard let m = me.member else { return "Signed in as \(me.email) — no account on this team; a lead adds the address in Team › People." }
		return m.active ? "Signed in as \(me.email) — member \(m.id) (\(m.name), \(m.role))." : "Signed in as \(me.email) — the account \(m.id) is not active."
	}

	var enrolledLine: String {
		"This Mac is enrolled as “\(status.deviceName ?? "this Mac")” on \(status.server). Its key part is protected by: \(status.protection ?? "(not recorded)")."
	}

	func enrol(server typed: String, name: String, secret: String, protect: String) {
		let id = signInId
		let profile = profilePath
		let server = (try? AppBridge.normalize(server: typed)) ?? typed
		run("Enrolling this Mac…", { try AppBridge.enrol(profile: profile, server: server, signIn: id, deviceName: name, secret: secret, protect: protect) }) { _ in
			self.signInId = nil
			self.nextServer = nil
			self.refresh()
			self.showInFinder()
			self.message = "Enrolled. Gorani is in Finder, under Locations."
		}
	}

	/// Sign out: Finder lets go of the domain (its files leave this Mac),
	/// then the core tells the server and forgets this Mac's key parts.
	func signOut(then next: String? = nil) {
		let profile = profilePath
		NSFileProviderManager.remove(domain) { _ in }
		run("Signing out…", { try AppBridge.signOut(profile: profile) }) { warning in
			self.nextServer = next
			self.me = nil
			self.devices = []
			self.cases = []
			self.refresh()
			self.message = warning ?? (next == nil ? "Signed out." : "Signed out. Sign in to the new server, then enrol with your vault password.")
		}
	}

	// ── Finder ─────────────────────────────────────────────────────────

	func showInFinder() {
		NSFileProviderManager.add(domain) { error in
			DispatchQueue.main.async {
				if let error { self.message = "Not added to Finder: \(error.localizedDescription)" }
				self.refresh()
			}
		}
	}

	func removeFromFinder() {
		NSFileProviderManager.remove(domain) { error in
			DispatchQueue.main.async {
				if let error { self.message = "Not removed: \(error.localizedDescription)" }
				self.refresh()
			}
		}
	}

	/// After a change the extension reads only when it starts (the area,
	/// accepting unverified files): Finder lets the domain go and takes it
	/// again. Nothing is lost: the files are the server's.
	func resetFinder() {
		NSFileProviderManager.remove(domain) { _ in
			NSFileProviderManager.add(self.domain) { _ in
				DispatchQueue.main.async { self.refresh() }
			}
		}
	}

	func openInFinder() {
		guard let manager = NSFileProviderManager(for: domain) else { return }
		manager.getUserVisibleURL(for: .rootContainer) { url, _ in
			DispatchQueue.main.async {
				if let url { NSWorkspace.shared.open(url) }
			}
		}
	}

	func openWeb() {
		if let url = URL(string: status.enrolled ? status.server : defaultServer) { NSWorkspace.shared.open(url) }
	}

	// ── Sync ───────────────────────────────────────────────────────────

	func save(_ app: AppSettings, restartFinder: Bool = false, then: (() -> Void)? = nil) {
		let profile = profilePath
		run("Saving…", { try AppBridge.save(profile: profile, app: app) }) { _ in
			self.refresh()
			if restartFinder { self.resetFinder() }
			self.message = "Saved."
			then?()
		}
	}

	/// Pause: Finder's domain is disconnected (its files stay listed, nothing
	/// moves), and the choice is kept for the next start.
	func setPaused(_ on: Bool) {
		var app = status.app ?? AppSettings()
		app.paused = on
		save(app) {
			guard let manager = NSFileProviderManager(for: self.domain) else { return }
			if on {
				manager.disconnect(reason: "Paused from Gorani's menu.", options: []) { _ in }
			} else {
				manager.reconnect { _ in }
			}
		}
	}

	func setStartAtLogin(_ on: Bool) {
		do {
			if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
			message = on ? "Gorani starts when you log in." : "Gorani no longer starts when you log in."
		} catch {
			message = "Start at login: \(error.localizedDescription) — see System Settings › General › Login Items."
		}
		objectWillChange.send()
	}

	func loadCases() {
		let profile = profilePath
		run("Opening your key to read the cases' titles…", { try AppBridge.cases(profile: profile) }) { list in
			self.cases = list.filter { !$0.closed }
			self.message = ""
		}
	}

	// ── This Mac & devices ─────────────────────────────────────────────

	func loadDevices() {
		let profile = profilePath
		run("Listing your computers…", { try AppBridge.devices(profile: profile) }) { list in
			self.devices = list
			self.message = ""
		}
	}

	func revoke(_ device: DeviceInfo) {
		let profile = profilePath
		run("Revoking…", { try AppBridge.revoke(profile: profile, id: device.id) }) { _ in
			self.message = "Revoked “\(device.name)”."
			self.loadDevices()
		}
	}

	func protect(_ want: String) {
		let profile = profilePath
		run("Moving this Mac's key part…", { try AppBridge.protect(profile: profile, want: want) }) { label in
			self.refresh()
			self.message = "This Mac's key part is now protected by: \(label)."
		}
	}

	// ── Advanced ───────────────────────────────────────────────────────

	func saveAdvanced(command: String, accessId: String, accessSecret: String, acceptUnverified: Bool, scanner: String) {
		let profile = profilePath
		var app = status.app ?? AppSettings()
		let restart = app.acceptUnverified != acceptUnverified
		app.acceptUnverified = acceptUnverified
		app.scanCommand = scanner.isEmpty ? nil : scanner
		run("Saving…", {
			try AppBridge.saveSignIn(profile: profile, accessTokenCmd: command, accessId: accessId, accessSecret: accessSecret)
			try AppBridge.save(profile: profile, app: app)
		}) { _ in
			self.refresh()
			if restart { self.resetFinder() }
			self.message = "Saved."
		}
	}
}
