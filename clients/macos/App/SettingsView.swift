// Copyright 2026- Seongwoo Hong. All rights reserved.

// The Mac app's Settings (commit 40d): the four tabs the Windows app has,
// in SwiftUI. Each control only asks AppModel, which asks the core.

import GoraniKit
import SwiftUI

struct SettingsView: View {
	@EnvironmentObject var model: AppModel

	var body: some View {
		VStack(alignment: .leading, spacing: 0) {
			TabView {
				AccountTab().tabItem { Label("Account", systemImage: "person.crop.circle") }
				SyncTab().tabItem { Label("Sync", systemImage: "arrow.triangle.2.circlepath") }
				DevicesTab().tabItem { Label("This Mac & devices", systemImage: "laptopcomputer") }
				AdvancedTab().tabItem { Label("Advanced", systemImage: "gearshape") }
			}
			Text(model.message)
				.font(.callout)
				.foregroundStyle(.secondary)
				.lineLimit(3)
				.padding(.horizontal, 20)
				.padding(.bottom, 12)
				.frame(maxWidth: .infinity, alignment: .leading)
		}
		.frame(width: 600, height: 470)
		.onAppear { model.refresh() }
	}
}

/// "Enrol this Mac first", for the tabs that need it.
struct NeedsEnrolment: View {
	var body: some View {
		Text("Enrol this Mac first, on the Account tab.")
			.foregroundStyle(.secondary)
			.frame(maxWidth: .infinity, maxHeight: .infinity)
	}
}

struct AccountTab: View {
	@EnvironmentObject var model: AppModel
	@State private var server = ""
	@State private var name = Host.current().localizedName ?? "this Mac"
	@State private var protect = "auto"
	@State private var secret = ""
	@State private var askSignOut = false
	@State private var askServer = false

	private var typedServer: String { (try? AppBridge.normalize(server: server)) ?? server }

	var body: some View {
		Form {
			Section {
				HStack {
					TextField("Server", text: $server)
					if model.status.enrolled && typedServer != model.status.server {
						Button("Change server…") { askServer = true }
					}
				}
				Button(model.pendingSignIn == nil ? "Sign in with your browser" : "Cancel signing in") { model.signIn(server: server) }
				Text(model.signedInLine).font(.callout).foregroundStyle(.secondary)
			}
			if model.status.enrolled {
				Section {
					Text(model.enrolledLine)
					Button("Sign out of this Mac…", role: .destructive) { askSignOut = true }
				}
			} else {
				Section {
					TextField("This Mac's name", text: $name)
					Picker("Protect its key with", selection: $protect) {
						ForEach(model.protections) { choice in Text(choice.label).tag(choice.value) }
					}
					Text(model.protections.first { $0.value == protect }?.detail ?? "").font(.caption).foregroundStyle(.secondary)
					SecureField("Vault password or recovery code", text: $secret)
					Button("Enrol this Mac") {
						model.enrol(server: server, name: name, secret: secret, protect: protect)
						secret = ""
					}
					.disabled(secret.isEmpty || model.busy)
				}
			}
		}
		.formStyle(.grouped)
		.onAppear { server = model.nextServer ?? (model.status.enrolled ? model.status.server : model.defaultServer) }
		.onChange(of: model.status.server) { _ in
			if model.status.enrolled { server = model.status.server }
		}
		.alert("Sign this Mac out?", isPresented: $askSignOut) {
			Button("Sign out", role: .destructive) { model.signOut() }
			Button("Cancel", role: .cancel) {}
		} message: {
			Text("Its copy of your key on \(model.status.server) is deleted, its key parts here are forgotten, and Gorani leaves Finder — your files stay on the server. To use Gorani here again, enrol with your vault password.")
		}
		.alert("Use another server?", isPresented: $askServer) {
			Button("Sign out and switch", role: .destructive) { model.signOut(then: typedServer) }
			Button("Cancel", role: .cancel) { server = model.status.server }
		} message: {
			Text("A Mac is enrolled on one server. Gorani signs this Mac out of \(model.status.server), then you enrol it on \(typedServer) with your vault password.")
		}
	}
}

struct SyncTab: View {
	@EnvironmentObject var model: AppModel
	@State private var area = ""

	var body: some View {
		if !model.status.enrolled {
			NeedsEnrolment()
		} else {
			Form {
				Toggle("Show Gorani in Finder", isOn: Binding(get: { model.finderShown }, set: { $0 ? model.showInFinder() : model.removeFromFinder() }))
				HStack {
					Picker("Show", selection: $area) {
						Text("My files").tag("")
						if let current = model.status.app?.caseId, !model.cases.contains(where: { $0.id == current }) {
							Text("Case \(current)").tag(current)
						}
						ForEach(model.cases) { c in Text(c.permission == "read" ? "\(c.title) (read only)" : c.title).tag(c.id) }
					}
					Button("Refresh") { model.loadCases() }
				}
				Toggle("Start Gorani when I log in", isOn: Binding(get: { model.startsAtLogin }, set: { model.setStartAtLogin($0) }))
				Toggle("Pause syncing", isOn: Binding(get: { model.paused }, set: { model.setPaused($0) }))
				HStack {
					Spacer()
					Button("Save") {
						var app = model.status.app ?? AppSettings()
						let chosen: String? = area.isEmpty ? nil : area
						let changed = app.caseId != chosen
						app.caseId = chosen
						model.save(app, restartFinder: changed)
					}
				}
			}
			.formStyle(.grouped)
			.onAppear { area = model.status.app?.caseId ?? "" }
		}
	}
}

struct DevicesTab: View {
	@EnvironmentObject var model: AppModel
	@State private var want = "auto"
	@State private var selected: String?
	@State private var askRevoke = false

	private var chosen: DeviceInfo? { model.devices.first { $0.id == selected } }

	private func seen(_ at: String?) -> String {
		guard let at, at.count >= 16 else { return at ?? "never" }
		return "\(at.prefix(10)) \(at.dropFirst(11).prefix(5)) UTC"
	}

	var body: some View {
		if !model.status.enrolled {
			NeedsEnrolment()
		} else {
			VStack(alignment: .leading, spacing: 10) {
				Text("This Mac's key part is protected by: \(model.status.protection ?? "(not recorded)")")
				HStack {
					Picker("Change it to", selection: $want) {
						ForEach(model.protections) { choice in Text(choice.label).tag(choice.value) }
					}
					Button("Change") { model.protect(want) }.disabled(model.busy)
				}
				Text(model.protections.first { $0.value == want }?.detail ?? "").font(.caption).foregroundStyle(.secondary)
				Text("Your computers").font(.headline).padding(.top, 6)
				List(model.devices, selection: $selected) { d in
					HStack {
						Text(d.this ? "\(d.name) (this Mac)" : d.revoked ? "\(d.name) (revoked)" : d.name)
						Spacer()
						Text(d.platform).foregroundStyle(.secondary)
						Text(d.protection ?? "").foregroundStyle(.secondary)
						Text(seen(d.lastSeen)).foregroundStyle(.secondary)
					}
				}
				.frame(minHeight: 150)
				HStack {
					Button("Refresh") { model.loadDevices() }
					Button("Revoke selected…") { askRevoke = true }
						.disabled(chosen == nil || chosen?.this == true || chosen?.revoked == true)
				}
			}
			.padding(20)
			.onAppear { if model.devices.isEmpty { model.loadDevices() } }
			.alert("Revoke “\(chosen?.name ?? "")”?", isPresented: $askRevoke) {
				Button("Revoke", role: .destructive) { if let d = chosen { model.revoke(d) } }
				Button("Cancel", role: .cancel) {}
			} message: {
				Text("Its copy of your key is deleted from the server: it can never open your files again, until it is enrolled anew.")
			}
		}
	}
}

struct AdvancedTab: View {
	@EnvironmentObject var model: AppModel
	@State private var command = ""
	@State private var accessId = ""
	@State private var accessSecret = ""
	@State private var acceptUnverified = false
	@State private var scanner = ""

	var body: some View {
		if !model.status.enrolled {
			NeedsEnrolment()
		} else {
			Form {
				TextField("Sign-in command", text: $command, prompt: Text("cloudflared access token -app=https://…"))
				TextField("Access service token ID", text: $accessId)
				SecureField("…and its secret", text: $accessSecret, prompt: Text(model.status.hasAccessSecret == true ? "(unchanged)" : ""))
				Toggle("Accept files whose uploader's signature cannot be checked", isOn: $acceptUnverified)
				TextField("Scanner for upload-link items", text: $scanner, prompt: Text("clamscan --no-summary"))
				Text("The scanner is what gorani-sync accept runs on an outsider's item: {} is the file's path, run without a shell.").font(.caption).foregroundStyle(.secondary)
				HStack {
					Spacer()
					Button("Save") {
						model.saveAdvanced(command: command, accessId: accessId, accessSecret: accessSecret, acceptUnverified: acceptUnverified, scanner: scanner)
						accessSecret = ""
					}
				}
			}
			.formStyle(.grouped)
			.onAppear {
				command = model.status.accessTokenCmd ?? ""
				accessId = model.status.accessId ?? ""
				acceptUnverified = model.status.app?.acceptUnverified ?? false
				scanner = model.status.app?.scanCommand ?? ""
			}
		}
	}
}
