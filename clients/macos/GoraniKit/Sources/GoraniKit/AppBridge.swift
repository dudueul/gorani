// Copyright 2026- Seongwoo Hong. All rights reserved.

// The Mac app's requests to the Rust core (commit 40d): its Settings
// window and menu-bar item, through `gorani_app` (clients/macos/src/app.rs).
// The same decisions the Windows app makes, in the same core; Swift only
// asks and shows. The browser's sign-in token never comes this way: the
// core keeps it under the sign-in's id.

import CGorani
import Foundation

/// One entry of the protection menu.
public struct ProtectionChoice: Codable, Hashable, Identifiable {
	public let value: String
	public let label: String
	public let detail: String
	public var id: String { value }
}

/// What the Settings window keeps beside the enrolment (the profile's `app`).
public struct AppSettings: Codable, Equatable {
	public var deviceName: String?
	public var folder: String?
	/// The area shown: nil for your own files, else a case id (the core's `case`).
	public var caseId: String?
	public var startAtLogin: Bool = false
	public var keepLocal: Bool = false
	public var acceptUnverified: Bool = false
	public var scanCommand: String?
	public var paused: Bool = false

	public init() {}

	enum CodingKeys: String, CodingKey {
		case deviceName, folder, startAtLogin, keepLocal, acceptUnverified, scanCommand, paused
		case caseId = "case"
	}

	public init(from decoder: Decoder) throws {
		let c = try decoder.container(keyedBy: CodingKeys.self)
		deviceName = try c.decodeIfPresent(String.self, forKey: .deviceName)
		folder = try c.decodeIfPresent(String.self, forKey: .folder)
		caseId = try c.decodeIfPresent(String.self, forKey: .caseId)
		startAtLogin = try c.decodeIfPresent(Bool.self, forKey: .startAtLogin) ?? false
		keepLocal = try c.decodeIfPresent(Bool.self, forKey: .keepLocal) ?? false
		acceptUnverified = try c.decodeIfPresent(Bool.self, forKey: .acceptUnverified) ?? false
		scanCommand = try c.decodeIfPresent(String.self, forKey: .scanCommand)
		paused = try c.decodeIfPresent(Bool.self, forKey: .paused) ?? false
	}
}

/// Where this Mac stands.
public struct AppStatus: Codable, Equatable {
	public var enrolled: Bool
	public var server: String
	public var member: String?
	public var deviceName: String?
	public var protection: String?
	public var signedIn: Bool?
	public var accessTokenCmd: String?
	public var accessId: String?
	public var hasAccessSecret: Bool?
	public var app: AppSettings?

	public init(enrolled: Bool, server: String) {
		self.enrolled = enrolled
		self.server = server
	}

	public static let unknown = AppStatus(enrolled: false, server: "")
}

public struct MemberInfo: Codable, Equatable {
	public let id: String
	public let name: String
	public let role: String
	public let active: Bool
}

/// Who the server says is signed in.
public struct Me: Codable, Equatable {
	public let email: String
	public let member: MemberInfo?
}

public struct DeviceInfo: Codable, Equatable, Identifiable {
	public let id: String
	public let name: String
	public let platform: String
	public let protection: String?
	public let createdAt: String?
	public let lastSeen: String?
	public let revoked: Bool
	public let this: Bool
}

public struct CaseInfo: Codable, Equatable, Identifiable {
	public let id: String
	public let title: String
	public let kind: String
	public let permission: String
	public let closed: Bool
	public let verified: Bool
}

/// A browser sign-in under way: open `url`, then wait on `id`.
public struct PendingSignIn: Codable, Equatable {
	public let id: String
	public let url: String
}

/// The requests, typed. Each may block (the network, the browser): call
/// them from a background task.
public enum AppBridge {
	/// One request, one answer — `{error}` thrown.
	@discardableResult
	public static func call(_ request: [String: Any]) throws -> [String: Any] {
		let data = try JSONSerialization.data(withJSONObject: request)
		let text = String(decoding: data, as: UTF8.self)
		guard let answer = text.withCString({ gorani_app($0) }) else {
			throw GoraniError(code: "io", message: "no answer")
		}
		defer { gorani_free(answer) }
		let json = try JSONSerialization.jsonObject(with: Data(String(cString: answer).utf8)) as? [String: Any] ?? [:]
		if let message = json["error"] as? String {
			throw GoraniError(code: "app", message: message)
		}
		return json
	}

	static func decode<T: Decodable>(_ value: Any?, as type: T.Type) throws -> T {
		guard let value else { throw GoraniError(code: "io", message: "an answer without its value") }
		let data = try JSONSerialization.data(withJSONObject: value)
		return try JSONDecoder().decode(type, from: data)
	}

	public static func defaults() throws -> (server: String, protections: [ProtectionChoice]) {
		let a = try call(["op": "defaults"])
		return (a["server"] as? String ?? "", try decode(a["protections"], as: [ProtectionChoice].self))
	}

	public static func status(profile: String) throws -> AppStatus {
		try decode(try call(["op": "status", "profile": profile]), as: AppStatus.self)
	}

	public static func normalize(server: String) throws -> String {
		try call(["op": "normalize", "server": server])["server"] as? String ?? server
	}

	public static func startSignIn(server: String) throws -> PendingSignIn {
		try decode(try call(["op": "signin.start", "server": server]), as: PendingSignIn.self)
	}

	/// Blocks until the browser hands the sign-in over (or five minutes, or
	/// a cancel). True: an enrolled profile saved it.
	@discardableResult
	public static func waitSignIn(id: String, profile: String) throws -> Bool {
		try call(["op": "signin.wait", "id": id, "profile": profile])["saved"] as? Bool ?? false
	}

	public static func cancelSignIn(id: String) {
		_ = try? call(["op": "signin.cancel", "id": id])
	}

	public static func whoami(server: String, signIn: String?, profile: String) throws -> Me {
		var r: [String: Any] = ["op": "whoami", "server": server, "profile": profile]
		if let signIn { r["signin"] = signIn }
		return try decode(try call(r), as: Me.self)
	}

	public static func enrol(profile: String, server: String, signIn: String?, deviceName: String, secret: String, protect: String) throws {
		var r: [String: Any] = ["op": "enrol", "profile": profile, "server": server, "deviceName": deviceName, "secret": secret, "protect": protect]
		if let signIn { r["signin"] = signIn }
		try call(r)
	}

	public static func signOut(profile: String) throws -> String? {
		try call(["op": "signout", "profile": profile])["warning"] as? String
	}

	public static func save(profile: String, app: AppSettings) throws {
		let data = try JSONEncoder().encode(app)
		let object = try JSONSerialization.jsonObject(with: data)
		try call(["op": "save", "profile": profile, "app": object])
	}

	public static func saveSignIn(profile: String, accessTokenCmd: String, accessId: String, accessSecret: String) throws {
		try call(["op": "saveSignIn", "profile": profile, "accessTokenCmd": accessTokenCmd, "accessId": accessId, "accessSecret": accessSecret])
	}

	public static func devices(profile: String) throws -> [DeviceInfo] {
		try decode(try call(["op": "devices", "profile": profile])["devices"], as: [DeviceInfo].self)
	}

	public static func revoke(profile: String, id: String) throws {
		try call(["op": "revoke", "profile": profile, "id": id])
	}

	public static func protect(profile: String, want: String) throws -> String {
		try call(["op": "protect", "profile": profile, "want": want])["protection"] as? String ?? want
	}

	public static func cases(profile: String) throws -> [CaseInfo] {
		try decode(try call(["op": "cases", "profile": profile])["cases"], as: [CaseInfo].self)
	}
}
