// Copyright 2026- Seongwoo Hong. All rights reserved.

// The Rust client core, from Swift (commit 39c): five C functions
// (Sources/CGorani/gorani.h) and one JSON protocol — the replica's
// (clients/core/src/replica.rs › dispatch). Nothing about keys, sealing or
// the server lives on this side; Swift asks, Rust answers.

import CGorani
import Foundation

/// One file or folder, as the core lists it.
public struct GoraniItem: Codable, Equatable, Hashable {
	public let id: String
	/// "" for the area's top.
	public let parent: String
	public let name: String
	/// "file" or "dir".
	public let kind: String
	public let size: UInt64
	/// The content version: a change means new bytes.
	public let version: Int64
	/// Seconds since 1970.
	public let modified: UInt64
	public let sample: Bool
	public let nameVerified: Bool

	public var isFolder: Bool { kind == "dir" }
}

/// A refusal, as the core names it (`code`: not_found, exists, not_empty,
/// is_dir, denied, read_only, too_big, io).
public struct GoraniError: Error, CustomStringConvertible {
	public let code: String
	public let message: String
	public var description: String { "\(message) (\(code))" }
}

/// What saving a new version came to.
public enum SaveOutcome: Equatable {
	case version(GoraniItem)
	/// Someone else saved first: theirs stands, these bytes are `copy`.
	case conflict(copy: GoraniItem)
}

/// A session with the core: the server (`open`) or the in-memory twin
/// (`memory`). Safe from any thread — the core takes one call at a time.
public final class GoraniBridge {
	private let session: OpaquePointer

	/// The area the profile names, unlocked with this Mac's enrolled copy.
	public init(profile: String, caseId: String? = nil, devEmail: String? = nil, acceptUnverified: Bool = false) throws {
		var error: UnsafeMutablePointer<CChar>?
		let s = profile.withCString { p in
			withOptional(caseId) { c in
				withOptional(devEmail) { e in gorani_open(p, c, e, acceptUnverified, &error) }
			}
		}
		guard let s else {
			let msg = error.map { String(cString: $0) } ?? "could not open the vault"
			if let error { gorani_free(error) }
			throw GoraniError(code: "io", message: msg)
		}
		session = s
	}

	/// The in-memory twin (tests; a demo without a server).
	public init(memoryArea: String) {
		session = memoryArea.withCString { gorani_open_memory($0) }
	}

	deinit {
		gorani_close(session)
	}

	/// One request, one answer — refusals thrown.
	@discardableResult
	public func call(_ request: [String: Any]) throws -> [String: Any] {
		let data = try JSONSerialization.data(withJSONObject: request)
		let text = String(decoding: data, as: UTF8.self)
		guard let answer = text.withCString({ gorani_call(session, $0) }) else {
			throw GoraniError(code: "io", message: "no answer")
		}
		defer { gorani_free(answer) }
		let json = try JSONSerialization.jsonObject(with: Data(String(cString: answer).utf8)) as? [String: Any] ?? [:]
		if let message = json["error"] as? String {
			throw GoraniError(code: json["code"] as? String ?? "io", message: message)
		}
		return json
	}

	private func decode<T: Decodable>(_ value: Any?, as type: T.Type) throws -> T {
		guard let value else { throw GoraniError(code: "io", message: "an answer without its value") }
		let data = try JSONSerialization.data(withJSONObject: value)
		return try JSONDecoder().decode(type, from: data)
	}

	// ── the protocol, typed ───────────────────────────────────────────

	/// Has anything changed since the last poll? (The first: yes.)
	public func poll() throws -> Bool {
		try call(["op": "poll"])["changed"] as? Bool ?? false
	}

	public func items() throws -> (items: [GoraniItem], readOnly: String?, area: String) {
		let a = try call(["op": "items"])
		return (try decode(a["items"], as: [GoraniItem].self), a["readOnly"] as? String, a["area"] as? String ?? "")
	}

	/// One version's whole bytes into a new file at `url`.
	@discardableResult
	public func download(id: String, version: Int64, to url: URL) throws -> UInt64 {
		let a = try call(["op": "download", "id": id, "version": version, "path": url.path])
		return (a["size"] as? NSNumber)?.uint64Value ?? 0
	}

	public func create(parent: String, name: String, from url: URL) throws -> GoraniItem {
		try decode(try call(["op": "create", "parent": parent, "name": name, "path": url.path])["item"], as: GoraniItem.self)
	}

	public func save(id: String, base: Int64, from url: URL) throws -> SaveOutcome {
		let a = try call(["op": "save", "id": id, "base": base, "path": url.path])
		if a["outcome"] as? String == "conflict" {
			return .conflict(copy: try decode(a["copy"], as: GoraniItem.self))
		}
		return .version(try decode(a["item"], as: GoraniItem.self))
	}

	public func mkdir(parent: String, name: String) throws -> GoraniItem {
		try decode(try call(["op": "mkdir", "parent": parent, "name": name])["item"], as: GoraniItem.self)
	}

	public func rename(id: String, parent: String, name: String) throws {
		try call(["op": "rename", "id": id, "parent": parent, "name": name])
	}

	public func trash(id: String) throws {
		try call(["op": "trash", "id": id])
	}
}

/// `body` with a C string for `value`, or NULL.
private func withOptional<R>(_ value: String?, _ body: (UnsafePointer<CChar>?) -> R) -> R {
	guard let value else { return body(nil) }
	return value.withCString { body($0) }
}
