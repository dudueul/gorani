// Copyright 2026- Seongwoo Hong. All rights reserved.

// What the File Provider extension knows of the area (commit 39c): the
// last listing, and enough history to answer "what changed since anchor N"
// — the question File Provider asks after every signal. An anchor is a
// generation number; a generation the model no longer remembers (the
// extension restarted, or fell far behind) is EXPIRED, and the system then
// enumerates everything again (NSFileProviderError.syncAnchorExpired).

import Foundation

public final class ReplicaModel {
	private let bridge: GoraniBridge
	private let lock = NSLock()
	public private(set) var generation: UInt64 = 0
	private var snapshots: [UInt64: [String: GoraniItem]] = [:]
	public private(set) var readOnly: String?
	public private(set) var area: String = ""
	/// How many generations are remembered for `changes(since:)`.
	private let keep: UInt64 = 16

	public init(bridge: GoraniBridge) {
		self.bridge = bridge
	}

	/// Ask the core; a new generation when the listing changed. `force`:
	/// list even if the feed says nothing moved. Returns whether it did.
	@discardableResult
	public func refresh(force: Bool = false) throws -> Bool {
		let changed = try bridge.poll()
		if !changed && !force && !isEmpty { return false }
		let (items, readOnly, area) = try bridge.items()
		// (Ids are unique on the server; were one ever listed twice, the
		// first stands — a listing is never a reason to crash the extension.)
		let now = Dictionary(items.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
		lock.lock()
		defer { lock.unlock() }
		self.readOnly = readOnly
		self.area = area
		if let last = snapshots[generation], last == now { return false }
		generation += 1
		snapshots[generation] = now
		if generation > keep { snapshots[generation - keep] = nil }
		return true
	}

	private var isEmpty: Bool {
		lock.lock()
		defer { lock.unlock() }
		return snapshots.isEmpty
	}

	private var current: [String: GoraniItem] {
		lock.lock()
		defer { lock.unlock() }
		return snapshots[generation] ?? [:]
	}

	public func item(_ id: String) -> GoraniItem? {
		current[id]
	}

	public var all: [GoraniItem] {
		current.values.sorted { $0.id < $1.id }
	}

	/// A folder's entries ("" for the top), by name.
	public func children(of parent: String) -> [GoraniItem] {
		current.values.filter { $0.parent == parent }.sorted { $0.name < $1.name }
	}

	/// What changed since `anchor`: the items new or different, the ids
	/// gone. Nil when that generation is no longer remembered.
	public func changes(since anchor: UInt64) -> (updated: [GoraniItem], deleted: [String])? {
		lock.lock()
		defer { lock.unlock() }
		guard let then = snapshots[anchor], let now = snapshots[generation] else { return nil }
		let updated = now.values.filter { then[$0.id] != $0 }.sorted { $0.id < $1.id }
		let deleted = then.keys.filter { now[$0] == nil }.sorted()
		return (updated, deleted)
	}

	/// An anchor's bytes (what File Provider stores), and back.
	public static func anchorData(_ g: UInt64) -> Data {
		withUnsafeBytes(of: g.bigEndian) { Data($0) }
	}

	public static func anchorValue(_ d: Data) -> UInt64? {
		guard d.count == 8 else { return nil }
		return d.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
	}
}
