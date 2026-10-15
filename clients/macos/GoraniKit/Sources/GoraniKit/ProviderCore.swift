// Copyright 2026- Seongwoo Hong. All rights reserved.

// What the File Provider extension does, without the extension (commit
// 39c): each NSFileProviderReplicatedExtension method is a call here, so
// `swift test` drives the same logic over the in-memory core that the
// extension runs over the server.
//
//   item      by id; the area's top is the root container
//   fetch     the CURRENT version's bytes into a new file the system takes over
//             (a requested older version is answered with the current one and
//             its item — the system then knows it moved on)
//   create    a folder, or a file from the contents the system hands over
//   modify    a rename/move and/or new contents (the version after the one the
//             system based its change on); a stale save is a conflict copy on
//             the server, and the item answered is theirs — nothing is lost
//   delete    to the area's Trash
//   changes   since an anchor (ReplicaModel)

import FileProvider
import Foundation
import UniformTypeIdentifiers

public final class ProviderCore {
	public let bridge: GoraniBridge
	public let model: ReplicaModel
	private let temp: URL

	public init(bridge: GoraniBridge, temporaryDirectory: URL = FileManager.default.temporaryDirectory) throws {
		self.bridge = bridge
		model = ReplicaModel(bridge: bridge)
		temp = temporaryDirectory.appendingPathComponent("gorani-fetch-\(UUID().uuidString)", isDirectory: true)
		try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
		try model.refresh(force: true)
	}

	public var readOnly: Bool { model.readOnly != nil }

	/// Refresh; whether the listing changed (the extension then signals).
	@discardableResult
	public func refresh() throws -> Bool {
		try model.refresh()
	}

	private func known(_ id: String) throws -> GoraniItem {
		if let i = model.item(id) { return i }
		try model.refresh(force: true)
		guard let i = model.item(id) else { throw NSFileProviderError(.noSuchItem) }
		return i
	}

	public func providerItem(_ id: String) throws -> NSFileProviderItem {
		if id.isEmpty { return GoraniRootItem(readOnly: readOnly) }
		return GoraniFileProviderItem(try known(id), readOnly: readOnly)
	}

	public func fetch(_ id: String) throws -> (URL, NSFileProviderItem) {
		let i = try known(id)
		if i.isFolder { throw NSFileProviderError(.noSuchItem) }
		let url = temp.appendingPathComponent(UUID().uuidString)
		do {
			try bridge.download(id: id, version: i.version, to: url)
		} catch let e as GoraniError where e.code == "io" {
			// Changed on the server meanwhile: once more, with what it is now.
			try model.refresh(force: true)
			let now = try known(id)
			try bridge.download(id: id, version: now.version, to: url)
			return (url, GoraniFileProviderItem(now, readOnly: readOnly))
		}
		return (url, GoraniFileProviderItem(i, readOnly: readOnly))
	}

	private func writable() throws {
		if readOnly { throw NSError(domain: NSCocoaErrorDomain, code: NSFileWriteNoPermissionError, userInfo: [NSLocalizedDescriptionKey: model.readOnly ?? "read-only"]) }
	}

	public func create(template: NSFileProviderItem, contents: URL?) throws -> NSFileProviderItem {
		try writable()
		let parent = GoraniFileProviderItem.id(template.parentItemIdentifier)
		let isFolder = template.contentType?.conforms(to: .folder) ?? false
		let made: GoraniItem
		if isFolder {
			made = try bridge.mkdir(parent: parent, name: template.filename)
		} else {
			var source = contents
			if source == nil {
				// (An empty file: the system hands over no contents for it.)
				let empty = temp.appendingPathComponent(UUID().uuidString)
				FileManager.default.createFile(atPath: empty.path, contents: Data())
				source = empty
			}
			made = try bridge.create(parent: parent, name: template.filename, from: source!)
		}
		try model.refresh(force: true)
		return GoraniFileProviderItem(model.item(made.id) ?? made, readOnly: readOnly)
	}

	/// `base`: the content version the system's change follows (nil: the current one).
	public func modify(_ id: String, base: Int64?, fields: NSFileProviderItemFields, template: NSFileProviderItem, contents: URL?) throws -> NSFileProviderItem {
		try writable()
		let current = try known(id)
		if fields.contains(.filename) || fields.contains(.parentItemIdentifier) {
			try bridge.rename(id: id, parent: GoraniFileProviderItem.id(template.parentItemIdentifier), name: template.filename)
		}
		if fields.contains(.contents), let url = contents, !current.isFolder {
			// A conflict needs nothing more here: the copy is on the server,
			// the next listing shows it, and the item answered below is theirs.
			_ = try bridge.save(id: id, base: base ?? current.version, from: url)
		}
		try model.refresh(force: true)
		return try providerItem(id)
	}

	public func delete(_ id: String) throws {
		try writable()
		try bridge.trash(id: id)
		try model.refresh(force: true)
	}

	// ── enumeration ───────────────────────────────────────────────────

	/// A container's items: the working set is everything; a folder (or
	/// the root container), what is directly in it.
	public func items(in container: NSFileProviderItemIdentifier) -> [NSFileProviderItem] {
		let list: [GoraniItem]
		if container == .workingSet {
			list = model.all
		} else if container == .trashContainer {
			list = []
		} else {
			list = model.children(of: GoraniFileProviderItem.id(container))
		}
		return list.map { GoraniFileProviderItem($0, readOnly: readOnly) }
	}

	public var anchor: Data { ReplicaModel.anchorData(model.generation) }

	/// Changes since `anchor` (nil: expired).
	public func changes(since anchor: Data) -> (updated: [NSFileProviderItem], deleted: [NSFileProviderItemIdentifier])? {
		guard let g = ReplicaModel.anchorValue(anchor), let c = model.changes(since: g) else { return nil }
		return (c.updated.map { GoraniFileProviderItem($0, readOnly: readOnly) }, c.deleted.map { GoraniFileProviderItem.identifier($0) })
	}

	/// The core's refusal as the error File Provider understands.
	public static func fileProviderError(_ error: Error) -> Error {
		guard let e = error as? GoraniError else { return error }
		switch e.code {
		case "not_found": return NSFileProviderError(.noSuchItem)
		case "exists": return NSFileProviderError(.filenameCollision)
		case "not_empty": return NSFileProviderError(.directoryNotEmpty)
		case "read_only": return NSError(domain: NSCocoaErrorDomain, code: NSFileWriteNoPermissionError, userInfo: [NSLocalizedDescriptionKey: e.message])
		case "denied": return NSError(domain: NSCocoaErrorDomain, code: NSFileReadNoPermissionError, userInfo: [NSLocalizedDescriptionKey: e.message])
		default: return NSFileProviderError(.serverUnreachable)
		}
	}
}

/// The enumerator the extension hands out, for a container.
public final class GoraniEnumerator: NSObject, NSFileProviderEnumerator {
	private let core: ProviderCore
	private let container: NSFileProviderItemIdentifier
	private let queue: DispatchQueue

	public init(core: ProviderCore, container: NSFileProviderItemIdentifier, queue: DispatchQueue) {
		self.core = core
		self.container = container
		self.queue = queue
	}

	public func invalidate() {}

	public func enumerateItems(for observer: NSFileProviderEnumerationObserver, startingAt page: NSFileProviderPage) {
		queue.async {
			observer.didEnumerate(self.core.items(in: self.container))
			observer.finishEnumerating(upTo: nil)
		}
	}

	public func enumerateChanges(for observer: NSFileProviderChangeObserver, from anchor: NSFileProviderSyncAnchor) {
		queue.async {
			guard let c = self.core.changes(since: anchor.rawValue) else {
				observer.finishEnumeratingWithError(NSFileProviderError(.syncAnchorExpired))
				return
			}
			if !c.updated.isEmpty { observer.didUpdate(c.updated) }
			if !c.deleted.isEmpty { observer.didDeleteItems(withIdentifiers: c.deleted) }
			observer.finishEnumeratingChanges(upTo: NSFileProviderSyncAnchor(rawValue: self.core.anchor), moreComing: false)
		}
	}

	public func currentSyncAnchor(completionHandler: @escaping (NSFileProviderSyncAnchor?) -> Void) {
		queue.async { completionHandler(NSFileProviderSyncAnchor(rawValue: self.core.anchor)) }
	}
}
