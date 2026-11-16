// Copyright 2026- Seongwoo Hong. All rights reserved.

// The macOS shell's logic, over the in-memory core (commit 39c) — what
// the File Provider extension does, without the system loading it:
//
//   1. items map to File Provider items: identifiers are server ids, the
//      top is the root container, a sample cannot be read, a read-only
//      area cannot be written, the version pair moves with the bytes;
//   2. fetch writes the current version's bytes; a sample's is refused;
//   3. create (a file, an empty file, a folder), modify (contents, a rename
//      and a move), delete — each the server's, through the bridge;
//   4. a stale save leaves theirs at the name and a conflict copy beside it;
//   5. changes since an anchor: additions, edits, deletions, and an
//      anchor too old to answer;
//   6. the enumerators answer the system's observers;
//   7. Finder's badges: a sample, a read-only area's items (39e);
//   8. Finder's "Always keep on this Mac" and "Free up space": the marks,
//      the content policy they give, a change Finder learns of, a sample
//      never kept, a folder freed with what is in it, one file freed out of
//      a kept folder (the rest still kept), the marks kept across restarts.

import FileProvider
import UniformTypeIdentifiers
import XCTest

@testable import GoraniKit

/// What the system hands `createItem`/`modifyItem`: a template.
final class Template: NSObject, NSFileProviderItem {
	let itemIdentifier: NSFileProviderItemIdentifier
	let parentItemIdentifier: NSFileProviderItemIdentifier
	let filename: String
	let contentType: UTType

	init(parent: NSFileProviderItemIdentifier, filename: String, type: UTType = .plainText, id: String = "template") {
		itemIdentifier = NSFileProviderItemIdentifier(rawValue: id)
		parentItemIdentifier = parent
		self.filename = filename
		contentType = type
	}
}

final class Observer: NSObject, NSFileProviderEnumerationObserver, NSFileProviderChangeObserver {
	var items: [NSFileProviderItem] = []
	var updated: [NSFileProviderItem] = []
	var deleted: [NSFileProviderItemIdentifier] = []
	var error: Error?
	let done: XCTestExpectation

	init(_ done: XCTestExpectation) {
		self.done = done
	}

	func didEnumerate(_ updatedItems: [NSFileProviderItem]) { items += updatedItems }
	func finishEnumerating(upTo nextPage: NSFileProviderPage?) { done.fulfill() }
	func finishEnumeratingWithError(_ error: Error) {
		self.error = error
		done.fulfill()
	}
	func didUpdate(_ updatedItems: [NSFileProviderItem]) { updated += updatedItems }
	func didDeleteItems(withIdentifiers deletedItemIdentifiers: [NSFileProviderItemIdentifier]) { deleted += deletedItemIdentifiers }
	func finishEnumeratingChanges(upTo anchor: NSFileProviderSyncAnchor, moreComing: Bool) { done.fulfill() }
}

final class ProviderCoreTests: XCTestCase {
	var bridge: GoraniBridge!
	var core: ProviderCore!
	var docs = "", a = "", sample = ""

	func put(_ parent: String, _ name: String, _ text: String) throws -> String {
		let item = try bridge.call(["op": "mem.put", "parent": parent, "name": name, "data": Data(text.utf8).base64EncodedString()])["item"] as? [String: Any]
		return item?["id"] as? String ?? ""
	}

	func content(_ id: String) throws -> String {
		let b64 = try bridge.call(["op": "mem.content", "id": id])["data"] as? String ?? ""
		return String(decoding: Data(base64Encoded: b64) ?? Data(), as: UTF8.self)
	}

	func file(_ text: String) -> URL {
		let url = FileManager.default.temporaryDirectory.appendingPathComponent("gorani-test-\(UUID().uuidString)")
		FileManager.default.createFile(atPath: url.path, contents: Data(text.utf8))
		return url
	}

	override func setUpWithError() throws {
		bridge = GoraniBridge(memoryArea: "ana")
		let d = try bridge.call(["op": "mem.dir", "parent": "", "name": "docs"])["item"] as? [String: Any]
		docs = d?["id"] as? String ?? ""
		a = try put(docs, "a.txt", "hello")
		sample = try put("", "bad.exe", "MZ")
		try bridge.call(["op": "mem.sample", "id": sample])
		core = try ProviderCore(bridge: bridge)
	}

	func testItemsMapToFileProviderItems() throws {
		let item = try core.providerItem(a)
		XCTAssertEqual(item.itemIdentifier.rawValue, a)
		XCTAssertEqual(item.parentItemIdentifier.rawValue, docs)
		XCTAssertEqual(item.filename, "a.txt")
		XCTAssertEqual(item.contentType, .plainText)
		XCTAssertEqual(GoraniFileProviderItem.contentVersion(item.itemVersion!), 1)
		XCTAssertTrue(item.capabilities!.contains(.allowsReading))
		XCTAssertTrue(item.capabilities!.contains(.allowsWriting))
		let top = core.items(in: .rootContainer).map { $0.filename }.sorted()
		XCTAssertEqual(top, ["bad.exe", "docs"], "the top: what has no folder")
		XCTAssertEqual(try core.providerItem(docs).parentItemIdentifier, .rootContainer)
		let bad = try core.providerItem(sample)
		XCTAssertFalse(bad.capabilities!.contains(.allowsReading), "a sample is listed, never readable")
		XCTAssertEqual(bad.contentType, .data)
		XCTAssertEqual(core.items(in: .workingSet).count, 3)
	}

	func testFetchWritesTheCurrentBytesAndRefusesASample() throws {
		let (url, item) = try core.fetch(a)
		XCTAssertEqual(try String(contentsOf: url, encoding: .utf8), "hello")
		XCTAssertEqual(item.itemIdentifier.rawValue, a)
		XCTAssertThrowsError(try core.fetch(sample))
	}

	func testCreateModifyDeleteReachTheCore() throws {
		let made = try core.create(template: Template(parent: GoraniFileProviderItem.identifier(docs), filename: "new.txt"), contents: file("made here"))
		XCTAssertEqual(try content(made.itemIdentifier.rawValue), "made here")
		let empty = try core.create(template: Template(parent: .rootContainer, filename: "empty.txt"), contents: nil)
		XCTAssertEqual(try content(empty.itemIdentifier.rawValue), "")
		let folder = try core.create(template: Template(parent: .rootContainer, filename: "out", type: .folder), contents: nil)
		XCTAssertEqual(folder.contentType, .folder)
		let v2 = try core.modify(made.itemIdentifier.rawValue, base: 1, fields: [.contents], template: made, contents: file("made here, then edited"))
		XCTAssertEqual(GoraniFileProviderItem.contentVersion(v2.itemVersion!), 2)
		XCTAssertEqual(try content(made.itemIdentifier.rawValue), "made here, then edited")
		let moved = try core.modify(made.itemIdentifier.rawValue, base: 2, fields: [.filename, .parentItemIdentifier], template: Template(parent: folder.itemIdentifier, filename: "renamed.txt"), contents: nil)
		XCTAssertEqual(moved.filename, "renamed.txt")
		XCTAssertEqual(moved.parentItemIdentifier, folder.itemIdentifier)
		XCTAssertThrowsError(try core.delete(folder.itemIdentifier.rawValue), "a folder with something in it")
		try core.delete(made.itemIdentifier.rawValue)
		try core.delete(folder.itemIdentifier.rawValue)
		XCTAssertThrowsError(try core.providerItem(made.itemIdentifier.rawValue))
	}

	func testAStaleSaveKeepsTheirsAndACopyOfMine() throws {
		try bridge.call(["op": "mem.edit", "id": a, "data": Data("theirs".utf8).base64EncodedString()])
		let answered = try core.modify(a, base: 1, fields: [.contents], template: try core.providerItem(a), contents: file("mine"))
		XCTAssertEqual(GoraniFileProviderItem.contentVersion(answered.itemVersion!), 2, "theirs, version 2, is what stands at the name")
		XCTAssertEqual(try content(a), "theirs")
		let copy = core.items(in: GoraniFileProviderItem.identifier(docs)).first { $0.filename.hasPrefix("a (conflict ") }
		XCTAssertNotNil(copy, "and mine is beside it")
		XCTAssertEqual(try content(copy!.itemIdentifier.rawValue), "mine")
	}

	func testChangesSinceAnAnchor() throws {
		let start = core.anchor
		let x = try put("", "x.txt", "new")
		XCTAssertTrue(try core.refresh())
		let after = try XCTUnwrap(core.changes(since: start))
		XCTAssertEqual(after.updated.map { $0.itemIdentifier.rawValue }, [x])
		XCTAssertTrue(after.deleted.isEmpty)
		let mid = core.anchor
		try bridge.call(["op": "mem.remove", "id": x])
		try bridge.call(["op": "mem.edit", "id": a, "data": Data("v2".utf8).base64EncodedString()])
		XCTAssertTrue(try core.refresh())
		let later = try XCTUnwrap(core.changes(since: mid))
		XCTAssertEqual(later.deleted.map { $0.rawValue }, [x])
		XCTAssertEqual(later.updated.map { $0.itemIdentifier.rawValue }, [a], "new bytes: an update")
		XCTAssertNil(core.changes(since: ReplicaModel.anchorData(999)), "an anchor never seen is expired")
		XCTAssertFalse(try core.refresh(), "nothing new, no new generation")
	}

	func testAReadOnlyAreaIsListedButNeverWritten() throws {
		try bridge.call(["op": "mem.readOnly", "why": "an evidence case is read-only"])
		_ = try core.model.refresh(force: true)
		XCTAssertFalse(try core.providerItem(a).capabilities!.contains(.allowsWriting))
		XCTAssertThrowsError(try core.create(template: Template(parent: .rootContainer, filename: "n.txt"), contents: file("x")))
		XCTAssertThrowsError(try core.delete(a))
	}

	func testEnumeratorsAnswerTheSystem() throws {
		let queue = DispatchQueue(label: "test")
		let all = Observer(expectation(description: "items"))
		GoraniEnumerator(core: core, container: .workingSet, queue: queue).enumerateItems(for: all, startingAt: NSFileProviderPage(rawValue: Data()))
		wait(for: [all.done], timeout: 5)
		XCTAssertEqual(all.items.count, 3)
		let anchor = NSFileProviderSyncAnchor(rawValue: core.anchor)
		_ = try put("", "y.txt", "y")
		_ = try core.refresh()
		let changes = Observer(expectation(description: "changes"))
		GoraniEnumerator(core: core, container: .workingSet, queue: queue).enumerateChanges(for: changes, from: anchor)
		wait(for: [changes.done], timeout: 5)
		XCTAssertEqual(changes.updated.map { $0.filename }, ["y.txt"])
		let stale = Observer(expectation(description: "expired"))
		GoraniEnumerator(core: core, container: .workingSet, queue: queue).enumerateChanges(for: stale, from: NSFileProviderSyncAnchor(rawValue: ReplicaModel.anchorData(12345)))
		wait(for: [stale.done], timeout: 5)
		XCTAssertEqual((stale.error as? NSFileProviderError)?.code, .syncAnchorExpired)
	}

	func testFinderBadgesWhatDeservesOne() throws {
		let decorations = { (id: String) in (try self.core.providerItem(id) as? GoraniFileProviderItem)?.decorations ?? [] }
		XCTAssertEqual(try decorations(sample), [GoraniFileProviderItem.decoration("sample")])
		XCTAssertEqual(try decorations(a), [], "an ordinary file: no badge")
		try bridge.call(["op": "mem.readOnly", "why": "an evidence case is read-only"])
		_ = try core.model.refresh(force: true)
		XCTAssertEqual(try decorations(a), [GoraniFileProviderItem.decoration("readOnly")])
		XCTAssertTrue(GoraniFileProviderItem.decoration("sample").rawValue.hasPrefix(GoraniFileProviderItem.decorationPrefix + "."), "named under the extension's id")
	}

	// ── 8. "Always keep on this Mac" and "Free up space" ──

	func policy(_ id: String, of other: ProviderCore? = nil) throws -> NSFileProviderContentPolicy? {
		let c: ProviderCore = other ?? core
		return (try c.providerItem(id) as? GoraniFileProviderItem)?.contentPolicy
	}

	func testAlwaysKeepMarksTheItemAndFinderLearnsOfIt() throws {
		let start = core.anchor
		let before = try XCTUnwrap(core.providerItem(a) as? GoraniFileProviderItem)
		XCTAssertEqual(try policy(a), .inherited, "as its folder is, until asked")
		XCTAssertEqual(core.keep([a]), [a], "a file: asked for at once")
		XCTAssertEqual(try policy(a), .downloadEagerlyAndKeepDownloaded, "downloaded and kept downloaded — the system's to do")
		XCTAssertEqual(try policy(docs), .inherited, "its folder is not kept")
		let changed = try XCTUnwrap(core.changes(since: start))
		XCTAssertEqual(changed.updated.map { $0.itemIdentifier.rawValue }, [a], "a change since the anchor: the system reads the new policy")
		let after = try XCTUnwrap(core.providerItem(a) as? GoraniFileProviderItem)
		XCTAssertNotEqual(after.itemVersion.metadataVersion, before.itemVersion.metadataVersion, "the metadata version moves with the mark")
		XCTAssertEqual(after.itemVersion.contentVersion, before.itemVersion.contentVersion, "…the content's does not: nothing to fetch again")
		let again = core.anchor
		core.keep([a])
		XCTAssertEqual(core.anchor, again, "kept already: no change")
	}

	func testASampleIsNeverKept() throws {
		XCTAssertEqual(core.keep([sample]), [])
		XCTAssertFalse(core.model.isKept(sample))
		XCTAssertEqual(try policy(sample), .downloadLazily, "never downloaded at once, whatever a folder above says")
		core.keep([""])
		XCTAssertEqual(core.model.kept, [docs], "the top: what is in it — the sample not")
	}

	func testFreeingAFolderFreesWhatIsInIt() throws {
		core.keep([docs, a])
		XCTAssertEqual(core.free([docs]), [docs], "the folder evicted, what is in it with it")
		XCTAssertTrue(core.model.kept.isEmpty)
		XCTAssertEqual(try policy(a), .inherited)
	}

	func testFreeingOneFileOutOfAKeptFolderKeepsTheRest() throws {
		let b = try put(docs, "b.txt", "bee")
		let sub = (try bridge.call(["op": "mem.dir", "parent": docs, "name": "sub"])["item"] as? [String: Any])?["id"] as? String ?? ""
		let c = try put(sub, "c.txt", "sea")
		let d = try put(sub, "d.txt", "dee")
		XCTAssertTrue(try core.refresh())
		core.keep([docs])
		XCTAssertEqual(core.free([c]), [c])
		XCTAssertFalse(core.model.isKept(docs), "the folder kept as a whole no more — or c would stay downloaded through it")
		XCTAssertEqual(core.model.kept, [a, b, d], "what else was kept through it is kept in its own right")
		XCTAssertEqual(try policy(c), .inherited)
	}

	func testTheMarksAreKeptAcrossARestart() throws {
		let file = FileManager.default.temporaryDirectory.appendingPathComponent("gorani-kept-\(UUID().uuidString).json")
		defer { try? FileManager.default.removeItem(at: file) }
		try ProviderCore(bridge: bridge, keptFile: file).keep([a])
		let again = try ProviderCore(bridge: bridge, keptFile: file)
		XCTAssertTrue(again.model.isKept(a), "saved on this Mac, read back at the next start")
		XCTAssertEqual(try policy(a, of: again), .downloadEagerlyAndKeepDownloaded)
		again.free([a])
		XCTAssertFalse(try ProviderCore(bridge: bridge, keptFile: file).model.isKept(a))
	}

	func testFinderActionsAreNamedUnderTheExtension() {
		XCTAssertEqual(ProviderCore.Action(identifier: GoraniFileProviderItem.decorationPrefix + ".keep"), .keep)
		XCTAssertEqual(ProviderCore.Action(identifier: GoraniFileProviderItem.decorationPrefix + ".free"), .free)
		XCTAssertNil(ProviderCore.Action(identifier: "com.example.keep"), "another extension's action is not ours")
	}

	func testTheCoresRefusalsBecomeFileProviderErrors() {
		XCTAssertEqual((ProviderCore.fileProviderError(GoraniError(code: "not_found", message: "x")) as? NSFileProviderError)?.code, .noSuchItem)
		XCTAssertEqual((ProviderCore.fileProviderError(GoraniError(code: "exists", message: "x")) as? NSFileProviderError)?.code, .filenameCollision)
		XCTAssertEqual((ProviderCore.fileProviderError(GoraniError(code: "io", message: "x")) as? NSFileProviderError)?.code, .serverUnreachable)
	}
}
