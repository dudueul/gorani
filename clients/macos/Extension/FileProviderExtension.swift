// Copyright 2026- Seongwoo Hong. All rights reserved.

// The File Provider extension (commit 39c): the system's calls, answered
// by ProviderCore (Sources/GoraniKit) over the Rust core — every decision
// is there, and tested there (`swift test`); this class only queues,
// translates errors, and tells the system when the server changed.
//
// It opens the vault from the profile in the app group's container
// (`gorani-sync setup --profile "<container>/gorani-sync.json"`, or the
// host app), unlocked with this Mac's enrolled copy.

import FileProvider
import Foundation
import GoraniKit

final class FileProviderExtension: NSObject, NSFileProviderReplicatedExtension {
	private let domain: NSFileProviderDomain
	private let queue = DispatchQueue(label: "io.gorani.fileprovider")
	private var core: ProviderCore?
	private var unavailable: Error = NSFileProviderError(.notAuthenticated)
	private var timer: DispatchSourceTimer?

	required init(domain: NSFileProviderDomain) {
		self.domain = domain
		super.init()
		do {
			guard let group = Bundle.main.object(forInfoDictionaryKey: "GoraniAppGroup") as? String,
				let dir = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)
			else { throw NSFileProviderError(.notAuthenticated) }
			let bridge = try GoraniBridge(profile: dir.appendingPathComponent("gorani-sync.json").path)
			core = try ProviderCore(bridge: bridge)
			startPolling()
		} catch {
			NSLog("Gorani: the vault did not open: %@", String(describing: error))
			unavailable = ProviderCore.fileProviderError(error)
		}
	}

	func invalidate() {
		timer?.cancel()
		timer = nil
	}

	/// The server is asked every few seconds; a change is signalled, and the
	/// system then asks the enumerator what changed.
	private func startPolling() {
		let t = DispatchSource.makeTimerSource(queue: queue)
		t.schedule(deadline: .now() + 3, repeating: 3)
		t.setEventHandler { [weak self] in
			guard let self, let core = self.core else { return }
			if (try? core.refresh()) == true {
				NSFileProviderManager(for: self.domain)?.signalEnumerator(for: .workingSet) { _ in }
			}
		}
		t.resume()
		timer = t
	}

	private func work(_ body: @escaping (ProviderCore) throws -> Void, failed: @escaping (Error) -> Void) -> Progress {
		queue.async {
			guard let core = self.core else { return failed(self.unavailable) }
			do { try body(core) } catch { failed(ProviderCore.fileProviderError(error)) }
		}
		return Progress()
	}

	func item(for identifier: NSFileProviderItemIdentifier, request: NSFileProviderRequest, completionHandler: @escaping (NSFileProviderItem?, Error?) -> Void) -> Progress {
		work({ core in completionHandler(try core.providerItem(GoraniFileProviderItem.id(identifier)), nil) }, failed: { completionHandler(nil, $0) })
	}

	func fetchContents(for itemIdentifier: NSFileProviderItemIdentifier, version requestedVersion: NSFileProviderItemVersion?, request: NSFileProviderRequest, completionHandler: @escaping (URL?, NSFileProviderItem?, Error?) -> Void) -> Progress {
		work({ core in
			let (url, item) = try core.fetch(GoraniFileProviderItem.id(itemIdentifier))
			completionHandler(url, item, nil)
		}, failed: { completionHandler(nil, nil, $0) })
	}

	func createItem(basedOn itemTemplate: NSFileProviderItem, fields: NSFileProviderItemFields, contents url: URL?, options: NSFileProviderCreateItemOptions, request: NSFileProviderRequest, completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
		work({ core in completionHandler(try core.create(template: itemTemplate, contents: url), [], false, nil) }, failed: { completionHandler(nil, [], false, $0) })
	}

	func modifyItem(_ item: NSFileProviderItem, baseVersion version: NSFileProviderItemVersion, changedFields: NSFileProviderItemFields, contents newContents: URL?, options: NSFileProviderModifyItemOptions, request: NSFileProviderRequest, completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
		work({ core in
			let done = try core.modify(GoraniFileProviderItem.id(item.itemIdentifier), base: GoraniFileProviderItem.contentVersion(version), fields: changedFields, template: item, contents: newContents)
			completionHandler(done, [], false, nil)
		}, failed: { completionHandler(nil, [], false, $0) })
	}

	func deleteItem(identifier: NSFileProviderItemIdentifier, baseVersion version: NSFileProviderItemVersion, options: NSFileProviderDeleteItemOptions, request: NSFileProviderRequest, completionHandler: @escaping (Error?) -> Void) -> Progress {
		work({ core in
			try core.delete(GoraniFileProviderItem.id(identifier))
			completionHandler(nil)
		}, failed: { completionHandler($0) })
	}

	func enumerator(for containerItemIdentifier: NSFileProviderItemIdentifier, request: NSFileProviderRequest) throws -> NSFileProviderEnumerator {
		guard let core else { throw unavailable }
		return GoraniEnumerator(core: core, container: containerItemIdentifier, queue: queue)
	}
}
