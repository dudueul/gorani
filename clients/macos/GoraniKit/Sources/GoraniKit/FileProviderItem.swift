// Copyright 2026- Seongwoo Hong. All rights reserved.

// An item as File Provider sees it (commit 39c): the server id is the
// identifier (stable across renames), the area's top is the root
// container, and the capabilities say what Finder may offer — a malware
// sample is listed but never readable, a read-only area (evidence, a read
// grant) never writable. The version pair: CONTENT changes with the
// version number (new bytes, fetched afresh), METADATA with it and the
// modified time.
//
// Finder's badges (commit 39e): a sample, an item of a read-only area, and
// a name that did not open in its place each carry a decoration — declared
// in the extension's Info.plist (project.yml), named under its bundle id.

import FileProvider
import Foundation
import UniformTypeIdentifiers

public final class GoraniFileProviderItem: NSObject, NSFileProviderItem, NSFileProviderItemDecorating {
	public let item: GoraniItem
	private let readOnly: Bool

	/// The extension's bundle id: decorations are named under it (the
	/// extension sets it at start; tests use the default).
	public static var decorationPrefix = "io.gorani.app.fileprovider"

	public static func decoration(_ name: String) -> NSFileProviderItemDecorationIdentifier {
		NSFileProviderItemDecorationIdentifier(rawValue: "\(decorationPrefix).\(name)")
	}

	public init(_ item: GoraniItem, readOnly: Bool) {
		self.item = item
		self.readOnly = readOnly
	}

	public static func identifier(_ id: String) -> NSFileProviderItemIdentifier {
		id.isEmpty ? .rootContainer : NSFileProviderItemIdentifier(rawValue: id)
	}

	/// The core's id for an identifier ("" for the root container).
	public static func id(_ identifier: NSFileProviderItemIdentifier) -> String {
		identifier == .rootContainer ? "" : identifier.rawValue
	}

	public var itemIdentifier: NSFileProviderItemIdentifier { Self.identifier(item.id) }
	public var parentItemIdentifier: NSFileProviderItemIdentifier { Self.identifier(item.parent) }
	public var filename: String { item.name }

	public var contentType: UTType {
		if item.isFolder { return .folder }
		// A sample is plain data to the system: nothing is associated with it.
		if item.sample { return .data }
		let ext = (item.name as NSString).pathExtension
		return UTType(filenameExtension: ext) ?? .data
	}

	public var capabilities: NSFileProviderItemCapabilities {
		var c: NSFileProviderItemCapabilities = []
		if item.isFolder {
			c.insert(.allowsContentEnumerating)
			if !readOnly { c.formUnion([.allowsAddingSubItems, .allowsRenaming, .allowsReparenting, .allowsDeleting]) }
		} else {
			if !item.sample { c.insert(.allowsReading) }
			if !readOnly { c.formUnion([.allowsWriting, .allowsRenaming, .allowsReparenting, .allowsDeleting]) }
		}
		return c
	}

	public var itemVersion: NSFileProviderItemVersion {
		NSFileProviderItemVersion(contentVersion: Data("\(item.version)".utf8), metadataVersion: Data("\(item.version):\(item.modified):\(item.sample)".utf8))
	}

	/// What Finder badges: a sample (warning), a read-only area's item
	/// (locked), a name the server could not show as verified (warning).
	public var decorations: [NSFileProviderItemDecorationIdentifier]? {
		var d: [NSFileProviderItemDecorationIdentifier] = []
		if item.sample { d.append(Self.decoration("sample")) }
		if readOnly { d.append(Self.decoration("readOnly")) }
		if !item.nameVerified { d.append(Self.decoration("unverifiedName")) }
		return d.isEmpty ? nil : d
	}

	public var documentSize: NSNumber? { item.isFolder ? nil : NSNumber(value: item.size) }

	public var contentModificationDate: Date? { Date(timeIntervalSince1970: TimeInterval(item.modified)) }

	public var creationDate: Date? { Date(timeIntervalSince1970: TimeInterval(item.modified)) }

	/// The version number a File Provider version carries (what a save is based on).
	public static func contentVersion(_ v: NSFileProviderItemVersion) -> Int64? {
		Int64(String(decoding: v.contentVersion, as: UTF8.self))
	}
}

/// The root container, as an item of its own.
public final class GoraniRootItem: NSObject, NSFileProviderItem {
	private let readOnly: Bool

	public init(readOnly: Bool) {
		self.readOnly = readOnly
	}

	public var itemIdentifier: NSFileProviderItemIdentifier { .rootContainer }
	public var parentItemIdentifier: NSFileProviderItemIdentifier { .rootContainer }
	public var filename: String { "Gorani" }
	public var contentType: UTType { .folder }
	public var capabilities: NSFileProviderItemCapabilities {
		readOnly ? [.allowsContentEnumerating] : [.allowsContentEnumerating, .allowsAddingSubItems]
	}
	public var itemVersion: NSFileProviderItemVersion {
		NSFileProviderItemVersion(contentVersion: Data("root".utf8), metadataVersion: Data("root".utf8))
	}
}
