// swift-tools-version:5.9
// Copyright 2026- Seongwoo Hong. All rights reserved.

// The macOS shell's Swift half (commit 39c, docs/DESKTOP.md › 39c), as a
// package so its logic is unit-tested without Xcode or a signed extension:
// `cargo build -p gorani-macos && (cd GoraniKit && swift test)` (CI does).
// It also builds gorani-keystore, the helper the Rust client asks for the
// Secure Enclave and the login Keychain (commit 39d).
// The File Provider extension and the host app (project.yml) compile the
// same GoraniKit sources.

import Foundation
import PackageDescription

// Where libgorani_macos.a was built: GORANI_LIB_DIR, else the workspace's debug target.
let here = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let libDir = ProcessInfo.processInfo.environment["GORANI_LIB_DIR"] ?? here.appendingPathComponent("../../../target/debug").standardized.path

let package = Package(
	name: "GoraniKit",
	platforms: [.macOS(.v13)],
	products: [
		.library(name: "GoraniKit", targets: ["GoraniKit"]),
		// The Secure Enclave and Keychain helper (commit 39d): installed
		// beside gorani-sync, spoken to over pipes by the Rust client.
		.executable(name: "gorani-keystore", targets: ["gorani-keystore"]),
	],
	targets: [
		.systemLibrary(name: "CGorani", path: "Sources/CGorani"),
		.target(
			name: "GoraniKit",
			dependencies: ["CGorani"],
			path: "Sources/GoraniKit",
			linkerSettings: [
				.unsafeFlags(["-L", libDir]),
				.linkedFramework("Security"),
				.linkedFramework("CoreFoundation"),
				.linkedFramework("SystemConfiguration"),
			]
		),
		// (Pure Swift — CryptoKit and Security — nothing of the Rust core.)
		.executableTarget(name: "gorani-keystore", path: "Sources/gorani-keystore"),
		.testTarget(name: "GoraniKitTests", dependencies: ["GoraniKit"], path: "Tests/GoraniKitTests"),
	]
)
