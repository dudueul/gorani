// Copyright 2026- Seongwoo Hong. All rights reserved.

// The Mac app's requests (commit 40d), over the real core — the ones that
// need no server: the menu, the URL rules, a Mac not enrolled yet, a
// sign-in started and cancelled, a refusal in the core's words.

import XCTest

@testable import GoraniKit

final class AppBridgeTests: XCTestCase {
	func testTheMenuAndTheDefaultServer() throws {
		let d = try AppBridge.defaults()
		XCTAssertEqual(d.server, "https://gorani.at.day")
		XCTAssertEqual(d.protections.first?.value, "auto", "the recommended choice first")
		XCTAssertTrue(d.protections.contains { $0.value == "presence" }, "Touch ID at each start is offered on a Mac")
	}

	func testTheServerIsTidiedAndHttpsOnly() throws {
		XCTAssertEqual(try AppBridge.normalize(server: "Gorani.Example/"), "https://gorani.example")
		XCTAssertThrowsError(try AppBridge.normalize(server: "http://gorani.example")) { error in
			XCTAssertTrue(String(describing: error).contains("in the clear"))
		}
	}

	func testAMacNotEnrolledYet() throws {
		let missing = FileManager.default.temporaryDirectory.appendingPathComponent("gorani-\(UUID().uuidString).json").path
		let status = try AppBridge.status(profile: missing)
		XCTAssertFalse(status.enrolled)
		XCTAssertEqual(status.server, "https://gorani.at.day")
		XCTAssertThrowsError(try AppBridge.enrol(profile: missing, server: "https://gorani.at.day", signIn: nil, deviceName: "test Mac", secret: "", protect: "auto"))
	}

	func testASignInCanBeCancelled() throws {
		let pending = try AppBridge.startSignIn(server: "https://gorani.at.day")
		XCTAssertTrue(pending.url.hasPrefix("https://gorani.at.day/api/v1/desktop/sign-in?port="))
		AppBridge.cancelSignIn(id: pending.id)
		XCTAssertThrowsError(try AppBridge.waitSignIn(id: pending.id, profile: "/nonexistent"))
	}

	func testSettingsRoundTripTheirShape() throws {
		var app = AppSettings()
		app.caseId = "c42"
		app.paused = true
		let back = try JSONDecoder().decode(AppSettings.self, from: JSONEncoder().encode(app))
		XCTAssertEqual(back, app)
		let fromCore = try JSONDecoder().decode(AppSettings.self, from: Data(#"{"keepLocal":true}"#.utf8))
		XCTAssertTrue(fromCore.keepLocal)
		XCTAssertNil(fromCore.caseId, "fields the core leaves out read as unset")
	}
}
