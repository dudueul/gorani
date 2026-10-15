// Copyright 2026- Seongwoo Hong. All rights reserved.

// gorani-keystore (commit 39d, docs/DESKTOP.md › 39d): the Mac's own stores
// for a device-secret part, for the Rust client (clients/core/src/devicekey/
// macos.rs) — which cannot reach CryptoKit itself. One request per run;
// parts cross only stdin and stdout, never argv or a file:
//
//   probe                          {"enclave": bool, "keychain": bool}
//   enclave-seal [--presence]      a new Secure Enclave key; the part agreed with a peer key
//                                  whose private half is dropped here → {"key","peer","part"}
//   enclave-open                   stdin {"key","peer"} → {"part"}
//   keychain-store ITEM LABEL      stdin: the part (hex) → a login Keychain item
//   keychain-lookup ITEM           → the part (hex)
//   keychain-clear ITEM
//
// The part from the enclave: HKDF-SHA256(ECDH(enclave key, peer), salt
// "gorani-enclave-part-v1", info = both public keys). The enclave never
// lets its key out; its "representation" is that key encrypted by this
// Mac's enclave — useless anywhere else, so the profile can keep it.

import CryptoKit
import Foundation
import Security

struct Failure: Error {
	let message: String
}

let service = "io.gorani.device"
let salt = Data("gorani-enclave-part-v1".utf8)

// A debug build may stand a software key in for the enclave, for machines
// without one (CI's virtual Macs). Its keys are marked "software:"; a
// release build has no such mode, and the client refuses them anyway.
#if DEBUG
	let software = ProcessInfo.processInfo.environment["GORANI_KEYSTORE_SOFTWARE"] == "1"
#else
	let software = false
#endif

func hex(_ d: Data) -> String {
	d.map { String(format: "%02x", $0) }.joined()
}

func unhex(_ text: String) -> Data? {
	let t = Array(text.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
	guard t.count % 2 == 0 else { return nil }
	var out = Data(capacity: t.count / 2)
	var i = 0
	while i < t.count {
		guard let b = UInt8(String(decoding: t[i..<i + 2], as: UTF8.self), radix: 16) else { return nil }
		out.append(b)
		i += 2
	}
	return out
}

func emit(_ object: [String: Any]) throws {
	let d = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
	FileHandle.standardOutput.write(d)
	FileHandle.standardOutput.write(Data("\n".utf8))
}

func readInput() -> Data {
	FileHandle.standardInput.readDataToEndOfFile()
}

func message(_ status: OSStatus) -> String {
	(SecCopyErrorMessageString(status, nil) as String?) ?? "OSStatus \(status)"
}

// ── the Secure Enclave ──────────────────────────────────────────────────

func agreed(_ shared: SharedSecret, _ mine: P256.KeyAgreement.PublicKey, _ peer: P256.KeyAgreement.PublicKey) -> String {
	let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: mine.x963Representation + peer.x963Representation, outputByteCount: 32)
	return key.withUnsafeBytes { hex(Data($0)) }
}

func enclaveSeal(presence: Bool) throws {
	let peer = P256.KeyAgreement.PrivateKey()
	let peerText = peer.publicKey.x963Representation.base64EncodedString()
	if software {
		let k = P256.KeyAgreement.PrivateKey()
		let shared = try k.sharedSecretFromKeyAgreement(with: peer.publicKey)
		try emit(["key": "software:" + k.rawRepresentation.base64EncodedString(), "peer": peerText, "part": agreed(shared, k.publicKey, peer.publicKey)])
		return
	}
	guard SecureEnclave.isAvailable else {
		throw Failure(message: "this Mac has no Secure Enclave (an Intel Mac without a T2 chip, or a virtual machine)")
	}
	var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
	if presence { flags.insert(.userPresence) }
	var error: Unmanaged<CFError>?
	guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
		throw Failure(message: "no access control for the key: \(error.map { String(describing: $0.takeRetainedValue()) } ?? "?")")
	}
	let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
	let shared = try k.sharedSecretFromKeyAgreement(with: peer.publicKey)
	try emit(["key": k.dataRepresentation.base64EncodedString(), "peer": peerText, "part": agreed(shared, k.publicKey, peer.publicKey)])
}

func enclaveOpen() throws {
	guard let request = try JSONSerialization.jsonObject(with: readInput()) as? [String: Any],
		let key = request["key"] as? String,
		let peerData = (request["peer"] as? String).flatMap({ Data(base64Encoded: $0) })
	else { throw Failure(message: "the request is not {key, peer}") }
	let peer = try P256.KeyAgreement.PublicKey(x963Representation: peerData)
	if key.hasPrefix("software:") {
		guard software, let raw = Data(base64Encoded: String(key.dropFirst("software:".count))) else {
			throw Failure(message: "a test build's software key is not a Secure Enclave key")
		}
		let k = try P256.KeyAgreement.PrivateKey(rawRepresentation: raw)
		try emit(["part": agreed(try k.sharedSecretFromKeyAgreement(with: peer), k.publicKey, peer)])
		return
	}
	guard let data = Data(base64Encoded: key) else { throw Failure(message: "the key is not base64") }
	let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data)
	try emit(["part": agreed(try k.sharedSecretFromKeyAgreement(with: peer), k.publicKey, peer)])
}

// ── the login Keychain ──────────────────────────────────────────────────

func query(_ item: String) -> [String: Any] {
	[kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: item]
}

/// The Keychain answers (a lookup of nothing is "not found", not "locked").
func keychainUsable() -> Bool {
	var q = query("probe-0")
	q[kSecReturnData as String] = false
	return SecItemCopyMatching(q as CFDictionary, nil) == errSecItemNotFound
}

func keychainStore(item: String, label: String) throws {
	guard let part = unhex(String(decoding: readInput(), as: UTF8.self)), part.count == 32 else {
		throw Failure(message: "the part on stdin is not 32 bytes of hex")
	}
	var q = query(item)
	q[kSecAttrLabel as String] = label
	q[kSecValueData as String] = part
	let status = SecItemAdd(q as CFDictionary, nil)
	guard status == errSecSuccess else { throw Failure(message: "the login Keychain did not take the part: \(message(status))") }
}

func keychainLookup(item: String) throws {
	var q = query(item)
	q[kSecReturnData as String] = true
	q[kSecMatchLimit as String] = kSecMatchLimitOne
	var found: CFTypeRef?
	let status = SecItemCopyMatching(q as CFDictionary, &found)
	guard status == errSecSuccess, let data = found as? Data else { throw Failure(message: "the login Keychain gave no part: \(message(status))") }
	FileHandle.standardOutput.write(Data(hex(data).utf8))
}

func keychainClear(item: String) {
	SecItemDelete(query(item) as CFDictionary)
}

// ── one request ─────────────────────────────────────────────────────────

let args = Array(CommandLine.arguments.dropFirst())
do {
	switch (args.first ?? "", args.count) {
	case ("probe", 1): try emit(["enclave": software || SecureEnclave.isAvailable, "keychain": keychainUsable()])
	case ("enclave-seal", _): try enclaveSeal(presence: args.contains("--presence"))
	case ("enclave-open", 1): try enclaveOpen()
	case ("keychain-store", 3): try keychainStore(item: args[1], label: args[2])
	case ("keychain-lookup", 2): try keychainLookup(item: args[1])
	case ("keychain-clear", 2): keychainClear(item: args[1])
	default: throw Failure(message: "usage: gorani-keystore probe | enclave-seal [--presence] | enclave-open | keychain-store ITEM LABEL | keychain-lookup ITEM | keychain-clear ITEM")
	}
} catch let f as Failure {
	FileHandle.standardError.write(Data((f.message + "\n").utf8))
	exit(1)
} catch {
	FileHandle.standardError.write(Data("\(error)\n".utf8))
	exit(1)
}
