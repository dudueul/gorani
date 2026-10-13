// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare's desktop core (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

//! The Rust formats against what the browser's TypeScript code sealed
//! (crates/formats/tests/vectors.json, from scripts/make-vectors.mjs): every
//! format opens, every unlock method opens the root, a content key unwraps
//! and opens. With `GORANI_RUST_OUT` set it also writes what Rust sealed, for
//! tests/unit/formats.test.mjs to open with the TypeScript code (both
//! directions). Byte equality between the two implementations is the
//! guarantee the whole vault rests on — keep this test red-proof.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use gorani_formats::chunked;
use gorani_formats::formats::{self, VaultPrivateKey, VaultPublicKey};
use gorani_formats::unlock::{self, DeviceCopy, Secret, UnlockMethod};
use serde_json::{json, Value};

fn vectors() -> Value {
	let path = std::env::var("GORANI_VECTORS")
		.unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors.json").to_string());
	serde_json::from_str(&std::fs::read_to_string(path).expect("vectors file")).expect("json")
}

fn b(v: &Value) -> Vec<u8> {
	STANDARD.decode(v.as_str().expect("string")).expect("base64")
}

fn s(v: &Value) -> &str {
	v.as_str().expect("string")
}

fn methods(v: &Value) -> Vec<UnlockMethod> {
	let u = &v["unlock"];
	vec![
		serde_json::from_value(u["password"].clone()).expect("password method"),
		serde_json::from_value(u["recovery"].clone()).expect("recovery method"),
		serde_json::from_value(u["passkey"].clone()).expect("passkey method"),
	]
}

#[test]
fn opens_what_the_browser_sealed_and_seals_what_it_opens() {
	let v = vectors();

	// P-256 (GV01)
	let p = &v["p256"];
	let p_priv = VaultPrivateKey::from_bytes(&b(&p["pkcs8"])).unwrap();
	let p_pub = VaultPublicKey::from_jwk(s(&p["x"]), s(&p["y"]), None).unwrap();
	assert_eq!(formats::key_id(&p_pub), s(&p["keyId"]), "P-256 key id");
	assert_eq!(&formats::open(&p_priv, &b(&p["sealed"])).unwrap()[..], b"sealed to P-256");
	assert_eq!(&formats::open_text(&p_priv, s(&p["sealedText"])).unwrap()[..], "a name, sealed (GV01)");

	// Hybrid (GK01 bundle, GV03)
	let h = &v["hybrid"];
	let h_priv = VaultPrivateKey::from_bytes(&b(&h["bundle"])).unwrap();
	assert!(h_priv.is_hybrid());
	let h_pub = VaultPublicKey::from_jwk(s(&h["x"]), s(&h["y"]), Some(s(&h["kem"]))).unwrap();
	assert_eq!(formats::key_id(&h_pub), s(&h["keyId"]), "hybrid key id");
	assert_eq!(formats::key_id(&formats::public_of(&h_priv)), s(&h["keyId"]), "public half from the bundle");
	assert_eq!(&formats::open(&h_priv, &b(&h["sealed"])).unwrap()[..], b"sealed post-quantum");
	assert_eq!(&formats::open_text(&h_priv, s(&h["sealedText"])).unwrap()[..], "한국어 이름.pdf");
	assert!(formats::open(&p_priv, &b(&h["sealed"])).is_err(), "GV03 needs the hybrid key");
	// GV01 opens with a hybrid key's P-256 half, as in the browser.
	let mixed = formats::seal(&VaultPublicKey::P256(match &formats::public_of(&h_priv) {
		VaultPublicKey::Hybrid { ec, .. } => *ec,
		_ => unreachable!(),
	}), b"x");
	assert_eq!(&formats::open(&h_priv, &mixed).unwrap()[..], b"x");

	// Content keys (GV02), wrapped to the hybrid key and to the P-256 key
	let c = &v["content"];
	let key = formats::unwrap_content_key(&h_priv, s(&c["wrapped"])).unwrap();
	let key_p = formats::unwrap_content_key(&p_priv, s(&c["wrappedP256"])).unwrap();
	assert_eq!(key.as_slice(), key_p.as_slice(), "both wraps open to the same key");
	assert_eq!(&formats::open_with(&key, &b(&c["sealed"])).unwrap()[..], b"an attachment's bytes");
	assert_eq!(&formats::open_text_with(&key, s(&c["sealedText"])).unwrap()[..], "한국어 문서");

	// Chunked files (GC01): the browser's frames open whole and by span
	let ch = &v["chunked"];
	let chunk = ch["chunk"].as_u64().unwrap();
	let plain = b(&ch["plain"]);
	let sealed = b(&ch["sealed"]);
	assert_eq!(chunked::sealed_size(plain.len() as u64, chunk), sealed.len() as u64, "sealed size arithmetic");
	assert_eq!(&chunked::open_chunked(&key, &sealed, chunk).unwrap()[..], &plain[..], "chunked whole");
	// The middle span (as a Range fetch would bring it) opens to those two
	// whole frames' plaintext (frames 1..=2 cover plain bytes 64..192); the
	// caller slices out the requested range in memory.
	let span = chunked::frames_for(100, 40, plain.len() as u64, chunk);
	let fetched = &sealed[span.start as usize..span.end as usize];
	let opened = chunked::open_span(&key, fetched, span, plain.len() as u64, chunk).unwrap();
	assert_eq!(&opened[..], &plain[64..192], "chunked span");
	// A reordered frame fails (position is authenticated)
	let frame = (chunk + chunked::FRAME_OVERHEAD) as usize;
	let mut reordered = sealed.clone();
	reordered[0..frame].copy_from_slice(&sealed[frame..frame * 2]);
	reordered[frame..frame * 2].copy_from_slice(&sealed[0..frame]);
	assert!(chunked::open_chunked(&key, &reordered, chunk).is_err(), "reordered frames must fail");

	// Every unlock method opens the root (the hybrid bundle)
	let root_bytes = b(&h["bundle"]);
	let ms = methods(&v);
	let pw = unlock::unlock(&ms, &Secret::Password("correct horse battery staple")).unwrap();
	assert_eq!(&pw.0[..], &root_bytes[..], "password");
	let rc = unlock::unlock(&ms, &Secret::RecoveryCode(s(&v["unlock"]["recoveryCode"]))).unwrap();
	assert_eq!(&rc.0[..], &root_bytes[..], "recovery code");
	let prf = b(&v["unlock"]["passkeyPrf"]);
	let pk = unlock::unlock(&ms, &Secret::PasskeyPrf(&prf)).unwrap();
	assert_eq!(&pk.0[..], &root_bytes[..], "passkey PRF");
	// The typed recovery code is read loosely: wrong case and dashes are fine.
	let loose = unlock::unlock(&ms, &Secret::RecoveryCode(&s(&v["unlock"]["recoveryCode"]).to_lowercase().replace('-', "")));
	assert!(loose.is_ok(), "normalised recovery code");

	// The device copy opens with the device secret, to the root bytes
	let d = &v["device"];
	let copy = DeviceCopy { wrapped: s(&d["wrapped"]).to_string(), salt: s(&d["salt"]).to_string() };
	assert_eq!(&unlock::open_device_copy(&copy.wrapped, &copy.salt, &b(&d["secret"])).unwrap()[..], &root_bytes[..]);

	// Tamper: a changed byte anywhere in a sealed object fails to open
	for (name, sealed) in [("v1", b(&p["sealed"])), ("v3", b(&h["sealed"])), ("v2", b(&c["sealed"]))] {
		let mut tampered = sealed.clone();
		let mid = tampered.len() / 2;
		tampered[mid] ^= 0x40;
		assert!(formats::open(&p_priv, &tampered).is_err() && formats::open(&h_priv, &tampered).is_err(), "{name} tampered bytes must fail");
		let key = formats::unwrap_content_key(&h_priv, s(&c["wrapped"])).unwrap();
		if name == "v2" {
			assert!(formats::open_with(&key, &tampered).is_err(), "v2 tampered bytes must fail");
		}
	}

	// What Rust sealed, for the TypeScript side (GORANI_RUST_OUT=<path>)
	if let Ok(out_path) = std::env::var("GORANI_RUST_OUT") {
		let mut rust_sealed = Vec::new();
		let n = chunked::frame_count(plain.len() as u64, chunk);
		for (i, frame) in plain.chunks(chunk as usize).enumerate() {
			rust_sealed.extend_from_slice(&chunked::seal_chunk(&key, frame, i as u64, i as u64 == n - 1));
		}
		let out = json!({
			"p256Sealed": STANDARD.encode(formats::seal(&p_pub, b"sealed by rust (GV01)")),
			"hybridSealed": STANDARD.encode(formats::seal(&h_pub, b"sealed by rust (GV03)")),
			"contentSealed": STANDARD.encode(formats::seal_with(&key, b"sealed by rust (GV02)")),
			"chunkedSealed": STANDARD.encode(&rust_sealed),
			"chunkedChunk": chunk,
			"chunkedPlain": STANDARD.encode(&plain),
			"textSealed": formats::seal_text(&h_pub, "러스트가 봉인한 이름.txt"),
			"rewrapped": formats::wrap_content_key(&p_pub, &key),
		});
		std::fs::write(out_path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
	}
}