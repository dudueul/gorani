// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Embeds gorani.exe's manifest (commit 40b, src/app/gorani.exe.manifest):
//! Common Controls 6 and per-monitor DPI awareness. With the MSVC linker
//! this takes no resource compiler: link.exe embeds the file itself
//! (/MANIFEST:EMBED with /MANIFESTINPUT), for the `gorani` binary only.

fn main() {
	let manifest = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default()).join("src").join("app").join("gorani.exe.manifest");
	println!("cargo:rerun-if-changed={}", manifest.display());
	if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
		println!("cargo:rustc-link-arg-bin=gorani=/MANIFEST:EMBED");
		println!("cargo:rustc-link-arg-bin=gorani=/MANIFESTINPUT:{}", manifest.display());
		println!("cargo:rustc-link-arg-bin=gorani=/MANIFESTUAC:NO");
	}
}
