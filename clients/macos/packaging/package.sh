#!/bin/bash
# Copyright 2026- Seongwoo Hong. All rights reserved.
#
# The Mac app, assembled (commit 39f, docs/DESKTOP.md › 39f): Xcode's
# build of the app and its File Provider extension, the CLI and the
# keystore helper put where the client looks for them, then — when a
# Developer ID identity is given — signed inside-out with the hardened
# runtime, notarized and stapled. Without one, an ad-hoc signed app for
# testing (Gatekeeper will not open it from a download).
#
#   package.sh <Gorani.app> <gorani-sync> <gorani-keystore> <out.zip>
#
# Signing, from the environment (package.yml passes the secrets; nothing
# here prints them):
#   SIGN_IDENTITY   the Developer ID Application identity (its SHA-1), in an unlocked keychain
#   TEAM_ID         the Apple team (the app group is "<TEAM_ID>.io.gorani")
#   NOTARY_KEY, NOTARY_KEY_ID, NOTARY_ISSUER   an App Store Connect API key (.p8 path), to notarize
set -euo pipefail

app=$1 sync=$2 keystore=$3 out=$4
ext="$app/Contents/PlugIns/GoraniFileProvider.appex"
[ -d "$ext" ] || { echo "no File Provider extension in $app" >&2; exit 1; }

# Where the client finds its helper: beside the program asking (devicekey/
# macos.rs). Two copies, because they run in two worlds: the CLI's is a
# plain program; the extension's runs inside the extension's sandbox, so it
# is signed to inherit it (a helper with "inherit" started by an
# unsandboxed parent is killed — hence not one copy for both).
install -m 0755 "$sync" "$app/Contents/MacOS/gorani-sync"
install -m 0755 "$keystore" "$app/Contents/MacOS/gorani-keystore"
install -m 0755 "$keystore" "$ext/Contents/MacOS/gorani-keystore"

ents=$(mktemp -d)
trap 'rm -rf "$ents"' EXIT
plist() { # file, then key/value XML
	local f=$1; shift
	printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>%s</dict></plist>\n' "$*" >"$ents/$f"
}

if [ -z "${SIGN_IDENTITY:-}" ]; then
	echo "no signing identity: an ad-hoc signed app, for testing only"
	codesign --force --deep --sign - "$app"
else
	: "${TEAM_ID:?TEAM_ID is needed to sign}"
	group="<key>com.apple.security.application-groups</key><array><string>$TEAM_ID.io.gorani</string></array>"
	sandbox="<key>com.apple.security.app-sandbox</key><true/>"
	plist helper.plist "$sandbox<key>com.apple.security.inherit</key><true/>"
	plist extension.plist "$sandbox<key>com.apple.security.network.client</key><true/>$group"
	plist app.plist "$sandbox$group"
	sign() { codesign --force --timestamp --options runtime --sign "$SIGN_IDENTITY" "$@"; }
	# Inside-out: what a bundle holds is signed before the bundle. Both
	# helpers share one identifier, so the login Keychain's access rule
	# (made for the CLI's copy) admits the extension's too.
	sign --identifier io.gorani.keystore --entitlements "$ents/helper.plist" "$ext/Contents/MacOS/gorani-keystore"
	sign --entitlements "$ents/extension.plist" "$ext"
	sign --identifier io.gorani.keystore "$app/Contents/MacOS/gorani-keystore"
	sign --identifier io.gorani.sync "$app/Contents/MacOS/gorani-sync"
	sign --entitlements "$ents/app.plist" "$app"
	codesign --verify --strict --deep --verbose=2 "$app"
fi

ditto -c -k --keepParent "$app" "$out"

if [ -n "${SIGN_IDENTITY:-}" ] && [ -n "${NOTARY_KEY:-}" ]; then
	xcrun notarytool submit "$out" --key "$NOTARY_KEY" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER" --wait
	xcrun stapler staple "$app"
	spctl --assess --type execute --verbose=2 "$app"
	rm -f "$out"
	ditto -c -k --keepParent "$app" "$out"
fi

# What came out, checked as a person would run it.
# (The CLI with no command says how to use it and exits non-zero: its words
# are what is checked.)
usage=$("$app/Contents/MacOS/gorani-sync" 2>&1 || true)
grep -q "usage: gorani-sync" <<<"$usage" || { echo "the bundled CLI does not answer: $usage" >&2; exit 1; }
"$app/Contents/MacOS/gorani-keystore" probe
nm -gU "$ext/Contents/MacOS/GoraniFileProvider" | grep -q gorani_call || { echo "the extension does not hold the core" >&2; exit 1; }
echo "packaged: $out"
