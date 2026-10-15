#!/bin/sh
# Copyright 2026- Seongwoo Hong. All rights reserved.
#
# Check a Gorani release before running anything from it (commit 39g,
# docs/INSTALL.md › Checking a download): SHA256SUMS signed by the release
# key, and every downloaded file the one it lists. macOS and Linux; needs
# OpenSSH 8.1 or later (`ssh -V`).
#
#   verify.sh [--signers FILE] DIR
#
# DIR holds SHA256SUMS, SHA256SUMS.sig and the files you downloaded (any
# of the release's). FILE: the release keys, default allowed_signers beside
# this script — pin your own copy once you have compared its fingerprint.
set -eu

fail() {
	echo "verify: $*" >&2
	echo "verify: DO NOT RUN anything from this download." >&2
	exit 1
}

signers="$(cd "$(dirname "$0")" && pwd)/allowed_signers"
if [ "${1:-}" = "--signers" ]; then
	signers=$2
	shift 2
fi
dir=${1:?usage: verify.sh [--signers FILE] DIR}

sums="$dir/SHA256SUMS"
[ -f "$sums" ] || fail "no SHA256SUMS in $dir"
[ -f "$sums.sig" ] || fail "no SHA256SUMS.sig in $dir — this release is not signed (yet)"
[ -f "$signers" ] || fail "no release keys at $signers"
grep -v '^[[:space:]]*#' "$signers" | grep -q '[^[:space:]]' || fail "$signers lists no release key yet"
command -v ssh-keygen >/dev/null || fail "ssh-keygen (OpenSSH 8.1 or later) is needed"

# 1. The list is the release manager's: a signature by a listed key, for
#    this principal and namespace (ssh-keygen says which key — compare its
#    fingerprint with the one you were given).
ssh-keygen -Y verify -f "$signers" -I release@gorani -n gorani-release -s "$sums.sig" <"$sums" ||
	fail "SHA256SUMS is not signed by a Gorani release key"

# 2. Each file here is the file the list names.
sha256() {
	if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{ print $1 }'
}
checked=0
while read -r sum name; do
	[ -n "$sum" ] || continue
	name=${name#\*}
	case "$name" in
	"" | */* | .*) fail "SHA256SUMS names a file it should not: '$name'" ;;
	esac
	[ -f "$dir/$name" ] || continue
	[ "$(sha256 "$dir/$name")" = "$sum" ] || fail "$name is not the file the release lists"
	echo "ok  $name"
	checked=$((checked + 1))
done <"$sums"
[ "$checked" -gt 0 ] || fail "none of the files SHA256SUMS lists is in $dir"

# (What is here but unlisted was not checked — said, not assumed.)
for f in "$dir"/*; do
	n=$(basename "$f")
	case "$n" in SHA256SUMS | SHA256SUMS.sig) continue ;; esac
	awk -v n="$n" '{ sub(/^\*/, "", $2) } $2 == n { found = 1 } END { exit !found }' "$sums" ||
		echo "verify: $n is not part of the release — not checked, do not run it" >&2
done
echo "verified: $checked file(s), signed by the release key above"
