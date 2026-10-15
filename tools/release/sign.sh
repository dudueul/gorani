#!/bin/sh
# Copyright 2026- Seongwoo Hong. All rights reserved.
#
# Sign and publish a release (commit 39g, docs/INSTALL.md › For the release
# manager) — on YOUR machine, with your key; the key never goes near CI or
# GitHub. package.yml leaves each tag as a draft release holding the files
# and SHA256SUMS; this:
#
#   1. downloads every file of the draft and checks each against SHA256SUMS
#      (and that SHA256SUMS lists nothing that is not there, and nothing is
#      there that it does not list);
#   2. shows you the list and asks;
#   3. signs SHA256SUMS (ssh-keygen -Y sign, namespace gorani-release);
#   4. checks the signature against allowed_signers — the key must be the
#      published one — exactly as verify.sh will for everyone else;
#   5. uploads SHA256SUMS.sig and publishes the release.
#
#   sign.sh TAG [KEY]        KEY: default ~/.ssh/gorani-release
#
# Needs gh (signed in, with write access to the repository) and OpenSSH 8.1+.
set -eu

fail() {
	echo "sign: $*" >&2
	exit 1
}

tag=${1:?usage: sign.sh TAG [KEY]}
key=${2:-$HOME/.ssh/gorani-release}
here=$(cd "$(dirname "$0")" && pwd)
[ -f "$key" ] || fail "no key at $key (make one: see allowed_signers)"
command -v gh >/dev/null || fail "gh is needed (https://cli.github.com)"
[ "$(gh release view "$tag" --json isDraft --jq .isDraft)" = "true" ] || fail "$tag is not a draft release — nothing to sign"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
gh release download "$tag" --dir "$work"
[ -f "$work/SHA256SUMS" ] || fail "the draft holds no SHA256SUMS"
[ ! -f "$work/SHA256SUMS.sig" ] || fail "the draft is already signed"

sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{ print $1 }'; }
listed=0
while read -r sum name; do
	[ -n "$sum" ] || continue
	name=${name#\*}
	[ -f "$work/$name" ] || fail "SHA256SUMS lists $name, which the draft does not hold"
	[ "$(sha "$work/$name")" = "$sum" ] || fail "$name is not the file SHA256SUMS lists"
	listed=$((listed + 1))
done <"$work/SHA256SUMS"
held=$(ls "$work" | grep -vx SHA256SUMS | wc -l | tr -d ' ')
[ "$held" -eq "$listed" ] || fail "the draft holds $held files and SHA256SUMS lists $listed"

echo "Release $tag — $listed files, each as SHA256SUMS lists it:"
cat "$work/SHA256SUMS"
printf 'Sign this list as the Gorani release key? [y/N] '
read -r answer
[ "$answer" = "y" ] || fail "not signed"

ssh-keygen -Y sign -f "$key" -n gorani-release "$work/SHA256SUMS"
"$here/verify.sh" --signers "$here/allowed_signers" "$work" ||
	fail "the signature does not verify against allowed_signers — is $key the published release key?"
gh release upload "$tag" "$work/SHA256SUMS.sig"
gh release edit "$tag" --draft=false
echo "sign: $tag is signed and published"
