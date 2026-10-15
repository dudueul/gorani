#!/bin/sh
# Copyright 2026- Seongwoo Hong. All rights reserved.
#
# The release check, checked (commit 39g; package.yml runs it on macOS and
# Linux over the files it built): with a throwaway key standing in for the
# release key, verify.sh must pass a signed list of these files — and
# refuse a changed file, a list signed by another key, an edited list and
# an unsigned one. The same commands a person runs.
#
#   test-verify.sh FILE...
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
sha() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

mkdir "$work/good" "$work/keys"
cp "$@" "$work/good/"
(cd "$work/good" && sha * >SHA256SUMS)
ssh-keygen -q -t ed25519 -N '' -f "$work/keys/release" -C "throwaway release key"
ssh-keygen -q -t ed25519 -N '' -f "$work/keys/other" -C "someone else"
printf 'release@gorani namespaces="gorani-release" %s\n' "$(cat "$work/keys/release.pub")" >"$work/keys/signers"
ssh-keygen -Y sign -f "$work/keys/release" -n gorani-release "$work/good/SHA256SUMS" 2>/dev/null

expect() { # expect pass|refuse NAME DIR
	if "$here/verify.sh" --signers "$work/keys/signers" "$3" >"$work/out" 2>&1; then got=pass; else got=refuse; fi
	if [ "$got" != "$1" ]; then
		cat "$work/out"
		echo "test-verify: $2 — expected $1, got $got" >&2
		exit 1
	fi
	echo "ok  $2 ($1)"
}
variant() { rm -rf "$work/$1" && cp -R "$work/good" "$work/$1" && echo "$work/$1"; }

expect pass "the release as signed" "$work/good"
d=$(variant changed) && first=$(ls "$d" | grep -v '^SHA256SUMS' | head -1) && printf x >>"$d/$first"
expect refuse "a changed file" "$d"
d=$(variant foreign) && rm "$d/SHA256SUMS.sig" && ssh-keygen -Y sign -f "$work/keys/other" -n gorani-release "$d/SHA256SUMS" 2>/dev/null
expect refuse "a list signed by another key" "$d"
d=$(variant edited) && printf '%064d  %s\n' 0 "$first" >>"$d/SHA256SUMS"
expect refuse "an edited list" "$d"
d=$(variant unsigned) && rm "$d/SHA256SUMS.sig"
expect refuse "an unsigned list" "$d"
d=$(variant namespace) && rm "$d/SHA256SUMS.sig" && ssh-keygen -Y sign -f "$work/keys/release" -n something-else "$d/SHA256SUMS" 2>/dev/null
expect refuse "the right key, another purpose" "$d"
echo "test-verify: the release check holds"
