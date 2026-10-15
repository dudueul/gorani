#!/bin/sh
# Copyright 2026- Seongwoo Hong. All rights reserved.
#
# A new release signing key (commit 39i, docs/INSTALL.md › For the release
# manager). Made on your machine, handed straight to GitHub as the Actions
# secret RELEASE_SIGNING_KEY, and pinned in allowed_signers beside this
# script. The private half is never shown, and never written anywhere but a
# temporary folder that is removed when this ends.
#
#   tools/release/new-key.sh [OWNER/REPO]      default: this checkout's GitHub repository
#
# Needs ssh-keygen (OpenSSH 8.1 or later) and gh (https://cli.github.com),
# signed in as someone who may set the repository's secrets. On Windows, run
# it from Git Bash (Git for Windows brings both bash and ssh-keygen).
#
# Then: commit and push tools/release/allowed_signers, and give each team
# member the fingerprint printed at the end — yourself, in person or over a
# channel you already trust, never through the release page.
#
# A new key REPLACES the old one. Releases signed before then still check
# against the allowed_signers a person saved before then, not the new one.
# Make a new key when the old one may have leaked (anyone who can read the
# secret, or change a workflow on main, could sign with it); there is no
# copy to back up — if it is lost, make another.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
fail() {
	echo "new-key: $*" >&2
	exit 1
}
command -v ssh-keygen >/dev/null || fail "ssh-keygen (OpenSSH 8.1 or later) is needed"
command -v gh >/dev/null || fail "gh is needed (https://cli.github.com) — or set the secret by hand: docs/INSTALL.md"
repo=${1:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}
[ -n "$repo" ] || fail "which repository? tools/release/new-key.sh OWNER/REPO"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
umask 077

# No passphrase: CI has no one to type it. (A hardware key cannot sign in
# CI either — the price of signing every build automatically.)
ssh-keygen -q -t ed25519 -N '' -C "gorani release key (CI), made $(date -u +%Y-%m-%d)" -f "$work/key"
gh secret set RELEASE_SIGNING_KEY --repo "$repo" <"$work/key"

# The pin: this file's comments kept, any older key's line replaced.
line="release@gorani namespaces=\"gorani-release\" $(cat "$work/key.pub")"
{
	grep -E '^[[:space:]]*(#|$)' "$here/allowed_signers" || true
	echo "$line"
} >"$work/allowed_signers"
cat "$work/allowed_signers" >"$here/allowed_signers"

cat <<EOF

The secret RELEASE_SIGNING_KEY is set on $repo, and the key is pinned in
tools/release/allowed_signers. Now:

  1. Commit and push that file:
       git add tools/release/allowed_signers && git commit -m "Release key" && git push
     (Until it is on main, builds with the new secret stop at signing: a
     signature nobody can check is worse than none.)
  2. Give each team member this fingerprint yourself:

       $(ssh-keygen -lf "$work/key.pub")

EOF
