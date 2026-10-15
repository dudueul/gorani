#!/bin/sh
# Copyright 2026- Seongwoo Hong. All rights reserved.
#
# A build, published as a GitHub release (commit 39i, docs/INSTALL.md): what
# package.yml's publish job runs over the files the run built — and
# SHA256SUMS.sig beside them, when the run signed them.
#
#   publish.sh [--dry-run] DIR
#
# Which release, from the ref the run built:
#   a tag vX.Y.Z      "Gorani vX.Y.Z", on that tag
#   the branch main   a new release per commit, "Gorani main · <date> · <commit>",
#                     on a tag main-<date>-<commit> made here (the commit's own
#                     date, so a re-run names the same release). Only the newest
#                     KEEP of these stay: older ones are deleted, with their tags.
#                     Releases from v* tags are never deleted.
# Either way the new release is marked Latest, so
# …/releases/latest/download/<file> is always the newest build. A re-run of
# the same commit replaces the files of the release its first run made.
#
# --dry-run (pull requests): reads the release list and prints what it would
# do — the release, its notes, the deletions — and changes nothing.
#
# From the run: GITHUB_REPOSITORY, GITHUB_SERVER_URL, GITHUB_RUN_ID,
# GITHUB_SHA, GITHUB_REF_NAME, GITHUB_REF_TYPE; GH_TOKEN (contents: write,
# unless --dry-run).
set -eu

KEEP=10

dry=""
if [ "${1:-}" = "--dry-run" ]; then
	dry=1
	shift
fi
dir=${1:?usage: publish.sh [--dry-run] DIR}
fail() {
	echo "publish: $*" >&2
	exit 1
}
# Every change goes through here: in a dry run, said instead of done.
change() {
	if [ -n "$dry" ]; then echo "would run: $*"; else "$@"; fi
}

repo=$GITHUB_REPOSITORY
sha=$GITHUB_SHA
short=$(printf %.7s "$sha")
[ -f "$dir/SHA256SUMS" ] || fail "no SHA256SUMS in $dir"

# ── which release ───────────────────────────────────────────────────────
case "$GITHUB_REF_TYPE:$GITHUB_REF_NAME" in
tag:v[0-9]*.[0-9]*.[0-9]*)
	tag=$GITHUB_REF_NAME
	title="Gorani $tag"
	from="the tag \`$tag\`"
	;;
*)
	# main — or, in a dry run (a pull request), what main would make of it.
	[ -n "$dry" ] || [ "$GITHUB_REF_TYPE:$GITHUB_REF_NAME" = "branch:main" ] ||
		fail "releases come from main or a v* tag, not $GITHUB_REF_TYPE $GITHUB_REF_NAME"
	day=$(TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%d "$sha")
	tag="main-$(echo "$day" | tr -d -)-$short"
	title="Gorani main · $day · $short"
	from="\`main\`"
	;;
esac

# ── its notes ───────────────────────────────────────────────────────────
notes=$(mktemp)
trap 'rm -f "$notes" "$notes.files"' EXIT
for f in "$dir"/*; do
	case "$(basename "$f")" in
	gorani-windows-x64-unsigned.msix) echo "| \`gorani-windows-x64-unsigned.msix\` | Windows 11: the Explorer folder and \`gorani-sync\`, installed (\`Add-AppxPackage -AllowUnsigned\`, as administrator) |" ;;
	gorani-windows-x64.zip) echo "| \`gorani-windows-x64.zip\` | Windows 10/11: the two programs, nothing installed |" ;;
	Gorani-macOS-arm64.zip) echo "| \`Gorani-macOS-arm64.zip\` | macOS, Apple silicon: the app and its Finder integration (signed and notarized) |" ;;
	gorani-macos-arm64-cli.tar.gz) echo "| \`gorani-macos-arm64-cli.tar.gz\` | macOS, Apple silicon: \`gorani-sync\` and its keystore helper |" ;;
	gorani-linux-x64.tar.gz) echo "| \`gorani-linux-x64.tar.gz\` | Linux x86-64: \`gorani-sync\` and \`gorani-mount\` (FUSE) |" ;;
	esac
done >"$notes.files"
{
	echo "Built by GitHub Actions ([run]($GITHUB_SERVER_URL/$repo/actions/runs/$GITHUB_RUN_ID)) from $from at [\`$short\`]($GITHUB_SERVER_URL/$repo/commit/$sha). The programs are unsigned — see docs/INSTALL.md."
	echo
	echo "| File | For |"
	echo "|---|---|"
	cat "$notes.files"
	echo
	if [ -f "$dir/SHA256SUMS.sig" ]; then
		echo "**Check before you run anything.** Put the files you want, \`SHA256SUMS\` and \`SHA256SUMS.sig\` in one folder, then run your saved copy of the check:"
		echo
		echo '```sh'
		echo 'sh verify.sh --signers allowed_signers <folder>                    # macOS, Linux'
		echo 'pwsh -File verify.ps1 -Dir <folder> -Signers allowed_signers      # Windows'
		echo '```'
		echo
		echo "The key fingerprint it prints must be the one you were given in person, not one read from this page (docs/INSTALL.md › Checking a download)."
	else
		echo "**Not signed.** No release signing key was set when this was built (the secret \`RELEASE_SIGNING_KEY\`), so there is no \`SHA256SUMS.sig\` and \`verify.sh\` refuses this release. \`SHA256SUMS\` alone shows only that a file arrived intact from this page — not who made it."
	fi
} >"$notes"

if [ -n "$dry" ]; then
	echo "── the release: $tag — $title"
	ls -l "$dir"
	echo "── its notes:"
	cat "$notes"
	echo "──"
fi

# ── the release ─────────────────────────────────────────────────────────
if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
	# A re-run: the same release, its files replaced.
	existed=1
	change gh release upload "$tag" "$dir"/* --repo "$repo" --clobber
	change gh release edit "$tag" --repo "$repo" --title "$title" --notes-file "$notes" --draft=false --latest
else
	existed=""
	case "$tag" in
	main-*) change gh release create "$tag" "$dir"/* --repo "$repo" --target "$sha" --title "$title" --notes-file "$notes" --latest ;;
	*) change gh release create "$tag" "$dir"/* --repo "$repo" --verify-tag --title "$title" --notes-file "$notes" --latest ;;
	esac
fi
[ -n "$dry" ] || echo "published: $GITHUB_SERVER_URL/$repo/releases/tag/$tag"

# ── the main builds kept: the newest KEEP ───────────────────────────────
# (In a dry run the new one is not in the list yet: one fewer of the
# others stays.)
keep=$KEEP
case "$dry:$existed:$tag" in 1::main-*) keep=$((KEEP - 1)) ;; esac
older=$(gh release list --repo "$repo" --limit 1000 --json tagName,createdAt \
	--jq "[.[] | select(.tagName | startswith(\"main-\"))] | sort_by(.createdAt) | reverse | .[$keep:] | .[].tagName")
for old in $older; do
	# Only this script's own tags (main-YYYYMMDD-commit), whatever the list holds.
	case "$old" in
	main-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f])
		change gh release delete "$old" --repo "$repo" --cleanup-tag --yes
		;;
	*) echo "publish: leaving $old (not a tag this script makes)" ;;
	esac
done
[ -n "$older" ] || echo "publish: no older main builds to remove (keeping the newest $KEEP)"
