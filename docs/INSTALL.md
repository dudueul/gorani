# Installing Gorani on a computer

> Copyright 2026- Seongwoo Hong. All rights reserved.
> For team members installing the desktop clients, and for the release
> manager who publishes them (commits 39g, 39i; how they are built:
> [DESKTOP.md](DESKTOP.md) › 39f–g, 39i).

The browser needs nothing installed. The desktop clients — Gorani as a
folder in Explorer or Finder, the `gorani-sync` command, and on Linux
`gorani-mount` — come one of these ways:

| System | The way | What you get | What vouches for it |
|---|---|---|---|
| Windows 10/11 | **the Microsoft Store**, a private listing (ask the release manager to add your Microsoft account) | the Explorer folder and `gorani-sync`, updated by the Store | Microsoft's signature on the package |
| Windows 11 | `gorani-windows-x64-unsigned.msix` | the same, without the Store; updated by installing the next one | **you**: the signed checksum, below |
| Windows 10/11 | `gorani-windows-x64.zip` | the two programs, nothing installed; run them from where you unpack them | **you**: the signed checksum, below |
| macOS (Apple silicon) | `Gorani-macOS-arm64.zip`, when the release has it | the app and its Finder integration, signed and notarized | Apple's notarization, and the signed checksum |
| macOS (Apple silicon) | `gorani-macos-arm64-cli.tar.gz` | `gorani-sync` and its keystore helper | **you**: the signed checksum, below |
| Linux (x86-64) | `gorani-linux-x64.tar.gz` | `gorani-sync`, and `gorani-mount` (the folder, through FUSE) | **you**: the signed checksum, below |

Everything but the Store's comes from the repository's **Releases** page.
The release marked **Latest** is always the newest build — of `main`, or a
version tag (`v1.2.3`), whichever came last; older builds of `main` are
kept (the newest 10), version releases for good. The newest of any file
also has a fixed address, for a bookmark or a script:

```
https://github.com/dudueul/gorani/releases/latest/download/gorani-windows-x64.zip
https://github.com/dudueul/gorani/releases/latest/download/SHA256SUMS
https://github.com/dudueul/gorani/releases/latest/download/SHA256SUMS.sig
```

(The repository is private: these open for people with access to it,
signed in. Others get the files from you — the signed checksum still
holds, whoever carries them.)

Whichever way, the computer is then enrolled once against the team's
server, **https://gorani.at.day** (the default — `--server` only for
another deployment), signing in through Cloudflare Access with
[`cloudflared`](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/):

```sh
cloudflared access login https://gorani.at.day
gorani-sync whoami --access-token-cmd "cloudflared access token -app=https://gorani.at.day"
gorani-sync setup --name "my laptop" \
  --access-token-cmd "cloudflared access token -app=https://gorani.at.day"
```

`whoami` says which account the sign-in belongs to, and `setup` enrols
that account; `--member` names another only where a lead set one up for
you to use. `gorani-sync signout` undoes it: the server deletes this
computer's copy, and its keys here are forgotten. (On Windows and macOS
the Gorani app's Settings window does the same: DESKTOP.md › 40.)

(DESKTOP.md › 33a, 34, 39d.) The browser needs only the address:
https://gorani.at.day.

## Checking a download

Everything outside the Store is unsigned, on purpose: what it carries
instead is a list of every file's SHA-256 (`SHA256SUMS`), signed by the
release key (`SHA256SUMS.sig`). Check before you run anything:

1. **Once: get the release key, and compare its fingerprint with the one
   the release manager gives you in person** (or over a channel you
   already trust — not the page you download from). Save
   `tools/release/allowed_signers`, `verify.sh` and `verify.ps1` from the
   repository somewhere of your own; that saved copy is your pin.
2. **Each release: download the files you want, `SHA256SUMS` and
   `SHA256SUMS.sig` into one folder**, then:

   ```sh
   # macOS / Linux
   sh verify.sh --signers allowed_signers ~/Downloads/gorani-v1.2.3
   ```

   ```powershell
   # Windows (OpenSSH 8.1 or later: Windows 11's own, or Git for Windows')
   pwsh -File verify.ps1 -Dir $HOME\Downloads\gorani-v1.2.3 -Signers .\allowed_signers
   ```

   It says which key signed — **that fingerprint must be the one you were
   given** — then `ok` for each file. Anything else ends with
   `DO NOT RUN anything from this download`, and you don't. A release
   whose notes say **Not signed** has no `SHA256SUMS.sig`, and the check
   refuses it: wait for the next one, or ask the release manager.

What this does and does not prove: that the files are the ones this
repository's own build (GitHub Actions, from `main` or a version tag)
made and signed, wherever they were copied afterwards. It does not prove
a person looked at them first, and it does not hold against someone able
to change the repository's workflows on `main` or read its secrets — the
key lives there (DESKTOP.md › 39i). If the release manager says the key
changed, compare the new fingerprint the same way and save the new
`allowed_signers`.

## Then, per system

**Windows, the unsigned MSIX** (Windows 11; an administrator, because it
installs programs for every user):

```powershell
Get-ChildItem $HOME\Downloads\gorani-v1.2.3 | Unblock-File      # once verified
Add-AppxPackage -Path $HOME\Downloads\gorani-v1.2.3\gorani-windows-x64-unsigned.msix -AllowUnsigned
gorani-sync setup …        # then: gorani-cloud <folder>
```

**Windows, the ZIP**: verify, `Unblock-File`, unpack, run `gorani-sync.exe`
and `gorani-cloud.exe` from that folder (without `Unblock-File`, SmartScreen
asks about an "unknown publisher" — after verifying, that is expected).

**macOS, the CLI**: verify, then

```sh
mkdir -p ~/gorani && tar -C ~/gorani -xzf gorani-macos-arm64-cli.tar.gz
xattr -dr com.apple.quarantine ~/gorani      # once verified: the download mark
~/gorani/gorani-sync setup …
```

Keep `gorani-keystore` beside `gorani-sync`: the Secure Enclave and the
login Keychain are reached through it (DESKTOP.md › 39d). An unsigned
helper makes the Keychain ask for permission again whenever it is replaced
by a new version — expected; a signed app does not.

**Linux**: verify, then

```sh
mkdir -p ~/gorani && tar -C ~/gorani -xzf gorani-linux-x64.tar.gz
~/gorani/gorani-sync setup …
~/gorani/gorani-mount ~/Gorani               # the folder, through FUSE (fusermount3)
```

Built on a current Ubuntu: an older distribution's C library may be too
old for it.

## For the release manager

**Once — the release key.** On your own machine, in a checkout of the
repository (macOS or Linux; on Windows, Git Bash), with
[`gh`](https://cli.github.com) signed in:

```sh
tools/release/new-key.sh
```

It makes the key, sets it as the repository's Actions secret
`RELEASE_SIGNING_KEY` (the private half is never shown or kept — there is
nothing to back up; a lost key is replaced by a new one), writes the
public half into `tools/release/allowed_signers`, and prints the key's
fingerprint. Then:

1. commit and push `tools/release/allowed_signers` (until it is on main,
   builds stop at signing — CI refuses a key the repository does not pin);
2. give each team member the fingerprint yourself.

Without `gh`: `ssh-keygen -t ed25519 -C "gorani release key (CI)" -f gorani-release`,
pressing Enter twice at the passphrase (CI has no one to type one); then
in the repository's *Settings › Secrets and variables › Actions*, a
new repository secret `RELEASE_SIGNING_KEY` holding the whole of the
file `gorani-release` (the private one); add
`release@gorani namespaces="gorani-release" <the contents of gorani-release.pub>`
as the last line of `tools/release/allowed_signers`, in place of any older
key's line; `ssh-keygen -lf gorani-release.pub` gives the fingerprint;
then delete both files.

Run it again to change the key — at once if it may have leaked. On a plan
with environments for private repositories, also limit the secret to
`main` and `v*` tags (DESKTOP.md › 39i).

**Once — the Store listing.** In Partner Center (an individual account is
free; it asks for an ID and a selfie): reserve the name "Gorani"; under
*Product identity* copy *Package/Identity/Name*, *Publisher* and
*PublisherDisplayName* into the repository's Actions **variables**
`STORE_IDENTITY_NAME`, `STORE_PUBLISHER`, `STORE_PUBLISHER_NAME`. Under
*Pricing and availability*, choose **Private audience** and a known-user
group holding your team's personal Microsoft accounts (a private listing
can be made public later; a public one never private again). The package
asks for full trust (`runFullTrust`): give the justification *"A Win32
Cloud Files sync provider and its command-line client; full trust is
required to register and serve a sync root."*

**Releases.**

- **Every build of main** is published by itself: a push that changes the
  programs (anything under `clients/`, `crates/`, `Cargo.toml` /
  `Cargo.lock`, `tools/release/`, or the package workflow) builds, checks,
  signs and publishes a release "Gorani main · date · commit", marked
  Latest. Older main builds beyond the newest 10 are removed.
- **A version**: `git tag v1.2.3 && git push origin v1.2.3`. The same,
  as "Gorani v1.2.3" — kept for good.
- **The Store**: from that run, download the workflow artifact
  `windows-store-upload` (`gorani-store.msix`, unsigned — Microsoft signs
  it) and upload it as a new submission. Certification takes hours to
  days, so a security fix reaches the unsigned builds' users first.

A run can also be started by hand (*Actions › package › Run workflow*) on
main or a tag; on any other branch it builds and checks, but publishes
nothing.
