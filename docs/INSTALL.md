# Installing Gorani on a computer

> Copyright 2026- Seongwoo Hong. All rights reserved.
> For team members installing the desktop clients, and for the release
> manager who publishes them (commit 39g; how they are built:
> [DESKTOP.md](DESKTOP.md) › 39f–g).

The browser needs nothing installed. The desktop clients — Gorani as a
folder in Explorer or Finder, and the `gorani-sync` command — come one of
these ways:

| System | The way | What you get | What vouches for it |
|---|---|---|---|
| Windows 10/11 | **the Microsoft Store**, a private listing (ask the release manager to add your Microsoft account) | the Explorer folder and `gorani-sync`, updated by the Store | Microsoft's signature on the package |
| Windows 11 | `gorani-windows-x64-unsigned.msix` | the same, without the Store; updated by installing the next one | **you**: the signed checksum, below |
| Windows 10/11 | `gorani-windows-x64.zip` | the two programs, nothing installed; run them from where you unpack them | **you**: the signed checksum, below |
| macOS (Apple silicon) | `Gorani-macOS-arm64.zip`, when the release has it | the app and its Finder integration, signed and notarized | Apple's notarization, and the signed checksum |
| macOS (Apple silicon) | `gorani-macos-arm64-cli.tar.gz` | `gorani-sync` and its keystore helper | **you**: the signed checksum, below |

Whichever way, the computer is then enrolled once: `gorani-sync setup`
(DESKTOP.md › 33a, 34, 39d).

## Checking a download

Everything outside the Store is unsigned, on purpose: what it carries
instead is a list of every file's SHA-256 (`SHA256SUMS`), signed by the
release manager's own key (`SHA256SUMS.sig`) — a key that never touches
GitHub or the build machines. Check before you run anything:

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
   `DO NOT RUN anything from this download`, and you don't.

What this does and does not prove: that the files are the ones the
release manager approved, whoever handed them to you and whatever
happened to GitHub after. It does not prove the build machine was honest —
the release manager signs what CI built (tools/release/sign.sh checks
every file against the list before asking).

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

## For the release manager

**Once — the release key.** On your own machine, a hardware key if you have
one:

```sh
ssh-keygen -t ed25519-sk -f ~/.ssh/gorani-release -C "gorani release key"
```

Add a line to `tools/release/allowed_signers` —
`release@gorani namespaces="gorani-release" <the contents of ~/.ssh/gorani-release.pub>` —
commit it, and give each team member its fingerprint
(`ssh-keygen -lf ~/.ssh/gorani-release.pub`) yourself.

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

**Each release.**

1. Tag it: `git tag v1.2.3 && git push origin v1.2.3`. The package workflow
   builds everything, checks it, and leaves a **draft** release with the
   files and `SHA256SUMS`.
2. Sign it: `tools/release/sign.sh v1.2.3`. It downloads the draft, checks
   each file against the list, shows you the list, asks, signs, checks the
   signature against `allowed_signers`, uploads `SHA256SUMS.sig` and
   publishes the release.
3. The Store: download the workflow's `windows-store-upload` artifact
   (`gorani-store.msix`, unsigned — Microsoft signs it) and upload it as a
   new submission. Certification takes hours to days, so a security fix
   reaches unsigned-build users first.

The repository is private: a release's files reach people with read
access to it. Others get the files from you — the signed checksum still
holds, whoever carries them.
