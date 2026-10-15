# Copyright 2026- Seongwoo Hong. All rights reserved.
#
# Check a Gorani release before running anything from it (commit 39g,
# docs/INSTALL.md › Checking a download): SHA256SUMS signed by the release
# key, and every downloaded file the one it lists. Windows; needs OpenSSH
# 8.1 or later (Windows 11's own, or Git for Windows').
#
#   verify.ps1 -Dir <folder> [-Signers <allowed_signers>]

param(
	[Parameter(Mandatory)] [string] $Dir,
	[string] $Signers = (Join-Path $PSScriptRoot 'allowed_signers')
)
$ErrorActionPreference = 'Stop'

function Fail([string] $why) {
	[Console]::Error.WriteLine("verify: $why")
	[Console]::Error.WriteLine('verify: DO NOT RUN anything from this download.')
	exit 1
}

$sums = Join-Path $Dir 'SHA256SUMS'
$sig = "$sums.sig"
if (-not (Test-Path $sums)) { Fail "no SHA256SUMS in $Dir" }
if (-not (Test-Path $sig)) { Fail "no SHA256SUMS.sig in $Dir — this release is not signed (yet)" }
if (-not (Test-Path $Signers)) { Fail "no release keys at $Signers" }
if (-not (Get-Content $Signers | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' })) { Fail "$Signers lists no release key yet" }
$keygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
if (-not $keygen) { Fail 'ssh-keygen (OpenSSH 8.1 or later) is needed: Settings › System › Optional features › OpenSSH Client' }

# 1. The list is the release manager's. (The list goes to ssh-keygen as raw
#    bytes — a PowerShell pipe would re-encode it and add a line ending,
#    and the signature would rightly fail.)
$out = Join-Path ([IO.Path]::GetTempPath()) "gorani-verify-$([guid]::NewGuid()).txt"
try {
	$p = Start-Process -FilePath $keygen.Source -ArgumentList @('-Y', 'verify', '-f', "`"$Signers`"", '-I', 'release@gorani', '-n', 'gorani-release', '-s', "`"$sig`"") `
		-RedirectStandardInput $sums -RedirectStandardOutput $out -NoNewWindow -Wait -PassThru
	Get-Content $out | Write-Output
	if ($p.ExitCode -ne 0) { Fail 'SHA256SUMS is not signed by a Gorani release key' }
} finally {
	Remove-Item $out -ErrorAction SilentlyContinue
}

# 2. Each file here is the file the list names.
$listed = @{}
foreach ($line in Get-Content $sums) {
	if ($line -notmatch '^([0-9a-f]{64}) [ *](.+)$') { if ($line -match '\S') { Fail "SHA256SUMS has a line it should not: '$line'" }; continue }
	$name = $Matches[2]
	if ($name -match '[\\/]' -or $name.StartsWith('.')) { Fail "SHA256SUMS names a file it should not: '$name'" }
	$listed[$name] = $Matches[1]
}
$checked = 0
foreach ($name in $listed.Keys) {
	$file = Join-Path $Dir $name
	if (-not (Test-Path -LiteralPath $file)) { continue }
	if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower() -ne $listed[$name]) { Fail "$name is not the file the release lists" }
	Write-Output "ok  $name"
	$checked++
}
if ($checked -eq 0) { Fail "none of the files SHA256SUMS lists is in $Dir" }
foreach ($f in Get-ChildItem -LiteralPath $Dir -File) {
	if ($f.Name -in 'SHA256SUMS', 'SHA256SUMS.sig') { continue }
	if (-not $listed.ContainsKey($f.Name)) { [Console]::Error.WriteLine("verify: $($f.Name) is not part of the release — not checked, do not run it") }
}
Write-Output "verified: $checked file(s), signed by the release key above"
# (A downloaded file carries the internet's mark; once verified, clear it:
#  Get-ChildItem <folder> | Unblock-File)
exit 0
