# Copyright 2026- Seongwoo Hong. All rights reserved.
#
# The release check, checked on Windows (commit 39g; package.yml runs it
# over the files it built) — test-verify.sh's cases, through verify.ps1
# and Windows' own OpenSSH.
#
#   test-verify.ps1 -Files a.zip,b.msix

param([Parameter(Mandatory)] [string[]] $Files)
$ErrorActionPreference = 'Stop'
$work = Join-Path ([IO.Path]::GetTempPath()) "gorani-test-verify-$([guid]::NewGuid())"
$good = Join-Path $work 'good'
$keys = Join-Path $work 'keys'
New-Item -ItemType Directory $good, $keys | Out-Null
try {
	Copy-Item $Files $good
	$lines = Get-ChildItem $good -File | ForEach-Object { "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())  $($_.Name)" }
	[IO.File]::WriteAllText((Join-Path $good 'SHA256SUMS'), (($lines -join "`n") + "`n"))
	foreach ($k in 'release', 'other') { & ssh-keygen -q -t ed25519 -N '' -f (Join-Path $keys $k) -C $k; if ($LASTEXITCODE) { throw 'ssh-keygen failed' } }
	$signers = Join-Path $keys 'signers'
	[IO.File]::WriteAllText($signers, "release@gorani namespaces=`"gorani-release`" $((Get-Content (Join-Path $keys 'release.pub')).Trim())`n")
	function Sign([string] $dir, [string] $key, [string] $ns = 'gorani-release') {
		& ssh-keygen -Y sign -f (Join-Path $keys $key) -n $ns (Join-Path $dir 'SHA256SUMS') 2>$null
		if ($LASTEXITCODE) { throw 'signing failed' }
	}
	function Variant([string] $name) {
		$d = Join-Path $work $name
		Copy-Item $good $d -Recurse
		return $d
	}
	function Expect([string] $want, [string] $what, [string] $dir) {
		& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'verify.ps1') -Dir $dir -Signers $signers *> (Join-Path $work 'out.txt')
		$got = if ($LASTEXITCODE -eq 0) { 'pass' } else { 'refuse' }
		if ($got -ne $want) { Get-Content (Join-Path $work 'out.txt'); throw "test-verify: $what — expected $want, got $got" }
		Write-Output "ok  $what ($want)"
	}
	Sign $good 'release'
	Expect 'pass' 'the release as signed' $good
	$first = (Get-ChildItem $good -File | Where-Object { $_.Name -notlike 'SHA256SUMS*' } | Select-Object -First 1).Name
	$d = Variant 'changed'; Add-Content -LiteralPath (Join-Path $d $first) -Value 'x'
	Expect 'refuse' 'a changed file' $d
	$d = Variant 'foreign'; Remove-Item (Join-Path $d 'SHA256SUMS.sig'); Sign $d 'other'
	Expect 'refuse' 'a list signed by another key' $d
	$d = Variant 'edited'; [IO.File]::AppendAllText((Join-Path $d 'SHA256SUMS'), "$('0' * 64)  $first`n")
	Expect 'refuse' 'an edited list' $d
	$d = Variant 'unsigned'; Remove-Item (Join-Path $d 'SHA256SUMS.sig')
	Expect 'refuse' 'an unsigned list' $d
	$d = Variant 'namespace'; Remove-Item (Join-Path $d 'SHA256SUMS.sig'); Sign $d 'release' 'something-else'
	Expect 'refuse' 'the right key, another purpose' $d
	Write-Output 'test-verify: the release check holds'
	$global:LASTEXITCODE = 0
} finally {
	Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
