# Copyright 2026- Seongwoo Hong. All rights reserved.
#
# Make the Windows package (commit 39f): the release builds, the logos
# (logos.py), the manifest filled in — packed by the Windows SDK's own
# makeappx. Signing is the workflow's (package.yml), with whichever
# certificate it has.
#
#   package.ps1 -Version 0.1.0.7 -Publisher "CN=…" -Out gorani.msix

param(
	[Parameter(Mandatory)] [string] $Version,
	[Parameter(Mandatory)] [string] $Publisher,
	[Parameter(Mandatory)] [string] $Out
)
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$layout = Join-Path ([IO.Path]::GetTempPath()) "gorani-msix-$([guid]::NewGuid())"
New-Item -ItemType Directory (Join-Path $layout 'Assets') | Out-Null
try {
	foreach ($exe in 'gorani-cloud.exe', 'gorani-sync.exe') {
		Copy-Item (Join-Path $repo "target\release\$exe") $layout
	}
	python -I (Join-Path $PSScriptRoot 'logos.py') (Join-Path $layout 'Assets')
	if ($LASTEXITCODE -ne 0) { throw 'the logos were not drawn' }
	# (The publisher is XML-escaped: a certificate subject may hold & or quotes.)
	$manifest = (Get-Content (Join-Path $PSScriptRoot 'AppxManifest.xml') -Raw).
		Replace('@VERSION@', $Version).
		Replace('@PUBLISHER@', [Security.SecurityElement]::Escape($Publisher))
	Set-Content -Path (Join-Path $layout 'AppxManifest.xml') -Value $manifest -Encoding utf8
	$makeappx = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" | Sort-Object FullName -Descending | Select-Object -First 1
	if (-not $makeappx) { throw 'makeappx.exe (the Windows SDK) is not installed' }
	& $makeappx.FullName pack /o /d $layout /p $Out
	if ($LASTEXITCODE -ne 0) { throw "makeappx failed ($LASTEXITCODE)" }
} finally {
	Remove-Item -Recurse -Force $layout -ErrorAction SilentlyContinue
}
