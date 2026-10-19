# Copyright 2026- Seongwoo Hong. All rights reserved.
#
# Make a Windows package (commit 39f–h): the release builds, the logos and
# Explorer's icon (Assets/, gorani.ico — the water deer, rendered from
# docs/assets/gorani.svg by tools/icons/render.mjs), the manifest filled
# in — packed by the Windows SDK's own
# makeappx, unsigned. Who signs it is the workflow's business
# (package.yml): Microsoft, for the Store's identity; nobody, for the
# unsigned one (its users check a signed checksum instead).
#
#   package.ps1 -Version 0.1.0.7 -Name Gorani.Client -Publisher "CN=…" -Out gorani.msix

param(
	[Parameter(Mandatory)] [string] $Version,
	[Parameter(Mandatory)] [string] $Name,
	[Parameter(Mandatory)] [string] $Publisher,
	[string] $PublisherDisplayName = 'Gorani',
	[Parameter(Mandatory)] [string] $Out
)
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$layout = Join-Path ([IO.Path]::GetTempPath()) "gorani-msix-$([guid]::NewGuid())"
New-Item -ItemType Directory (Join-Path $layout 'Assets') | Out-Null
try {
	foreach ($exe in 'gorani.exe', 'gorani-cloud.exe', 'gorani-sync.exe') {
		Copy-Item (Join-Path $repo "target\release\$exe") $layout
	}
	Copy-Item (Join-Path $PSScriptRoot 'Assets\*.png') (Join-Path $layout 'Assets')
	# (Beside the programs: shell.rs names it as Explorer's icon for the folder.)
	Copy-Item (Join-Path $PSScriptRoot 'gorani.ico') $layout
	# (The publisher is XML-escaped: a certificate subject may hold & or quotes.)
	$manifest = (Get-Content (Join-Path $PSScriptRoot 'AppxManifest.xml') -Raw).
		Replace('@VERSION@', $Version).
		Replace('@NAME@', [Security.SecurityElement]::Escape($Name)).
		Replace('@PUBLISHER_NAME@', [Security.SecurityElement]::Escape($PublisherDisplayName)).
		Replace('@PUBLISHER@', [Security.SecurityElement]::Escape($Publisher))
	Set-Content -Path (Join-Path $layout 'AppxManifest.xml') -Value $manifest -Encoding utf8
	$makeappx = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" | Sort-Object FullName -Descending | Select-Object -First 1
	if (-not $makeappx) { throw 'makeappx.exe (the Windows SDK) is not installed' }
	& $makeappx.FullName pack /o /d $layout /p $Out
	if ($LASTEXITCODE -ne 0) { throw "makeappx failed ($LASTEXITCODE)" }
} finally {
	Remove-Item -Recurse -Force $layout -ErrorAction SilentlyContinue
}
