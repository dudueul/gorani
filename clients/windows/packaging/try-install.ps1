# Copyright 2026- Seongwoo Hong. All rights reserved.
#
# Install a package as a person would, ask both commands, remove it
# (commit 39f–g; package.yml runs it for each package it makes).
#
#   try-install.ps1 -Path gorani.msix -Name Gorani.Client [-AllowUnsigned]

param(
	[Parameter(Mandatory)] [string] $Path,
	[Parameter(Mandatory)] [string] $Name,
	[switch] $AllowUnsigned
)
$ErrorActionPreference = 'Stop'

if ($AllowUnsigned) {
	# (Windows 11 and later; as administrator — it installs programs.)
	Add-AppxPackage -Path $Path -AllowUnsigned
} else {
	Add-AppxPackage -Path $Path
}
$p = Get-AppxPackage -Name $Name
if (-not $p) { throw "$Path did not install" }
Write-Output "installed $($p.PackageFullName)"
try {
	$apps = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
	foreach ($cmd in 'gorani', 'gorani-cloud', 'gorani-sync') {
		# (Each says how to use it: its words are checked. The app, a window
		# program, answers --version on the pipe and opens no window.)
		$said = & (Join-Path $apps "$cmd.exe") $(if ($cmd -eq 'gorani') { '--version' }) 2>&1 | Out-String
		if ($said -notmatch "usage: $cmd") { throw "the installed $cmd did not answer: $said" }
		Write-Output "$cmd answers from the package's alias"
	}
} finally {
	Remove-AppxPackage -Package $p.PackageFullName
}
if (Get-AppxPackage -Name $Name) { throw "$Path did not uninstall" }
$global:LASTEXITCODE = 0
