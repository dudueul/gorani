// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Locate cargo for test runners: rustup installs it into ~/.cargo/bin, which
 * is on PATH in an interactive shell but not always in a test harness. Try
 * the PATH first, then the standard rustup location. Returns the command to
 * spawn and the env to use.
 */

import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";

export function cargoCommand() {
	const check = (cmd) => {
		const r = spawnSync(cmd, ["--version"], { encoding: "utf8" });
		return r.status === 0;
	};
	if (check("cargo")) return { cmd: "cargo", env: process.env };
	const rustup = path.join(os.homedir(), ".cargo", "bin", "cargo");
	if (fs.existsSync(rustup) && check(rustup)) return { cmd: rustup, env: process.env };
	throw new Error("cargo not found: install Rust (rustup.rs) to run the Rust tests");
}