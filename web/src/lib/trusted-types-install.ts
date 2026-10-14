// Copyright 2026- Seongwoo Hong. All rights reserved.

// Side-effect module: installs the Trusted Types default policy the moment it
// is evaluated. main.ts imports it FIRST — ES imports are hoisted and run in
// order, so a call written in main.ts's body would run only after every other
// import had already executed (a subtle trap: "first line" is not "first").
import { installDefaultPolicy } from "./trusted-types";

installDefaultPolicy();
