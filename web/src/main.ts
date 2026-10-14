// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The entry module: the one script the built app ships. It loads the
//! stylesheet (Tailwind's compiled output), registers the custom elements,
//! and hands over to <gorani-app>. Keep it this small — everything else is a
//! module imported lazily where it is used, so the lock screen paints before
//! the explorer's code is even fetched.
//!
//! The Trusted Types default policy comes FIRST (lib/trusted-types.ts): it
//! must exist before any code reaches a script-URL sink.

import "./lib/trusted-types-install";
import "./styles/global.css";
import "./app-root";
