// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The Windows shell (commit 39b, docs/DESKTOP.md › 39b): a Cloud Files
//! sync root over the client core's replica (clients/core/src/replica.rs),
//! registered with Explorer as a provider's folder where it can be (39e,
//! shell.rs).
//! `names` is platform-neutral (tested everywhere); the rest is Windows'.

pub mod names;

#[cfg(windows)]
pub mod cf;
#[cfg(windows)]
pub mod provider;
#[cfg(windows)]
pub mod shell;
#[cfg(windows)]
mod watch;
