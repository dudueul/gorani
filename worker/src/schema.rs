// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Schema migrations with a ledger — run once each, survive every restart.
//!
//! # The bug this module exists for (commit 25)
//!
//! Both Durable Objects used to run their whole `MIGRATIONS` list in the
//! constructor, every time, with `.expect(..)`:
//!
//! ```text
//! for stmt in MIGRATIONS { sql.exec(stmt, None).expect("member migration"); }
//! ```
//!
//! `CREATE TABLE IF NOT EXISTS` is idempotent; `ALTER TABLE … ADD COLUMN` is
//! NOT — the second run fails with "duplicate column name". A Durable Object
//! is constructed again whenever the runtime evicts it (idle for a while, a
//! deploy, a host move), so the SECOND construction of every member's DO
//! panicked — and a panic in a wasm Worker aborts the instance: the request
//! hangs until the runtime cancels it ("your Worker's code had hung"). In
//! production that is every member store, minutes after its first use.
//!
//! No test saw it because every suite starts from a fresh SQLite directory,
//! and one dev server lives for the whole run: each DO was constructed
//! exactly once. `api:restart` (tests/api/restart.test.mjs) now starts a
//! second server on the SAME state — the restart the suites never did.
//!
//! # The rule now
//!
//! - A ledger table records the index of every migration that has run.
//!   A migration's index is its position in the list, so the list is
//!   **append-only**: never reorder, never edit a shipped statement, add a
//!   new one at the end (the classic "migrations are history" rule).
//! - A store created before the ledger existed has no ledger rows but has
//!   already run every statement. On that first ledgered start the one
//!   error forgiven is `ALTER TABLE … ADD COLUMN` meeting a column that is
//!   already there — exactly the statement class that cannot be written
//!   idempotently in SQLite. Every other error stops the migration.
//! - A failed migration does not panic. The DO keeps the error and answers
//!   every request with a 500 naming it: a loud, diagnosable failure beats
//!   a hang, and nothing half-migrated gets written to.

use worker::SqlStorage;

const LEDGER: &str = "CREATE TABLE IF NOT EXISTS schema_ledger (n INTEGER PRIMARY KEY, at TEXT NOT NULL)";

#[derive(serde::Deserialize)]
struct Applied {
	next: i64,
}

/// Run every migration after the last recorded one; record each as it lands.
pub(crate) fn migrate(sql: &SqlStorage, migrations: &[&str]) -> Result<(), String> {
	sql.exec(LEDGER, None).map_err(|e| format!("schema ledger: {e}"))?;
	let next = sql
		.exec("SELECT COALESCE(MAX(n) + 1, 0) AS next FROM schema_ledger", None)
		.and_then(|c| c.one::<Applied>())
		.map_err(|e| format!("schema ledger read: {e}"))?
		.next;
	for (n, stmt) in migrations.iter().enumerate().skip(next.max(0) as usize) {
		if let Err(e) = sql.exec(stmt, None) {
			let msg = e.to_string();
			if !(is_add_column(stmt) && msg.contains("duplicate column name")) {
				return Err(format!("migration {n} failed: {msg}"));
			}
			// A pre-ledger store already has this column (see the module docs).
		}
		sql.exec("INSERT INTO schema_ledger (n, at) VALUES (?1, strftime('%Y-%m-%dT%H:%M:%fZ','now'))", Some(vec![(n as i64).into()]))
			.map_err(|e| format!("schema ledger write: {e}"))?;
	}
	Ok(())
}

fn is_add_column(stmt: &str) -> bool {
	let s = stmt.trim_start().to_ascii_uppercase();
	s.starts_with("ALTER TABLE") && s.contains(" ADD COLUMN ")
}

#[cfg(test)]
mod tests {
	use super::is_add_column;

	#[test]
	fn only_add_column_is_forgivable() {
		assert!(is_add_column("ALTER TABLE files ADD COLUMN owner TEXT"));
		assert!(is_add_column("  alter table shares add column ready INTEGER DEFAULT 0"));
		assert!(!is_add_column("ALTER TABLE files RENAME TO old_files"));
		assert!(!is_add_column("CREATE TABLE IF NOT EXISTS x (a)"));
		assert!(!is_add_column("DROP TABLE files"));
	}
}
