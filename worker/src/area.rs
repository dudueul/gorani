// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Areas — the stores a request can address (commit 26, docs/CASES.md).
//!
//! A member's own area and a case are the SAME kind of store: the same
//! Durable Object class (`GoraniMemberDO`), the same rows, change feed,
//! GV04 places and backups. What differs is only where they live, so an
//! area is a string with one convention, and these helpers are the only
//! code that knows it:
//!
//! | area | DO instance | object keys | GV04 `store` |
//! |---|---|---|---|
//! | `jinu` (a member id) | `member:jinu` | `files/jinu/…` | `jinu` |
//! | `case:ir-2026-014` | `case:ir-2026-014` | `cases/ir-2026-014/…` | `case:ir-2026-014` |
//!
//! Member ids cannot contain `:` (auth.rs › valid_member_id), so the two
//! namespaces cannot collide — not in DO names, not in object keys, not in
//! the places GV04 binds every sealed value to.

/// The case id inside a case area, or None for a member's own area.
pub(crate) fn case_of(area: &str) -> Option<&str> {
	area.strip_prefix("case:")
}

/// A case id: 2–40 of a–z, 0–9 and dashes (readable on purpose — an
/// incident code like `ir-2026-014`; never put a secret in it).
pub(crate) fn valid_case_id(id: &str) -> bool {
	(2..=40).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A well-formed area: a member id, or `case:` + a case id.
pub(crate) fn valid_area(area: &str) -> bool {
	match case_of(area) {
		Some(c) => valid_case_id(c),
		None => crate::auth::valid_member_id(area),
	}
}

/// The Durable Object instance that stores the area.
pub(crate) fn do_name(area: &str) -> String {
	match case_of(area) {
		Some(_) => area.to_string(),
		None => format!("member:{area}"),
	}
}

/// The object-key prefix of the area's files (no trailing slash).
pub(crate) fn key_prefix(area: &str) -> String {
	match case_of(area) {
		Some(c) => format!("cases/{c}"),
		None => format!("files/{area}"),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_two_namespaces_never_meet() {
		assert_eq!((do_name("jinu"), key_prefix("jinu")), ("member:jinu".into(), "files/jinu".into()));
		assert_eq!((do_name("case:ir-14"), key_prefix("case:ir-14")), ("case:ir-14".into(), "cases/ir-14".into()));
		assert!(valid_area("jinu") && valid_area("case:ir-2026-014"));
		assert!(!valid_area("case:") && !valid_area("case:IR 14") && !valid_area("case:../x") && !valid_area("a:b"));
		// A member id can never look like a case area.
		assert!(!crate::auth::valid_member_id("case:ir-14"));
	}
}
