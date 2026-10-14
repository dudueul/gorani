// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The nightly maintenance pass (Cloudflare Cron Triggers — wrangler.jsonc ›
//! `triggers` › `crons`). One scheduled event fans out over the family
//! registry and, per member, knocks on the member DO's `cron` door: the DO
//! then runs its own retention housekeeping and prunes its backup manifests.
//!
//! This module holds NO secrets and touches NO storage: the keys live in the
//! DOs (and the client), the objects in the backend — the cron only knows
//! the knock pattern. One member's failure must not starve the rest, so the
//! fan-out collects errors and keeps walking; a failed pass is loud in
//! observability and simply retried by tomorrow's trigger.

use worker::*;

/// The active member ids from the family registry (GoraniFamilyDO ›
/// `member-ids`, an internal route — the Worker never exposes it).
///
/// This used to read `GET state`, the members' own registry view. When the
/// security review (commit 23) made that view members-only, the cron — which
/// has no member identity — got a 403 body, parsed it as "no members", and
/// the nightly pass quietly did nothing. The lesson is in the shape: a
/// system job reads a system answer, and an answer it cannot parse is an
/// error, not an empty list.
async fn member_ids(env: &Env) -> Result<Vec<String>> {
	let namespace = env.durable_object("FAMILY")?;
	let stub = namespace.id_from_name("family")?.get_stub()?;
	let req = Request::new_with_init("https://do.internal/member-ids", &RequestInit { method: Method::Get, ..Default::default() })?;
	let mut resp = stub.fetch_with_request(req).await?;
	if resp.status_code() != 200 {
		return Err(Error::RustError(format!("registry member-ids: HTTP {}", resp.status_code())));
	}
	let body: serde_json::Value = resp.json().await?;
	body.get("ids")
		.and_then(|m| m.as_array())
		.map(|ids| ids.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
		.ok_or_else(|| Error::RustError("registry member-ids: no ids".into()))
}

/// The pass itself. No identity exists at 03:17 UTC — the DOs see the system
/// actor `cron`, which is exactly how their audit trail records it.
pub async fn run(env: Env) -> Result<()> {
	for member in member_ids(&env).await? {
		let namespace = env.durable_object("MEMBER")?;
		let stub = namespace.id_from_name(&format!("member:{member}"))?.get_stub()?;
		let headers = Headers::new();
		headers.set("x-gorani-actor", "cron")?;
		let req = Request::new_with_init(
			"https://do.internal/cron",
			&RequestInit { method: Method::Post, headers, body: Some(serde_json::json!({}).to_string().into()), ..Default::default() },
		)?;
		if let Err(e) = stub.fetch_with_request(req).await {
			console_log!("gorani cron: member {member} failed: {e}");
		}
	}
	Ok(())
}