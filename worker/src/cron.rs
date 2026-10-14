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

/// Ids from the family registry's internal doors (GoraniFamilyDO ›
/// `member-ids`, the active members — the Worker never exposes it).
///
/// This used to read `GET state`, the members' own registry view. When the
/// security review (commit 23) made that view members-only, the cron — which
/// has no member identity — got a 403 body, parsed it as "no members", and
/// the nightly pass quietly did nothing. The lesson is in the shape: a
/// system job reads a system answer, and an answer it cannot parse is an
/// error, not an empty list.
///
/// The same door serves the case ids (`case-ids`, commit 26): a case is a
/// store like a member's own (area.rs), so it gets the same nightly pass.
async fn registry_ids(env: &Env, route: &str) -> Result<Vec<String>> {
	let namespace = env.durable_object("FAMILY")?;
	let stub = namespace.id_from_name("family")?.get_stub()?;
	let req = Request::new_with_init(&format!("https://do.internal/{route}"), &RequestInit { method: Method::Get, ..Default::default() })?;
	let mut resp = stub.fetch_with_request(req).await?;
	if resp.status_code() != 200 {
		return Err(Error::RustError(format!("registry {route}: HTTP {}", resp.status_code())));
	}
	let body: serde_json::Value = resp.json().await?;
	body.get("ids")
		.and_then(|m| m.as_array())
		.map(|ids| ids.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
		.ok_or_else(|| Error::RustError(format!("registry {route}: no ids")))
}

/// Every area the pass visits: each active member's own, then each case.
async fn areas(env: &Env) -> Result<Vec<String>> {
	let mut out = registry_ids(env, "member-ids").await?;
	out.extend(registry_ids(env, "case-ids").await?.into_iter().map(|c| format!("case:{c}")));
	Ok(out)
}

/// The pass itself. No identity exists at 03:17 UTC — the DOs see the system
/// actor `cron`, which is exactly how their audit trail records it.
/// The fan-out. Every member is visited even when one fails (one broken
/// store must not starve the rest of their maintenance) — and then the pass
/// FAILS if any did (commit 25, O10). It used to log a thrown error and
/// ignore every answer: a member whose pass returned 500 every night, or
/// whose deletes never reached S3, looked exactly like a healthy one.
pub async fn run(env: Env) -> Result<()> {
	let mut failures: Vec<String> = Vec::new();
	// The legal holds, from the record (commit 29f): each case store is told
	// its own before its pass, so a hold change whose call to the store was
	// lost is corrected tonight — and a held store purges nothing tonight.
	let held: Vec<String> = registry_ids(&env, "case-holds").await?;
	for member in areas(&env).await? {
		let body = match crate::area::case_of(&member) {
			Some(case) => serde_json::json!({ "hold": held.iter().any(|h| h == case) }),
			None => serde_json::json!({}),
		};
		let namespace = env.durable_object("MEMBER")?;
		let stub = namespace.id_from_name(&crate::area::do_name(&member))?.get_stub()?;
		let headers = Headers::new();
		headers.set("x-gorani-actor", "cron")?;
		headers.set("x-gorani-member", &member)?;
		let req = Request::new_with_init(
			"https://do.internal/cron",
			&RequestInit { method: Method::Post, headers, body: Some(body.to_string().into()), ..Default::default() },
		)?;
		match stub.fetch_with_request(req).await {
			Ok(resp) if resp.status_code() < 300 => {}
			Ok(mut resp) => {
				let status = resp.status_code();
				let body = resp.text().await.unwrap_or_default();
				failures.push(format!("{member}: HTTP {status} {}", body.chars().take(300).collect::<String>()));
			}
			Err(e) => failures.push(format!("{member}: {e}")),
		}
	}
	// Each area's audit trail, and the registry's: today's checkpoint to the
	// bucket, then the 7-year retention (commit 29, docs/CUSTODY.md). After
	// the passes above, so the checkpoint covers what they shipped.
	for area in areas(&env).await?.into_iter().chain(std::iter::once("registry".to_string())) {
		if let Err(e) = crate::audit::checkpoint_area(&env, &area).await {
			failures.push(format!("{area}: audit checkpoint: {e}"));
		}
		if let Err(e) = crate::audit::prune_area(&env, &area).await {
			failures.push(format!("{area}: audit retention: {e}"));
		}
	}
	if failures.is_empty() {
		return Ok(());
	}
	for f in &failures {
		console_error!("gorani cron: {f}");
	}
	Err(Error::RustError(format!("{} member pass(es) failed — {}", failures.len(), failures.join("; "))))
}