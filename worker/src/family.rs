// Copyright 2026- Seongwoo Hong. All rights reserved.

//! `GoraniFamilyDO` — the family registry: one instance per deployment
//! (named `family`). It holds the small, deliberately readable structure the
//! whole product is organised around: who the members are (names, roles,
//! Access emails) and the parents' master **public** half. It never holds a
//! private key: the master's private half exists only sealed to each
//! parent's root, in that parent's GoraniMemberDO settings.
//!
//! The member's *data* lives in a separate `GoraniMemberDO` (named
//! `member:<id>`) — one SQLite database per member, so one member's file
//! store never crowds another's. See member.rs.
//!
//! Bootstrap rule: the first member is created by any authenticated caller
//! (the family deploys behind Cloudflare Access; whoever first signs up
//! creates the first parent). After that, only an active parent may change
//! the registry — the same one-way hierarchy the keys give, enforced here on
//! the readable structure too.
//!
//! The Worker is the only caller: it authenticates (auth.rs), forwards the
//! actor's email, and routes here. The DO re-checks role rules itself, so a
//! routing mistake cannot escalate.

use serde::Deserialize;
use worker::{durable_object, DurableObject, Env, Error, Request, Response, Result, State};

use crate::auth;

/// APPEND-ONLY: a statement's index is its identity in the schema ledger
/// (schema.rs). Never reorder or edit a shipped line; add new ones at the end.
pub const MIGRATIONS: &[&str] = &[
	// Family-level key/values: the master's public half, deployment flags.
	"CREATE TABLE IF NOT EXISTS family (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
	// The registry. Names are readable by design (docs/FAMILY.md); emails are
	// how Access identities map to members.
	"CREATE TABLE IF NOT EXISTS members (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		role TEXT NOT NULL CHECK (role IN ('parent','child')),
		emails TEXT NOT NULL DEFAULT '[]',
		active INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL
	)",
	// Share links are created inside a member's DO; the PUBLIC route only
	// knows the share id, so the registry indexes id → member (no secrets —
	// the share's keys live in the link's fragment).
	"CREATE TABLE IF NOT EXISTS share_index (id TEXT PRIMARY KEY, member_id TEXT NOT NULL)",
	// The registry's own audit lines (actor, action, target; readable — this
	// table holds no secrets).
	"CREATE TABLE IF NOT EXISTS audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		at TEXT NOT NULL,
		actor TEXT NOT NULL,
		action TEXT NOT NULL,
		target TEXT NOT NULL,
		details TEXT
	)",
	// Migration v2 (commit 26, docs/CASES.md › Roles): the team's four roles.
	// SQLite cannot change a CHECK constraint in place, so the table is
	// rebuilt — copy, drop, rename — each statement once, under the ledger
	// (schema.rs). parent → lead, child → analyst. `expires_at`: externals'
	// access ends on its own.
	"CREATE TABLE IF NOT EXISTS members_v2 (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		role TEXT NOT NULL CHECK (role IN ('lead','analyst','auditor','external')),
		emails TEXT NOT NULL DEFAULT '[]',
		active INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL,
		expires_at TEXT
	)",
	"INSERT OR IGNORE INTO members_v2 (id, name, role, emails, active, created_at) SELECT id, name, CASE role WHEN 'parent' THEN 'lead' ELSE 'analyst' END, emails, active, created_at FROM members",
	"DROP TABLE members",
	"ALTER TABLE members_v2 RENAME TO members",
	// Migration v3 (commit 26, docs/CASES.md › Areas and their keys): cases
	// and grants. A case's title is sealed (GV04, place `case.title`) — the
	// id is readable structure, an incident code. The key's PUBLIC halves
	// sit here so the registry can check every grant names the current key;
	// each grant holds one copy of the case key sealed to the grantee's root.
	// `prev_*` hold the key being rotated AWAY from while the reseal walk
	// runs (case_rekey → case_rekey_done): a walk interrupted half-way can
	// resume, because the old key is not gone until the walk says so.
	"CREATE TABLE IF NOT EXISTS cases (
		id TEXT PRIMARY KEY,
		kind TEXT NOT NULL CHECK (kind IN ('evidence','working')),
		title_sealed TEXT,
		key_id TEXT NOT NULL,
		public_key TEXT NOT NULL,
		created_by TEXT NOT NULL,
		created_at TEXT NOT NULL,
		closed_at TEXT,
		rotation_required INTEGER NOT NULL DEFAULT 0,
		prev_key_id TEXT
	)",
	"CREATE TABLE IF NOT EXISTS case_grants (
		case_id TEXT NOT NULL,
		member_id TEXT NOT NULL,
		permission TEXT NOT NULL CHECK (permission IN ('read','write','manage')),
		key_sealed TEXT NOT NULL,
		key_id TEXT NOT NULL,
		granted_by TEXT NOT NULL,
		granted_at TEXT NOT NULL,
		expires_at TEXT,
		prev_key_sealed TEXT,
		PRIMARY KEY (case_id, member_id)
	)",
	// Migration v4 (commit 27, docs/CASES.md › Member identity keys): each
	// member's identity PUBLIC key (self-signed over their root's digest),
	// the certificates leads sign after comparing fingerprints, and the
	// granter's signature on every case-key copy (and on the previous copy
	// while a rotation walks — a resumed walk must not trust an unsigned
	// old key, or the server could launder values sealed to its own).
	"CREATE TABLE IF NOT EXISTS identities (
		member_id TEXT PRIMARY KEY,
		key_id TEXT NOT NULL,
		public_key TEXT NOT NULL,
		root_digest TEXT NOT NULL,
		signature TEXT NOT NULL,
		created_at TEXT NOT NULL
	)",
	"CREATE TABLE IF NOT EXISTS identity_certs (
		member_id TEXT NOT NULL,
		by_member TEXT NOT NULL,
		key_id TEXT NOT NULL,
		root_digest TEXT NOT NULL,
		signature TEXT NOT NULL,
		at TEXT NOT NULL,
		PRIMARY KEY (member_id, by_member)
	)",
	"ALTER TABLE case_grants ADD COLUMN signature TEXT",
	"ALTER TABLE case_grants ADD COLUMN signed_by TEXT",
	"ALTER TABLE case_grants ADD COLUMN prev_signature TEXT",
	"ALTER TABLE case_grants ADD COLUMN prev_signed_by TEXT",
];

/// The four roles (docs/CASES.md), with the family's names accepted as
/// aliases while the migration lasts (removed with the master key, stage 5).
pub(crate) fn normalize_role(role: &str) -> Option<&'static str> {
	match role {
		"lead" | "parent" => Some("lead"),
		"analyst" | "child" => Some("analyst"),
		"auditor" => Some("auditor"),
		"external" => Some("external"),
		_ => None,
	}
}

#[derive(Debug, Deserialize)]
struct MemberRow {
	id: String,
	name: String,
	role: String,
	emails: String,
	active: i64,
	created_at: String,
	expires_at: Option<String>,
}

/// The registry's state, as GET /state returns it.
#[derive(serde::Serialize)]
struct FamilyState {
	members: Vec<serde_json::Value>,
	master: Option<serde_json::Value>,
	audit: Vec<serde_json::Value>,
}

#[durable_object]
pub struct GoraniFamilyDO {
	sql: worker::SqlStorage,
	/// A failed migration, kept instead of panicking (schema.rs).
	schema: std::result::Result<(), String>,
}

impl DurableObject for GoraniFamilyDO {
	fn new(state: State, _env: Env) -> Self {
		let sql = state.storage().sql();
		// The same ledger as the member stores (schema.rs). This list has no
		// ADD COLUMN yet — which is why the registry survived restarts while
		// every member store hung — but the next one would have broken it too.
		let schema = crate::schema::migrate(&sql, MIGRATIONS);
		Self { sql, schema }
	}

	async fn fetch(&self, req: Request) -> Result<Response> {
		if let Err(e) = &self.schema {
			return json_error(500, &format!("registry schema: {e}"));
		}
		// Errors become JSON with their message: an opaque 500 helps nobody,
		// least of all the tests that must tell refusals from faults.
		match self.dispatch(req).await {
			Ok(r) => Ok(r),
			Err(e) => json_error(500, &e.to_string()),
		}
	}

}

impl GoraniFamilyDO {

	async fn dispatch(&self, mut req: Request) -> Result<Response> {
		let path = req.path().trim_start_matches('/').to_string();
		let actor = req.headers().get("x-gorani-actor")?.unwrap_or_default();
		match (req.method().to_string().as_str(), path.as_str()) {
			// The registry lists every member's Access emails and the last 100
			// audit lines. Authentication (Access) only proves *someone* signed
			// in; the registry is for members. Before the first member exists
			// there is nothing to protect and the bootstrap screen needs the
			// (empty) answer, so an empty registry stays readable.
			("GET", "state") => {
				if self.active_count()? > 0 {
					match self.actor_row(&actor)? {
						None => return json_error(403, "not a team member"),
						// An external responder sees the cases they are granted,
						// not the team: the registry lists every member's emails
						// (docs/CASES.md › Roles).
						Some(r) if r.role == "external" => return json_error(403, "external members do not see the team registry"),
						Some(_) => {}
					}
				}
				self.state().await
			}
			("GET", "actor") => {
				let target = req.headers().get("x-gorani-target")?;
				self.actor(&actor, target.as_deref()).await
			}
			// The system's own view (the nightly cron): active member ids only.
			// Internal — routes.rs maps no public path here.
			("GET", "member-ids") => {
				let rows: Vec<IdRow> = self.sql.exec("SELECT id FROM members WHERE active = 1 ORDER BY id", None)?.to_array()?;
				Ok(Response::from_json(&serde_json::json!({ "ids": rows.into_iter().map(|r| r.id).collect::<Vec<_>>() }))?)
			}
			("GET", id) if id.starts_with("member-exists/") => {
				let exists = self.member_row(&id["member-exists/".len()..])?.is_some();
				Ok(Response::from_json(&serde_json::json!({ "exists": exists }))?)
			}
			("POST", "members") => {
				let body = req.json::<NewMember>().await?;
				self.create_member(&actor, body).await
			}
			("PATCH", id) if id.starts_with("members/") => {
				let body = req.json::<PatchMember>().await?;
				self.patch_member(&actor, &id["members/".len()..], body).await
			}
			("POST", id) if id.starts_with("members/") && id.ends_with("/deactivate") => {
				self.deactivate(&actor, &id["members/".len()..id.len() - "/deactivate".len()]).await
			}
			("PUT", "master") => {
				let body = req.json::<serde_json::Value>().await?;
				self.set_master(&actor, body).await
			}
			("POST", "shares-index") => {
				let body = req.json::<ShareIndexPut>().await?;
				self.share_index_put(body).await
			}
			("DELETE", id) if id.starts_with("shares-index/") => {
				let member = req.headers().get("x-gorani-member")?.unwrap_or_default();
				self.share_index_release(&id["shares-index/".len()..], &member).await
			}
			("GET", id) if id.starts_with("share-owner/") => self.share_owner(&id["share-owner/".len()..]).await,
			// ── Cases (commit 26, docs/CASES.md) ──
			("POST", "cases") => {
				let body = req.json::<serde_json::Value>().await?;
				self.case_create(&actor, body).await
			}
			("GET", "cases") => self.case_list(&actor).await,
			("GET", "case-access") => {
				let case = req.headers().get("x-gorani-case")?.unwrap_or_default();
				self.case_access(&actor, &case).await
			}
			("GET", "case-ids") => {
				let rows: Vec<IdRow> = self.sql.exec("SELECT id FROM cases ORDER BY id", None)?.to_array()?;
				Ok(Response::from_json(&serde_json::json!({ "ids": rows.into_iter().map(|r| r.id).collect::<Vec<_>>() }))?)
			}
			("PUT", id) if id.starts_with("case-grants/") => match id["case-grants/".len()..].split_once('/') {
				Some((case, member)) => {
					let body = req.json::<serde_json::Value>().await?;
					self.case_grant(&actor, case, member, body).await
				}
				None => json_error(400, "case-grants/<case>/<member>"),
			},
			("DELETE", id) if id.starts_with("case-grants/") => match id["case-grants/".len()..].split_once('/') {
				Some((case, member)) => self.case_revoke(&actor, case, member).await,
				None => json_error(400, "case-grants/<case>/<member>"),
			},
			("POST", id) if id.starts_with("case-key-done/") => self.case_rekey_done(&actor, &id["case-key-done/".len()..]).await,
			("PUT", id) if id.starts_with("case-key/") => {
				let body = req.json::<serde_json::Value>().await?;
				self.case_rekey(&actor, &id["case-key/".len()..], body).await
			}
			("POST", id) if id.starts_with("case-close/") => self.case_close(&actor, &id["case-close/".len()..]).await,
			// ── Identities (commit 27, docs/CASES.md › Member identity keys) ──
			("GET", "identities") => self.identities(&actor).await,
			("PUT", "identity") => {
				let body = req.json::<serde_json::Value>().await?;
				self.identity_put(&actor, body).await
			}
			("DELETE", id) if id.starts_with("identity/") => self.identity_reset(&actor, &id["identity/".len()..]).await,
			("PUT", id) if id.starts_with("certs/") => {
				let body = req.json::<serde_json::Value>().await?;
				self.cert_put(&actor, &id["certs/".len()..], body).await
			}
			_ => Response::error("Not Found", 404),
		}
	}

	/// Which member (if any) an Access email belongs to, and its role — the
	/// Worker resolves every member-scoped request through this. A child may
	/// act only for themselves; a parent for anyone (routes.rs enforces).
	///
	/// With `x-gorani-target`, the same answer also says whether the member
	/// being *addressed* exists and is active — so the route can refuse a
	/// URL naming a member the registry never had (which would otherwise
	/// conjure an empty `member:<id>` Durable Object on first touch) in the
	/// same round trip, not a second one.
	async fn actor(&self, email: &str, target: Option<&str>) -> Result<Response> {
		let Some(row) = self.actor_row(email)? else { return Ok(Response::from_json(&serde_json::Value::Null)?) };
		let mut out = serde_json::json!({ "id": row.id, "role": row.role });
		if let Some(t) = target {
			out["target"] = match self.member_row(t)? {
				Some(m) => serde_json::json!({ "exists": true, "active": m.active != 0 }),
				None => serde_json::json!({ "exists": false, "active": false }),
			};
		}
		Ok(Response::from_json(&out)?)
	}

	/// The active member row an Access email maps to (emails compare
	/// case-insensitively, as Access issues them).
	fn actor_row(&self, email: &str) -> Result<Option<EmailRoleRow>> {
		if email.is_empty() {
			return Ok(None);
		}
		// An external whose access has expired is nobody: the expiry is
		// enforced here, on every request, not by a cleanup job.
		let rows: Vec<EmailRoleRow> = self
			.sql
			.exec("SELECT id, role, emails FROM members WHERE active = 1 AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now'))", None)?
			.to_array()?;
		Ok(rows.into_iter().find(|r| serde_json::from_str::<Vec<String>>(&r.emails).map(|list| list.iter().any(|e| e.eq_ignore_ascii_case(email))).unwrap_or(false)))
	}

	fn member_row(&self, id: &str) -> Result<Option<ActiveRow>> {
		Ok(self.sql.exec("SELECT active FROM members WHERE id = ?1", Some(vec![id.into()]))?.to_array::<ActiveRow>()?.into_iter().next())
	}

	fn active_count(&self) -> Result<i64> {
		Ok(self.sql.exec("SELECT COUNT(*) AS n FROM members WHERE active = 1", None)?.one::<Count>()?.n)
	}

	/// An email may map to exactly one member. Two rows sharing an email
	/// would make "who is this caller?" depend on row order — a parent's
	/// identity resolving to a child's row, or worse, the reverse. `except`
	/// is the member being edited (its own emails don't conflict with it).
	fn email_taken(&self, emails: &[String], except: Option<&str>) -> Result<Option<String>> {
		let rows: Vec<EmailRoleRow> = self.sql.exec("SELECT id, role, emails FROM members", None)?.to_array()?;
		for r in rows.iter().filter(|r| Some(r.id.as_str()) != except) {
			let list: Vec<String> = serde_json::from_str(&r.emails).unwrap_or_default();
			if let Some(e) = emails.iter().find(|e| list.iter().any(|x| x.eq_ignore_ascii_case(e))) {
				return Ok(Some(e.clone()));
			}
		}
		Ok(None)
	}

	async fn state(&self) -> Result<Response> {
		let members: Vec<MemberRow> = self.sql.exec("SELECT id, name, role, emails, active, created_at, expires_at FROM members ORDER BY created_at, id", None)?.to_array()?;
		let master = self.sql.exec("SELECT v FROM family WHERE k = 'master'", None)?.to_array::<FamilyKv>().ok().and_then(|mut k| k.pop()).map(|k| serde_json::from_str(&k.v).unwrap_or(serde_json::Value::Null));
		let audit: Vec<AuditRow> = self.sql.exec("SELECT id, at, actor, action, target, details FROM audit ORDER BY id DESC LIMIT 100", None)?.to_array()?;
		Ok(Response::from_json(&FamilyState {
			members: members
				.into_iter()
				.map(|m| {
					serde_json::json!({
						"id": m.id, "name": m.name, "role": m.role,
						"emails": serde_json::from_str::<serde_json::Value>(&m.emails).unwrap_or(serde_json::json!([])),
						"active": m.active != 0, "createdAt": m.created_at, "expiresAt": m.expires_at,
					})
				})
				.collect(),
			master,
			audit: audit
				.into_iter()
				.map(|a| serde_json::json!({ "id": a.id, "at": a.at, "actor": a.actor, "action": a.action, "target": a.target, "details": a.details }))
				.collect(),
		})?)
	}

	async fn create_member(&self, actor: &str, body: NewMember) -> Result<Response> {
		if !auth::valid_member_id(&body.id) {
			return json_error(400, "member id: 2–32 chars of a–z, 0–9, dashes");
		}
		let Some(role) = normalize_role(&body.role) else {
			return json_error(400, "role must be lead, analyst, auditor or external");
		};
		// Externals need an expiry (docs/CASES.md: their access ends on its
		// own); nobody else may have one.
		match (role, body.expires_at.as_deref()) {
			("external", None) => return json_error(400, "an external member needs expiresAt"),
			("external", Some(_)) => {}
			(_, Some(_)) => return json_error(400, "only external members expire"),
			_ => {}
		}
		let has_members = self.sql.exec("SELECT COUNT(*) AS n FROM members WHERE active = 1", None)?.one::<Count>()?.n > 0;
		if has_members && !self.is_lead(actor).await? {
			return json_error(403, "only a lead may add members");
		}
		// The bootstrap (O18): the first member needs the Worker's proof that
		// the operator's BOOTSTRAP_TOKEN was presented — and is a lead (a team
		// whose only member cannot manage it has no one to run it).
		if !has_members {
			if body.bootstrap.as_deref() != Some("ok") {
				return json_error(403, body.bootstrap.as_deref().unwrap_or("the first member needs the bootstrap token"));
			}
			if role != "lead" {
				return json_error(400, "the first member must be a lead");
			}
		}
		if let Some(e) = self.email_taken(&body.emails, None)? {
			return json_error(409, &format!("{e} already belongs to another member"));
		}
		let emails = serde_json::to_string(&body.emails).unwrap_or_else(|_| "[]".into());
		if let Err(e) = self.sql.exec(
			"INSERT INTO members (id, name, role, emails, active, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, 1, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?5)",
			Some(vec![body.id.clone().into(), body.name.clone().into(), role.into(), emails.clone().into(), crate::files_store::bind(body.expires_at.clone())]),
		) {
			return json_error(409, if e.to_string().contains("UNIQUE") { "member id already exists" } else { "insert failed" });
		}
		self.audit(actor, "member.create", &body.id, Some(&serde_json::json!({ "role": role, "name": body.name, "expiresAt": body.expires_at }))).await?;
		self.state().await
	}

	async fn patch_member(&self, actor: &str, id: &str, body: PatchMember) -> Result<Response> {
		if !self.is_lead(actor).await? {
			return json_error(403, "only a lead may change members");
		}
		let Some(current) = self.sql.exec("SELECT role FROM members WHERE id = ?1", Some(vec![id.into()]))?.to_array::<RoleRow>()?.into_iter().next() else {
			return json_error(404, "no such member");
		};
		// A role change (commit 26): promotion, demotion, an analyst made
		// auditor. The last active lead cannot be demoted — the team would
		// have nobody left to manage it.
		if let Some(r) = &body.role {
			let Some(role) = normalize_role(r) else { return json_error(400, "role must be lead, analyst, auditor or external") };
			if current.role == "lead" && role != "lead" && self.active_leads()? <= 1 {
				return json_error(409, "cannot demote the last lead");
			}
			if role == "external" && body.expires_at.is_none() {
				return json_error(400, "an external member needs expiresAt");
			}
			self.sql.exec("UPDATE members SET role = ?1 WHERE id = ?2", Some(vec![role.into(), id.into()]))?;
			if role != "external" {
				self.sql.exec("UPDATE members SET expires_at = NULL WHERE id = ?1", Some(vec![id.into()]))?;
			}
		}
		if let Some(exp) = &body.expires_at {
			self.sql.exec("UPDATE members SET expires_at = ?1 WHERE id = ?2 AND role = 'external'", Some(vec![exp.clone().into(), id.into()]))?;
		}
		if let Some(emails) = &body.emails {
			if let Some(e) = self.email_taken(emails, Some(id))? {
				return json_error(409, &format!("{e} already belongs to another member"));
			}
		}
		if let Some(name) = &body.name {
			self.sql.exec("UPDATE members SET name = ?1 WHERE id = ?2", Some(vec![name.clone().into(), id.into()]))?;
		}
		if let Some(emails) = &body.emails {
			self.sql.exec("UPDATE members SET emails = ?1 WHERE id = ?2", Some(vec![serde_json::to_string(emails).unwrap_or_else(|_| "[]".into()).into(), id.into()]))?;
		}
		self.audit(actor, "member.update", id, Some(&serde_json::json!({ "role": body.role, "expiresAt": body.expires_at }))).await?;
		self.state().await
	}

	async fn deactivate(&self, actor: &str, id: &str) -> Result<Response> {
		if !self.is_lead(actor).await? {
			return json_error(403, "only a lead may deactivate members");
		}
		let Some(row) = self.sql.exec("SELECT role FROM members WHERE id = ?1", Some(vec![id.into()]))?.to_array::<RoleRow>()?.into_iter().next() else {
			return json_error(404, "no such member");
		};
		if row.role == "lead" && self.active_leads()? <= 1 {
			return json_error(409, "cannot deactivate the last lead");
		}
		self.sql.exec("UPDATE members SET active = 0 WHERE id = ?1", Some(vec![id.into()]))?;
		// The removed member's root still holds their copy of the family
		// shared-area key — the audit line says so, because the NEXT step
		// (the client-driven family-area rotation, docs/FAMILY.md › Removing
		// a member) is what actually closes their access.
		self.audit(actor, "member.deactivate", id, Some(&serde_json::json!({ "familyKeyRotationRequired": true }))).await?;
		self.state().await
	}

	/// The master's **public** half, stored once and never rewritten (a
	/// master rotation is a new key; rotating is done by re-sealing copies,
	/// and the registry simply learns the new public — see docs/FAMILY.md).
	async fn set_master(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		if self.sql.exec("SELECT v FROM family WHERE k = 'master'", None)?.to_array::<FamilyKv>().map(|v| !v.is_empty()).unwrap_or(false) {
			return json_error(409, "the master key is already set");
		}
		if !self.is_lead(actor).await? {
			// Before any lead exists, the bootstrap creator may set it.
			let has_members = self.sql.exec("SELECT COUNT(*) AS n FROM members WHERE active = 1", None)?.one::<Count>()?.n > 0;
			if has_members {
				return json_error(403, "only a lead may set the master key");
			}
		}
		let v = serde_json::to_string(&body).map_err(|_| Error::RustError("bad master JSON".into()))?;
		self.sql.exec("INSERT INTO family (k, v) VALUES ('master', ?1)", Some(vec![v.into()]))?;
		self.audit(actor, "master.set", "master", None).await?;
		self.state().await
	}

	/// Claim a share id for its owner member — the FIRST step of creating a
	/// share (routes.rs › share_create), before any S3 call. The public
	/// /s/f/:id routes resolve the owner through this index.
	///
	/// Write-once on purpose (security review, commit 23). This used to be
	/// `INSERT OR REPLACE`, and share ids are chosen by the client: any
	/// member who had seen a link (the id is in its URL) could create a
	/// share with the same id, re-point the public link to their own DO,
	/// and — because the copy object is `shares/<id>`, one namespace for the
	/// whole deployment — complete a multipart upload over the original
	/// owner's sealed copy. A 409 here stops both at the door.
	async fn share_index_put(&self, body: ShareIndexPut) -> Result<Response> {
		let inserted = self
			.sql
			.exec(
				"INSERT INTO share_index (id, member_id) VALUES (?1, ?2) ON CONFLICT(id) DO NOTHING",
				Some(vec![body.id.into(), body.member_id.into()]),
			)?
			.rows_written();
		if inserted == 0 {
			return json_error(409, "that share id is taken");
		}
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	/// Undo a claim whose share never came to exist (the S3 init or the
	/// member DO refused). Only the claiming member's row is removed.
	async fn share_index_release(&self, id: &str, member: &str) -> Result<Response> {
		self.sql.exec("DELETE FROM share_index WHERE id = ?1 AND member_id = ?2", Some(vec![id.into(), member.into()]))?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	async fn share_owner(&self, id: &str) -> Result<Response> {
		let rows: Vec<OwnerRow> = self.sql.exec("SELECT member_id FROM share_index WHERE id = ?1", Some(vec![id.into()]))?.to_array()?;
		let member = rows.into_iter().next().map(|r| r.member_id);
		Ok(Response::from_json(&serde_json::json!({ "memberId": member }))?)
	}

	fn active_leads(&self) -> Result<i64> {
		Ok(self.sql.exec("SELECT COUNT(*) AS n FROM members WHERE role = 'lead' AND active = 1", None)?.one::<Count>()?.n)
	}

	async fn is_lead(&self, email: &str) -> Result<bool> {
		if email.is_empty() {
			return Ok(false);
		}
		let rows: Vec<EmailRow> = self
			.sql
			.exec("SELECT emails FROM members WHERE role = 'lead' AND active = 1", None)?
			.to_array()?;
		for r in rows {
			if let Ok(list) = serde_json::from_str::<Vec<String>>(&r.emails) {
				if list.iter().any(|e| e.eq_ignore_ascii_case(email)) {
					return Ok(true);
				}
			}
		}
		Ok(false)
	}

	// ── Cases and grants (commit 26, docs/CASES.md) ─────────────────────
	//
	// The registry decides WHO may hold a case's key; it never holds one.
	// A grant row carries the case key sealed (by the granter's client) to
	// the grantee's root; the registry checks the shape and the policy:
	//
	//   - only a lead creates a case, and becomes its first manager;
	//   - only a MANAGER of the case grants and revokes (holding the key is
	//     what lets them seal it — a lead who is not on the case cannot add
	//     anyone to it: D2's least privilege; D4's quorum is the way in);
	//   - an auditor's grant is read-only; an external's must expire, no
	//     later than the external themselves;
	//   - every grant names the CURRENT key id (a stale copy is refused);
	//   - revoking marks the case `rotation_required` until a manager commits
	//     a new key with a fresh copy for every remaining grantee.

	fn member_by_email(&self, email: &str) -> Result<Option<EmailRoleRow>> {
		self.actor_row(email)
	}

	fn grant_of(&self, case: &str, member: &str) -> Result<Option<GrantRow>> {
		Ok(self
			.sql
			.exec(
				"SELECT permission, key_sealed, key_id, expires_at, prev_key_sealed, signature, signed_by, prev_signature, prev_signed_by FROM case_grants WHERE case_id = ?1 AND member_id = ?2 AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
				Some(vec![case.into(), member.into()]),
			)?
			.to_array::<GrantRow>()?
			.into_iter()
			.next())
	}

	/// Grants that no longer let anyone in — an expired grant, a deactivated
	/// or expired member — but whose holder KEPT the key copy. They count as
	/// a pending rotation exactly like a revoke, and a rotation drops them.
	const STALE_GRANTS: &'static str = "case_id = ?1 AND (
		(expires_at IS NOT NULL AND expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		OR member_id IN (SELECT id FROM members WHERE active = 0 OR (expires_at IS NOT NULL AND expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now'))))";

	fn stale_grants(&self, case: &str) -> Result<i64> {
		Ok(self.sql.exec(&format!("SELECT COUNT(*) AS n FROM case_grants WHERE {}", Self::STALE_GRANTS), Some(vec![case.into()]))?.one::<Count>()?.n)
	}

	fn case_row(&self, case: &str) -> Result<Option<CaseRow>> {
		Ok(self
			.sql
			.exec("SELECT id, kind, title_sealed, key_id, public_key, created_by, created_at, closed_at, rotation_required, prev_key_id FROM cases WHERE id = ?1", Some(vec![case.into()]))?
			.to_array::<CaseRow>()?
			.into_iter()
			.next())
	}

	async fn case_create(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if me.role != "lead" {
			return json_error(403, "only a lead opens a case");
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let Some(id) = get("id").filter(|i| crate::area::valid_case_id(i)) else { return json_error(400, "case id: 2–40 of a–z, 0–9, dashes") };
		let kind = get("kind").unwrap_or_else(|| "working".into());
		if kind != "evidence" && kind != "working" {
			return json_error(400, "kind: evidence or working");
		}
		let (Some(key_id), Some(key_sealed)) = (get("keyId"), get("keySealed")) else { return json_error(400, "keyId and keySealed (the case key, sealed to your root) are required") };
		let Some(public_key) = body.get("publicKey").filter(|p| p.is_object()) else { return json_error(400, "publicKey { ec, kem } required") };
		if !gorani_formats::formats::is_sealed_text(&key_sealed) || get("titleSealed").is_some_and(|t| !gorani_formats::placed::is_placed_text(&t)) {
			return json_error(400, "the key copy must be sealed; the title placed (GV04)");
		}
		let Some(signature) = get("signature").filter(|s| is_signature(s)) else { return json_error(400, "signature required: your identity's signature over the grant (docs/CASES.md › Member identity keys)") };
		if self.case_row(&id)?.is_some() {
			return json_error(409, "a case with this id exists");
		}
		self.sql.exec(
			"INSERT INTO cases (id, kind, title_sealed, key_id, public_key, created_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
			Some(vec![id.clone().into(), kind.clone().into(), crate::files_store::bind(get("titleSealed")), key_id.clone().into(), public_key.to_string().into(), me.id.clone().into()]),
		)?;
		self.sql.exec(
			"INSERT INTO case_grants (case_id, member_id, permission, key_sealed, key_id, granted_by, granted_at, signature, signed_by) VALUES (?1, ?2, 'manage', ?3, ?4, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?5, ?2)",
			Some(vec![id.clone().into(), me.id.clone().into(), key_sealed.into(), key_id.into(), signature.into()]),
		)?;
		self.audit(actor, "case.create", &id, Some(&serde_json::json!({ "kind": kind }))).await?;
		Ok(Response::from_json(&serde_json::json!({ "id": id, "kind": kind }))?)
	}

	/// The caller's cases: every case they are granted (with their key copy),
	/// and — for leads and auditors — every case's structure, without keys.
	async fn case_list(&self, actor: &str) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		let cases: Vec<CaseRow> = self.sql.exec("SELECT id, kind, title_sealed, key_id, public_key, created_by, created_at, closed_at, rotation_required, prev_key_id FROM cases ORDER BY created_at, id", None)?.to_array()?;
		let mut out = Vec::new();
		for c in cases {
			let grant = self.grant_of(&c.id, &me.id)?;
			if grant.is_none() && me.role != "lead" && me.role != "auditor" {
				continue;
			}
			// Who else is on the case — not for externals, who see only their
			// own grant (the registry view is closed to them, stage 2).
			let grantees: Vec<GranteeRow> = if me.role == "external" {
				Vec::new()
			} else {
				// Live grants only: an ended one (expired, deactivated holder)
				// opens nothing and is dropped by the next rotation — listing it
				// would have the manager seal the new key to someone who left.
				self.sql.exec(&format!("SELECT member_id, permission, expires_at FROM case_grants WHERE case_id = ?1 AND rowid NOT IN (SELECT rowid FROM case_grants WHERE {}) ORDER BY member_id", Self::STALE_GRANTS), Some(vec![c.id.clone().into()]))?.to_array()?
			};
			out.push(serde_json::json!({
				"id": c.id, "kind": c.kind, "titleSealed": c.title_sealed, "keyId": c.key_id,
				"publicKey": serde_json::from_str::<serde_json::Value>(&c.public_key).unwrap_or(serde_json::Value::Null),
				"createdBy": c.created_by, "createdAt": c.created_at, "closed": c.closed_at.is_some(), "rotationRequired": c.rotation_required != 0 || self.stale_grants(&c.id)? > 0,
				// A rotation whose reseal walk has not finished: the previous
				// key (id here, each grantee's copy in their grant) still opens
				// what the walk has not reached.
				"rotating": c.prev_key_id.as_ref().map(|k| serde_json::json!({ "prevKeyId": k })),
				// The copy and WHO SIGNED IT: the grantee's client verifies the
				// signature against an identity it trusts before opening.
				"grant": grant.map(|g| serde_json::json!({
					"permission": g.permission, "keySealed": g.key_sealed, "keyId": g.key_id, "expiresAt": g.expires_at,
					"signature": g.signature, "signedBy": g.signed_by,
					"prevKeySealed": g.prev_key_sealed, "prevSignature": g.prev_signature, "prevSignedBy": g.prev_signed_by,
				})),
				"grantees": grantees.into_iter().map(|g| serde_json::json!({ "member": g.member_id, "permission": g.permission, "expiresAt": g.expires_at })).collect::<Vec<_>>(),
			}));
		}
		Ok(Response::from_json(&serde_json::json!({ "cases": out }))?)
	}

	/// The Worker's per-request question (internal): may this email use this
	/// case, and how? `null` when not (no member, no live grant, no case).
	async fn case_access(&self, actor: &str, case: &str) -> Result<Response> {
		let (Some(me), Some(c)) = (self.member_by_email(actor)?, self.case_row(case)?) else { return Ok(Response::from_json(&serde_json::Value::Null)?) };
		match self.grant_of(case, &me.id)? {
			Some(g) => Ok(Response::from_json(&serde_json::json!({ "id": me.id, "role": me.role, "permission": g.permission, "closed": c.closed_at.is_some() }))?),
			// Auditors and leads read every case's AUDIT and read log (not its
			// content — they would need the key); the Worker narrows by route.
			None if me.role == "auditor" || me.role == "lead" => Ok(Response::from_json(&serde_json::json!({ "id": me.id, "role": me.role, "permission": "audit", "closed": c.closed_at.is_some() }))?),
			None => Ok(Response::from_json(&serde_json::Value::Null)?),
		}
	}

	fn require_manager(&self, actor: &str, case: &str) -> std::result::Result<EmailRoleRow, Response> {
		let me = self.member_by_email(actor).ok().flatten().ok_or_else(|| json_error_raw(403, "not a team member"))?;
		match self.grant_of(case, &me.id).ok().flatten() {
			Some(g) if g.permission == "manage" => Ok(me),
			_ => Err(json_error_raw(403, "only a manager of this case may change its grants")),
		}
	}

	async fn case_grant(&self, actor: &str, case: &str, member: &str, body: serde_json::Value) -> Result<Response> {
		let me = match self.require_manager(actor, case) {
			Ok(m) => m,
			Err(r) => return Ok(r),
		};
		let Some(c) = self.case_row(case)? else { return json_error(404, "no such case") };
		if c.closed_at.is_some() {
			return json_error(409, "the case is closed");
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let permission = get("permission").unwrap_or_else(|| "read".into());
		if !["read", "write", "manage"].contains(&permission.as_str()) {
			return json_error(400, "permission: read, write or manage");
		}
		let Some(target) = self.sql.exec("SELECT role, expires_at FROM members WHERE id = ?1 AND active = 1", Some(vec![member.into()]))?.to_array::<RoleExpiryRow>()?.into_iter().next() else {
			return json_error(404, "no such active member");
		};
		// Role caps (docs/CASES.md › Roles).
		if target.role == "auditor" && permission != "read" {
			return json_error(400, "an auditor's grant is read-only");
		}
		if target.role == "external" {
			if permission == "manage" {
				return json_error(400, "an external member cannot manage a case");
			}
			match (get("expiresAt"), target.expires_at.as_deref()) {
				(None, _) => return json_error(400, "an external member's grant needs expiresAt"),
				(Some(g), Some(m)) if g.as_str() > m => return json_error(400, "a grant cannot outlive the external member's own expiry"),
				_ => {}
			}
		} else if get("expiresAt").is_some() {
			return json_error(400, "only an external member's grant expires");
		}
		let (Some(key_sealed), Some(key_id)) = (get("keySealed"), get("keyId")) else { return json_error(400, "keySealed and keyId required") };
		if key_id != c.key_id {
			return json_error(409, "the grant names an old case key — rotate first, or seal the current key");
		}
		if !gorani_formats::formats::is_sealed_text(&key_sealed) {
			return json_error(400, "the key copy must be sealed text");
		}
		// The signer is the granting manager, recorded by the registry (never
		// taken from the body); the signature is checked by the GRANTEE's
		// client — the registry only refuses what cannot be one.
		let Some(signature) = get("signature").filter(|s| is_signature(s)) else { return json_error(400, "signature required: your identity's signature over the grant") };
		self.sql.exec(
			"INSERT INTO case_grants (case_id, member_id, permission, key_sealed, key_id, granted_by, granted_at, expires_at, signature, signed_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?7, ?8, ?6) ON CONFLICT (case_id, member_id) DO UPDATE SET permission = ?3, key_sealed = ?4, key_id = ?5, granted_by = ?6, granted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), expires_at = ?7, signature = ?8, signed_by = ?6",
			Some(vec![case.into(), member.into(), permission.clone().into(), key_sealed.into(), key_id.into(), me.id.into(), crate::files_store::bind(get("expiresAt")), signature.into()]),
		)?;
		self.audit(actor, "case.grant", case, Some(&serde_json::json!({ "member": member, "permission": permission, "expiresAt": get("expiresAt") }))).await?;
		self.case_list(actor).await
	}

	async fn case_revoke(&self, actor: &str, case: &str, member: &str) -> Result<Response> {
		if let Err(r) = self.require_manager(actor, case) {
			return Ok(r);
		}
		// LIVE managers: a deactivated lead's manage grant would leave a case
		// nobody can grant, rotate or close (only the quorum could, stage 5).
		let managers = self
			.sql
			.exec(
				&format!("SELECT COUNT(*) AS n FROM case_grants WHERE case_id = ?1 AND permission = 'manage' AND member_id != ?2 AND rowid NOT IN (SELECT rowid FROM case_grants WHERE {})", Self::STALE_GRANTS),
				Some(vec![case.into(), member.into()]),
			)?
			.one::<Count>()?
			.n;
		if managers == 0 {
			return json_error(409, "cannot remove the case's last manager");
		}
		let gone = self.sql.exec("DELETE FROM case_grants WHERE case_id = ?1 AND member_id = ?2", Some(vec![case.into(), member.into()]))?.rows_written();
		if gone == 0 {
			return json_error(404, "no such grant");
		}
		// The revoked member KEPT their copy of the case key (it was theirs to
		// open): until a manager rotates, they can still open anything sealed
		// to it that they can get hold of. The flag makes that visible.
		self.sql.exec("UPDATE cases SET rotation_required = 1 WHERE id = ?1", Some(vec![case.into()]))?;
		self.audit(actor, "case.revoke", case, Some(&serde_json::json!({ "member": member, "rotationRequired": true }))).await?;
		self.case_list(actor).await
	}

	/// Rotate a case key, step 1 of 2: the new public halves and a fresh copy
	/// for EVERY remaining grantee, in one write. Each grantee's old copy
	/// moves to `prev_key_sealed` — the reseal walk (client-side,
	/// rotation.ts) runs AFTER this commit and needs the old key to open
	/// what it re-seals; a tab that dies mid-walk resumes from the grants.
	/// (The order matters: walking first, as a member store's rotation does,
	/// would leave a crashed walk's values under a key that lived only in
	/// the dead tab.) Step 2 is case_rekey_done.
	async fn case_rekey(&self, actor: &str, case: &str, body: serde_json::Value) -> Result<Response> {
		let me = match self.require_manager(actor, case) {
			Ok(m) => m,
			Err(r) => return Ok(r),
		};
		let Some(c) = self.case_row(case)? else { return json_error(404, "no such case") };
		if c.prev_key_id.is_some() {
			return json_error(409, "a rotation is still walking — finish it (POST …/key/done) before starting another");
		}
		if body.get("keyId").and_then(|k| k.as_str()) == Some(c.key_id.as_str()) {
			return json_error(409, "a rotation needs a NEW key");
		}
		if body.get("titleSealed").and_then(|t| t.as_str()).is_some_and(|t| !gorani_formats::placed::is_placed_text(t)) {
			return json_error(400, "the title must be placed sealed text (GV04)");
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let Some(key_id) = get("keyId") else { return json_error(400, "keyId required") };
		let Some(public_key) = body.get("publicKey").filter(|p| p.is_object()) else { return json_error(400, "publicKey required") };
		// member → (copy, signature)
		let copies: std::collections::BTreeMap<String, (String, String)> = body
			.get("grants")
			.and_then(|g| g.as_array())
			.map(|list| {
				list.iter()
					.filter_map(|g| Some((g.get("member")?.as_str()?.to_string(), (g.get("keySealed")?.as_str()?.to_string(), g.get("signature")?.as_str()?.to_string()))))
					.collect()
			})
			.unwrap_or_default();
		// Grants that ended by themselves (expiry, deactivation) go with the
		// old key: nobody seals the new one to a holder who left.
		let dropped = self.sql.exec(&format!("DELETE FROM case_grants WHERE {}", Self::STALE_GRANTS), Some(vec![case.into()]))?.rows_written();
		if dropped > 0 {
			// Their holders still hold the old key: the rotation is owed even
			// if THIS attempt is refused below.
			self.sql.exec("UPDATE cases SET rotation_required = 1 WHERE id = ?1", Some(vec![case.into()]))?;
		}
		let current: Vec<GranteeRow> = self.sql.exec("SELECT member_id, permission, expires_at FROM case_grants WHERE case_id = ?1", Some(vec![case.into()]))?.to_array()?;
		let want: std::collections::BTreeSet<&str> = current.iter().map(|g| g.member_id.as_str()).collect();
		let have: std::collections::BTreeSet<&str> = copies.keys().map(String::as_str).collect();
		if want != have {
			return json_error(409, "a rotation re-seals the key for exactly the current grantees — no more, no fewer");
		}
		if copies.values().any(|(k, sig)| !gorani_formats::formats::is_sealed_text(k) || !is_signature(sig)) {
			return json_error(400, "every copy must be sealed text, with the rotating manager's signature");
		}
		for (member, (sealed, signature)) in &copies {
			self.sql.exec(
				"UPDATE case_grants SET prev_key_sealed = key_sealed, prev_signature = signature, prev_signed_by = signed_by, key_sealed = ?1, key_id = ?2, signature = ?5, signed_by = ?6 WHERE case_id = ?3 AND member_id = ?4",
				Some(vec![sealed.clone().into(), key_id.clone().into(), case.into(), member.clone().into(), signature.clone().into(), me.id.clone().into()]),
			)?;
		}
		// `rotation_required` stays set until the walk is done: until then the
		// old key still opens part of the store.
		self.sql.exec(
			"UPDATE cases SET prev_key_id = key_id, key_id = ?1, public_key = ?2, title_sealed = COALESCE(?3, title_sealed) WHERE id = ?4",
			Some(vec![key_id.clone().into(), public_key.to_string().into(), crate::files_store::bind(get("titleSealed")), case.into()]),
		)?;
		self.audit(actor, "case.rekey", case, Some(&serde_json::json!({ "keyId": key_id, "grantees": copies.len(), "endedGrantsDropped": dropped }))).await?;
		self.case_list(actor).await
	}

	/// Rotate a case key, step 2 of 2: the walk re-sealed everything, so the
	/// previous copies go and the case is no longer owed a rotation. (The
	/// registry cannot verify the walk — it cannot open anything; the
	/// manager's client proves it first with rotation.ts › opensAnything.)
	async fn case_rekey_done(&self, actor: &str, case: &str) -> Result<Response> {
		if let Err(r) = self.require_manager(actor, case) {
			return Ok(r);
		}
		let Some(c) = self.case_row(case)? else { return json_error(404, "no such case") };
		let Some(prev) = c.prev_key_id else { return json_error(409, "no rotation is walking") };
		self.sql.exec("UPDATE case_grants SET prev_key_sealed = NULL, prev_signature = NULL, prev_signed_by = NULL WHERE case_id = ?1", Some(vec![case.into()]))?;
		self.sql.exec("UPDATE cases SET prev_key_id = NULL, rotation_required = 0 WHERE id = ?1", Some(vec![case.into()]))?;
		self.audit(actor, "case.rekey.done", case, Some(&serde_json::json!({ "keyId": c.key_id, "retired": prev }))).await?;
		self.case_list(actor).await
	}

	async fn case_close(&self, actor: &str, case: &str) -> Result<Response> {
		if let Err(r) = self.require_manager(actor, case) {
			return Ok(r);
		}
		self.sql.exec("UPDATE cases SET closed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1 AND closed_at IS NULL", Some(vec![case.into()]))?;
		self.audit(actor, "case.close", case, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	// ── Identities and certificates (commit 27) ─────────────────────────
	//
	// The registry stores PUBLIC identity keys and the signatures over them;
	// it verifies none of it, and needs to verify none of it: every client
	// checks every signature against the identities IT pinned (identity.ts ›
	// buildTrust). What the registry does enforce is the bookkeeping that
	// keeps a stale signature from looking current:
	//
	//   - a member registers their own identity, once; a new one (a lost
	//     device, a re-enrolment) needs a reset first, by the member or a lead;
	//   - a reset drops every certificate OF that identity and BY it — a
	//     signature from a key that is gone vouches for nothing;
	//   - only leads certify, and a certificate must name the member's
	//     CURRENT identity key and root digest.

	/// Every active member's identity and its certificates — for any member,
	/// externals included (an external must verify who granted them; ids and
	/// keys, no emails).
	async fn identities(&self, actor: &str) -> Result<Response> {
		if self.member_by_email(actor)?.is_none() {
			return json_error(403, "not a team member");
		}
		let rows: Vec<IdentityRow> = self
			.sql
			.exec("SELECT i.member_id, i.key_id, i.public_key, i.root_digest, i.signature FROM identities i JOIN members m ON m.id = i.member_id WHERE m.active = 1 ORDER BY i.member_id", None)?
			.to_array()?;
		let mut out = Vec::new();
		for r in rows {
			let certs: Vec<CertRow> = self.sql.exec("SELECT by_member, key_id, root_digest, signature FROM identity_certs WHERE member_id = ?1 ORDER BY by_member", Some(vec![r.member_id.clone().into()]))?.to_array()?;
			out.push(serde_json::json!({
				"member": r.member_id, "keyId": r.key_id, "rootDigest": r.root_digest, "signature": r.signature,
				"publicKey": serde_json::from_str::<serde_json::Value>(&r.public_key).unwrap_or(serde_json::Value::Null),
				"certs": certs.into_iter().map(|c| serde_json::json!({ "by": c.by_member, "keyId": c.key_id, "rootDigest": c.root_digest, "signature": c.signature })).collect::<Vec<_>>(),
			}));
		}
		Ok(Response::from_json(&serde_json::json!({ "identities": out }))?)
	}

	async fn identity_put(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let (Some(key_id), Some(root_digest), Some(signature)) = (get("keyId").filter(|k| is_hex256(k)), get("rootDigest").filter(|k| is_hex256(k)), get("signature").filter(|s| is_signature(s))) else {
			return json_error(400, "keyId and rootDigest (SHA-256 hex) and the self-signature are required");
		};
		let Some(public_key) = body.get("publicKey").filter(|p| is_p256_jwk(p)) else { return json_error(400, "publicKey: a P-256 JWK { kty, crv, x, y }") };
		let existing: Option<IdRow> = self.sql.exec("SELECT key_id AS id FROM identities WHERE member_id = ?1", Some(vec![me.id.clone().into()]))?.to_array()?.into_iter().next();
		match existing {
			Some(e) if e.id == key_id => return Ok(Response::from_json(&serde_json::json!({ "ok": true, "unchanged": true }))?),
			Some(_) => return json_error(409, "you already have an identity — reset it first (DELETE …/identity), then have it verified again"),
			None => {}
		}
		let pk = serde_json::json!({ "kty": "EC", "crv": "P-256", "x": public_key["x"], "y": public_key["y"] });
		self.sql.exec(
			"INSERT INTO identities (member_id, key_id, public_key, root_digest, signature, created_at) VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
			Some(vec![me.id.clone().into(), key_id.clone().into(), pk.to_string().into(), root_digest.into(), signature.into()]),
		)?;
		self.audit(actor, "identity.register", &me.id, Some(&serde_json::json!({ "keyId": key_id }))).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	async fn identity_reset(&self, actor: &str, member: &str) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if me.id != member && me.role != "lead" {
			return json_error(403, "an identity is reset by its member or a lead");
		}
		let gone = self.sql.exec("DELETE FROM identities WHERE member_id = ?1", Some(vec![member.into()]))?.rows_written();
		if gone == 0 {
			return json_error(404, "no identity to reset");
		}
		let certs = self.sql.exec("DELETE FROM identity_certs WHERE member_id = ?1 OR by_member = ?1", Some(vec![member.into()]))?.rows_written();
		self.audit(actor, "identity.reset", member, Some(&serde_json::json!({ "certsDropped": certs }))).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true, "certsDropped": certs }))?)
	}

	async fn cert_put(&self, actor: &str, member: &str, body: serde_json::Value) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if me.role != "lead" {
			return json_error(403, "only a lead certifies an identity");
		}
		if me.id == member {
			return json_error(400, "a certificate is for someone else (your own identity is self-signed)");
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let (Some(key_id), Some(root_digest), Some(signature)) = (get("keyId"), get("rootDigest"), get("signature").filter(|s| is_signature(s))) else {
			return json_error(400, "keyId, rootDigest and signature required");
		};
		if self.sql.exec("SELECT COUNT(*) AS n FROM identities WHERE member_id = ?1", Some(vec![me.id.clone().into()]))?.one::<Count>()?.n == 0 {
			return json_error(409, "register your own identity first — a certificate is signed with it");
		}
		let current: Option<IdentityRow> = self.sql.exec("SELECT member_id, key_id, public_key, root_digest, signature FROM identities WHERE member_id = ?1", Some(vec![member.into()]))?.to_array()?.into_iter().next();
		match current {
			None => return json_error(404, "that member has no identity yet"),
			Some(c) if c.key_id != key_id || c.root_digest != root_digest => return json_error(409, "the certificate names an identity or root that is not the member's current one — compare fingerprints again"),
			Some(_) => {}
		}
		self.sql.exec(
			"INSERT INTO identity_certs (member_id, by_member, key_id, root_digest, signature, at) VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT (member_id, by_member) DO UPDATE SET key_id = ?3, root_digest = ?4, signature = ?5, at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
			Some(vec![member.into(), me.id.clone().into(), key_id.clone().into(), root_digest.into(), signature.into()]),
		)?;
		self.audit(actor, "identity.certify", member, Some(&serde_json::json!({ "keyId": key_id }))).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	async fn audit(&self, actor: &str, action: &str, target: &str, details: Option<&serde_json::Value>) -> Result<()> {
		self.sql
			.exec(
				"INSERT INTO audit (at, actor, action, target, details) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?1, ?2, ?3, ?4)",
				Some(vec![
					actor.into(),
					action.into(),
					target.into(),
					details.map(|d| d.to_string()).unwrap_or_default().into(),
				]),
			)
			.map(|_| ())
			.map_err(Error::from)
	}
}

// Row/JSON helpers shared by the DOs live in `store_util.rs`; the small
// private ones here stay close to their use.
#[derive(serde::Deserialize)]
struct FamilyKv {
	v: String,
}
#[derive(serde::Deserialize)]
struct AuditRow {
	id: i64,
	at: String,
	actor: String,
	action: String,
	target: String,
	details: Option<String>,
}
#[derive(serde::Deserialize)]
struct Count {
	n: i64,
}
#[derive(serde::Deserialize)]
struct RoleRow {
	role: String,
}
#[derive(serde::Deserialize)]
struct EmailRow {
	emails: String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShareIndexPut {
	id: String,
	member_id: String,
}
#[derive(serde::Deserialize)]
struct OwnerRow {
	member_id: String,
}
#[derive(serde::Deserialize)]
struct GrantRow {
	permission: String,
	key_sealed: String,
	key_id: String,
	expires_at: Option<String>,
	prev_key_sealed: Option<String>,
	signature: Option<String>,
	signed_by: Option<String>,
	prev_signature: Option<String>,
	prev_signed_by: Option<String>,
}
#[derive(serde::Deserialize)]
struct GranteeRow {
	member_id: String,
	permission: String,
	expires_at: Option<String>,
}
#[derive(serde::Deserialize)]
struct RoleExpiryRow {
	role: String,
	expires_at: Option<String>,
}
#[derive(serde::Deserialize)]
#[allow(dead_code)] // the full row: some readers use part of it
struct CaseRow {
	id: String,
	kind: String,
	title_sealed: Option<String>,
	key_id: String,
	public_key: String,
	created_by: String,
	created_at: String,
	closed_at: Option<String>,
	rotation_required: i64,
	prev_key_id: Option<String>,
}
#[derive(serde::Deserialize)]
struct IdRow {
	id: String,
}
#[derive(serde::Deserialize)]
struct IdentityRow {
	member_id: String,
	key_id: String,
	public_key: String,
	root_digest: String,
	signature: String,
}
#[derive(serde::Deserialize)]
struct CertRow {
	by_member: String,
	key_id: String,
	root_digest: String,
	signature: String,
}

/// Can this be an ECDSA P-256 signature (WebCrypto's raw r ‖ s, base64)?
/// A shape check only — clients verify (identity.ts).
fn is_signature(s: &str) -> bool {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.decode(s).map(|b| b.len() == 64).unwrap_or(false)
}

/// A SHA-256 in lowercase hex.
fn is_hex256(s: &str) -> bool {
	s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `{ kty: "EC", crv: "P-256", x, y }` with 32-byte coordinates.
fn is_p256_jwk(v: &serde_json::Value) -> bool {
	use base64::Engine;
	let coord = |k: &str| v.get(k).and_then(|c| c.as_str()).and_then(|c| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(c).ok()).is_some_and(|b| b.len() == 32);
	v.get("kty").and_then(|k| k.as_str()) == Some("EC") && v.get("crv").and_then(|k| k.as_str()) == Some("P-256") && coord("x") && coord("y")
}
#[derive(serde::Deserialize)]
struct ActiveRow {
	active: i64,
}
#[derive(serde::Deserialize)]
struct EmailRoleRow {
	id: String,
	role: String,
	emails: String,
}
#[derive(Debug, Deserialize)]
struct NewMember {
	id: String,
	name: String,
	role: String,
	#[serde(default)]
	emails: Vec<String>,
	/// The Worker's bootstrap verdict ("ok", or why not) — set by routes.rs
	/// on every create, overwriting anything a client sent (O18).
	#[serde(default, rename = "__bootstrap")]
	bootstrap: Option<String>,
	/// External members only: when their access ends (ISO 8601).
	#[serde(default, rename = "expiresAt")]
	expires_at: Option<String>,
}
#[derive(Debug, Deserialize)]
struct PatchMember {
	#[serde(default)]
	name: Option<String>,
	#[serde(default)]
	emails: Option<Vec<String>>,
	#[serde(default)]
	role: Option<String>,
	#[serde(default, rename = "expiresAt")]
	expires_at: Option<String>,
}

/// A JSON error response ({ "error": … } with a status), the shape every
/// gorani route and test relies on.
pub fn json_error(status: u16, message: &str) -> Result<Response> {
	Ok(Response::from_json(&serde_json::json!({ "error": message }))?.with_status(status))
}

/// The same, as a bare Response (for `Result<_, Response>` refusals).
fn json_error_raw(status: u16, message: &str) -> Response {
	json_error(status, message).unwrap_or_else(|_| Response::error(message, status).expect("a plain error response"))
}