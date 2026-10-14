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
];

#[derive(Debug, Deserialize)]
struct MemberRow {
	id: String,
	name: String,
	role: String,
	emails: String,
	active: i64,
	created_at: String,
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
				if self.active_count()? > 0 && self.actor_row(&actor)?.is_none() {
					return json_error(403, "not a family member");
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
		let rows: Vec<EmailRoleRow> = self.sql.exec("SELECT id, role, emails FROM members WHERE active = 1", None)?.to_array()?;
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
		let members: Vec<MemberRow> = self.sql.exec("SELECT id, name, role, emails, active, created_at FROM members ORDER BY created_at, id", None)?.to_array()?;
		let master = self.sql.exec("SELECT v FROM family WHERE k = 'master'", None)?.to_array::<FamilyKv>().ok().and_then(|mut k| k.pop()).map(|k| serde_json::from_str(&k.v).unwrap_or(serde_json::Value::Null));
		let audit: Vec<AuditRow> = self.sql.exec("SELECT id, at, actor, action, target, details FROM audit ORDER BY id DESC LIMIT 100", None)?.to_array()?;
		Ok(Response::from_json(&FamilyState {
			members: members
				.into_iter()
				.map(|m| {
					serde_json::json!({
						"id": m.id, "name": m.name, "role": m.role,
						"emails": serde_json::from_str::<serde_json::Value>(&m.emails).unwrap_or(serde_json::json!([])),
						"active": m.active != 0, "createdAt": m.created_at,
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
		if !(body.role == "parent" || body.role == "child") {
			return json_error(400, "role must be parent or child");
		}
		let has_members = self.sql.exec("SELECT COUNT(*) AS n FROM members WHERE active = 1", None)?.one::<Count>()?.n > 0;
		if has_members && !self.is_parent(actor).await? {
			return json_error(403, "only a parent may add members");
		}
		if let Some(e) = self.email_taken(&body.emails, None)? {
			return json_error(409, &format!("{e} already belongs to another member"));
		}
		let emails = serde_json::to_string(&body.emails).unwrap_or_else(|_| "[]".into());
		if let Err(e) = self.sql.exec(
			"INSERT INTO members (id, name, role, emails, active, created_at) VALUES (?1, ?2, ?3, ?4, 1, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
			Some(vec![body.id.clone().into(), body.name.clone().into(), body.role.clone().into(), emails.clone().into()]),
		) {
			return json_error(409, if e.to_string().contains("UNIQUE") { "member id already exists" } else { "insert failed" });
		}
		self.audit(actor, "member.create", &body.id, Some(&serde_json::json!({ "role": body.role, "name": body.name }))).await?;
		self.state().await
	}

	async fn patch_member(&self, actor: &str, id: &str, body: PatchMember) -> Result<Response> {
		if !self.is_parent(actor).await? {
			return json_error(403, "only a parent may change members");
		}
		if self.member_row(id)?.is_none() {
			return json_error(404, "no such member");
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
		self.audit(actor, "member.update", id, None).await?;
		self.state().await
	}

	async fn deactivate(&self, actor: &str, id: &str) -> Result<Response> {
		if !self.is_parent(actor).await? {
			return json_error(403, "only a parent may deactivate members");
		}
		let Some(row) = self.sql.exec("SELECT role FROM members WHERE id = ?1", Some(vec![id.into()]))?.to_array::<RoleRow>()?.into_iter().next() else {
			return json_error(404, "no such member");
		};
		if row.role == "parent" {
			let parents = self.sql.exec("SELECT COUNT(*) AS n FROM members WHERE role = 'parent' AND active = 1", None)?.one::<Count>()?.n;
			if parents <= 1 {
				return json_error(409, "cannot deactivate the last parent");
			}
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
		if !self.is_parent(actor).await? {
			// Before any parent exists, the bootstrap creator may set it.
			let has_members = self.sql.exec("SELECT COUNT(*) AS n FROM members WHERE active = 1", None)?.one::<Count>()?.n > 0;
			if has_members {
				return json_error(403, "only a parent may set the master key");
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

	async fn is_parent(&self, email: &str) -> Result<bool> {
		if email.is_empty() {
			return Ok(false);
		}
		let rows: Vec<EmailRow> = self
			.sql
			.exec("SELECT emails FROM members WHERE role = 'parent' AND active = 1", None)?
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
struct IdRow {
	id: String,
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
}
#[derive(Debug, Deserialize)]
struct PatchMember {
	#[serde(default)]
	name: Option<String>,
	#[serde(default)]
	emails: Option<Vec<String>>,
}

/// A JSON error response ({ "error": … } with a status), the shape every
/// gorani route and test relies on.
pub fn json_error(status: u16, message: &str) -> Result<Response> {
	Ok(Response::from_json(&serde_json::json!({ "error": message }))?.with_status(status))
}