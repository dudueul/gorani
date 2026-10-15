// Copyright 2026- Seongwoo Hong. All rights reserved.

//! `gorani-sync`: the command line. Platform shells replace the UI; the
//! commands stay (scriptability, tests, power users).
//!
//! ```text
//! setup                                   enrol this computer (the device's wrapped root copy)
//! cases                                   the cases you are granted: kind, permission, title, state
//! ls    [--case C]                        the change feed of your area, or of case C
//! pull  --id F [--case C] [--out O]       a file, decrypted to disk — and, where its uploader
//!       [--accept-unverified]             signed it, checked against what they signed
//! push  --file P [--case C] [--name N]    a file, sealed and uploaded; into an evidence case
//!       [--source S --collector W         with your signed content hash and the intake record
//!        --method M --collected-at T      (where it came from, who collected it, how, when)
//!        --notes X]
//! ```

use std::path::{Path, PathBuf};

use gorani_client_core::area::{self, open_area, open_team, Area};
use gorani_client_core::cases::{self, CaseRow, HashCheck, IntakeFields};
use gorani_client_core::{api, devicekey, session, transfer, DeviceProfile, Error, Session};
use gorani_formats::formats::VaultPrivateKey;
use gorani_formats::placed::{self, Place};

fn main() {
	let args: Vec<String> = std::env::args().skip(1).collect();
	if let Err(e) = run(&args) {
		eprintln!("error: {e}");
		std::process::exit(1);
	}
}

/// Files up to this size go up whole (one request), larger ones as GC01 frames — as the browser does.
const WHOLE_LIMIT: u64 = 48 * 1024 * 1024;

/// Flags that take no value.
const SWITCHES: &[&str] = &["accept-unverified", "tpm-pin"];

fn profile_path() -> PathBuf {
	let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
	PathBuf::from(home).join(".gorani-sync.json")
}

fn read_line(prompt: &str) -> String {
	use std::io::Write;
	print!("{prompt}");
	std::io::stdout().flush().ok();
	let mut s = String::new();
	std::io::stdin().read_line(&mut s).ok();
	s.trim().to_string()
}

fn read_secret(prompt: &str) -> String {
	// Nohup-proof: the terminal echo is disabled where the platform allows.
	let pw = rpassword::read_password().ok();
	match pw {
		Some(p) => p.trim().to_string(),
		None => read_line(prompt),
	}
}

fn run(args: &[String]) -> Result<(), Error> {
	// Flags: --server --member --name --secret --device-secret --dev-email
	//        --access-token-cmd ("cloudflared access token -app=https://<host>":
	//          the member signs in through Access — commit 33a)
	//        --access-id --access-secret (an Access service token; not enough
	//          alone — its JWT has no email, docs/DESKTOP.md)
	//        --file --id --out --profile --case --device
	//        --source --collector --method --collected-at --notes (intake, 33c)
	//        --accept-unverified (a switch)
	//        --protect auto|tpm|keyring|tpm+keyring|file (where the device secret lives — commit 34)
	//        --tpm-pin (a switch) --tpm-pcrs 7 (the TPM part's PIN and boot state — commit 36)
	let mut flags: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
	let mut pos: Vec<String> = Vec::new();
	let mut i = 0;
	while i < args.len() {
		let a = &args[i];
		if let Some(name) = a.strip_prefix("--") {
			if SWITCHES.contains(&name) {
				flags.insert(name.to_string(), "1".into());
				i += 1;
				continue;
			}
			if let Some(v) = args.get(i + 1) {
				flags.insert(name.to_string(), v.clone());
				i += 2;
				continue;
			}
		}
		pos.push(a.clone());
		i += 1;
	}
	let flag = |k: &str| flags.get(k).cloned();
	let req_flag = |k: &str| -> Result<String, Error> { flag(k).ok_or_else(|| Error::Config(format!("--{k} is required"))) };

	match pos.first().map(String::as_str) {
		Some("setup") => {
			let mut profile = DeviceProfile {
				server: req_flag("server")?,
				member: req_flag("member")?,
				device_id: String::new(),
				token: String::new(),
				access_token_cmd: flag("access-token-cmd"),
				access_id: flag("access-id"),
				access_secret: flag("access-secret"),
				device_secret: flag("device-secret"),
				device_protectors: Vec::new(),
				pending_protectors: Vec::new(),
				dev_email: flag("dev-email"),
			};
			let name = flag("name").unwrap_or_else(|| "this computer".into());
			let secret = flag("secret").unwrap_or_else(|| read_secret("Vault password or recovery code: "));
			// Where the device secret lives (commit 34): the TPM and/or the login
			// keyring by default — never silently a file.
			let want: devicekey::Want = flag("protect").as_deref().unwrap_or("auto").parse()?;
			let sess = session::enrol(&mut profile, &name, &secret, want, &tpm_options(&flag)?)?;
			let path = flag("profile").map(PathBuf::from).unwrap_or_else(profile_path);
			session::save_profile(&path, &profile)?;
			let protection = if profile.device_secret.is_some() { "file".to_string() } else { devicekey::label(&profile.device_protectors) };
			println!("enrolled device {} for root {} (member {}) — device secret protected by: {protection}", profile.device_id, sess.settings.key_id, profile.member);
			if protection == "file" {
				eprintln!("warning: this computer's device secret is in {} — anyone who copies that file, with the member's sign-in, can open this computer's copy of the root. Move it: gorani-sync protect", path.display());
			}
		}
		Some("protect") => {
			// Move an enrolled computer's secret to new protectors without
			// enrolling again: the server's copy is re-wrapped (commit 34).
			let path = flag("profile").map(PathBuf::from).unwrap_or_else(profile_path);
			let mut profile = session::load_profile(&path)?;
			if let Some(e) = flag("dev-email") {
				profile.dev_email = Some(e);
			}
			let want: devicekey::Want = flag("protect").as_deref().unwrap_or("auto").parse()?;
			// --secret: open the root with the password or recovery code instead
			// of the device copy — after the boot state a TPM part was sealed to
			// changed (commit 36).
			let label = session::protect(&path, &mut profile, want, &tpm_options(&flag)?, flag("secret").as_deref())?;
			println!("device {} — device secret now protected by: {label}", profile.device_id);
		}
		Some("devices") => {
			// No unlock: listing and revoking need only the member's sign-in.
			let profile = session::load_profile(&flag("profile").map(PathBuf::from).unwrap_or_else(profile_path))?;
			let me = profile.device_id.clone();
			let client = api::Client::new(with_dev_email(profile, &flag));
			let listed = client.devices()?;
			for d in listed.as_array().cloned().unwrap_or_default() {
				let protection = match d["protection"].as_str() {
					Some("file") => "⚠ file (the secret sits in the profile)".to_string(),
					Some(p) => p.to_string(),
					None => "(not recorded)".to_string(),
				};
				let state = if d["revoked"].as_bool() == Some(true) { " [revoked]" } else { "" };
				let this = if d["id"].as_str() == Some(me.as_str()) { "  ← this computer" } else { "" };
				println!("  {}  {:<24} {:<8} protected by: {protection}  last seen {}{state}{this}", d["id"].as_str().unwrap_or("?"), d["name"].as_str().unwrap_or("?"), d["platform"].as_str().unwrap_or("?"), d["lastSeen"].as_str().unwrap_or("never"));
			}
		}
		Some("revoke") => {
			let profile = session::load_profile(&flag("profile").map(PathBuf::from).unwrap_or_else(profile_path))?;
			let device = req_flag("device")?;
			if device == profile.device_id {
				eprintln!("note: revoking THIS computer — it will not unlock again until it is enrolled anew");
			}
			api::Client::new(with_dev_email(profile, &flag)).revoke_device(&device)?;
			println!("revoked device {device}: its copy of the root is deleted; it can never unlock again");
		}
		Some("cases") => {
			let (profile, sess) = unlocked(&flag)?;
			let member = profile.member.clone();
			let client = api::Client::new(profile);
			let Some((_, trust)) = open_team(&client, &sess, &member)? else {
				return Err(Error::Config("your vault has no identity yet — open it once in the web app (Team)".into()));
			};
			let root = VaultPrivateKey::from_bytes(&sess.root).map_err(|_| Error::Open("root bundle"))?;
			let listed = area::listed_cases(&client)?;
			let mine: Vec<&CaseRow> = listed.iter().filter(|c| c.grant.is_some()).collect();
			println!("{} case(s) granted to you", mine.len());
			for c in mine {
				let g = c.grant.as_ref().expect("filtered");
				let mut state: Vec<String> = Vec::new();
				if c.closed {
					state.push("closed".into());
				}
				if c.hold.is_some() {
					state.push("legal hold".into());
				}
				if c.rotation_required {
					state.push("rotation owed".into());
				}
				if let Some(at) = &g.expires_at {
					state.push(format!("grant expires {at}"));
				}
				// The key is opened to SAY whether it opens: a grant from someone
				// you have not verified is listed, and named as such.
				let (title, key) = match cases::open_case_key(&root, c, &trust) {
					Ok(k) => (cases::open_title(&k, c).unwrap_or_else(|| "(untitled)".into()), format!("key verified — granted by {}", g.signed_by.as_deref().unwrap_or("?"))),
					Err(e) => ("(title not opened)".into(), format!("⚠ key not opened: {e}")),
				};
				let state = if state.is_empty() { String::new() } else { format!(" [{}]", state.join(", ")) };
				println!("  {}  {:<8} {:<6} {title}{state}\n      {key}", c.id, c.kind, g.permission);
			}
		}
		Some("ls") => {
			let (profile, sess) = unlocked(&flag)?;
			let member = profile.member.clone();
			let client = api::Client::new(profile);
			let area = open_area(&client, &sess, &member, flag("case").as_deref())?;
			let client = client.in_area(&area.name);
			let (cursor, changes) = client.changes(0)?;
			println!("cursor {cursor}, {} changes", changes.len());
			for c in &changes {
				let kind = c["kind"].as_str().unwrap_or("");
				// Each name opens only in the place its row names (O6): a name
				// the server moved here, or minted, prints as unverified.
				if kind == "version.put" {
					// (Its `file` is the id, not a row: the name is in the file.put beside it.)
					println!("  {kind:>12}  {} v{}", c["data"]["file"].as_str().unwrap_or("?"), c["data"]["version"]);
				} else if let Some(file) = c["data"].get("file") {
					let id = file["id"].as_str().unwrap_or_default();
					let name = area.open(&Place::file_name(&area.name, id), file["name"].as_str().unwrap_or_default());
					println!("  {kind:>12}  {}  {id}", name.unwrap_or_else(|| UNVERIFIED.into()));
				} else if let Some(folder) = c["data"].get("folder") {
					let id = folder["id"].as_str().unwrap_or_default();
					let name = area.open(&Place::folder_name(&area.name, id), folder["name"].as_str().unwrap_or_default());
					println!("  {kind:>12}  [folder] {}", name.unwrap_or_else(|| UNVERIFIED.into()));
				}
			}
		}
		Some("pull") => {
			let (profile, sess) = unlocked(&flag)?;
			let id = req_flag("id")?;
			let out = flag("out").unwrap_or_else(|| format!("./{id}"));
			let member = profile.member.clone();
			let client = api::Client::new(profile);
			let area = open_area(&client, &sess, &member, flag("case").as_deref())?;
			let client = client.in_area(&area.name);
			let keys = client.keys(&[id.clone()])?;
			let k = &keys["keys"][&id];
			let ck = k["key"].as_str().unwrap_or_default().to_string();
			let chunk = k["chunk"].as_u64();
			let size = k["size"].as_u64();
			let version = k["version"].as_i64().filter(|v| *v >= 1).ok_or(Error::Open("the server did not say which version this is"))?;
			// A malware sample is never written to disk raw (D8, commit 29e;
			// docs/CUSTODY.md › stage 5): desktop antivirus would quarantine it
			// mid-investigation, or a double-click would run it. Either mark
			// counts — the readable flag, or the sealed type the server cannot
			// clear (`application/x-gorani-sample; original=…`).
			let sealed_type = k["type"].as_str().unwrap_or_default();
			let typed_sample = area.open(&Place::file_type(&area.name, &id, version), sealed_type).is_some_and(|t| t.starts_with("application/x-gorani-sample"));
			if k["sample"].as_bool() == Some(true) || typed_sample {
				return Err(Error::Open("this is a malware sample — gorani-sync never writes one to disk raw; download it zipped from the web app (password: infected)"));
			}
			// The key opens only from THIS file's THIS version's place (O6).
			let ck_key = placed::unwrap_placed_key(&area.key, &Place::file_key(&area.name, &id, version), &ck).map_err(|_| Error::Open("content key (not sealed for this file and version)"))?;
			let hash_sealed = k["hash"].as_str().map(str::to_string);
			// What the uploader signed, asked BEFORE --out is written (33c).
			let judge = |sha256: &str, size: u64| judge_content(&area, &id, version as u64, hash_sealed.as_deref(), sha256, size, flag("accept-unverified").is_some());
			if let Some(chunk) = chunk.filter(|c| *c > 0) {
				// Streamed to disk a window of frames at a time (D12, commit 33b
				// — transfer.rs): each frame opened in its place, so a reordered,
				// altered or cut-short object fails before --out is touched; the
				// bytes land in <out>.part and are renamed on success only.
				let size = size.ok_or(Error::Open("the server did not say the file's size"))?;
				let sha256 = transfer::pull_frames(&client, &id, version as u64, &ck_key, chunk, size, Path::new(&out), |sha| judge(sha, size))?;
				println!("pulled {id} → {out} ({size} bytes, SHA-256 {sha256})");
			} else {
				let plain = {
					let sealed = client.fetch(&id, Some(version as u64), None)?;
					gorani_formats::formats::open_with(&ck_key, &sealed).map_err(|_| Error::Open("content"))?
				};
				// The listing's size and the opened bytes must agree before
				// anything touches the disk.
				if size.is_some_and(|s| s != plain.len() as u64) {
					return Err(Error::Open("content size does not match the file's size"));
				}
				judge(&transfer::hex(&<sha2::Sha256 as sha2::Digest>::digest(&plain[..])), plain.len() as u64)?;
				std::fs::write(&out, &*plain)?;
				println!("pulled {id} → {out}");
			}
			if let (Some((_, trust)), Some(intake)) = (&area.team, k["intake"].as_str()) {
				if let Some(line) = cases::describe_intake(&area.key, trust, &area.name, &id, Some(intake)) {
					println!("  {line}");
				}
			}
		}
		Some("push") => {
			let (profile, sess) = unlocked(&flag)?;
			let path = req_flag("file")?;
			let name = flag("name").unwrap_or_else(|| Path::new(&path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default());
			let member = profile.member.clone();
			let journal_dir = flag("profile").map(PathBuf::from).unwrap_or_else(profile_path).with_extension("uploads");
			let client = api::Client::new(profile);
			let area = open_area(&client, &sess, &member, flag("case").as_deref())?;
			let client = client.in_area(&area.name);
			if area.case.as_ref().is_some_and(|c| c.rotation_required) {
				eprintln!("note: this case's key rotation is owed (someone's grant was revoked, and they kept the key) — its manager rotates it in the web app");
			}
			// An evidence item says where it came from (commit 29g) — asked for
			// before a large file is hashed, not after.
			let intake = intake_fields(&flag);
			if area.is_evidence() && intake.is_none() {
				return Err(Error::Config("an evidence file needs its intake record: --source (the host or device), --collector (who), --method (how, the tool), --collected-at (ISO 8601) [--notes]".into()));
			}
			let meta = std::fs::metadata(&path)?;
			// Large files (D12, commit 33b): GC01 frames at chunk_for(size),
			// read from disk one at a time, journalled so a stopped push resumes.
			if meta.len() > WHOLE_LIMIT {
				let size = meta.len();
				let chunk = gorani_formats::chunked::chunk_for(size).ok_or(Error::Config("a file is at most 255 GiB".into()))?;
				eprintln!("hashing {name} ({size} bytes)…");
				let (sha256, hashed) = transfer::sha256_file(Path::new(&path))?;
				if hashed != size {
					return Err(Error::Config("the file changed while it was being read".into()));
				}
				let modified = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
				let journal = transfer::Journal::new(journal_dir);
				let jkey = transfer::Journal::key_for(&member, &area.name, &name, size, modified, &sha256);
				let progress = |done: u64, total: u64| {
					if done == total || done % 16 == 0 {
						eprintln!("  {done}/{total} parts");
					}
				};
				let row = match journal.get(&jkey).filter(|r| r.member == member && r.area == area.name && r.size == size) {
					Some(prior) => {
						// The same file, stopped part-way: the SAME id, key and
						// sealed (and signed) fields the stored frames were made with.
						let ck_sealed = prior.fields.iter().find(|(k, _)| k == "ck").map(|(_, v)| v.clone()).unwrap_or_default();
						let key = placed::unwrap_placed_key(&area.key, &Place::file_key(&area.name, &prior.file_id, 1), &ck_sealed).map_err(|_| Error::Open("the journalled content key"))?;
						eprintln!("resuming {name} from part {} of {}", prior.parts.len() + 1, gorani_formats::chunked::frame_count(size, prior.chunk));
						let (file_id, chunk) = (prior.file_id.clone(), prior.chunk);
						match transfer::push_frames(&client, &journal, &jkey, Path::new(&path), &key, &member, &file_id, chunk, size, prior.fields.clone(), Some(prior), progress) {
							Err(Error::Http(404, body)) if body.contains("no such upload") => {
								journal.delete(&jkey);
								return Err(Error::Config("the server no longer has the earlier upload (its window passed) — run push again to start over".into()));
							}
							other => other?,
						}
					}
					None => {
						let file_id = gorani_client_core::new_item_id();
						let ck = gorani_formats::formats::new_content_key();
						let key = gorani_formats::formats::import_content_key(&ck);
						let mut fields = area.new_file_fields(&file_id, &name, &ck, size, &sha256, intake.as_ref())?;
						fields.push(("chunk".into(), chunk.to_string()));
						transfer::push_frames(&client, &journal, &jkey, Path::new(&path), &key, &member, &file_id, chunk, size, fields, None, progress)?
					}
				};
				println!("pushed: {} ({size} bytes in {} parts, SHA-256 {sha256}){}", row["id"].as_str().unwrap_or("?"), gorani_formats::chunked::frame_count(size, chunk), signed_note(&area, intake.is_some()));
				return Ok(());
			}
			let bytes = std::fs::read(&path)?;
			let sha256 = transfer::hex(&<sha2::Sha256 as sha2::Digest>::digest(&bytes));
			// The id first — the name, type, key, hash and intake are sealed
			// into places that name it (O6); a new file is version 1.
			let file_id = gorani_client_core::new_item_id();
			let ck = gorani_formats::formats::new_content_key();
			let key = gorani_formats::formats::import_content_key(&ck);
			let sealed = gorani_formats::formats::seal_with(&key, &bytes);
			let fields = api::UploadFields { form: area.new_file_fields(&file_id, &name, &ck, bytes.len() as u64, &sha256, intake.as_ref())? };
			let row = client.upload_whole(&fields, &sealed)?;
			println!("pushed: {} ({} bytes, SHA-256 {sha256}){}", row["id"].as_str().unwrap_or("?"), bytes.len(), signed_note(&area, intake.is_some()));
		}
		_ => {
			eprintln!("usage: gorani-sync <setup|protect|devices|revoke|cases|ls|pull|push> [--protect auto|tpm|keyring|tpm+keyring|file --tpm-pin --tpm-pcrs 7] [--case C] [--server S --member M --name N --secret S --device-secret H --access-token-cmd CMD --dev-email E --file P --id I --out O --profile P --source S --collector W --method M --collected-at T --notes X --accept-unverified]");
			std::process::exit(2);
		}
	}
	Ok(())
}

/// The intake fields, when any was given (all are checked by sign_intake).
fn intake_fields(flag: &dyn Fn(&str) -> Option<String>) -> Option<IntakeFields> {
	let any = ["source", "collector", "method", "collected-at", "notes"].iter().any(|k| flag(k).is_some());
	any.then(|| IntakeFields {
		source: flag("source").unwrap_or_default(),
		collector: flag("collector").unwrap_or_default(),
		method: flag("method").unwrap_or_default(),
		collected_at: flag("collected-at").unwrap_or_default(),
		notes: flag("notes").unwrap_or_default(),
	})
}

fn signed_note(area: &Area, intake: bool) -> String {
	match &area.team {
		Some((s, _)) => format!(" — content hash signed by {}{}", s.member, if intake { ", intake recorded" } else { "" }),
		None => String::new(),
	}
}

/// What the uploader signed, against what was decrypted (cases.rs ›
/// check_content_hash) — printed, and decisive:
///
/// - a **mismatch** or an **invalid** record refuses the pull: nothing is
///   written (a trusted person vouched for other bytes, or someone forged
///   their voice);
/// - **untrusted** or **unsigned** in an EVIDENCE case refuses too, unless
///   `--accept-unverified`: evidence that cannot be tied to a person you
///   verified is not silently handed over as if it could;
/// - elsewhere they are written, with the line saying what they are.
fn judge_content(area: &Area, id: &str, version: u64, hash: Option<&str>, sha256: &str, size: u64, accept_unverified: bool) -> Result<(), Error> {
	let Some((_, trust)) = &area.team else {
		if hash.is_some() {
			println!("  content signed by its uploader — not checked (this vault has no identity yet)");
		}
		return Ok(());
	};
	let check = cases::check_content_hash(&area.key, trust, &area.name, id, version, hash, sha256, size);
	println!("  {}", check.describe());
	match check {
		HashCheck::Verified { .. } => Ok(()),
		HashCheck::Mismatch { .. } | HashCheck::Invalid { .. } => Err(Error::Config("refusing to write it — the content is not what its signature says".into())),
		HashCheck::Untrusted { .. } | HashCheck::Unsigned if area.is_evidence() && !accept_unverified => Err(Error::Config("refusing to write unverified evidence — pass --accept-unverified to write it anyway".into())),
		_ => Ok(()),
	}
}

/// The TPM part's options (commit 36): `--tpm-pin` (a PIN, asked twice — or
/// GORANI_TPM_PIN) and `--tpm-pcrs 7` (sealed to the boot state).
fn tpm_options(flag: &dyn Fn(&str) -> Option<String>) -> Result<devicekey::TpmOptions, Error> {
	Ok(devicekey::TpmOptions {
		pin: if flag("tpm-pin").is_some() { Some(devicekey::choose_pin()?) } else { None },
		pcrs: flag("tpm-pcrs").as_deref().map(devicekey::TpmOptions::parse_pcrs).transpose()?.unwrap_or_default(),
	})
}

fn with_dev_email(mut profile: DeviceProfile, flag: &dyn Fn(&str) -> Option<String>) -> DeviceProfile {
	if let Some(e) = flag("dev-email") {
		profile.dev_email = Some(e);
	}
	profile
}

fn unlocked(flag: &dyn Fn(&str) -> Option<String>) -> Result<(DeviceProfile, Session), Error> {
	let path = flag("profile").map(PathBuf::from).unwrap_or_else(profile_path);
	let mut profile = session::load_profile(&path)?;
	if let Some(e) = flag("dev-email") {
		profile.dev_email = Some(e);
	}
	// This computer's own wrapped copy when it holds one (the enrolment's
	// point: no password per command), else a typed secret.
	let sess = match flag("secret") {
		Some(secret) => session::unlock(&profile, &secret)?,
		None if session::has_device_copy(&profile) => session::unlock_device(&profile)?,
		None => session::unlock(&profile, &read_secret("Vault password or recovery code: "))?,
	};
	Ok((profile, sess))
}

/// What a name that does not open in its place prints as (O6).
const UNVERIFIED: &str = "⚠ unverified — not sealed here";
