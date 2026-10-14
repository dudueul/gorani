// Copyright 2026- Seongwoo Hong. All rights reserved.

//! `gorani-sync`: the command line. Platform shells replace the UI; the
//! commands stay (scriptability, tests, power users).

use std::path::PathBuf;

use gorani_client_core::{api, session, DeviceProfile, Error, Session};
use gorani_formats::placed::Place;

fn main() {
	let args: Vec<String> = std::env::args().skip(1).collect();
	if let Err(e) = run(&args) {
		eprintln!("error: {e}");
		std::process::exit(1);
	}
}

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
	//        --access-id --access-secret (Cloudflare Access service token)
	//        --file --id --out --profile
	let mut flags: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
	let mut pos: Vec<String> = Vec::new();
	let mut i = 0;
	while i < args.len() {
		let a = &args[i];
		if let Some(name) = a.strip_prefix("--") {
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
				access_id: flag("access-id"),
				access_secret: flag("access-secret"),
				device_secret: flag("device-secret"),
				dev_email: flag("dev-email"),
			};
			let name = flag("name").unwrap_or_else(|| "this computer".into());
			let secret = flag("secret").unwrap_or_else(|| read_secret("Vault password or recovery code: "));
			let sess = session::enrol(&mut profile, &name, &secret, "cli")?;
			let path = flag("profile").map(PathBuf::from).unwrap_or_else(profile_path);
			session::save_profile(&path, &profile)?;
			println!("enrolled device {} for root {} (member {})", profile.device_id, sess.settings.key_id, profile.member);
		}
		Some("ls") => {
			let (profile, sess) = unlocked(&flag)?;
			let member = profile.member.clone();
			let client = api::Client::new(profile);
			let (cursor, changes) = client.changes(0)?;
			println!("cursor {cursor}, {} changes", changes.len());
			for c in &changes {
				let kind = c["kind"].as_str().unwrap_or("");
				// Each name opens only in the place its row names (O6): a name
				// the server moved here, or minted, prints as unverified.
				if let Some(file) = c["data"].get("file") {
					let id = file["id"].as_str().unwrap_or_default();
					let name = open_name(&sess, &Place::file_name(&member, id), file["name"].as_str().unwrap_or_default());
					println!("  {kind:>12}  {}", name.unwrap_or_else(|| UNVERIFIED.into()));
				} else if let Some(folder) = c["data"].get("folder") {
					let id = folder["id"].as_str().unwrap_or_default();
					let name = open_name(&sess, &Place::folder_name(&member, id), folder["name"].as_str().unwrap_or_default());
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
			let keys = client.keys(&[id.clone()])?;
			let ck = keys["keys"][&id]["key"].as_str().unwrap_or_default().to_string();
			let chunk = keys["keys"][&id]["chunk"].as_u64();
			let size = keys["keys"][&id]["size"].as_u64();
			let version = keys["keys"][&id]["version"].as_i64().filter(|v| *v >= 1).ok_or(Error::Open("the server did not say which version this is"))?;
			// A malware sample is never written to disk raw (D8, commit 29e;
			// docs/CUSTODY.md › stage 5): desktop antivirus would quarantine it
			// mid-investigation, or a double-click would run it. Either mark
			// counts — the readable flag, or the sealed type the server cannot
			// clear (`application/x-gorani-sample; original=…`).
			let sealed_type = keys["keys"][&id]["type"].as_str().unwrap_or_default();
			let typed_sample = open_name(&sess, &Place::file_type(&member, &id, version), sealed_type).is_some_and(|t| t.starts_with("application/x-gorani-sample"));
			if keys["keys"][&id]["sample"].as_bool() == Some(true) || typed_sample {
				return Err(Error::Open("this is a malware sample — gorani-sync never writes one to disk raw; download it zipped from the web app (password: infected)"));
			}
			let store = sess.files_store()?;
			// The key opens only from THIS file's THIS version's place (O6).
			let ck_key = gorani_formats::placed::unwrap_placed_key(&store, &Place::file_key(&member, &id, version), &ck).map_err(|_| Error::Open("content key (not sealed for this file and version)"))?;
			let plain = if let Some(chunk) = chunk.filter(|c| *c > 0) {
				// The reference reader, not a hand-rolled loop (security review,
				// commit 23). The loop that stood here counted frames with FLOOR
				// division: an empty or shortened body opened to zero bytes and
				// `pull` happily overwrote --out with nothing, and every honest
				// file whose size was not a multiple of the chunk failed. The
				// format's own reader rounds up and binds the final flag, so a
				// truncation at any frame boundary is an authentication failure.
				let sealed = client.fetch(&id, Some(version as u64), None)?;
				gorani_formats::chunked::open_chunked(&ck_key, &sealed, chunk).map_err(|_| Error::Open("content (altered, reordered or cut short)"))?
			} else {
				let sealed = client.fetch(&id, Some(version as u64), None)?;
				gorani_formats::formats::open_with(&ck_key, &sealed).map_err(|_| Error::Open("content"))?
			};
			// The listing's size and the opened bytes must agree before anything
			// touches the disk.
			if size.is_some_and(|s| s != plain.len() as u64) {
				return Err(Error::Open("content size does not match the file's size"));
			}
			std::fs::write(&out, &*plain)?;
			println!("pulled {id} → {out}");
		}
		Some("push") => {
			let (profile, sess) = unlocked(&flag)?;
			let path = req_flag("file")?;
			let name = flag("name").unwrap_or_else(|| std::path::Path::new(&path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default());
			let bytes = std::fs::read(&path)?;
			let member = profile.member.clone();
			let client = api::Client::new(profile);
			// The id first — the name, type and key are sealed into places
			// that name it (O6); a new file is version 1.
			let file_id = new_item_id();
			let name_sealed = sess.seal_into(&Place::file_name(&member, &file_id), &name)?;
			let type_sealed = sess.seal_into(&Place::file_type(&member, &file_id, 1), "application/octet-stream")?;
			let ck = gorani_formats::formats::new_content_key();
			let key = gorani_formats::formats::import_content_key(&ck);
			let sealed = gorani_formats::formats::seal_with(&key, &bytes);
			let ck_wrapped = gorani_formats::placed::wrap_placed_key(&sess.files_store()?, &Place::file_key(&member, &file_id, 1), &ck).map_err(|_| Error::Open("files store key"))?;
			let fields = api::UploadFields {
				form: vec![
					("file_id".into(), file_id),
					("ck".into(), ck_wrapped),
					("name".into(), name_sealed),
					("type".into(), type_sealed),
					("size".into(), bytes.len().to_string()),
				],
			};
			let row = client.upload_whole(&fields, &sealed)?;
			println!("pushed: {}", row["id"].as_str().unwrap_or("?"));
		}
		_ => {
			eprintln!("usage: gorani-sync <setup|ls|pull|push> [--server S --member M --name N --secret S --device-secret H --access-id I --access-secret S --dev-email E --file P --id I --out O --profile P]");
			std::process::exit(2);
		}
	}
	Ok(())
}

fn unlocked(flag: &dyn Fn(&str) -> Option<String>) -> Result<(DeviceProfile, Session), Error> {
	let path = flag("profile").map(PathBuf::from).unwrap_or_else(profile_path);
	let mut profile = session::load_profile(&path)?;
	if let Some(e) = flag("dev-email") {
		profile.dev_email = Some(e);
	}
	let secret = flag("secret").unwrap_or_else(|| read_secret("Vault password or recovery code: "));
	let sess = session::unlock(&profile, &secret)?;
	Ok((profile, sess))
}



/// What a name that does not open in its place prints as (O6).
const UNVERIFIED: &str = "⚠ unverified — not sealed here";

/// Open a name in the place its row names (the files store key, opened from
/// the root and verified — `Session::files_store`).
fn open_name(sess: &Session, place: &Place, sealed: &str) -> Option<String> {
	let store = sess.files_store().ok()?;
	gorani_formats::placed::open_placed_text(&store, place, sealed).ok().map(|s| s.to_string())
}

/// A fresh file id, chosen before sealing (128 random bits, base64url — the
/// Worker's id allow-list). The twin of `places.ts › newItemId`.
fn new_item_id() -> String {
	use base64::Engine;
	let mut b = [0u8; 16];
	rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
	base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}