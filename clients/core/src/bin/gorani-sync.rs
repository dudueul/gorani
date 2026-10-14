// Copyright 2026- Seongwoo Hong. All rights reserved.

//! `gorani-sync`: the command line. Platform shells replace the UI; the
//! commands stay (scriptability, tests, power users).

use std::path::PathBuf;

use gorani_client_core::{api, session, DeviceProfile, Error, Session};

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
			let (profile, sess) = unlocked(&flag, &req_flag)?;
			let client = api::Client::new(profile);
			let (cursor, changes) = client.changes(0)?;
			println!("cursor {cursor}, {} changes", changes.len());
			for c in &changes {
				let kind = c["kind"].as_str().unwrap_or("");
				if let Some(file) = c["data"].get("file") {
					let name = open_name(&sess, file["name"].as_str().unwrap_or_default());
					println!("  {kind:>12}  {}", name.unwrap_or_else(|| "(sealed)".into()));
				} else if let Some(folder) = c["data"].get("folder") {
					let name = open_name(&sess, folder["name"].as_str().unwrap_or_default());
					println!("  {kind:>12}  [folder] {}", name.unwrap_or_else(|| "(sealed)".into()));
				}
			}
		}
		Some("pull") => {
			let (profile, sess) = unlocked(&flag, &req_flag)?;
			let id = req_flag("id")?;
			let out = flag("out").unwrap_or_else(|| format!("./{id}"));
			let client = api::Client::new(profile);
			let keys = client.keys(&[id.clone()])?;
			let ck = keys["keys"][&id]["key"].as_str().unwrap_or_default().to_string();
			let chunk = keys["keys"][&id]["chunk"].as_u64();
			let size = keys["keys"][&id]["size"].as_u64();
			let store = sess.files_store()?;
			let ck_key = gorani_formats::formats::unwrap_content_key(&store, &ck).map_err(|_| Error::Open("content key"))?;
			let plain = if let Some(chunk) = chunk.filter(|c| *c > 0) {
				// The reference reader, not a hand-rolled loop (security review,
				// commit 23). The loop that stood here counted frames with FLOOR
				// division: an empty or shortened body opened to zero bytes and
				// `pull` happily overwrote --out with nothing, and every honest
				// file whose size was not a multiple of the chunk failed. The
				// format's own reader rounds up and binds the final flag, so a
				// truncation at any frame boundary is an authentication failure.
				let sealed = client.fetch(&id, None, None)?;
				gorani_formats::chunked::open_chunked(&ck_key, &sealed, chunk).map_err(|_| Error::Open("content (altered, reordered or cut short)"))?
			} else {
				let sealed = client.fetch(&id, None, None)?;
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
			let (profile, sess) = unlocked(&flag, &req_flag)?;
			let path = req_flag("file")?;
			let name = flag("name").unwrap_or_else(|| std::path::Path::new(&path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default());
			let bytes = std::fs::read(&path)?;
			let client = api::Client::new(profile);
			let name_sealed = sess.seal_for_files(&name)?;
			let type_sealed = sess.seal_for_files("application/octet-stream")?;
			let ck = gorani_formats::formats::new_content_key();
			let key = gorani_formats::formats::import_content_key(&ck);
			let sealed = gorani_formats::formats::seal_with(&key, &bytes);
			let ck_wrapped = gorani_formats::formats::wrap_content_key(&files_public(&sess)?, &ck);
			let fields = api::UploadFields {
				form: vec![
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

fn unlocked(flag: &dyn Fn(&str) -> Option<String>, req_flag: &dyn Fn(&str) -> Result<String, Error>) -> Result<(DeviceProfile, Session), Error> {
	let path = flag("profile").map(PathBuf::from).unwrap_or_else(profile_path);
	let mut profile = session::load_profile(&path)?;
	if let Some(e) = flag("dev-email") {
		profile.dev_email = Some(e);
	}
	let secret = flag("secret").unwrap_or_else(|| read_secret("Vault password or recovery code: "));
	let sess = session::unlock(&profile, &secret)?;
	Ok((profile, sess))
}



fn files_public(sess: &Session) -> Result<gorani_formats::formats::VaultPublicKey, Error> {
	let key = sess.settings.stores.get("files").ok_or(Error::Open("no files store key"))?;
	gorani_formats::formats::VaultPublicKey::from_jwk(&key.public_key.x, &key.public_key.y, key.pq_public_key.as_deref()).map_err(|_| Error::Format("bad store JWK"))
}

/// Open a sealed name with the root (the settings' store key is opened from
/// the root; for the feed, the names are sealed to the store key too).
fn open_name(sess: &Session, sealed: &str) -> Option<String> {
	let store = sess.files_store().ok()?;
	gorani_formats::formats::open_text(&store, sealed).ok().map(|s| s.to_string())
}