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
	match args.first().map(String::as_str) {
		Some("setup") => {
			let server = read_line("Server: ");
			let member = read_line("Member id: ");
			let mut profile = DeviceProfile { server, member, device_id: String::new(), token: String::new(), access_id: None, access_secret: None };
			let name = read_line("This computer's name: ");
			let secret = read_secret("Vault password or recovery code: ");
			let sess = session::enrol(&mut profile, &name, &secret, "cli")?;
			let dev_secret = profile.access_secret.clone().unwrap_or_default();
			session::save_profile(&profile_path(), &profile)?;
			println!("enrolled: device {} (root {})", profile.device_id, sess.settings.key_id);
			println!("device secret (kept in the profile): {dev_secret}");
		}
		Some("ls") => {
			let (profile, sess) = unlocked()?;
			let client = api::Client::new(profile);
			let (cursor, changes) = client.changes(0)?;
			println!("cursor {cursor}, {} changes", changes.len());
			for c in &changes {
				let kind = c["kind"].as_str().unwrap_or("");
				if let Some(file) = c["data"].get("file") {
					let name = open_name(&sess, file["name"].as_str().unwrap_or_default());
					println!("  {kind:>12}  {}", name.unwrap_or_else(|| "(sealed)".into()));
				}
			}
		}
		Some("pull") => {
			let (profile, sess) = unlocked()?;
			let id = args.get(1).ok_or(Error::Config("pull <file-id> [out]".into()))?.clone();
			let out = args.get(2).cloned().unwrap_or_else(|| format!("./{id}"));
			let client = api::Client::new(profile);
			let keys = client.keys(&[id.clone()])?;
			let ck = keys["keys"][&id]["key"].as_str().unwrap_or_default().to_string();
			let chunk = keys["keys"][&id]["chunk"].as_u64().map(|c| c as usize);
			let store = sess.files_store()?;
			let ck_key = gorani_formats::formats::unwrap_content_key(&store, &ck).map_err(|_| Error::Open("content key"))?;
			let plain = if let Some(chunk) = chunk.filter(|c| *c > 0) {
				let sealed = client.fetch(&id, None, None)?;
				let frame = chunk + 28;
				let frames = sealed.len() / frame;
				let mut out_bytes = Vec::new();
				for i in 0..frames {
					let at = i * frame;
					let len = std::cmp::min(frame, sealed.len() - at);
					let iv = &sealed[at..at + 12];
					let body = &sealed[at + 12..at + len];
					let mut aad = vec![b'G', b'C', b'0', b'1'];
					aad.extend_from_slice(&(i as u64).to_be_bytes());
					aad.push(u8::from(i == frames - 1));
					let nonce = &sealed[at..at + 12];
					let plain = gorani_formats::chunked::open_chunk_frame(&ck_key, nonce, body, &aad).map_err(|_| Error::Open("frame"))?;
					out_bytes.extend_from_slice(&plain);
				}
				out_bytes
			} else {
				let sealed = client.fetch(&id, None, None)?;
				let plain = gorani_formats::formats::open_with(&ck_key, &sealed).map_err(|_| Error::Open("content"))?;
				plain.to_vec()
			};
			std::fs::write(out, plain)?;
			println!("pulled {id}");
		}
		Some("push") => {
			let (profile, sess) = unlocked()?;
			let path = args.get(1).ok_or(Error::Config("push <path> [name]".into()))?;
			let name = args.get(2).cloned().unwrap_or_else(|| std::path::Path::new(path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default());
			let bytes = std::fs::read(path)?;
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
			eprintln!("usage: gorani-sync <setup|ls|pull <id> [out]|push <path> [name]>");
			std::process::exit(2);
		}
	}
	Ok(())
}

fn unlocked() -> Result<(DeviceProfile, Session), Error> {
	let profile = session::load_profile(&profile_path())?;
	let sess = session::unlock(&profile, &read_secret("Vault password or recovery code: "))?;
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