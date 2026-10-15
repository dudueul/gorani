// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The collector (commit 37b, docs/COLLECTORS.md): a machine that drops
//! evidence into case inboxes with no person signed in — an acquisition
//! server, an EDR export, a collection script.
//!
//! It is the one client that never holds a store key. What it holds:
//!
//! ```text
//! identity key   P-256, made here at `collector init`; its public half is what two
//!                leads register (Team › Collectors); its private half and the Access
//!                service token's secret are sealed in the profile under a key from
//!                the DEVICE SECRET — whose parts the TPM and/or the keyring hold
//!                (devicekey.rs, as a member's computer)
//! pins           the leads this machine was told to believe, by member and key id
//!                (or fingerprint), under a MAC from the same secret — a profile
//!                edited by someone without the TPM/keyring fails it
//! ```
//!
//! A drop (`collect`):
//!
//! ```text
//! 1. whoami                     the registry's word that this token is an ACTIVE collector,
//!                               registered with THIS machine's key
//! 2. the case's inbox key       public halves + a manager's signature over
//!                               stmt("gorani-inbox-v1", case, key digest); checked against
//!                               the pins (and one-hop certificates they made) — a key the
//!                               server made itself is refused before anything is sealed
//! 3. seal                       bytes under a fresh content key (GV02 whole, GC01 frames);
//!                               the content key and the metadata sealed to the inbox key (GV03)
//! 4. sign                       stmt("gorani-collect-v1", case, item, collector, SHA-256, size,
//!                               name, type, source, method, collected-at, notes) — sealed
//!                               INSIDE the metadata (in the clear it would let the store test
//!                               a guess about the content)
//! 5. send                       with the stamp imprint, SHA-256(signature): the RFC 3161
//!                               token the store fetches proves the item existed by then
//! 6. log                        one line in this machine's own log — the check on a server
//!                               that withholds items
//! ```
//!
//! What a collector cannot do, by construction: read anything — the inbox
//! private key is sealed under the case key, which it never sees; not even
//! what it sent (the content key went to the inbox key at once). So a
//! compromised collector leaks only what it collects from then on.

use std::path::{Path, PathBuf};

use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{json, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::api::Jwk;
use crate::devicekey::{self, Protector};
use crate::identity::{self, fingerprint, identity_key_id, stmt, Pin, RegistryIdentity};
use crate::Error;
use gorani_formats::formats::{self, VaultPublicKey};

/// The profile file (`~/.gorani-collector.json` by default). Nothing in it
/// is a secret alone: the sealed half needs this machine's protectors.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorProfile {
	pub server: String,
	/// The id the leads register this collector under (Team › Collectors).
	pub id: String,
	pub key_id: String,
	pub public_key: Jwk,
	/// The Access service token's Client ID — its JWT's `common_name`, which
	/// the registry matches. Not a secret; the token's SECRET is sealed.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub access_id: Option<String>,
	pub protectors: Vec<Protector>,
	/// `{ identityKey, accessSecret }` under the profile key (GV02 text).
	pub sealed: String,
	#[serde(default)]
	pub pins: Vec<Pin>,
	/// HMAC over everything above but the protectors (`profile_bytes`).
	pub mac: String,
	/// Dev mode (wrangler dev): the common name sent as `x-gorani-dev-collector`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub dev_collector: Option<String>,
}

/// What `collector init` prints — what the leads paste into Team › Collectors.
pub struct Introduction {
	pub id: String,
	pub public_key: Jwk,
	pub key_id: String,
	pub fingerprint: String,
}

/// The two keys the device secret gives this profile: one seals, one MACs.
struct ProfileKeys {
	seal: Zeroizing<[u8; 32]>,
	mac: Zeroizing<[u8; 32]>,
}

fn profile_keys(secret: &[u8; 32]) -> ProfileKeys {
	let h = Hkdf::<Sha256>::new(Some(b"gorani-collector-v1"), &secret[..]);
	let mut seal = Zeroizing::new([0u8; 32]);
	let mut mac = Zeroizing::new([0u8; 32]);
	h.expand(b"seal", &mut seal[..]).expect("32 bytes is a valid HKDF length");
	h.expand(b"mac", &mut mac[..]).expect("32 bytes is a valid HKDF length");
	ProfileKeys { seal, mac }
}

/// The bytes the MAC covers. Pins sorted (one set, one spelling), as the
/// member's identity record (identity.rs › identity_record_bytes).
fn profile_bytes(p: &CollectorProfile) -> Result<Vec<u8>, Error> {
	let ec = identity::ec_raw_of_jwk(&p.public_key)?;
	let mut pins: Vec<&Pin> = p.pins.iter().collect();
	pins.sort_by(|a, b| format!("{}\0{}", a.member, a.key_id).cmp(&format!("{}\0{}", b.member, b.key_id)));
	let access = p.access_id.clone().unwrap_or_default();
	let dev = p.dev_collector.clone().unwrap_or_default();
	let mut fields: Vec<&[u8]> = vec![p.server.as_bytes(), p.id.as_bytes(), p.key_id.as_bytes(), &ec, access.as_bytes(), p.sealed.as_bytes(), dev.as_bytes()];
	for pin in &pins {
		fields.push(pin.member.as_bytes());
		fields.push(pin.key_id.as_bytes());
	}
	Ok(stmt("gorani-collector-profile-v1", &fields))
}

fn mac_of(keys: &ProfileKeys, p: &CollectorProfile) -> Result<String, Error> {
	let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&keys.mac[..]).expect("HMAC takes any key length");
	m.update(&profile_bytes(p)?);
	Ok(crate::encode(&m.finalize().into_bytes()))
}

/// A pin as given on the command line: `member:<key id or fingerprint>`.
/// A fingerprint (the 32 hex digits people read aloud, spaces optional) is
/// 128 bits — enough against a server grinding keys — and is resolved to
/// the full key id against the registry at use.
pub fn parse_pins(s: &str) -> Result<Vec<Pin>, Error> {
	s.split(',')
		.map(str::trim)
		.filter(|p| !p.is_empty())
		.map(|p| {
			let (member, key) = p.split_once(':').ok_or_else(|| Error::Config(format!("--pins {p}: member:<key id or fingerprint>")))?;
			let key: String = key.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_lowercase();
			if !(32..=64).contains(&key.len()) || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
				return Err(Error::Config(format!("--pins {p}: the key is its fingerprint (32 hex digits) or its full id (64)")));
			}
			Ok(Pin { member: member.trim().to_string(), key_id: key })
		})
		.collect()
}

fn jwk_of(key: &SigningKey) -> Jwk {
	let point = key.verifying_key().to_encoded_point(false);
	let b64u = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
	Jwk { x: b64u(point.x().expect("uncompressed")), y: b64u(point.y().expect("uncompressed")), kty: Some("EC".into()), crv: Some("P-256".into()) }
}

/// Settings for a new collector profile.
pub struct Init<'a> {
	pub server: &'a str,
	pub id: &'a str,
	pub pins: Vec<Pin>,
	pub access_id: Option<String>,
	pub access_secret: Option<Zeroizing<String>>,
	pub dev_collector: Option<String>,
	pub want: devicekey::Want,
	pub tpm: &'a devicekey::TpmOptions,
}

/// `collector init`: a fresh identity key and device secret, sealed into a
/// new profile. Returns it and what to give the leads.
pub fn init(i: Init) -> Result<(CollectorProfile, Introduction), Error> {
	if !(2..=32).contains(&i.id.len()) || !i.id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
		return Err(Error::Config("--id: 2–32 of a–z, 0–9, dashes (what the leads register it as)".into()));
	}
	if i.pins.is_empty() {
		return Err(Error::Config("--pins: at least one lead this collector believes (member:fingerprint, compared with them in person) — without pins it could not tell a case's inbox key from the server's".into()));
	}
	let key = SigningKey::random(&mut rand_core::OsRng);
	let public_key = jwk_of(&key);
	let key_id = identity_key_id(&public_key)?;
	let (protectors, secret) = devicekey::create(i.want, &format!("gorani collector {} ({})", i.id, i.server.trim_end_matches('/')), i.tpm)?;
	let keys = profile_keys(&secret);
	let inner = Zeroizing::new(json!({ "identityKey": crate::encode(&key.to_bytes()), "accessSecret": i.access_secret.as_deref().map(|s| s.as_str()) }).to_string());
	let mut p = CollectorProfile {
		server: i.server.trim_end_matches('/').into(),
		id: i.id.into(),
		key_id: key_id.clone(),
		public_key: public_key.clone(),
		access_id: i.access_id,
		protectors,
		sealed: formats::seal_text_with(&keys.seal, &inner),
		pins: i.pins,
		mac: String::new(),
		dev_collector: i.dev_collector,
	};
	p.mac = mac_of(&keys, &p)?;
	Ok((p, Introduction { id: i.id.into(), public_key, key_id: key_id.clone(), fingerprint: fingerprint(&key_id) }))
}

/// A profile opened: the MAC checked, the identity key and the token's secret out.
pub struct Opened {
	pub profile: CollectorProfile,
	key: SigningKey,
	access_secret: Option<Zeroizing<String>>,
	keys: ProfileKeys,
}

impl Opened {
	/// ECDSA P-256 / SHA-256, P1363, base64 — what the browser verifies.
	pub fn sign(&self, statement: &[u8]) -> String {
		let sig: Signature = self.key.sign(statement);
		crate::encode(&sig.to_bytes())
	}

	/// Add pins (re-MAC'd under the same device secret).
	pub fn add_pins(&mut self, pins: Vec<Pin>) -> Result<(), Error> {
		for pin in pins {
			self.profile.pins.retain(|p| p.member != pin.member);
			self.profile.pins.push(pin);
		}
		self.profile.mac = mac_of(&self.keys, &self.profile)?;
		Ok(())
	}
}

/// Open a profile: ask the protectors for the device secret, check the MAC
/// (the pins, the key, the server are as `init` wrote them), open the sealed
/// half, and check the key is the profile's key.
pub fn open(profile: CollectorProfile) -> Result<Opened, Error> {
	let secret = devicekey::open(&profile.protectors)?;
	let keys = profile_keys(&secret);
	let refused = Error::Open("the collector profile does not verify under this machine's device secret — it was edited, or it belongs to another machine");
	let Ok(mac) = base64::engine::general_purpose::STANDARD.decode(&profile.mac) else { return Err(refused) };
	let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&keys.mac[..]).expect("HMAC takes any key length");
	m.update(&profile_bytes(&profile)?);
	m.verify_slice(&mac).map_err(|_| refused)?;
	let inner = formats::open_text_with(&keys.seal, &profile.sealed).map_err(|_| Error::Open("the profile's sealed half does not open"))?;
	let v: Value = serde_json::from_str(&inner).map_err(|_| Error::Format("the profile's sealed half is not JSON"))?;
	let raw = crate::decode(v["identityKey"].as_str().unwrap_or_default())?;
	let key = SigningKey::from_slice(&raw).map_err(|_| Error::Format("the identity key is not a P-256 scalar"))?;
	if identity_key_id(&jwk_of(&key))? != profile.key_id {
		return Err(Error::Open("the profile's identity key is not its key id's"));
	}
	let access_secret = v["accessSecret"].as_str().map(|s| Zeroizing::new(s.to_string()));
	Ok(Opened { profile, key, access_secret, keys })
}

pub fn save(path: &Path, p: &CollectorProfile) -> Result<(), Error> {
	use std::io::Write;
	let bytes = serde_json::to_vec_pretty(p).map_err(|e| Error::Config(e.to_string()))?;
	let tmp = path.with_extension("tmp");
	let mut opts = std::fs::OpenOptions::new();
	opts.write(true).create(true).truncate(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		opts.mode(0o600);
	}
	let mut f = opts.open(&tmp)?;
	f.write_all(&bytes)?;
	f.sync_all()?;
	std::fs::rename(&tmp, path)?;
	Ok(())
}

pub fn load(path: &Path) -> Result<CollectorProfile, Error> {
	serde_json::from_slice(&std::fs::read(path)?).map_err(|e| Error::Config(format!("collector profile: {e}")))
}

// ── the drop routes ───────────────────────────────────────────────────

/// `/api/v1/collect/…` as this collector: the service token (or the dev
/// header), nothing of any member's.
pub struct CollectClient<'a> {
	o: &'a Opened,
	agent: ureq::Agent,
}

impl<'a> CollectClient<'a> {
	pub fn new(o: &'a Opened) -> Self {
		let agent = ureq::AgentBuilder::new().redirects(0).timeout_connect(std::time::Duration::from_secs(15)).timeout(std::time::Duration::from_secs(120)).build();
		Self { o, agent }
	}

	fn req(&self, method: &str, rest: &str) -> ureq::Request {
		let mut r = self.agent.request(method, &format!("{}/api/v1/collect{rest}", self.o.profile.server)).set("Accept-Encoding", "identity");
		if let (Some(id), Some(secret)) = (&self.o.profile.access_id, &self.o.access_secret) {
			r = r.set("CF-Access-Client-Id", id).set("CF-Access-Client-Secret", secret);
		}
		if let Some(cn) = &self.o.profile.dev_collector {
			r = r.set("x-gorani-dev-collector", cn);
		}
		r
	}

	fn answer(res: Result<ureq::Response, ureq::Error>) -> Result<Value, Error> {
		match res {
			Ok(r) => r.into_json().map_err(|e| Error::Config(format!("bad answer: {e}"))),
			Err(ureq::Error::Status(code, r)) => Err(Error::Http(code, r.into_string().unwrap_or_default())),
			Err(e) => Err(Error::Config(e.to_string())),
		}
	}

	pub fn get(&self, rest: &str) -> Result<Value, Error> {
		Self::answer(self.req("GET", rest).call())
	}

	pub fn post_json(&self, rest: &str, body: Value) -> Result<Value, Error> {
		Self::answer(self.req("POST", rest).send_json(body))
	}

	pub fn put_part(&self, rest: &str, frame: &[u8]) -> Result<String, Error> {
		let mut last = String::new();
		for attempt in 0..3u32 {
			if attempt > 0 {
				std::thread::sleep(std::time::Duration::from_secs(4u64.pow(attempt - 1)));
			}
			match self.req("PUT", rest).set("Content-Type", "application/octet-stream").send_bytes(frame) {
				Ok(r) => return r.into_json::<Value>().ok().and_then(|v| v["etag"].as_str().map(str::to_string)).ok_or_else(|| Error::Config("the part's answer had no etag".into())),
				Err(ureq::Error::Status(code, r)) if code < 500 && code != 429 => return Err(Error::Http(code, r.into_string().unwrap_or_default())),
				Err(e) => last = e.to_string(),
			}
		}
		Err(Error::Config(format!("a part failed three times: {last}")))
	}

	pub fn post_form(&self, rest: &str, fields: &[(String, String)], file: Option<&[u8]>) -> Result<Value, Error> {
		let boundary = format!("gorani{}", crate::new_item_id().replace(['-', '_'], "0"));
		let mut body = Vec::new();
		for (k, v) in fields {
			body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").as_bytes());
		}
		if let Some(sealed) = file {
			body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sealed.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
			body.extend_from_slice(sealed);
			body.extend_from_slice(b"\r\n");
		}
		body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
		Self::answer(self.req("POST", rest).set("Content-Type", &format!("multipart/form-data; boundary={boundary}")).send_bytes(&body))
	}
}

/// The registry's word on who this token is — which must be THIS machine's
/// registration (the same id, the same key): a token moved to another
/// machine, or a registration of another key, stops here.
pub fn whoami(c: &CollectClient) -> Result<Value, Error> {
	let me = c.get("/whoami")?;
	if me["id"].as_str() != Some(c.o.profile.id.as_str()) {
		return Err(Error::Config(format!("this service token is registered as collector {}, not {} — check the token or the profile", me["id"].as_str().unwrap_or("?"), c.o.profile.id)));
	}
	if me["keyId"].as_str() != Some(c.o.profile.key_id.as_str()) {
		return Err(Error::Config("this collector is registered with ANOTHER identity key than this machine's — the leads must register the key `collector init` printed here".into()));
	}
	Ok(me)
}

/// The inbox key a drop seals to, checked.
pub struct InboxKey {
	pub key_id: String,
	pub public: VaultPublicKey,
	pub signed_by: String,
	pub kind: String,
}

/// Fetch the case's current inbox key and believe it only if a manager the
/// pins vouch for signed it — pinned, or certified by a pinned lead (one
/// hop, identity.rs › trust_rules). The registry serves the identities;
/// the pins decide.
pub fn inbox_key(c: &CollectClient, case: &str) -> Result<InboxKey, Error> {
	let v = c.get(&format!("/cases/{case}/inbox-key"))?;
	let registry: Vec<RegistryIdentity> = serde_json::from_value(v["identities"].clone()).map_err(|_| Error::Format("the identities"))?;
	let pins = resolve_pins(&c.o.profile.pins, &registry);
	let trust = identity::trust_rules(&format!("collector:{}", c.o.profile.id), &pins, &registry);
	let k = &v["key"];
	let key_id = k["keyId"].as_str().unwrap_or_default().to_string();
	let signed_by = k["signedBy"].as_str().unwrap_or_default().to_string();
	let ec: Jwk = serde_json::from_value(k["publicKey"]["ec"].clone()).map_err(|_| Error::Format("the inbox key's EC half"))?;
	let kem_b64 = k["publicKey"]["kem"].as_str().unwrap_or_default();
	let kem = crate::decode(kem_b64)?;
	let digest = identity::hybrid_digest(&identity::ec_raw_of_jwk(&ec)?, &kem);
	let Some(signer) = trust.of(&signed_by) else {
		return Err(Error::Open("the case's inbox key was signed by someone this collector's pins do not vouch for — refusing to seal anything to it (pin the lead, or ask a lead you pinned to certify the case's manager)"));
	};
	if !signer.verify(&stmt("gorani-inbox-v1", &[case.as_bytes(), digest.as_bytes()]), k["signature"].as_str().unwrap_or_default()) {
		return Err(Error::Open("the inbox key's signature does not verify — it is not the key its manager made; refusing to seal anything to it"));
	}
	let public = VaultPublicKey::from_jwk(&ec.x, &ec.y, Some(kem_b64)).map_err(|_| Error::Format("the inbox key"))?;
	if formats::key_id(&public) != key_id {
		return Err(Error::Open("the inbox key's id is not its key's"));
	}
	Ok(InboxKey { key_id, public, signed_by, kind: v["kind"].as_str().unwrap_or_default().to_string() })
}

/// Pins by fingerprint become pins by full key id — the registry entry of
/// that member whose id STARTS with the pinned digits (≥ 128 bits).
fn resolve_pins(pins: &[Pin], registry: &[RegistryIdentity]) -> Vec<Pin> {
	pins.iter()
		.filter_map(|p| registry.iter().find(|e| e.member == p.member && p.key_id.len() >= 32 && e.key_id.starts_with(&p.key_id)).map(|e| Pin { member: p.member.clone(), key_id: e.key_id.clone() }))
		.collect()
}

/// What the collector says about an item (signed, then sealed).
pub struct Intake {
	pub name: String,
	pub mime: String,
	pub source: String,
	pub method: String,
	pub collected_at: String,
	pub notes: String,
}

/// The collector's statement (inbox.ts › inboxStatements.collect).
#[allow(clippy::too_many_arguments)]
pub fn collect_statement(case: &str, item: &str, collector: &str, sha256: &str, size: u64, i: &Intake) -> Vec<u8> {
	stmt(
		"gorani-collect-v1",
		&[case.as_bytes(), item.as_bytes(), collector.as_bytes(), sha256.as_bytes(), size.to_string().as_bytes(), i.name.as_bytes(), i.mime.as_bytes(), i.source.as_bytes(), i.method.as_bytes(), i.collected_at.as_bytes(), i.notes.as_bytes()],
	)
}

/// Files up to this size go whole, larger as GC01 frames (as a member's push).
const WHOLE_LIMIT: u64 = 48 * 1024 * 1024;

/// The result of a drop.
pub struct Dropped {
	pub item: String,
	pub size: u64,
	pub sha256: String,
	pub inbox_key_id: String,
	pub parts: u64,
}

/// Drop a file into a case's inbox (steps 1–5 of the module's sketch).
pub fn collect(o: &Opened, case: &str, path: &Path, intake: &Intake, item: Option<String>, log: &Path) -> Result<Dropped, Error> {
	for (what, v) in [("source", &intake.source), ("method", &intake.method), ("collected-at", &intake.collected_at)] {
		if v.trim().is_empty() {
			return Err(Error::Config(format!("--{what} is required: an item says where it came from, how and when")));
		}
	}
	let c = CollectClient::new(o);
	whoami(&c)?;
	let inbox = inbox_key(&c, case)?;
	let item = item.unwrap_or_else(crate::new_item_id);
	let size = std::fs::metadata(path)?.len();
	let (sha256, hashed) = crate::transfer::sha256_file(path)?;
	if hashed != size {
		return Err(Error::Config("the file changed while it was being read".into()));
	}
	let signature = o.sign(&collect_statement(case, &item, &o.profile.id, &sha256, size, intake));
	let meta = json!({
		"case": case, "item": item, "collector": o.profile.id,
		"name": intake.name, "type": intake.mime, "size": size, "sha256": sha256,
		"source": intake.source, "method": intake.method, "collectedAt": intake.collected_at, "notes": intake.notes,
		"signature": signature,
	});
	let ck = formats::new_content_key();
	let key = formats::import_content_key(&ck);
	let mut fields: Vec<(String, String)> = vec![
		("item_id".into(), item.clone()),
		("inbox_key_id".into(), inbox.key_id.clone()),
		("size".into(), size.to_string()),
		("ck".into(), formats::wrap_content_key(&inbox.public, &key)),
		("meta".into(), formats::seal_text(&inbox.public, &meta.to_string())),
		("stamp".into(), identity::stamp_imprint(&signature)?),
	];
	let base = format!("/cases/{case}/items");
	let parts = if size <= WHOLE_LIMIT {
		let bytes = Zeroizing::new(std::fs::read(path)?);
		if bytes.len() as u64 != size {
			return Err(Error::Config("the file changed while it was being read".into()));
		}
		c.post_form(&base, &fields, Some(&formats::seal_with(&key, &bytes)))?;
		1
	} else {
		let chunk = gorani_formats::chunked::chunk_for(size).ok_or(Error::Config("an item is at most 255 GiB".into()))?;
		let count = gorani_formats::chunked::frame_count(size, chunk);
		let plan = c.post_json(&format!("{base}/uploads"), json!({ "itemId": item, "size": size, "chunk": chunk }))?;
		let upload = plan["uploadId"].as_str().unwrap_or_default().to_string();
		if plan["parts"].as_u64() != Some(count) {
			return Err(Error::Config(format!("the server planned {} parts for {count} frames", plan["parts"])));
		}
		let mut f = std::fs::File::open(path)?;
		let mut buf = Zeroizing::new(vec![0u8; chunk as usize]);
		let mut etags = Vec::new();
		for i in 0..count {
			use std::io::Read;
			let want = if i == count - 1 { (size - i * chunk) as usize } else { chunk as usize };
			f.read_exact(&mut buf[..want])?;
			let frame = gorani_formats::chunked::seal_chunk(&key, &buf[..want], i, i == count - 1);
			etags.push(json!({ "partNumber": i + 1, "etag": c.put_part(&format!("{base}/uploads/{upload}/{}", i + 1), &frame)? }));
		}
		fields.push(("chunk".into(), chunk.to_string()));
		fields.push(("parts".into(), Value::Array(etags).to_string()));
		c.post_form(&format!("{base}/uploads/{upload}/complete"), &fields, None)?;
		count
	};
	append_log(log, &json!({ "at": now_iso(), "case": case, "item": item, "name": intake.name, "size": size, "sha256": sha256, "inboxKey": inbox.key_id, "inboxKeySignedBy": inbox.signed_by, "stamp": identity::stamp_imprint(&signature)? }))?;
	Ok(Dropped { item, size, sha256, inbox_key_id: inbox.key_id, parts })
}

/// This machine's own record of what it sent — one JSON line per drop,
/// append-only from here. It holds the SHA-256 in the clear: it is the
/// collector's log, on the collector, as sensitive as the evidence it saw.
fn append_log(path: &Path, line: &Value) -> Result<(), Error> {
	use std::io::Write;
	let mut opts = std::fs::OpenOptions::new();
	opts.append(true).create(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		opts.mode(0o600);
	}
	let mut f = opts.open(path)?;
	writeln!(f, "{line}")?;
	Ok(())
}

fn now_iso() -> String {
	// Seconds since the epoch as UTC, without a date crate: civil-from-days.
	let s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
	let (days, rem) = (s.div_euclid(86_400), s.rem_euclid(86_400));
	let z = days + 719_468;
	let era = z.div_euclid(146_097);
	let doe = z - era * 146_097;
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = doy - (153 * mp + 2) / 5 + 1;
	let m = if mp < 10 { mp + 3 } else { mp - 9 };
	let y = yoe + era * 400 + i64::from(m <= 2);
	format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Where the log sits: beside the profile.
pub fn log_path(profile: &Path) -> PathBuf {
	profile.with_extension("log")
}

#[cfg(test)]
mod tests {
	use super::*;

	fn fresh(pins: &str) -> (CollectorProfile, Introduction) {
		init(Init { server: "http://x", id: "edr-1", pins: parse_pins(pins).unwrap(), access_id: Some("abc.access".into()), access_secret: Some(Zeroizing::new("s3cret".into())), dev_collector: None, want: devicekey::Want::FILE, tpm: &devicekey::TpmOptions::default() }).unwrap()
	}

	#[test]
	fn a_profile_opens_and_signs_with_the_key_it_introduced() {
		let (p, intro) = fresh("ana:0123456789abcdef0123456789abcdef");
		assert_eq!(intro.key_id, p.key_id);
		let o = open(p).unwrap();
		assert_eq!(o.access_secret.as_deref().map(|s| s.as_str()), Some("s3cret"));
		let sig = o.sign(b"statement");
		assert_eq!(crate::decode(&sig).unwrap().len(), 64, "P1363, as WebCrypto");
	}

	#[test]
	fn an_edited_profile_is_refused() {
		let (p, _) = fresh("ana:0123456789abcdef0123456789abcdef");
		for edit in [
			|p: &mut CollectorProfile| p.pins.push(Pin { member: "mallory".into(), key_id: "f".repeat(64) }),
			|p: &mut CollectorProfile| p.server = "https://elsewhere.example".into(),
			|p: &mut CollectorProfile| p.id = "edr-2".into(),
			|p: &mut CollectorProfile| p.dev_collector = Some("x".into()),
		] {
			let mut q = p.clone();
			edit(&mut q);
			assert!(open(q).err().unwrap().to_string().contains("does not verify"));
		}
		// A profile whose protector is another machine's (another secret) fails the same way.
		let (other, _) = fresh("ana:0123456789abcdef0123456789abcdef");
		let mut q = p.clone();
		q.protectors = other.protectors;
		assert!(open(q).is_err());
	}

	#[test]
	fn pins_parse_from_fingerprints_and_resolve_to_full_ids() {
		let pins = parse_pins("ana:3F2A 9C1B 0000 1111 2222 3333 4444 5555").unwrap();
		assert_eq!(pins[0].key_id, "3f2a9c1b000011112222333344445555");
		assert!(parse_pins("ana:3f2a").is_err(), "too short to be a fingerprint");
		assert!(parse_pins("ana").is_err());
		let reg = |member: &str, key_id: &str| RegistryIdentity { member: member.into(), key_id: key_id.into(), public_key: Jwk { x: String::new(), y: String::new(), kty: None, crv: None }, root_digest: String::new(), signature: String::new(), active: None, certs: vec![] };
		let full = format!("3f2a9c1b000011112222333344445555{}", "e".repeat(32));
		let registry = vec![reg("ana", &full), reg("bo", &full)];
		let resolved = resolve_pins(&pins, &registry);
		assert_eq!(resolved.len(), 1, "only the pinned member's entry");
		assert_eq!(resolved[0].key_id, full);
		assert!(resolve_pins(&parse_pins("ana:0000000000000000000000000000000f").unwrap(), &registry).is_empty(), "other digits match nothing");
	}

	#[test]
	fn the_clock_prints_iso_8601() {
		let t = now_iso();
		assert_eq!(t.len(), 20);
		assert!(t.ends_with('Z') && t.as_bytes()[10] == b'T');
	}
}
