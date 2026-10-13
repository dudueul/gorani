# Architecture: the trust map first

> Copyright 2026- Seongwoo Hong. All rights reserved.

## The one-sentence model

The server is a courier with a locked filing cabinet: it carries sealed
containers, tracks what is where, and cannot open anything — the family's
devices are the only places a key exists unwrapped.

```text
   [ Browser SPA ]──sealed bytes──▶[ Gorani Worker (Rust) ]──ciphertext──▶[ MinIO / S3 ]
         ▲                                │
         └─── wrapped keys, metadata ◀── GoraniMemberDO (SQLite, one per member)
```

## Layers

| Layer | Technology | Reads plaintext? |
|---|---|---|
| Web SPA (web/) | Lit 3 + TypeScript + Tailwind v4, static assets | Yes — your own content, in your browser, after you unlock |
| Worker (worker/) | Rust → wasm32 (workers-rs) | **Never** |
| Member database | Durable Object `GoraniMemberDO`, SQLite | Structure only (sizes, times, folder shape, ids) |
| Object storage | Any S3-compatible bucket via SigV4 | **Never** |
| Native clients (clients/) | Rust (Windows cfapi / Linux FUSE / macOS FileProvider) | Yes — on your device, after its own unlock |

## Languages, per trust zone (Lesson 2)

- **Browser — TypeScript + WebCrypto.** The vault key is imported
  *non-extractable*: page scripts can use it to open content but can never
  read its bytes. wasm crypto would hold raw key bytes in linear memory and
  give that property up — so browser crypto stays TS (@noble ML-KEM,
  hash-wasm Argon2id are the audited exceptions, used for the bytes that
  wrap *around* the key, never the key itself).
- **Worker — Rust.** Memory safety for the program that handles everyone's
  ciphertext; it shares `crates/formats` with the clients so byte layouts
  have one reference implementation.
- **Media parsing — Rust → WASM.** mp4-hls-core parses MP4 boxes and builds
  the `.hlsmeta` index. It never touches a key, so WASM is safe here.

## The member object (commit ⑥)

One `GoraniMemberDO` per family member (instance name `member:<id>`), SQLite
via `new_sqlite_classes`: vault settings (public keys + wrapped private
copies), files/folders/versions, a change feed (every row change takes the
next cursor via SQLite triggers), 180-day journal for point-in-time restore,
devices, shares, music metadata, audit log. A future `GoraniFilesDO` split
follows Mailflare's `files-home` pattern when one member's store outgrows
its object; the name is reserved, the split is documented but not built.

## Failure

The Worker aborts on panic (kill + clean restart rather than serve a broken
answer), refuses any unsealed byte or name before storing it, and fails
closed when Cloudflare Access is not configured in production. The bucket is
private; the Worker holds its S3 keys in secrets; clients never see them.

## What is deliberately NOT here

- No SSR, no server-rendered HTML pipeline: three static files and a JSON API.
- No third-party origins anywhere: no CDN fonts, no analytics, no remote images.
- No DRM: family content is end-to-end encrypted; the MSE player plays
  bytes the family's own devices decrypted.