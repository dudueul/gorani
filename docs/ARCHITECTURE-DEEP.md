# Architecture deep-dive (with diagrams)

> Copyright 2026- Seongwoo Hong. All rights reserved.
> Companion to ARCHITECTURE.md — the flows, drawn. Diagrams are Mermaid (they render on GitHub).

## 1. The whole system, one picture

```mermaid
flowchart LR
    subgraph clients[Trust zone: family devices]
        W[Browser SPA<br/>Lit + WebCrypto<br/>non-extractable keys]
        N[Native clients<br/>gorani-sync / shells<br/>Rust, Zeroizing keys]
    end
    subgraph edge[Trust zone: Cloudflare]
        A[Cloudflare Access<br/>JWT verified in-worker<br/>fail-closed]
        WKR[Gorani Worker<br/>Rust → wasm32<br/>never decrypts]
        subgraph dos[State]
            F[GoraniFamilyDO<br/>registry + master pub]
            M[GoraniMemberDO<br/>per member: vault, files,<br/>journal, devices, shares]
        end
    end
    subgraph storage[Trust zone: object storage]
        S3[(MinIO / R2 / any S3<br/>ciphertext only)]
    end
    W -- "GV-sealed bytes<br/>HTTPS + Access" --> A --> WKR
    N -- "sealed bytes<br/>HTTPS + Access" --> A
    WKR -- "ciphertext<br/>SigV4 or R2 binding" --> S3
    WKR <--> dos
```

**Storage priority** (section 3's step W→S): if the deployment binds an R2
bucket, every object operation is an in-process call into R2 — no signing,
no HTTP hop, no egress — and the SigV4 adapter serves any other
S3-compatible endpoint when no binding exists. One contract, two
transports, chosen at boot (`worker/src/s3.rs › r2_bucket`). Reads add an edge
cache (`worker/src/cache.rs`): whole-object entries for small blobs (the
platform slices Ranges itself) and deterministic frame-span entries for
GC01 media — keyed by storage span, immutable by construction, ciphertext
only. The same trust rule as everywhere else: the edge never learns a
plaintext byte.

**Read the zones, not the boxes**: a device and the object storage never
talk directly; the Worker sees only ciphertext; the DOs hold structure
plus sealed text. The one thing that turns plaintext into ciphertext is
always in the leftmost zone.

## 2. Unlock: three ways to the same root

```mermaid
sequenceDiagram
    participant U as Member
    participant B as Browser (Lit)
    participant D as MemberDO

    U->>B: pick member, choose method
    alt passkey
        B->>U: WebAuthn ceremony (Face ID / PIN)
        U-->>B: PRF output (256-bit, never leaves device)
        B->>B: KEK = HKDF(PRF, salt, "gorani-passkey-v1")
    else password
        B->>B: KEK = Argon2id(password, salt, 64 MiB)
    else recovery code
        B->>B: KEK = HKDF(code, salt, "gorani-recovery-v1")
    end
    B->>B: GW01-open(KEK, methods[kind].wrapped) → root bundle (bytes, an instant)
    B->>B: importKey NON-EXTRACTABLE → session root
    B->>B: wipe bundle bytes
    B->>D: GET vault (already fetched) — server taught nothing new
    opt "stay unlocked"
        B->>B: device hold = AES-GCM(non-extractable device key, root bundle) in IndexedDB
    end
```

Every unlock method derives a KEK from a secret the server never sees; the
server stores only GW01-wrapped copies. Locking drops the session and (if
held) the device key.

## 3. Upload and the sealed-in boundary

```mermaid
sequenceDiagram
    participant B as Browser / CLI
    participant W as Worker (Rust)
    participant D as MemberDO
    participant S as MinIO (S3)

    B->>B: file id = 128 random bits (chosen FIRST — the places name it)
    B->>B: content key = 32 random bytes
    B->>B: object = GV02(key, bytes) — or GC01 frames if > 48 MB
    B->>B: name/type/ck = GV04(store key, place = file id [+ version 1])
    B->>W: POST files (multipart: file_id + sealed object + placed name/type/key)
    W->>W: CHECK: id shape · bytes start GV02 · names are GV04 · size honest
    W->>S: PutObject(files/<m>/<id>/v-<uuid>, ciphertext)
    W->>D: INSERT files + file_versions (owner = first uploader, contributors trail)
    D-->>D: triggers: journal ← file.put + version.put (one counter)
    W-->>B: { id, version }
    Note over W,S: the server held ciphertext and stored ciphertext —<br/>it never had a key that opens anything
```

The refusal path matters as much: unsealed bytes or plain names are
rejected with 400 **before** anything is stored — the zero-trust boundary
is enforced, not promised.

## 4. Download and streaming playback

```mermaid
sequenceDiagram
    participant P as Player (browser <video>)
    participant SW as Media SW (scope /media/)
    participant W as Worker
    participant S as MinIO

    P->>SW: GET /media/<id> Range: bytes=a-b (native player chooses)
    SW->>SW: map plaintext range → whole GC01 frames
    SW->>W: GET files/<id> Range: ciphertext frames
    W->>S: GetObject (Range passthrough)
    S-->>W: ciphertext frames
    W-->>SW: ciphertext (the worker can't decrypt)
    SW->>SW: decrypt frame by frame (content key from the page, cloned non-extractable)
    SW-->>P: 206, plaintext bytes, honest Content-Range
    Note over P,SW: the browser's own player parses the MP4 and seeks —<br/>no MSE, no box surgery, no DRM
```

## 5. The family hierarchy (why the denials hold)

```mermaid
flowchart TB
    subgraph parents[Parents' roots]
        PR1[Mom root] --> PM1[master priv, sealed GV03]
        PR2[Dad root] --> PM2[master priv, sealed GV03]
    end
    PM["parents' MASTER key pair"] --- PM1 & PM2
    MPub[master PUBLIC half] -- "seals each child's store PRIVATE key" --> CS1[Jinu store priv · guardian.storeSealed]
    MPub --> CS2[Sora store priv · guardian.storeSealed]
    subgraph children[Children's roots]
        CR1[Jinu root] --> K1[Jinu store priv, own copy]
        CR2[Sora root] --> K2[Sora store priv, own copy]
    end
    K1 -. cannot reach .-> PM1
    CS1 -.-> J1[Jinu's content keys]
    K1 -.-> J1
```

- A child's root opens **only** their own store + the family area.
- The master is sealed to parents' roots, never to children's — a child's
  compromise stays contained.
- Rotating the master re-seals a handful of store keys; content never
  re-encrypts. `tests/unit/family.test.mjs` walks all of it.

## 6. Backup / disaster (the container the server can't open)

```mermaid
sequenceDiagram
    participant O as Owner's browser
    participant W as Worker + MemberDO job
    participant S as MinIO

    O->>O: generate hybrid backup key → DOWNLOAD key file (private half)
    O->>W: PUT backup-key (public half only)
    W->>W: job: rows + sealed objects → GB1 writer (file key per run, sealed GV03 into header)
    W->>S: backups/<stamp>.gbak
    Note over W,S: disaster strikes
    O->>W: GET backups/<stamp>.gbak
    O->>O: GB1 reader: unwrap file key (key file) → decrypt segments → rows + sealed objects
    O->>W: POST backup/restore (rows) → fresh object keys
    O->>W: PUT restore/object?k=… (sealed objects re-landed)
    W->>D: upsert rows (ids preserved) — triggers journal, devices converge
```

## 7. Growth (the 10 GB answer)

```mermaid
flowchart LR
    A[member DO metadata] --> B{dbSize trend?}
    B -- bounded --> R[retention: journal 180d,<br/>audit cap, trash purge,<br/>dead shares removed — landed]
    B -- one member large --> C[split: GoraniFilesDO<br/>files:<member> — reserved name,<br/>feed lives with the rows]
    B -- still large --> D[shard by file-id hash,<br/>per-shard cursors]
    D -- never, ideally --> E[external SQL<br/>LAST resort: breaks<br/>trigger-colocated feed]
```

`GET …/vault-stats` reports `database_size()` — the split decision is made
on measurement.