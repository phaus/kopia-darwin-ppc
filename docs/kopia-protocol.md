# Kopia API-Server Wire Protocol — Implementation Contract for a Thin C Client

Scope: kopia **v0.23.1** (source at `/tmp/kopia-src`, tag v0.23.1). Target: a minimal C client running on
Mac OS X 10.5 (PowerPC) that backs up directories and creates snapshots on an existing kopia server started as:

```
kopia server start --address 0.0.0.0:51515 --server-username myuser --server-password ... --tls-cert-file ...
```

The client must produce data that a **standard kopia CLI** can list and restore. Everything the server can do
(content encryption, index packs, compaction, maintenance) stays server-side.

---

## 0. Executive Summary — READ THIS FIRST

**The repository protocol of kopia ≥ 0.15 is gRPC (HTTP/2 + protobuf + TLS), not a REST/JSON API.**

- The `/api/v1/*` HTTP endpoints that still exist are the **HTML-UI API** and the **server control API**
  (`internal/server/server.go:123-190`). They can trigger/inspect server-side uploads, list sources and
  snapshots, and read objects — but they have **no endpoint to write contents or manifests**. A backup client
  cannot use them to upload data (`/api/v1/sources/upload` only triggers the server's own source managers for
  server-local paths, `internal/server/api_snapshots.go:196-198`).
- All content/manifest writes go through a single bidirectional gRPC stream:
  **`kopia_repository.KopiaRepository/Session`** (`internal/grpcapi/repository_server.proto`,
  registered at `internal/server/grpc_session.go:622-625`).
- The gRPC service is multiplexed onto the same TCP port as the UI: the router dispatches to gRPC when
  `ProtoMajor == 2 && Content-Type: application/grpc` (`internal/server/grpc_session.go:639-659`). It is
  enabled by default (`--grpc` default `true`, `cli/command_server_start.go:93`).
- There is **no h2c fallback** anywhere in the codebase — gRPC requires TLS (the client creds also hard-require
  it: `repo/grpc_repository_client.go:850-853`). Plaintext mode (`--insecure`) cannot carry gRPC
  (Go's `http.Server` does not serve cleartext HTTP/2 without an h2c wrapper; kopia has none).
- Consequently the C client must implement: **TLS ≥ 1.2 (ALPN `h2`), HTTP/2 framing, protobuf encoding of one
  small message set, and the buzhash32 chunk splitter**. It does **not** need: AES, scrypt, pack formats,
  index encoding, compression (optional; `0` = none is accepted).

**What the client sends is plaintext.** The server computes content IDs, encrypts, packs, and indexes
(`internal/server/grpc_session.go:279-304` → `repo/content`). The client only needs the *hash function*
(optionally, for local dedup/verification) — it receives `hash_function` + `hmac_secret` in the session
handshake but may equally use the content ID returned by the server.

---

## 1. Transport & Authentication

### 1.1 Base URL and paths

- Client connects to `https://host:port` (the `kopia://` and `unix+https://` schemes are aliases;
  `repo/grpc_repository_client.go:896-910`). The gRPC path is
  **`/kopia_repository.KopiaRepository/Session`** (proto package `kopia_repository`, service `KopiaRepository`,
  method `Session`, `internal/grpcapi/repository_server.proto`).
- There is **no `/api/v1/version` and no REST handshake endpoint**. The handshake is the first message *inside*
  the gRPC stream (see §2.3). The only REST endpoints a client might optionally use are:
  - `GET /api/v1/control/status` — server/repository status (control API, Basic auth as `--server-username`)
    (`internal/server/server.go:181`).
  - `POST /api/v1/control/flush` — flush the server's own writers (not needed by the gRPC client;
    `internal/server/server.go:182`).
  - `GET /api/v1/objects/{objectID}` — read an object (restore path only; `internal/server/server.go:138`).
  Full route table: `internal/server/server.go:123-190`.

### 1.2 TLS requirements

- **Server side, PEM files provided** (the scenario above): `http.Server.ServeTLS(l, certFile, keyFile)` with
  `httpServer.TLSConfig == nil` (`cli/command_server_start.go:230-238`, `cli/command_server_tls.go:120-136`).
  Go (this release targets `go 1.25.8`, `go.mod:3`) defaults a *server* to **minimum TLS 1.2, maximum TLS 1.3**
  (Go ≥ 1.22 server default). Only the in-memory generated-cert path sets an explicit `MinVersion: TLS 1.3`
  (`cli/command_server_tls.go:146`).
  → **The client must support TLS 1.2** (ALPN must offer `h2`; Go's server negotiates ALPN automatically for
  HTTP/2). On OS X 10.5 PPC this requires an OpenSSL ≥ 1.0.1 build (TLS 1.2 + ALPN, e.g. ECDHE-RSA-AES128-GCM).
  TLS 1.0-capable stacks (system OpenSSL 0.9.8) **will fail the handshake**.
- **Client side, how kopia itself trusts the server:** certificate *pinning* by SHA-256 of the DER-encoded leaf
  certificate — `InsecureSkipVerify: true` plus `VerifyPeerCertificate` comparing `sha256(cert.Raw)` against the
  configured lowercase hex fingerprint (`internal/tlsutil/tlsutil.go:130-160`). The fingerprint is stored in the
  local config as `serverCertFingerprint` (`repo/api_server_repository.go:12-17`) and supplied via
  `kopia repository connect server --server-cert-fingerprint` (`cli/command_repository_connect_server.go:44-49`).
  → A C client can do the same: `SHA256(der_cert)` must equal the pinned fingerprint; no CA validation needed.
  The server prints its fingerprint as `SERVER CERT SHA256: <hex>` when it generates a cert itself
  (`cli/command_server_tls.go:103,156`); for a provided cert, compute it from the PEM file.

### 1.3 Authentication model — two *different* credential systems

**A) gRPC repository access (what the backup client uses).** Per-RPC gRPC *metadata*, sent as HTTP/2 headers on
the `Session` call (`repo/grpc_repository_client.go:835-853`):

```
kopia-hostname: <client hostname>     (e.g. "my-mac")
kopia-username: <user part>           (e.g. "myuser")
kopia-password: <password>
kopia-version:  <build version string>   (informational)
kopia-build-info: <build info>           (informational)
kopia-repo: github.com/kopia/kopia      (informational)
kopia-os: <os>   kopia-arch: <arch>     (informational)
```

The server concatenates `kopia-username + "@" + kopia-hostname` and validates the pair against the
**authenticator chain** (`internal/server/grpc_session.go:63-85`). The chain contains:

1. `AuthenticateSingleUser(--server-username, --server-password)` — matches the **literal string** equal to
   `--server-username` (`cli/command_server_start.go:366-367`, `internal/auth/authn.go:37-48`). Because the
   gRPC username is always `user@host`, this authenticator **only matches if `user@host == "--server-username"`**
   — practically only when the client sends an *empty* `kopia-hostname` and `kopia-username` equal to the flag.
   → In the scenario (`--server-username myuser`), gRPC access does **not** work out of the box this way.
2. `AuthenticateRepositoryUsers()` — user accounts stored **in the repository** as manifests of type `"user"`
   (`internal/auth/authn_repo.go:27-68`, `internal/user/user_manager.go:17-18`), created with
   `kopia server user add myuser@my-mac --user-password ...`. Password check is scrypt-based and runs
   **server-side** (`internal/user/user_profile.go:59-70`). Profiles are cached ~10 s.

**→ Setup required for the C client:** `kopia server user add <user>@<client-host> --user-password <pw>`
(or send `kopia-username=control`, `kopia-hostname=""` … which still needs the string `control@` — don't; just
create the repo user). `--server-username`/`--server-password` are only the **HTTP Basic-auth** credentials for
the UI (`/api/v1/...`, realm `Kopia`, `internal/server/server.go:197-249`) and the control API
(`requireServerControlUser`, `internal/server/server.go:330-344`).

**Authorization** after login: `auth.DefaultAuthorizer()` evaluates ACLs
(`internal/auth/authz_acl.go:168-171`). The default ACLs grant: content append to `*@*`, and **full access to
snapshots whose labels match the caller's own username+hostname** (`internal/auth/authz_acl.go:60-66`).
So the client user must label snapshots with its own `username`/`hostname`, or writes are rejected with
`ACCESS_DENIED` (`internal/server/grpc_session.go:283-285, 352-354`).

**B) How the standard CLI connects** (`kopia repository connect server`): writes `APIServerInfo{url,
serverCertFingerprint, localCacheKeyDerivationAlgorithm}` into the config file
(`cli/command_repository_connect_server.go:36-56`, `repo/api_server_repository.go:12-17`), then opens the same
gRPC client with `--override-username`/`--override-hostname` (or OS defaults) and prompts for the *repository
user* password (`cli/command_repository_connect_server.go:60-79` → `repo.ConnectAPIServer` →
`openGRPCAPIRepository`, `repo/grpc_repository_client.go:856-894`). There is **no token/session-ticket
mechanism** — every gRPC call carries the three headers; there is no cookie, no HMAC token, no OAuth flow.

### 1.4 gRPC wire-level requirements

- HTTP/2 POST to `/kopia_repository.KopiaRepository/Session`, `content-type: application/grpc`, `te: trailers`.
- Messages framed as: 1 byte compression flag (0) + 4 bytes big-endian length + protobuf bytes.
- Max message size both ways: **20 MiB** (`repo.MaxGRPCMessageSize = 20 << 20`,
  `repo/grpc_repository_client.go:34-37`; server sets the same limits in `GRPCRouterHandler`).
- It is a **bidi stream**: client sends `SessionRequest`, server answers with `SessionResponse` carrying the
  same `request_id`. Request IDs are client-allocated starting at 1 and incrementing
  (`repo/grpc_repository_client.go:146-195`). The **first** request on the stream must be
  `InitializeSession`, else the server errors (`internal/server/grpc_session.go:208-209, 589-607`).
- `has_more = true` on a response means more responses for the same `request_id` follow (used only by
  `FindManifests` pagination, `internal/server/grpc_session.go:370-400`).
- Errors come either as gRPC status (auth/stream failures: `PermissionDenied`, `Unavailable`) or as
  `ErrorResponse` inside a `SessionResponse` (`internal/server/grpc_session.go:535-569`).

---

## 2. Repository / Manifest API Surface (the gRPC protocol)

Complete message set from `internal/grpcapi/repository_server.proto`. Field numbers are the wire contract.

### 2.1 Session envelope

```protobuf
message SessionRequest {
  int64 request_id = 1;
  map<string,string> trace_context = 2;     // optional W3C traceparent; may be omitted
  oneof request {
    InitializeSessionRequest initialize_session = 10;
    GetContentInfoRequest get_content_info = 11;
    FlushRequest flush = 12;
    WriteContentRequest write_content = 13;
    GetContentRequest get_content = 14;
    GetManifestRequest get_manifest = 15;
    PutManifestRequest put_manifest = 16;
    FindManifestsRequest find_manifests = 17;
    DeleteManifestRequest delete_manifest = 18;
    PrefetchContentsRequest prefetch_contents = 19;
    ApplyRetentionPolicyRequest apply_retention_policy = 20;
    SendNotificationRequest send_notification = 21;
  }
}

message SessionResponse {
  int64 request_id = 1;
  bool has_more = 3;
  oneof response {
    ErrorResponse error = 2;                 // code: UNKNOWN_ERROR=0, CLIENT_ERROR=1, CONTENT_NOT_FOUND=2,
                                             // MANIFEST_NOT_FOUND=3, OBJECT_NOT_FOUND=4, ACCESS_DENIED=5,
                                             // STREAM_BROKEN=6
    InitializeSessionResponse initialize_session = 10;
    GetContentInfoResponse get_content_info = 11;
    FlushResponse flush = 12;
    WriteContentResponse write_content = 13;
    GetContentResponse get_content = 14;
    GetManifestResponse get_manifest = 15;
    PutManifestResponse put_manifest = 16;
    FindManifestsResponse find_manifests = 17;
    DeleteManifestResponse delete_manifest = 18;
    PrefetchContentsResponse prefetch_contents = 19;
    ApplyRetentionPolicyResponse apply_retention_policy = 20;
    SendNotificationResponse send_notification = 21;
  }
}
```

### 2.2 Endpoints needed by a backup-only client

| Purpose | Request → Response | Server handler |
|---|---|---|
| Session init | `InitializeSessionRequest` → `InitializeSessionResponse` | `grpc_session.go:589-607` |
| Write one content (chunk) | `WriteContentRequest{prefix, data, compression}` → `WriteContentResponse{content_id}` | `grpc_session.go:279-304` |
| Flush everything to storage | `FlushRequest{}` → `FlushResponse{}` | `grpc_session.go:306-321` |
| Put snapshot manifest | `PutManifestRequest{json_data, labels}` → `PutManifestResponse{manifest_id}` | `grpc_session.go:348-366` |
| (optional) dedup probe | `GetContentInfoRequest{content_id}` → `GetContentInfoResponse{info}` | `grpc_session.go:216-250` |
| (optional) verify/dedup | `FindManifestsRequest{labels, page_size}` → `FindManifestsResponse` | `grpc_session.go:370-400` |

**Not needed for backup** (client MAY ignore): `GetContentRequest` (restore), `GetManifestRequest` /
`DeleteManifestRequest` (GC/retention), `PrefetchContentsRequest` (cache hint), `ApplyRetentionPolicyRequest`,
`SendNotificationRequest`.

```protobuf
message InitializeSessionRequest  { string purpose = 1; bool read_only = 2; }
message InitializeSessionResponse { RepositoryParameters parameters = 1; }

message RepositoryParameters {          // sent by server after auth (grpc_session.go:597-603)
  string hash_function = 1;             // e.g. "BLAKE2B-256-128"
  bytes  hmac_secret  = 2;              // raw key bytes for the hash function
  string splitter     = 3;              // e.g. "DYNAMIC-4M-BUZHASH"
  bool   supports_content_compression = 4;
}

message WriteContentRequest  { string prefix = 1; bytes data = 2; uint32 compression = 3; }
message WriteContentResponse { string content_id = 1; }

message PutManifestRequest  { bytes json_data = 1; map<string,string> labels = 2; }
message PutManifestResponse { string manifest_id = 1; }

message GetContentInfoRequest  { string content_id = 1; }
message GetContentInfoResponse { ContentInfo info = 1; }

message ContentInfo {   // mirrors content.Info; informational
  string id = 1; uint32 packed_length = 2; int64 timestamp_seconds = 3;
  string pack_blob_id = 4; uint32 pack_offset = 5; bool deleted = 6;
  uint32 format_version = 7; uint32 original_length = 8;
}
```

Semantics notes:

- `purpose` is a free-form string (the CLI uses `"cli:snapshot-create"` etc.); `read_only=false` for backup.
- `prefix` must be "" (user data) or one letter `'g'..'z'` (`repo/content/index/id.go:22-29`). Sending prefix
  `"m"` is refused (`internal/server/grpc_session.go:287-290`).
- `compression` is a compression header ID or **0 = no compression** (`repo/content/content_manager.go:37`).
  IDs (`repo/compression/compression_ids.go:12-36`): gzip `0x1000..0x1002`, zstd `0x1100..0x1103`
  (`0x1101` = zstd-fastest, kopia's default *metadata* compressor), S2 `0x1200..`, pgzip `0x1300..`,
  deflate `0x1500..`. Compression is optional and transparent on read — a thin client may always send 0.
- **WriteContent is idempotent**: the server dedups by content ID and returns the same ID
  (`repo/content/content_manager.go:789-830`). The Go client additionally does a `GetContentInfo` round-trip
  for chunks ≥ 50 000 bytes before writing (`repo/grpc_repository_client.go:41-42,723-749`) — optional.
- `PutManifest` requires the `"type"` label (`repo/manifest/manifest_manager.go:73-76`) and returns a
  **random 16-byte hex** manifest ID (`repo/manifest/manifest_manager.go:77-88` —
  `manifestIDLength = 16`, hex-encoded; note: *not* a content ID). The manifest body itself is stored by the
  **server** as a content with prefix `"m"` (`repo/manifest/manifest_manager.go:36`), encrypted like any other
  content. `GetManifestResponse.json_data` is the exact JSON that was stored.

---

## 3. Where Encryption Happens in API-Server Mode

**Server-side. The client sends plaintext.**

- The server's `WriteContent` handler calls `dw.ContentManager().WriteContent(...)` directly
  (`internal/server/grpc_session.go:292`) → `repo/content/content_manager.go:789-830`, which:
  1. computes `contentID = IDFromHash(prefix, hashData(data))`
     (`repo/content/content_manager_lock_free.go:194-203`),
  2. compresses if `comp != 0` (index v2 only; `content_manager_lock_free.go:41-70`),
  3. **encrypts** with the repository key and IV derived from the content ID
     (`content_manager_lock_free.go:30-35`, `getPackedContentIV`), then appends to pack blobs
     (`p` = regular, `q` = special/prefixed, `repo/content/content_manager.go:34-35,733-737`).
- Same for manifests: `PutManifest` handler → `dw.PutManifest` → manifest JSON becomes an encrypted
  `"m"`-prefixed content (`internal/server/grpc_session.go:348-366`).
- Packing, index-blob writing, compaction and maintenance all happen inside the server's content manager.
  **NOT NEEDED on the client**: encryption, pack format, index format, sessions (`"s"`-prefixed *blobs* are
  server session markers, `repo/content/sessions.go:20-22`), compaction, epoch management.

### 3.1 Content ID format (what `WriteContentResponse.content_id` looks like)

`content_id = <prefix><lowercase hex of hash>` (`repo/content/index/id.go:100-104,168-175`):

- prefix: "" for file data chunks, `"k"` for directory-object chunks, `"x"` for indirect-index chunks,
  `"m"` for manifest contents (server-internal only).
- hash: **`hash_function(params.hmac_secret, data)`, truncated**. Default for new repositories:
  `BLAKE2B-256-128` = keyed BLAKE2B-256 with the 16-byte `hmac_secret` as key, output truncated to 16 bytes
  (`repo/hashing/hashing.go:41,66-86`; `repo/hashing/blake_hashes.go:11`) → 32 hex chars.
  HMAC-SHA256 variants give 64/32 hex chars (`repo/hashing/sha_hashes.go:10-14`).
- The hash is over the **uncompressed** data (compression happens after hashing, `content_manager_lock_free.go:30-70`).
- The Go client computes the same ID locally and verifies the server's answer
  (`repo/grpc_repository_client.go:751-780`); mismatch → hard error. **A thin C client may simply use the
  server-returned ID** and skip local hashing entirely (dedup then costs one extra write that the server
  discards). If it *does* verify, it must implement the exact keyed-hash from §3.1.

---

## 4. Object Layer (client-side)

### 4.1 Splitter — exact parameters

The splitter name arrives in `RepositoryParameters.splitter` (default new repositories:
`"DYNAMIC-4M-BUZHASH"`, `repo/splitter/splitter.go:89`). Algorithm
(`repo/splitter/splitter_buzhash32.go:26-83` + `github.com/chmduquesne/rollinghash v4.0.0 buzhash32`):

- avg = `4 MiB`; **min = avg/2 = 2 MiB; max = avg*2 = 8 MiB; mask = avg-1 = 0x3FFFFF**; window = **64 bytes**
  (`repo/splitter/splitter.go:9-10,50-75`).
- Maintain buzhash32 over a sliding 64-byte window. Initialized by hashing 64 zero bytes
  (`splitter_buzhash32.go:20-24`). For each byte `c` entering and byte `o` leaving the window
  (`Roll`, rollinghash `buzhash32.go`):

  ```
  sum = rotl32(sum, 1) ^ (table[o] <<< nRotate) ^ table[c]      // nRotate = 64 % 32 = 0
  ```

- A split point occurs **after byte i** when `sum & mask == 0`, but never before 2 MiB and always at 8 MiB at
  the latest (`splitter_buzhash32.go:26-67`). Table = `GenerateHashes(1)`: Go `rand.New(rand.NewSource(1))`,
  256 distinct `uint32` values taken from `random.Int63()` truncated to `uint32` (skipping repeats).
  **Exact table** (regenerated 2026-11-10 from the vendored library, row = 8 entries):

  ```c
  /* buzhash32 table[256], seed 1 */
  0x07fcfd52, 0x5f3f164f, 0x6695721d, 0x7b4d7c03, 0x49c6e2d1, 0x0d1d68d8, 0x7916001e, 0x22c4d294,
  0x392907a0, 0x189deb99, 0xf3875d04, 0x95e94627, 0xba517936, 0x83c471d4, 0x7cb3ad0b, 0xa42655d9,
  0x7c4e0b68, 0xd4491d1b, 0x25632186, 0xa9d78d73, 0x169c1121, 0xbb158644, 0xb68e6a3f, 0x759805f5,
  0x2cdf5b8a, 0x57d29245, 0xc5d6d268, 0x6b83d0e2, 0x7674cb74, 0xb068d9db, 0xbb9457d8, 0xa15d523b,
  0x794209ff, 0x9da1d7eb, 0x5a25e0cb, 0xf840ec4b, 0x36d4ff9b, 0xf4a5ee3b, 0x5ad145f4, 0xf6740304,
  0x3f71f8cb, 0x91018d7c, 0xfccae224, 0xb186b51f, 0x7d9e8fbc, 0x93f93f33, 0xf63a5b6f, 0x19476c36,
  0xbc897d06, 0x169873f5, 0x724c7af1, 0x581eeb39, 0x2257bb7d, 0x6f269a28, 0xbe8e9981, 0x7039374b,
  0x25416fed, 0xded7e411, 0x6678e7aa, 0x244fcd36, 0x56aa6b86, 0xde4561ad, 0x3e99b0a8, 0xbed80a3a,
  0xe58348b0, 0xaf63e58d, 0x406aec9d, 0xc233f007, 0xa5ead0bd, 0x050143a6, 0x738b6829, 0x3699caf3,
  0x967cd710, 0x06f665a6, 0x25fd3d7f, 0x0fd6e479, 0x26fbf29b, 0x16de4c35, 0x2bf3394b, 0x4af864ba,
  0x1cb9e6c6, 0x41439089, 0x69a39144, 0xc34f182d, 0x421657ff, 0xf9fc6568, 0x8b02c917, 0x6c9c64b7,
  0x83d17909, 0xea3d4ca5, 0xaf635d47, 0x7fc78769, 0xbe14186f, 0x3539b1ea, 0xe9174548, 0xc051e18a,
  0x07b73658, 0x29ec300c, 0xa250bf34, 0xa7ed5d97, 0xfe3dea79, 0xb8b352f7, 0xc9b344e9, 0x8e5f0475,
  0x1941e52a, 0x2694763d, 0x6b40eabc, 0x8485d68b, 0x336eacca, 0x4399a363, 0x67149b9c, 0xae10a901,
  0x5a5ffefb, 0x563b26de, 0x6f00f02b, 0x9f06397d, 0x545836c4, 0x31d6416b, 0x12f4128d, 0x752f33ff,
  0x4a305605, 0x0c8dc214, 0x72521a90, 0x8eb3e4a1, 0x83efc6c6, 0x090ec04f, 0xc1540864, 0xec2c8aaa,
  0x70ab53ba, 0x38d3b494, 0x878d4063, 0xa317ae3f, 0x3cb62f07, 0xf360412c, 0x4ffbf3a9, 0x22d554b4,
  0x3f190476, 0x0796a710, 0xf5c353cf, 0x04f59bb7, 0x2d230176, 0xe2d6a9ce, 0x3f1d7427, 0xafd915bb,
  0xb01aa47d, 0xcde2c269, 0x7417bf38, 0x1e094f9a, 0x55ece0ea, 0xcb94539b, 0x13d346b5, 0x54e0c0c1,
  0x6db30e37, 0xdc02b390, 0xa6e222f5, 0xe2f8c1fe, 0x2e166bdf, 0x67588a74, 0x21898f34, 0x4c330f1d,
  0x19af53ba, 0x70658b94, 0x133c9673, 0x4efeeadd, 0x0f212551, 0x070f0914, 0x6f241c57, 0xf13e41b7,
  0x3be70cb0, 0xf4b6f47f, 0x20f31127, 0x6551cb89, 0x289cbd2c, 0x8946f23d, 0x40a79c3b, 0x03c6d982,
  0x0365790c, 0x0cf52517, 0x0bb131e8, 0x3da5475c, 0x139efcca, 0xbcd44eb4, 0xa54af747, 0xb73c32ed,
  0x9f6c47ac, 0xe8ba8f22, 0x54043a66, 0x3b0a7f20, 0xb4926431, 0xe17c02d5, 0x8f0d2558, 0x014fbff2,
  0x7f803594, 0x79b76fbe, 0x33fe2656, 0x792c8ee8, 0x6b41292d, 0xfdff9c32, 0x82093298, 0x59483870,
  0xb2d5a113, 0x2dd96e5a, 0x5b8e56a9, 0xebd9dda9, 0x04f9ce92, 0xcb440950, 0xa67e52b1, 0x49f6d261,
  0x92417fc3, 0x1c3b6bd9, 0xb027b7e0, 0x1f765a41, 0x44c9ab40, 0x45d99121, 0xfd7a84af, 0x99b75788,
  0xe3abff4a, 0xa88aa67f, 0x736e41cc, 0x9cbcbe5e, 0x7b3ccebc, 0xe1b7fa93, 0x315ae6af, 0x9cced2e2,
  0x19ea0f2f, 0xa9770722, 0x84a6bfdc, 0x88f03f07, 0xa44a03a4, 0x27a6b885, 0xb580c8ba, 0x018153da,
  0xb648e604, 0x51180278, 0x893a310f, 0x728f5f4c, 0x37f5198b, 0x3cc0ea9b, 0xe39d02db, 0x13883142,
  0xca599392, 0xc12d154e, 0xc176163d, 0x5c92e2b8, 0xf9f95ede, 0xb802bdfc, 0x8a928585, 0xdca6e10b,
  0x887953e8, 0x48b9e962, 0xe533e9a3, 0x5e0ce6e5, 0x1dba77ae, 0xc8214b8a, 0x53b428d7, 0x4cf20a65,
  ```

- **Splitter choice does not affect correctness** — only dedup efficiency. The chunk boundaries are recorded in
  the object structure itself (§4.3), so a C client could even use `FIXED-4M` splitting and the resulting
  objects remain fully valid/restorable. Implementing buzhash exactly is recommended to dedup against
  future/parallel standard-kopia snapshots of the same source.

### 4.2 The object writer protocol

There is **no object-builder session API** on the server (`/api/v1/objects` is GET-only). The client drives
everything through `WriteContent` (§2.2), mirroring `repo/object/object_writer.go`:

1. Feed file bytes into the splitter; at every split point emit the accumulated buffer as one chunk.
2. For each chunk: `SessionRequest.write_content{prefix, data, compression}`; record the returned `content_id`.
3. Result object ID:
   - **1 chunk** → object ID = that chunk's content ID (`object_writer.go:289-295`).
   - **N chunks** → build an *indirect object*: JSON of `repo/object/indirect.go:4-8,14-30` written via a
     nested object writer with prefix forced to `"x"` for unprefixed objects (`object_writer.go:296-311`):
     ```json
     {"stream":"kopia:indirect","entries":[{"s":0,"l":4194304,"o":"<id1>"},{"s":4194304,"l":123,"o":"<id2>"}]}
     ```
     (`Start` tag `"s"`, `Length` tag `"l"`, both `omitempty`; `Object` tag `"o"`; final JSON has a trailing
     `\n` because the Go encoder is `json.Encoder`). The resulting object ID gets an `"I"` prefix
     (`repo/object/objectid.go:50-70`). Multi-level indirection allowed (indirect-of-indirect → `"II"`).
- Prefixes used per writer (`snapshot/snapshotfs/dir_writer.go:17-22`,
  `snapshot/snapshotfs/repofs.go:24`, `snapshot/upload/upload.go:244-252`):
  - file data: prefix `""` → contents land in `p` pack blobs;
  - directory JSON objects: prefix `"k"` → contents land in `q` (metadata) pack blobs;
  - indirect-index JSON of file objects: prefix `"x"` (forced, `object_writer.go:20,307-309`);
    for `"k"`-prefixed writers the indirect index also uses `"k"`.
- Object-level compression prefix `"Z"` only appears when compression happened at the *object* layer
  (legacy repos); with `supports_content_compression=true` compression is a per-content flag and object IDs
  stay unprefixed (`object_writer.go:186-238`).

### 4.3 Directory objects — JSON schema

A directory is one object (prefix `"k"`) containing exactly this JSON (written with `json.Encoder`, i.e. one
trailing newline; entries sorted *directories first, then by name* — `snapshot/snapshotfs/dir_manifest_builder.go:94-113`;
builder at `dir_manifest_builder.go:16-113`, writer at `dir_writer.go:16-36`):

```json
{"stream":"kopia:directory","entries":[ ... DirEntry ... ],"summary":{ ... DirectorySummary ... }}
```

`DirEntry` (`snapshot/manifest.go:121-130`):

| field | JSON | type / format |
|---|---|---|
| Name | `name` | string, `omitempty` |
| Type | `type` | `"f"` file, `"d"` dir, `"s"` symlink (`snapshot/manifest.go:44-47`) |
| Permissions | `mode` | **octal string** with leading `0`, e.g. `"0644"`; omitted when 0 (`manifest.go:49-77`) |
| FileSize | `size` | int64, `omitempty` |
| ModTime | `mtime` | UTC timestamp, **RFC 3339 with nanoseconds**, e.g. `2026-11-10T12:00:00.123456789Z` (`fs/utc_timestamp.go:10-33`) |
| UserID | `uid` | uint32 |
| GroupID | `gid` | uint32 |
| ObjectID | `obj` | string (§4.4) — **no omitempty** |
| DirSummary | `summ` | object, only for directories (`fs/entry.go:182-196`) |

`DirectorySummary` (`fs/entry.go:182-196`): `size`, `files`, `symlinks`, `dirs`, `maxTime` (UTC timestamp),
`incomplete` (string, omitempty), `numFailed`, `numIgnoredErrors` (omitempty), `errors` (first ≤10 failed
entries — `MaxFailedEntriesPerDirectorySummary = 10`, `fs/entry.go:172-173`; each `{"path":...,"error":...}`,
`fs/entry.go:176-179`). The dir's own `summary.dirs` counts itself (`+1`, `dir_manifest_builder.go:97`).

The snapshot's `rootEntry` is a `DirEntry` of the root directory with `summ` filled in.

### 4.4 Object ID formats (string form)

`repo/object/objectid.go:41-70` and `repo/content/index/id.go:100-104`:

- Single-content object: `<optional content prefix><hex hash>` — e.g. `0a1b…` (file chunk, no prefix) or
  `k9c0d…` (directory object). **The old `'k'`/`'s'` content prefixes are gone**; `'k'` survives only as the
  *object* prefix for directories, and `'s'` is a **blob** prefix for session markers (`repo/content/sessions.go:20-22`),
  never part of an object ID.
- Multi-chunk object: `"I" + <indirect object ID>` (nested → `"II…"`, `objectid.go:50-56`).
- Object-layer-compressed: `"Z"` prefix before the content ID part (`objectid.go:57-62`).
- Content prefix letters are lowercase `g..z`; the hex part is lowercase.

---

## 5. Snapshot Manifest

Written with `PutManifest` (§2.2). Labels (exact keys, `snapshot/manager.go:17-24,64-78` + `SaveSnapshot`
`snapshot/manager.go:113-146`):

```
"type"     = "snapshot"
"username" = <source user, e.g. "control">
"hostname" = <source host, e.g. "my-mac">
"path"     = <absolute source path>
```

(`username`/`hostname` must match the gRPC login `kopia-username`/`kopia-hostname` for the default ACL to grant
write access, §1.3.) Extra `tags` are merged into labels (collisions rejected). The manifest payload is the
JSON of `snapshot.Manifest` (`snapshot/manifest.go:18-35`), with `"id"` present but empty:

```json
{
  "id": "",
  "source": {"host": "my-mac", "userName": "myuser", "path": "/Users/myuser/data"},
  "description": "",
  "startTime": "2026-11-10T12:00:00.123456789Z",
  "endTime":   "2026-11-10T12:00:05.987654321Z",
  "stats": {
    "totalSize": 0, "excludedTotalSize": 0,
    "fileCount": 0, "cachedFiles": 0, "nonCachedFiles": 0,
    "dirCount": 0, "excludedFileCount": 0, "excludedDirCount": 0,
    "ignoredErrorCount": 0, "errorCount": 0
  },
  "rootEntry": {
    "name": "data", "type": "d", "mode": "0755",
    "size": 0, "mtime": "2026-11-10T11:00:00Z",
    "uid": 501, "gid": 20,
    "obj": "k<64/32 hex>",
    "summ": {"size": 1234, "files": 2, "symlinks": 0, "dirs": 1,
             "maxTime": "2026-11-10T11:00:00Z", "numFailed": 0}
  }
}
```

Field-by-field citations: `Manifest` `snapshot/manifest.go:18-35` (`id`, `source`, `description`,
`startTime`, `endTime`, `stats`, `incomplete,omitempty`, `rootEntry`, `tags,omitempty`, `pins,omitempty`);
`SourceInfo{host,userName,path}` `snapshot/source.go:12-16`; `Stats` `snapshot/stats.go:10-35`
(`totalSize`, `excludedTotalSize`, `fileCount`, `cachedFiles`, `nonCachedFiles`, `dirCount`,
`excludedFileCount`, `excludedDirCount`, `ignoredErrorCount`, `errorCount`); timestamps are
`fs.UTCTimestamp` = nanoseconds serialized as RFC 3339 UTC (`fs/utc_timestamp.go:10-33`).
`RootEntry` is the root directory's `DirEntry` (`snapshot/manifest.go:121-130`).
`SaveSnapshot` clears `id`, validates source fields, merges tags, then `PutManifest`
(`snapshot/manager.go:114-146`). The returned random manifest ID is what
`kopia snapshot list` / `kopia restore <id>` resolves.

---

## 6. Minimal Happy-Path Sequence — "back up one small file and snapshot it"

Assumes a repo user `myuser@my-mac` exists (§1.3) and the TLS cert fingerprint is pinned. One gRPC stream to
`/kopia_repository.KopiaRepository/Session` suffices; `rid` = client request counter starting at 1.

1. **TLS connect** to `host:51515` (TLS 1.2+, ALPN `h2`; verify SHA-256 pin, §1.2).
2. **Start stream**: `POST /kopia_repository.KopiaRepository/Session`, headers `content-type: application/grpc`,
   `te: trailers`, plus `kopia-username: myuser`, `kopia-hostname: my-mac`, `kopia-password: <pw>` (§1.3).
3. **Handshake** — `rid=1`: `SessionRequest{initialize_session:{purpose:"backup", read_only:false}}`.
   Expect `InitializeSessionResponse.parameters{hash_function, hmac_secret, splitter,
   supports_content_compression}` (`grpc_session.go:589-607`). Store `splitter` (choose splitter §4.1) and
   optionally `hash_function`/`hmac_secret` (§3.1). Abort on `ErrorResponse`.
4. **Write the file** (single chunk if ≤ max segment size): `rid=2`:
   `write_content{prefix:"", data:<plaintext bytes>, compression:0}` → keep `content_id`.
5. **Write the root directory object**: build
   `{"stream":"kopia:directory","entries":[{"name":"hello.txt","type":"f","mode":"0644","size":N,
   "mtime":"...Z","uid":501,"gid":20,"obj":"<content_id from step 4>"}],"summary":{...}}` + `\n`, then
   `rid=3`: `write_content{prefix:"k", data:<dir JSON>, compression:0}` → `dir_obj_id`.
6. **Flush** — `rid=4`: `flush{}` → wait for `flush{}` response
   (`grpc_session.go:306-321`). Without this the server may still hold data in its write buffers and nothing
   is visible to any other client (`handleWriteSessionResult` flushes on the Go client's behalf,
   `repo/repository.go:462-476` — a raw stream client must do it itself).
7. **Put the snapshot manifest** — `rid=5`:
   `put_manifest{json_data:<manifest JSON per §5, id:"", rootEntry.obj = dir_obj_id, startTime/endTime,
   stats>, labels:{"type":"snapshot","username":"myuser","hostname":"my-mac","path":"/Users/myuser/data"}}`
   → `manifest_id` (`grpc_session.go:348-366`).
   (Order matters: manifest *after* flush is safest so the referenced contents are committed; alternatively
   put the manifest and flush once at the end — the Go client flushes only at session end. Either is valid as
   long as **one `flush` completes before the client disconnects**.)
8. **Disconnect** (close stream; HTTP/2 GOAWAY). Optionally `POST /api/v1/control/refresh` with Basic auth to
   make the server's UI reflect the new snapshot immediately.
9. **Verification with standard CLI** (reading the same repository): `kopia snapshot list --all`,
   `kopia restore <manifest_id-or-rootEntry>` / `kopia snapshot restore <id>`. The CLI reads the manifest via
   `FindManifests{type:snapshot, username, hostname, path}` and restores by walking `rootEntry` → dir JSON →
   `obj` IDs (`snapshot/snapshotfs/*`). No server restart needed: the flush wrote index blobs to storage.

Multi-chunk files (size > max segment size): repeat step 4 per chunk, then build the indirect JSON object
(§4.3/§4.2) with prefix `"x"`, and put `"I"+<indirect id>` into the DirEntry `obj`.

---

## 7. Implications for the C Client (crypto/protocol weight)

1. **TLS 1.2 minimum is non-negotiable.** The Go 1.25 server rejects TLS 1.0/1.1. OS X 10.5 ships OpenSSL
   0.9.x → you need a MacPorts/self-built OpenSSL ≥ 1.0.1 (TLS 1.2 + ALPN or manual `h2` over TLS) on the PPC
   side, or a TLS-terminating proxy that itself speaks TLS 1.2+ to kopia and something older to the Mac
   (proxying gRPC requires HTTP/2 passthrough — stunnel ≥ 5 with `protocol = proxy`/h2 support, or HAProxy).
   This is the single biggest portability risk.
2. **HTTP/2 is required** (no h2c, no HTTP/1.1 fallback for the repository protocol). A minimal HTTP/2 client
   (SETTINGS, HEADERS with HPACK — literal without indexing is sufficient, DATA frames, trailers) is enough;
   flow-control windows must be respected (initial peer window 64 KiB default; 20 MiB max frame payload limit
   is fine since each message ≤ 20 MiB but you must send WINDOW_UPDATE for large DATA streams both ways).
3. **Protobuf encoding is tiny** — ~15 messages, no reflection needed; hand-roll encoders for the field
   numbers in §2.
4. **No client-side crypto is strictly required**: contents are sent plaintext; content IDs come back from the
   server; manifest IDs come back from the server. Optional: keyed BLAKE2B-256-128 / HMAC-SHA256 to compute
   content IDs locally for dedup and verification (§3.1).
5. **The buzhash splitter is the only real algorithm to port** (§4.1) — ~60 lines of C, no dependencies, but
   the 256×u32 table must be byte-exact. A fixed-size splitter is a valid (non-dedup-friendly) fallback.
6. **Clock skew**: the server rejects blob timestamps skewed > 5 min (`repo/content/sessions.go:41-56`) —
   server-side only, but keep the PPC clock roughly correct anyway (snapshots store wall-clock times).
7. **Access control**: snapshot manifests must carry the logging-in user's `username`/`hostname` labels
   (§1.3), or `put_manifest` returns `ACCESS_DENIED` (`ErrorResponse.code = 5`).

### Explicitly NOT NEEDED (server-side only)

- Content encryption, encryption key derivation, per-content IVs (`repo/content/content_manager_lock_free.go`).
- Pack blob format, index blob format v1/v2, compaction, epoch/index management (`repo/content/index*`).
- Session blob bookkeeping (`repo/content/sessions.go`).
- Repository format blob (`kopia.repository`) parsing — the client never sees it; parameters arrive via
  `RepositoryParameters`.
- Policy manifests, maintenance, retention/GC, `ApplyRetentionPolicy`, `PrefetchContents`, `GetContent`
  (restore), `DeleteManifest`.
- Compression (send `compression = 0`; kopia's own default for file data is `"none"`,
  `snapshot/policy/policy_tree.go:16-17` — metadata defaults to zstd-fastest, but 0 is always legal).
- HTML-UI/Control REST API beyond optional status/flush/refresh calls.
