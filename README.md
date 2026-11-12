# kopia-darwin-ppc

<p align="center"><img src="docs/logo.svg" width="96" alt="kopia-darwin-ppc — one object, chunked"></p>

A native **kopia backup client for old PowerPC Macs** (Mac OS X 10.4 Tiger / 10.5 Leopard, G4/G5).

Kopia itself cannot run on these machines (Go does not support `darwin/ppc`, and Leopard's
system OpenSSL is far too old for modern TLS). This tool speaks the **kopia repository
server protocol** natively in C — a thin client that pushes backups to a kopia
repository server (`kopia server start`) over TLS + HTTP/2 + gRPC, with zero external
dependencies beyond a statically linked [mbedTLS](https://github.com/Mbed-TLS/mbedtls).

Also included: a minimal local backup tool (content-addressable store with SHA-256
deduplication and snapshot manifests) for backups to local/USB disks.

## How it works

The kopia repository server protocol (verified against kopia v0.23.1) is a single
gRPC bidirectional stream — `/kopia_repository.KopiaRepository/Session` — over HTTP/2.
A thin client does remarkably little crypto work because **the server handles it**:

- the server encrypts contents (AES-256-GCM), computes content IDs, packs and compacts
  the index — the client sends **plaintext** chunks and receives content IDs back;
- authentication is three gRPC metadata headers (`kopia-username`, `kopia-hostname`,
  `kopia-password`) validated against repo-level server users (`kopia server user add user@host`);
- TLS is mandatory (kopia has no h2c), so the client statically links mbedTLS and pins
  the server certificate by SHA-256 fingerprint — the same trust model as
  `kopia repository connect server --server-cert-fingerprint …`.

What the client implements:

- buzhash32 rolling-hash chunking (window 64, avg 4 MB, min 2 MB, max 8 MB, seed-1
  table — matching kopia's `DYNAMIC-4M-BUZHASH` splitter);
- directory objects (`{"stream":"kopia:directory",…}` — written with content prefix `k`);
- multi-chunk indirect objects (`{"stream":"kopia:indirect",…}` — prefix `x`,
  object ID = `I<content-id>`);
- snapshot manifests (labels `type=snapshot`, `hostname`, `username`, `path`);
- HTTP/2 framing with HPACK (RFC 7541, incl. Huffman decoding), flow control and
  gRPC message framing — all hand-rolled, ~1500 lines of C99.

The full wire-protocol specification (extracted from the kopia source, with exact
message formats and file references) is in [`docs/kopia-protocol.md`](docs/kopia-protocol.md).

## Requirements

- **Target**: PowerPC Mac running Mac OS X 10.5 Leopard (tested) — binary links only
  `libSystem.B.dylib`, `libz.1.dylib`, `libgcc_s.1.dylib`; no MacPorts/LegacySupport needed
- **Build machine**: any x86_64 Linux with the
  [osxcross](https://github.com/tpoechtrager/osxcross) toolchain (`oppc32-gcc`, targeting
  `powerpc-apple-darwin9`, from the Mac OS X 10.5 SDK) and mbedTLS 2.28 static libs
  built for ppc32
- A kopia repository server reachable over the network (tested with kopia 0.23.1)

## Building

Full setup guide (osxcross + Mac OS X 10.5 SDK + Apple GCC 4.2.1 + static mbedTLS):
[`docs/cross-compile.md`](docs/cross-compile.md). Short version:

```bash
# toolchain + mbedtls locations (adjust to your setup)
CROSS32=/opt/osxcross/target/bin/oppc32-gcc
MBEDTLS=/opt/mbedtls-mbedtls-2.28.10          # built with: make lib CFLAGS="-std=c99 -Iinclude"

make cross32 \
  MBEDTLS_CFLAGS="-I$MBEDTLS/include" \
  CROSS_MBEDTLS_LIBS="$MBEDTLS/library/libmbedtls.a $MBEDTLS/library/libmbedx509.a $MBEDTLS/library/libmbedcrypto.a"
# -> bin/kopia-darwin-ppc  (Mach-O ppc_7400)

make native    # x86_64 Linux test binary (needs libmbedtls-dev)
```

`ppc64` (G5) builds the same way with `oppc64-gcc` and 64-bit mbedTLS libs.

A native x86_64 build is included as a fast interop-test harness (`make test` runs a
smoke test against a local kopia server).

## Usage

```
kopia-darwin-ppc kopia-push --url https://kopia.example.com:51515 \
    --user root --hostname my-g4 \
    [--password SECRET | --password-file FILE] \
    [--fingerprint XX:XX:…:XX] \
    [--ignore PATTERN]... [--ignore-file FILE]... <file-or-directory>
```

Uploads the path (file or directory, recursively) and creates a kopia snapshot.
The password can also come from `KOPIA_PASSWORD` (precedence: `--password`,
`--password-file`, environment).
Local CAS backend commands (`init`, `add`, `snapshot`, `list`, `restore`, `verify`)
are documented in the repo (see `src/main.c` usage output).

### Ignoring files

`kopia-push` skips paths matched by ignore rules, with kopia/gitignore semantics
for a documented subset:

| Rule | Meaning |
|---|---|
| `*.log` | bare names match at any depth, files and directories |
| `Library/Caches` | a pattern with separators anchors to the source root |
| `build/` | trailing `/`: directories only |
| `!keep.log` | `!` re-includes (last matching rule wins) |
| `**/foo` | `**` as a whole segment spans any number of directories |
| `# …`, blank | comments and blank lines are ignored |

Rules come from three sources, all combined (later sources don't override
earlier ones, the rule *order* within the list decides):

- `--ignore PATTERN` flags
- `--ignore-file FILE` files (one rule per line, `#` comments)
- a `.kopiaignore` in the source root, kopia-compatible

Matched directories are pruned — their subtrees are never walked — so ignore
rules also shorten the run, not just the snapshot. As in git, a file cannot be
re-included under a directory that is itself excluded. `.kopiaignore` files
themselves are data and are included in the snapshot.

### Server-side setup (one-time)

```bash
# inside the kopia server container / on the server host
kopia --config-file=/app/config/repository.config server user add root@my-g4 --user-password SECRET
# if the repository uses ACLs, grant the new user access:
kopia --config-file=/app/config/repository.config server acl add --user root@my-g4 --target type=content --access FULL
kopia --config-file=/app/config/repository.config server acl add --user root@my-g4 --target type=snapshot --access FULL
kopia --config-file=/app/config/repository.config server acl add --user root@my-g4 --target type=policy --access FULL
```

Notes:

- `server acl` uses `key=value` target syntax, and the server only re-reads users/ACLs
  on its refresh interval (default 4h; `--refresh-interval=10s` on `kopia server start`
  makes new users usable quickly).
- `kopia server refresh` (control API) also forces a refresh, but needs the
  *control* username/password (`--server-control-username`/`--server-control-password`),
  which are separate from `--server-username`/`--server-password`.

### Cron (daily/hourly backups)

Wrap the call in a small root-owned script (holds the password, mode 700) and schedule it:

```cron
17 * * * * /usr/local/bin/kopia-cron
```

with `/usr/local/bin/kopia-cron` roughly:

```sh
#!/bin/sh
LOCK=/var/run/kopia-darwin-ppc.lock
mkdir "$LOCK" 2>/dev/null || exit 0      # skip if previous run still going
trap 'rmdir "$LOCK"' EXIT
exec >> /var/log/kopia-darwin-ppc.log 2>&1
echo "=== $(date) kopia backup start"
/usr/local/bin/kopia-push --url https://kopia.example.com:51515 \
    --user root --hostname my-g4 --password-file /usr/local/etc/kopia-auth \
    --fingerprint XX:XX:…:XX /Users/youruser
echo "=== $(date) rc=$?"
```

The wrapper holds the password in `/usr/local/etc/kopia-auth` (mode 600) so it
is not visible in `ps` output while a run is active.

On Leopard, `/usr/bin/cron` is launched by launchd by default — no extra service setup.

## Verified interop (kopia 0.23.1)

- `InitializeSession` — client reads server parameters (`BLAKE2B-256-128`,
  `DYNAMIC-4M-BUZHASH`) and adapts
- single-file and directory-tree backups from a PowerPC G4 (Mac mini, 10.5.8)
- multi-chunk files (20 MB → 6-chunk indirect object)
- symlink round-trips (valid/absolute/dangling/relative/to-dir/2000-char/UTF-8-dir)
  — see `tests/symlink-roundtrip.sh`
- snapshots listed by the standard `kopia snapshot list --all`, restores via
  `kopia restore` are byte-identical
- certificate fingerprint pinning enforced (wrong fingerprint rejected)

## Known limitations

- ignore rules cover the common gitignore subset (see "Ignoring files"); no
  per-directory `.kopiaignore` files below the source root, no `[a-z]` classes
  and no backslash escapes
- no incremental *transfer* yet — every run re-reads and re-sends all files
  (server-side dedup still avoids duplicate storage, and unchanged large contents
  are skipped server-side, but data is re-transferred)
- special files (FIFOs, sockets, devices) are skipped — logged with their path
  and counted in the run summary (kopia itself doesn't back them up either);
  symlinks *are* backed up since v0.3 (type `"s"`, dangling links included)
- `compress_level` / encryption fields of the local CAS repo are placeholders
- local CAS `add` has no directory recursion
- ppc64 binary builds but is untested (no G5 available)

## License / provenance

Wire-protocol specification derived from the kopia source code (kopia is Apache-2.0);
the buzhash table is generated exactly like
[`chmduquesne/rollinghash`](https://github.com/chmduquesne/rollinghash) (`GenerateHashes(1)`).
Everything else is original C99 code written for this project.
