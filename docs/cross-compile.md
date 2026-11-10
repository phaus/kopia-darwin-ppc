# Cross-compiling kopia-darwin-ppc for PowerPC Macs

How to build Mach-O `ppc_7400` / `ppc64` binaries on an x86_64 Linux host, targeting
Mac OS X 10.5 Leopard (darwin9). This is the setup used for the release binaries.

**What the toolchain is:**

| Component | Version | Purpose |
|-----------|---------|---------|
| [osxcross](https://github.com/tpoechtrager/osxcross) | commit `af8300c` (2.x) | cross-compiler framework, cctools, wrappers |
| cctools / ld64 | `cctools-877.8-ld64-253.9` | assembler + linker (fetched by osxcross) |
| **Apple GCC 4.2.1** | build `5575` (dot 11) | the actual ppc/ppc64 compiler (clang cannot target darwin9 ppc) |
| Mac OS X 10.5 SDK | `MacOSX10.5.sdk` | headers + libraries (libSystem, libz, libgcc) |
| [mbedTLS](https://github.com/Mbed-TLS/mbedtls) | 2.28.10 | static TLS library, built per arch |

Resulting binaries link **only** against Leopard system libraries
(`libSystem.B.dylib`, `libz.1.dylib`, `libgcc_s.1.dylib` / `libgcc_s_ppc64.1.dylib`) —
no MacPorts, no LegacySupport, no runtime TLS library.

## 1. Host

Any x86_64 Linux machine. Tested on Debian 13 (trixie) with GCC 14. Roughly:

```bash
apt-get install -y build-essential clang git cmake libxml2-dev libssl-dev \
  zlib1g-dev libbz2-dev liblzma-dev uuid-dev xz-utils patch libtinfo-dev
```

## 2. The SDK (the one part you must source yourself)

The Mac OS X 10.5 SDK is Apple-proprietary and cannot be redistributed. Two common ways
to obtain it:

- generate it from an **Xcode 3.1.x installer** (`.dmg`) on any Mac with
  `osxcross/tools/gen_sdk_package.sh xcode_314.dmg`;
- copy `MacOSX10.5.sdk` from an existing Leopard installation
  (`/Developer/SDKs/MacOSX10.5.sdk`).

Do **not** commit the SDK to a public repository. Place a `MacOSX10.5.sdk.tar.gz`
(or `.tar.xz`) in the osxcross `tarballs/` directory.

## 3. osxcross

```bash
git clone https://github.com/tpoechtrager/osxcross /opt/osxcross
cd /opt/osxcross
git checkout af8300c          # the 2.x state this recipe was verified with

# put the SDK in place:
#   tar -C target/SDK -xzf /path/to/MacOSX10.5.sdk.tar.gz
# (or simply drop MacOSX10.5.sdk.tar.gz into tarballs/ before building)

./build.sh                    # cctools, ld64, clang/oclang wrappers
./build_gcc.sh gcc-5575.11.tar.gz   # Apple GCC 4.2.1 for i386/x86_64/ppc/ppc64 darwin9
```

`./build_gcc.sh` is the important step: modern clang cannot emit darwin9 ppc code, but
Apple's GCC 4.2 can. The tarball is Apple's GCC 4.2.1 source drop (`5575.11`) — it is
fetched from Apple's open-source downloads or mirrored; osxcross's `build_gcc.sh`
documents where.

**Verify:**

```bash
export PATH=/opt/osxcross/target/bin:$PATH
oppc32-gcc -dumpmachine       # -> powerpc-apple-darwin9
oppc64-gcc -dumpmachine       # -> powerpc64-apple-darwin9
oppc32-gcc --version          # -> powerpc-apple-darwin9-gcc (GCC) 4.2.1 (Apple Inc. build 5575) (dot 11)

printf '#include <stdio.h>\nint main(){puts("ok");return 0;}\n' > /tmp/t.c
oppc32-gcc /tmp/t.c -o /tmp/t32 && file /tmp/t32   # -> Mach-O ppc_7400 executable
```

Note: `oppc32-gcc` and `oppc64-gcc` are convenience symlinks to the same Apple-GCC
wrapper (`powerpc64-apple-darwin9-wrapper`), which picks the architecture from how it
is invoked.

## 4. mbedTLS 2.28 (static, per architecture)

kopia-darwin-ppc links TLS statically — Leopard's own OpenSSL 0.9.7 is far too old for
a modern kopia server (TLS 1.2+), so mbedTLS is cross-built for each architecture.

```bash
# get the source (self-contained tarball, no submodules):
curl -LO https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/mbedtls-2.28.10.tar.gz
tar xzf mbedtls-2.28.10.tar.gz && cd mbedtls-mbedtls-2.28.10

# ppc32 (G4):
export CC=/opt/osxcross/target/bin/oppc32-gcc
export AR=/opt/osxcross/target/bin/powerpc-apple-darwin9-ar
export ARFLAGS=ru
export RANLIB=/opt/osxcross/target/bin/powerpc-apple-darwin9-ranlib
make lib CFLAGS="-std=c99 -Iinclude" -j"$(nproc)"
# -> library/libmbedtls.a libmbedx509.a libmbedcrypto.a

# ppc64 (G5): copy the tree and repeat with the oppc64-gcc / powerpc64-* tools
```

The `-std=c99` matters: Apple GCC 4.2 defaults to gnu89 and mbedTLS 2.28 uses
`for`-loop declarations.

## 5. Build kopia-darwin-ppc

```bash
git clone https://github.com/phaus/kopia-darwin-ppc
cd kopia-darwin-ppc

MBEDTLS=/opt/mbedtls-mbedtls-2.28.10   # ppc32 libs; use the ppc64 dir for cross64

make cross32 \
  MBEDTLS_CFLAGS="-I$MBEDTLS/include" \
  CROSS_MBEDTLS_LIBS="$MBEDTLS/library/libmbedtls.a $MBEDTLS/library/libmbedx509.a $MBEDTLS/library/libmbedcrypto.a"
# -> bin/kopia-darwin-ppc (Mach-O ppc_7400)

make cross64 \
  MBEDTLS_CFLAGS="-I$MBEDTLS-PPC64/include" \
  CROSS_MBEDTLS_LIBS="<ppc64 libmbedtls.a libmbedx509.a libmbedcrypto.a>"
# -> bin/kopia-darwin-ppc64 (Mach-O ppc64)
```

Check the result links only system libraries:

```bash
/opt/osxcross/target/bin/i386-apple-darwin9-otool -L bin/kopia-darwin-ppc
# /usr/lib/libz.1.dylib, /usr/lib/libgcc_s.1.dylib (or libgcc_s_ppc64.1.dylib),
# /usr/lib/libSystem.B.dylib — nothing else
```

## 6. Interop testing

Any x86_64 machine can also run a **test kopia server** plus a native build
(`make native`, needs `libmbedtls-dev`) to verify produced binaries without touching
a real Mac:

```bash
KOPIA_PASSWORD=… kopia --config-file=/tmp/test/repository.config \
  repository create filesystem --path /tmp/test-repo
kopia --config-file=/tmp/test/repository.config server user add test@test --user-password testpw
kopia --config-file=/tmp/test/repository.config server start \
  --tls-cert-file=… --tls-key-file=… --address=0.0.0.0:51535 \
  --server-username=control --server-password=controlpw

./tests/smoke.sh bin/kopia-darwin-ppc-native
```

## Gotchas collected the hard way

- **Apple GCC 4.2 defaults to gnu89** — pass `-std=c99` (the Makefile does).
- **No `fmemopen` on Darwin** — don't use it in portable code paths.
- **HTTP/2 flow control is not optional**: the server's per-stream window starts at
  64 KB and the client must send stream-level `WINDOW_UPDATE`s, or the backup
  deadlocks after ~1300 small responses (see `src/kopia_h2.c`).
- **gRPC responses arrive out of order** — the kopia server processes requests in
  concurrent goroutines; match responses by `request_id`, don't consume FIFO.
- **Leopard's OpenSSL is unusable** for kopia (TLS 1.0 only, no ALPN) — hence the
  static mbedTLS and certificate **pinning** by SHA-256 fingerprint.
- Keep the toolchain on a persistent path (`/opt/osxcross`); osxcross also supports
  exposing it via a `/tmp` symlink recreated by `tmpfiles.d` at boot.
