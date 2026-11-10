# kopia-darwin-ppc — native + PowerPC cross builds
#
# Targets:
#   make            native build (x86_64 Linux; interop test harness)
#   make cross32    Mach-O ppc_7400 via osxcross (for PowerPC G4) -> bin/kopia-darwin-ppc
#   make cross64    Mach-O ppc64 via osxcross (G5 only) -> bin/kopia-darwin-ppc64
#   make all-cross  both PPC binaries
#   make test       native build + interop smoke test vs a local kopia server
#
# Prerequisites:
#   - osxcross with macports-legacy ppc targets (oppc32-gcc / oppc64-gcc)
#   - mbedTLS 2.28 static libs for the target arch; pass via MBEDTLS_CFLAGS /
#     CROSS_MBEDTLS_LIBS (see README)

CROSS32 ?= /opt/osxcross/target/bin/oppc32-gcc
CROSS64 ?= /opt/osxcross/target/bin/oppc64-gcc

CFLAGS  ?= -O2 -Wall -Wextra -std=c99 -D_FILE_OFFSET_BITS=64
INC     := -Iinclude
MBEDTLS_CFLAGS ?=
LDLIBS  ?= -lz
MBEDTLS_LIBS ?= -lmbedtls -lmbedx509 -lmbedcrypto

SRC := src/main.c src/backup.c src/kopia_client.c src/kopia_json.c src/kopia_splitter.c src/kopia_sha256.c \
       src/kopia_tls.c src/kopia_hpack.c src/kopia_h2.c src/kopia_pb.c src/kopia_session.c src/kopia_upload.c

BIN := bin

.PHONY: all native cross32 cross64 all-cross clean test

all: native

native:
	@mkdir -p $(BIN)
	$(CC) $(CFLAGS) $(MBEDTLS_CFLAGS) $(INC) $(SRC) -o $(BIN)/kopia-darwin-ppc-native $(LDLIBS) $(MBEDTLS_LIBS)

cross32:
	@mkdir -p $(BIN)
	$(CROSS32) $(CFLAGS) $(MBEDTLS_CFLAGS) $(INC) $(SRC) -o $(BIN)/kopia-darwin-ppc $(LDLIBS) $(CROSS_MBEDTLS_LIBS)

cross64:
	@mkdir -p $(BIN)
	$(CROSS64) $(CFLAGS) $(MBEDTLS_CFLAGS) $(INC) $(SRC) -o $(BIN)/kopia-darwin-ppc64 $(LDLIBS) $(CROSS_MBEDTLS_LIBS)

all-cross: cross32 cross64

test: native
	./tests/smoke.sh $(BIN)/kopia-darwin-ppc-native

clean:
	rm -rf $(BIN)
