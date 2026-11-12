#!/bin/sh
# Interop smoke test vs a local kopia server (v0.23.1).
#
# Expects a test repository + server, e.g.:
#   KOPIA_PASSWORD=testpass123 kopia --config-file=/tmp/test/repository.config \
#     repository create filesystem --path /tmp/test-repo
#   kopia --config-file=/tmp/test/repository.config server user add test@test --user-password testpw
#   kopia --config-file=/tmp/test/repository.config server start --tls-cert-file=... --tls-key-file=... \
#     --address=0.0.0.0:51535 --server-username=control --server-password=controlpw
#
# Env: KOPIA_TEST_SERVER   (default http://127.0.0.1:51535 — set https://… if TLS)
#      KOPIA_TEST_CONFIG   (default /tmp/test/repository.config)

set -e
BIN="${1:-bin/kopia-darwin-ppc-native}"
SERVER="${KOPIA_TEST_SERVER:-http://127.0.0.1:51535}"

echo "== binary"
"$BIN" 2>&1 | head -3

echo "== kopia test server reachable"
curl -sk -o /dev/null -w "server http:%{http_code}\n" "$SERVER/"

echo "== repo usable via kopia CLI"
kopia --config-file="${KOPIA_TEST_CONFIG:-/tmp/test/repository.config}" snapshot list 2>&1 | head -2

echo "== smoke ok (client integration assertions added with kopia_client.c)"
