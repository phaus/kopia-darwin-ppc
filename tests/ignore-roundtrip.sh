#!/bin/sh
# End-to-end ignore-rule test: local kopia server + client push + kopia restore.
# Exercises all three rule sources at once (--ignore, --ignore-file, default
# .kopiaignore), directory pruning, negation, dir-only patterns and
# --password-file. Asserts excluded paths are absent from the restore and the
# ignored-files/dirs diag line has the exact expected counts.
#
# Requires: kopia CLI on PATH, openssl; the client binary as $1 (default
# bin/kopia-darwin-ppc-native).
#
# Env: WORK (workdir, default /tmp/kpp-ignore-test)
#      PORT (server port, default 51537)

set -e

BIN="${1:-bin/kopia-darwin-ppc-native}"
WORK="${WORK:-/tmp/kpp-ignore-test}"
PORT="${PORT:-51537}"
PASSWORD=ignoretest123
URL="https://127.0.0.1:$PORT"

fail() { echo "FAIL: $*" >&2; exit 1; }

command -v kopia >/dev/null || fail "kopia CLI not on PATH"
[ -x "$BIN" ] || fail "client binary $BIN not found/executable"

rm -rf "$WORK"
mkdir -p "$WORK/repo"

CF="$WORK/repo.config"
export KOPIA_PASSWORD=$PASSWORD

echo "== repo + server user"
kopia --config-file=$CF repository create filesystem --path="$WORK/repo" \
    --override-username=control --override-hostname=testhost >/dev/null
kopia --config-file=$CF server user add test@test --user-password "$PASSWORD" >/dev/null

echo "== TLS cert"
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 2 -nodes -subj "/CN=localhost" 2>/dev/null
FP=$(openssl x509 -in "$WORK/cert.pem" -noout -fingerprint -sha256 | sed 's/.*=//')

echo "== start server on :$PORT"
kopia --config-file=$CF server start \
    --tls-cert-file="$WORK/cert.pem" --tls-key-file="$WORK/key.pem" \
    --address=127.0.0.1:$PORT --server-username=control --server-password=controlpw \
    > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null' EXIT
sleep 3

echo "== test tree + rule files"
D="$WORK/data"
mkdir -p "$D/.svn" "$D/node_modules/pkg" "$D/project/build" "$D/data" "$D/logs" "$D/Library/Caches"

echo "kept" > "$D/keep.txt"
echo "junk" > "$D/debug.log"
echo "svn"  > "$D/.svn/entries"
echo "js"   > "$D/node_modules/pkg/x.js"
echo "obj"  > "$D/project/build/out.o"
echo "src"  > "$D/project/keep-src.c"
echo "data" > "$D/data/keep.txt"
echo "app"  > "$D/logs/app.log"
echo "keep" > "$D/logs/keep.log"
echo "cacheprofile" > "$D/Library/Caches/junk"

# rule source 1: default .kopiaignore in the source root
printf '# rules\n*.log\n!keep.log\n.svn\n' > "$D/.kopiaignore"
# rule source 2: extra file
printf 'build/\nLibrary/Caches\n' > "$WORK/extra.ignore"
# rule source 3: --ignore flag (node_modules), plus --password-file
printf '%s\n' "$PASSWORD" > "$WORK/pwfile"
chmod 600 "$WORK/pwfile"

echo "== client push"
"$BIN" kopia-push --url $URL --user test --hostname test \
    --password-file "$WORK/pwfile" \
    --fingerprint "$FP" \
    --ignore node_modules \
    --ignore-file "$WORK/extra.ignore" \
    "$D" > "$WORK/client.log" 2>&1 || { cat "$WORK/client.log"; fail "push failed"; }

grep -q "^diag: ignored 2 files, 4 dirs by ignore rules$" "$WORK/client.log" \
    || { echo "expected 'diag: ignored 2 files, 4 dirs'"; cat "$WORK/client.log"; fail "ignored-count line"; }
ROOT_OBJ=$(sed -n 's/^object: //p' "$WORK/client.log")
[ -n "$ROOT_OBJ" ] || fail "no object id in client output"

echo "== restore"
kopia --config-file=$CF restore "$ROOT_OBJ" "$WORK/restore" >/dev/null

echo "== assertions: kept"
[ "$(cat "$WORK/restore/keep.txt")" = "kept" ] || fail "keep.txt"
[ "$(cat "$WORK/restore/project/keep-src.c")" = "src" ] || fail "keep-src.c"
[ "$(cat "$WORK/restore/data/keep.txt")" = "data" ] || fail "data/keep.txt (negation must not kill dir)"
[ "$(cat "$WORK/restore/logs/keep.log")" = "keep" ] || fail "logs/keep.log (negated rule)"
[ -f "$WORK/restore/.kopiaignore" ] || fail ".kopiaignore itself is data and must be included"

echo "== assertions: ignored"
[ ! -e "$WORK/restore/debug.log" ] || fail "debug.log must be ignored"
[ ! -e "$WORK/restore/.svn" ] || fail ".svn must be ignored"
[ ! -e "$WORK/restore/node_modules" ] || fail "node_modules must be ignored"
[ ! -e "$WORK/restore/project/build" ] || fail "project/build must be pruned"
[ ! -e "$WORK/restore/logs/app.log" ] || fail "logs/app.log must be ignored"
[ ! -e "$WORK/restore/Library/Caches" ] || fail "Library/Caches must be pruned"

echo "PASS: ignore round-trip ok ($ROOT_OBJ)"
