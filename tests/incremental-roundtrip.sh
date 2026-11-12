#!/bin/sh
# End-to-end incremental-cache test: local kopia server + client push.
#
# 1. push #1: full upload                      -> OBJ1
# 2. push #2, tree unchanged: object id must be IDENTICAL (everything reused)
# 3. push #3, one file modified + one added + one deleted: object changes,
#    only the touched dirs re-uploaded; restore verifies contents
# 4. corrupt the cache: push #4 falls back to a full push, restore verifies
#
# Requires: kopia CLI on PATH, openssl; the client binary as $1.
# Env: WORK (default /tmp/kpp-incremental-test), PORT (default 51538)

set -e

BIN="${1:-bin/kopia-darwin-ppc-native}"
WORK="${WORK:-/tmp/kpp-incremental-test}"
PORT="${PORT:-51538}"
PASSWORD=incrtest123
URL="https://127.0.0.1:$PORT"

fail() { echo "FAIL: $*" >&2; exit 1; }

command -v kopia >/dev/null || fail "kopia CLI not on PATH"
[ -x "$BIN" ] || fail "client binary $BIN not found/executable"

rm -rf "$WORK"
mkdir -p "$WORK/repo" "$WORK/cache"

CF="$WORK/repo.config"
export KOPIA_PASSWORD=$PASSWORD
export KOPIA_CACHE_DIR="$WORK/cache"

echo "== repo + server user + TLS"
kopia --config-file=$CF repository create filesystem --path="$WORK/repo" \
    --override-username=control --override-hostname=testhost >/dev/null 2>&1
kopia --config-file=$CF server user add test@test --user-password "$PASSWORD" >/dev/null
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 2 -nodes -subj "/CN=localhost" 2>/dev/null

kopia --config-file=$CF server start \
    --tls-cert-file="$WORK/cert.pem" --tls-key-file="$WORK/key.pem" \
    --address=127.0.0.1:$PORT --server-username=control --server-password=controlpw \
    > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null' EXIT
sleep 3

push() { # $1 = log file
    "$BIN" kopia-push --url $URL --user test --hostname test \
        --password "$PASSWORD" \
        --fingerprint "$(openssl x509 -in "$WORK/cert.pem" -noout -fingerprint -sha256 | sed 's/.*=//')" \
        "$WORK/data" > "$1" 2>&1 || { cat "$1"; fail "push failed"; }
    sed -n 's/^object: //p' "$1"
}

echo "== tree v1"
D="$WORK/data"
mkdir -p "$D/sub" "$D/emptydir"
echo "one" > "$D/a.txt"
echo "two" > "$D/sub/b.txt"

OBJ1=$(push "$WORK/push1.log")
[ -n "$OBJ1" ] || fail "no object from push1"
grep -q "incremental cache" "$WORK/push1.log" && fail "push1 must not claim cache reuse"

echo "== push2 (unchanged) -> must equal $OBJ1"
OBJ2=$(push "$WORK/push2.log")
[ "$OBJ2" = "$OBJ1" ] || fail "unchanged push produced $OBJ2, want $OBJ1"
grep -q "^diag: reused 2 files, 3 dirs from incremental cache$" "$WORK/push2.log" \
    || { cat "$WORK/push2.log"; fail "push2 reuse counts"; }

echo "== tree v2: modify a.txt, add new.txt, delete sub/b.txt"
echo "one CHANGED" > "$D/a.txt"
echo "new" > "$D/new.txt"
rm "$D/sub/b.txt"

OBJ3=$(push "$WORK/push3.log")
[ -n "$OBJ3" ] && [ "$OBJ3" != "$OBJ2" ] || fail "changed push must produce a new object"
grep -q "^diag: reused 0 files, 1 dirs from incremental cache$" "$WORK/push3.log" \
    || { cat "$WORK/push3.log"; fail "push3 reuse counts"; }

echo "== restore push3"
kopia --config-file=$CF restore "$OBJ3" "$WORK/restore3" >/dev/null
[ "$(cat "$WORK/restore3/a.txt")" = "one CHANGED" ] || fail "a.txt content"
[ "$(cat "$WORK/restore3/new.txt")" = "new" ] || fail "new.txt content"
[ ! -e "$WORK/restore3/sub/b.txt" ] || fail "deleted b.txt must be gone"
[ -d "$WORK/restore3/emptydir" ] || fail "emptydir must survive"
[ -d "$WORK/restore3/sub" ] || fail "sub must survive"

echo "== corrupt cache -> full push fallback"
CACHE=$(ls "$WORK/cache"/cache-*.dat 2>/dev/null | head -1)
[ -n "$CACHE" ] || fail "no cache file written"
printf 'garbage' > "$CACHE"
OBJ4=$(push "$WORK/push4.log")
[ -n "$OBJ4" ] && [ "$OBJ4" = "$OBJ3" ] || fail "full push of unchanged tree must be deterministic ($OBJ4 != $OBJ3)"
grep -q "reused" "$WORK/push4.log" && fail "push4 must be a full push"
kopia --config-file=$CF restore "$OBJ4" "$WORK/restore4" >/dev/null
[ "$(cat "$WORK/restore4/a.txt")" = "one CHANGED" ] || fail "a.txt after fallback push"

echo "== push5: cache rebuilt, reuses again"
OBJ5=$(push "$WORK/push5.log")
[ "$OBJ5" = "$OBJ4" ] || fail "push5 should reuse the rebuilt cache ($OBJ5 != $OBJ4)"
grep -q "^diag: reused 2 files, 3 dirs from incremental cache$" "$WORK/push5.log" \
    || { cat "$WORK/push5.log"; fail "push5 reuse counts"; }

echo "PASS: incremental cache round-trip ok (OBJ1=$OBJ1)"
