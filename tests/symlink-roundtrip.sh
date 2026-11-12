#!/bin/sh
# End-to-end symlink round-trip test: local kopia server (v0.23+) + client push
# + kopia restore, asserting symlink semantics (valid/absolute/relative/dangling/
# to-dir/long-target), empty and multi-chunk files, and special-file skipping.
#
# Requires: kopia CLI on PATH, openssl; the client binary as $1 (default
# bin/kopia-darwin-ppc-native).
#
# Env: WORK (workdir, default /tmp/kpp-symlink-test)
#      PORT (server port, default 51536)

set -e

BIN="${1:-bin/kopia-darwin-ppc-native}"
WORK="${WORK:-/tmp/kpp-symlink-test}"
PORT="${PORT:-51536}"
PASSWORD=testpass123
URL="https://127.0.0.1:$PORT"
FP=""

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
kopia --config-file=$CF server user add test@test --user-password testpw >/dev/null

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

echo "== test tree"
D="$WORK/data"
mkdir -p "$D/nested/deep" "$D/fifodir" "$D/ünicode"
echo "hello symlink test" > "$D/a.txt"
: > "$D/empty.txt"
head -c 9437721 /dev/urandom > "$D/big.bin"          # multi-chunk (> 8 MB max)
echo "nested" > "$D/nested/deep/b.txt"
echo "utf8" > "$D/ünicode/dädatei.txt"
ln -s a.txt "$D/link-to-a"                            # valid, relative
ln -s "$D/a.txt" "$D/link-abs"                        # absolute
ln -s nowhere "$D/link-dangling"                      # dangling
ln -s nested/deep/b.txt "$D/link-rel-deep"            # relative, nested target
ln -s nested "$D/link-dir"                            # to directory
ln -s a.txt "$D/ünicode/link-utf8"                    # symlink under UTF-8 dir
mkfifo "$D/fifodir/pipe"                              # must be skipped

LONG=$(printf 'x%.0s' $(seq 1 2000))
ln -s "$LONG" "$D/link-long"                          # 2000-char target

echo "== client push"
"$BIN" kopia-push --url $URL --user test --hostname test --password testpw \
    --fingerprint "$FP" "$D" > "$WORK/client.log" 2>&1 || { cat "$WORK/client.log"; fail "push failed"; }
grep -q "diag: skipping special file" "$WORK/client.log" || fail "fifo skip not logged"
ROOT_OBJ=$(sed -n 's/^object: //p' "$WORK/client.log")
[ -n "$ROOT_OBJ" ] || fail "no object id in client output"

echo "== restore"
kopia --config-file=$CF restore "$ROOT_OBJ" "$WORK/restore" >/dev/null

echo "== assertions"
[ "$(cat "$WORK/restore/a.txt")" = "hello symlink test" ] || fail "a.txt content"
[ "$(wc -c < "$WORK/restore/empty.txt")" = "0" ] || fail "empty.txt size"
[ "$(wc -c < "$WORK/restore/big.bin")" = "9437721" ] || fail "big.bin size"
[ "$(wc -c < "$WORK/restore/nested/deep/b.txt")" = "7" ] || fail "b.txt size"
cmp -s "$WORK/big.bin" "$WORK/restore/big.bin" || cmp -s "$D/big.bin" "$WORK/restore/big.bin" || fail "big.bin bytes"

[ "$(readlink "$WORK/restore/link-to-a")" = "a.txt" ] || fail "link-to-a target"
[ "$(readlink "$WORK/restore/link-abs")" = "$D/a.txt" ] || fail "link-abs target"
[ "$(readlink "$WORK/restore/link-dangling")" = "nowhere" ] || fail "dangling target"
[ "$(readlink "$WORK/restore/link-rel-deep")" = "nested/deep/b.txt" ] || fail "rel-deep target"
[ "$(readlink "$WORK/restore/link-dir")" = "nested" ] || fail "link-dir target"
[ "$(readlink "$WORK/restore/ünicode/link-utf8")" = "a.txt" ] || fail "utf8 symlink target"
[ "$(readlink "$WORK/restore/link-long")" = "$LONG" ] || fail "long target (expected 2000 chars)"

[ -e "$WORK/restore/fifodir/pipe" ] && fail "fifo must not be restored"
[ "$(cat "$WORK/restore/ünicode/dädatei.txt")" = "utf8" ] || fail "utf8 file content"

echo "PASS: symlink round-trip ok ($ROOT_OBJ)"
