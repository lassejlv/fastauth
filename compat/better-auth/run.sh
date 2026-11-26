#!/usr/bin/env bash
# Runs Better Auth's TypeScript client against the axum_sqlite example, or with SERVER=actix
# against actix_sqlite (the same app on actix-web): builds the example, starts it on
# localhost:$PORT (3000 unless set) with a fresh database, runs compat.ts, and stops the server.
# Needs cargo and bun. Exits non-zero when any check fails. With DATABASE_URL set to an empty
# MySQL database (mysql://...), the axum server runs on MySQL.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
port="${PORT:-3000}"
kind="${SERVER:-axum}"
features="sqlite,two-factor,organization,admin,api-key"
case "$kind" in
  axum) ;;
  actix) features="actix,$features" ;;
  *) echo "SERVER must be axum or actix, not $kind" >&2; exit 1 ;;
esac
if [[ -n "${DATABASE_URL:-}" ]]; then
  [[ "$kind" == axum ]] || { echo "DATABASE_URL (MySQL) needs SERVER=axum" >&2; exit 1; }
  features="$features,mysql"
fi
example="${kind}_sqlite"
work="$(mktemp -d)"
server=""

cleanup() {
  if [[ -n "$server" ]]; then kill "$server" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

if curl -s -o /dev/null "http://127.0.0.1:$port"; then
  echo "something is already listening on port $port; stop it first or set PORT" >&2
  exit 1
fi

echo "building the $example example"
cargo build --manifest-path "$root/Cargo.toml" -p fastauth --example "$example" --features "$features"
bin="$root/target/debug/examples/$example"

echo "installing the client"
(cd "$here" && bun install --frozen-lockfile)

echo "starting the server (log: $work/server.log)"
(cd "$work" && NO_COLOR=1 PORT="$port" exec "$bin" >"$work/server.log" 2>&1) &
server=$!
for _ in $(seq 1 50); do
  if curl -s -o /dev/null "http://127.0.0.1:$port/api/auth/get-session"; then break; fi
  if ! kill -0 "$server" 2>/dev/null; then cat "$work/server.log" >&2; exit 1; fi
  sleep 0.2
done

cd "$here"
FASTAUTH_URL="http://localhost:$port" FASTAUTH_LOG="$work/server.log" bun run compat.ts
