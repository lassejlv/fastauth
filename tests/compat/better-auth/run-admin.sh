#!/usr/bin/env bash
# Runs Better Auth's adminClient against the admin plugin's example server: builds
# crates/plugins/admin/examples/admin_server.rs, starts it on localhost:$PORT (3000 by
# default; in memory, with an admin account), runs admin.ts, and stops the server. Needs cargo
# and bun.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
work="$(mktemp -d)"
server=""
port="${PORT:-3000}"

cleanup() {
  if [[ -n "$server" ]]; then kill "$server" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

if curl -s -o /dev/null http://127.0.0.1:$port; then
  echo "something is already listening on port $port; stop it first or set PORT" >&2
  exit 1
fi

echo "building the admin_server example"
cargo build --manifest-path "$root/Cargo.toml" -p fastauth-plugin-admin --example admin_server --features axum
bin="$root/target/debug/examples/admin_server"

echo "installing the client"
(cd "$here" && bun install --frozen-lockfile)

echo "starting the server (log: $work/server.log)"
(cd "$work" && PORT="$port" exec "$bin" >"$work/server.log" 2>&1) &
server=$!
for _ in $(seq 1 50); do
  if curl -s -o /dev/null http://127.0.0.1:$port/api/auth/get-session; then break; fi
  if ! kill -0 "$server" 2>/dev/null; then cat "$work/server.log" >&2; exit 1; fi
  sleep 0.2
done

cd "$here"
FASTAUTH_URL="http://localhost:$port" bun run admin.ts
