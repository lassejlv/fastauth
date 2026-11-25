#!/usr/bin/env bash
# Runs Better Auth's TypeScript client against the axum_sqlite example:
# builds the example, starts it on localhost:3000 with a fresh database, runs compat.ts,
# and stops the server. Needs cargo and bun. Exits non-zero when any check fails.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
server=""

cleanup() {
  if [[ -n "$server" ]]; then kill "$server" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

if curl -s -o /dev/null http://127.0.0.1:3000; then
  echo "something is already listening on port 3000; stop it first" >&2
  exit 1
fi

echo "building the axum_sqlite example"
cargo build --manifest-path "$root/Cargo.toml" -p fastauth --example axum_sqlite --features sqlite,two-factor,organization,admin,api-key
bin="$root/target/debug/examples/axum_sqlite"

echo "installing the client"
(cd "$here" && bun install --frozen-lockfile)

echo "starting the server (log: $work/server.log)"
(cd "$work" && NO_COLOR=1 exec "$bin" >"$work/server.log" 2>&1) &
server=$!
for _ in $(seq 1 50); do
  if curl -s -o /dev/null http://127.0.0.1:3000/api/auth/get-session; then break; fi
  if ! kill -0 "$server" 2>/dev/null; then cat "$work/server.log" >&2; exit 1; fi
  sleep 0.2
done

cd "$here"
FASTAUTH_URL=http://localhost:3000 FASTAUTH_LOG="$work/server.log" bun run compat.ts
