#!/usr/bin/env bash
# The Better Auth cross-app suite: a Better Auth 1.7.8 app (better-auth/, its config in
# better-auth/app.config.ts) and a fastauth app on axum (fastauth/) on ONE Postgres 17, the way
# a phased cutover runs them. suite/dual.ts creates the schema with Better Auth's migration,
# seeds users, sessions and SSO rows, applies fastauth's review-only migrations, and checks
# that each app accepts the other's sign-ins, sign-outs, password changes, refreshes, fields,
# hashes and social accounts.
#
# Needs cargo, node and Docker. Starts a throwaway postgres:17 container on a free port and
# removes it on exit; with DATABASE_URL set to an empty Postgres database it uses that instead.
# DUAL_ADMIN=0 skips the last stage (the admin plugin's migrations). Exits non-zero when any
# check fails.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
work="$(mktemp -d)"
container=""

cleanup() {
  if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

echo "building the fastauth app"
cargo build --manifest-path "$root/Cargo.toml" -p fastauth-compat-better-auth-dual
bin="$root/target/debug/fastauth-compat-better-auth-dual"

echo "installing Better Auth 1.7.8"
(cd "$here" && npm ci --no-audit --no-fund --silent)

if [[ -z "${DATABASE_URL:-}" ]]; then
  container="fastauth-dual-pg-$$"
  docker run -d --rm --name "$container" -e POSTGRES_PASSWORD=dual -p 127.0.0.1::5432 postgres:17 >/dev/null
  port="$(docker port "$container" 5432/tcp | head -1 | cut -d: -f2)"
  for _ in $(seq 1 60); do
    docker exec "$container" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break
    sleep 1
  done
  docker exec "$container" pg_isready -h 127.0.0.1 -U postgres >/dev/null || { echo "Postgres didn't start" >&2; exit 1; }
  export DATABASE_URL="postgres://postgres:dual@127.0.0.1:$port/postgres"
fi

cd "$here"
status=0
FASTAUTH_BIN="$bin" SUITE_DIR="$here" WORK="$work" OUTBOX="$work/outbox.jsonl" NO_COLOR=1 \
  node suite/dual.ts || status=$?
if [[ $status -ne 0 && -n "${DUAL_KEEP_LOGS:-}" ]]; then
  mkdir -p "$DUAL_KEEP_LOGS" && cp "$work"/*.log "$DUAL_KEEP_LOGS"/ 2>/dev/null || true
fi
exit $status
