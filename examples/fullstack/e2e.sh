#!/usr/bin/env bash
# The fullstack example's end-to-end suite: Playwright drives the React app in Chrome against
# the real server and a throwaway Postgres container.
#
#   examples/fullstack/e2e.sh                       # run the suite
#   examples/fullstack/e2e.sh --screenshots DIR     # also save light and dark screenshots
#   examples/fullstack/e2e.sh -- --grep passkey     # pass arguments to playwright test
#
# Needs cargo, docker, node with npm, and Chrome (CHROME_PATH, else Playwright's "chrome"
# channel). PORT (default 3290) is where the server listens. Exits non-zero when a test fails.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
port="${PORT:-3290}"
screenshots=""
playwright_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --screenshots) screenshots="$(mkdir -p "$2" && cd "$2" && pwd)"; shift 2 ;;
    --) shift; playwright_args=("$@"); break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

work="$(mktemp -d)"
container="fastauth-fullstack-e2e-$$"
server=""
cleanup() {
  if [[ -n "$server" ]]; then kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true; fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

if curl -s -o /dev/null "http://127.0.0.1:$port"; then
  echo "something is already listening on port $port; stop it or set PORT" >&2
  exit 1
fi

echo "starting Postgres ($container)"
docker run -d --rm --name "$container" -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=acme \
  -p 127.0.0.1::5432 postgres:17-alpine >/dev/null
pg_port="$(docker port "$container" 5432/tcp | head -1 | sed 's/.*://')"

echo "building the server"
cargo build --manifest-path "$root/Cargo.toml" -p fastauth-example-fullstack --bins
bin="$root/target/debug"

echo "building the web app"
(cd "$here/web" && npm ci --no-audit --no-fund && npm run build)

for _ in $(seq 1 60); do
  docker exec "$container" pg_isready -U postgres -d acme >/dev/null 2>&1 && break
  sleep 0.5
done
sleep 1

export DATABASE_URL="postgres://postgres:postgres@127.0.0.1:$pg_port/acme"
export FASTAUTH_SECRET="$(openssl rand -hex 32)"
export PORT="$port"
export APP_URL="http://localhost:$port"
export TRUSTED_PROXIES=1
export MAIL_OUTBOX="$work/outbox.jsonl"
export WEB_DIST="$here/web/dist"
export ADMIN_EMAIL="admin@acme.test"
export ADMIN_PASSWORD="admin password 1"
export GITHUB_CLIENT_ID="e2e-placeholder-client-id"
export GITHUB_CLIENT_SECRET="e2e-placeholder-client-secret"

echo "starting the server (log: $work/server.log)"
NO_COLOR=1 "$bin/server" >"$work/server.log" 2>&1 &
server=$!
for _ in $(seq 1 100); do
  if curl -s -o /dev/null "http://127.0.0.1:$port/api/features"; then break; fi
  if ! kill -0 "$server" 2>/dev/null; then cat "$work/server.log" >&2; exit 1; fi
  sleep 0.2
done

echo "checking migrations/ against the auth config"
"$bin/fastauth" status

echo "running Playwright"
status=0
(cd "$here/web" && E2E_BASE_URL="$APP_URL" SCREENSHOTS="$screenshots" \
  npx playwright test "${playwright_args[@]}") || status=$?
if [[ $status -ne 0 ]]; then
  echo "server log tail:" >&2
  tail -50 "$work/server.log" >&2
fi
exit $status
