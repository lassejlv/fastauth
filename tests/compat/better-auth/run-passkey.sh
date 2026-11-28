#!/usr/bin/env bash
# Runs Better Auth's passkeyClient in headless Chrome against the passkey plugin's
# compat_server example, with Chrome's virtual authenticator answering WebAuthn.
# Builds the example and the browser bundle, starts the server on localhost:$PORT (3000 unless
# set) with a fresh in-memory database, runs passkey.ts and stops the server. Needs cargo, bun
# and Chrome or Chromium (CHROME_PATH, else google-chrome, chromium or chromium-browser on
# PATH). Exits non-zero when any check fails. With DATABASE_URL set to an empty MySQL database
# (mysql://...), the server runs on MySQL.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
port="${PORT:-3000}"
work="$(mktemp -d)"
server=""

cleanup() {
  if [[ -n "$server" ]]; then kill "$server" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

chrome="${CHROME_PATH:-$(command -v google-chrome || command -v chromium || command -v chromium-browser || true)}"
if [[ -z "$chrome" ]]; then
  echo "no Chrome or Chromium found; install one or set CHROME_PATH" >&2
  exit 1
fi

if curl -s -o /dev/null "http://127.0.0.1:$port"; then
  echo "something is already listening on port $port; stop it first or set PORT" >&2
  exit 1
fi

echo "building the fastauth-plugin-passkey compat_server example"
cargo build --manifest-path "$root/Cargo.toml" -p fastauth-plugin-passkey --example compat_server
bin="$root/target/debug/examples/compat_server"

echo "installing the client"
(cd "$here" && bun install --frozen-lockfile)
(cd "$here" && bun build passkey-page.ts --target=browser --outfile "$work/passkey-client.js")

echo "starting the server (log: $work/server.log)"
(cd "$work" && NO_COLOR=1 PORT="$port" exec "$bin" >"$work/server.log" 2>&1) &
server=$!
for _ in $(seq 1 50); do
  if curl -s -o /dev/null "http://127.0.0.1:$port/api/auth/get-session"; then break; fi
  if ! kill -0 "$server" 2>/dev/null; then cat "$work/server.log" >&2; exit 1; fi
  sleep 0.2
done

cd "$here"
FASTAUTH_URL="http://localhost:$port" PASSKEY_BUNDLE="$work/passkey-client.js" CHROME_PATH="$chrome" \
  bun run passkey.ts
