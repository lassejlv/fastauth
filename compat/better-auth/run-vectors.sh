#!/usr/bin/env bash
# Golden vectors for Better Auth compatibility, checked in both directions. fastauth verifies
# vectors/better-auth.json (signed cookies from better-call 1.4.2, password hashes from
# @better-auth/utils 0.5.0) byte for byte, and Better Auth's code verifies what fastauth makes:
# vectors/fastauth.json and a fresh set written by this run. Needs cargo and node.
#
# To regenerate better-auth.json: cd vectors && npm ci && node generate.mjs
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

(cd "$here/vectors" && npm ci --no-audit --no-fund --silent)
FASTAUTH_VECTORS_OUT="$work/fastauth.json" \
  cargo test --manifest-path "$root/Cargo.toml" -p fastauth-core --lib compat::
node "$here/vectors/check.mjs" "$here/vectors/fastauth.json"
node "$here/vectors/check.mjs" "$work/fastauth.json"
