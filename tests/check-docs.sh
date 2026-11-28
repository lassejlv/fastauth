#!/usr/bin/env bash
# Compiles every ```rust block in docs/ against the workspace crates. See tests/docs-check/README.md.
#
#   tests/check-docs.sh              check docs/
#   DOCS_DIR=path tests/check-docs.sh  check another copy of the docs tree
set -uo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
crate="$repo/target/docs-check"
tool="$repo/tests/docs-check/docs_check.py"
docs="${DOCS_DIR:-$repo/docs}"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo/target}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}"
export CARGO_PROFILE_TEST_DEBUG="${CARGO_PROFILE_TEST_DEBUG:-0}"

failed=()

echo "== generating $crate"
python3 "$tool" generate --docs "$docs" --out "$crate" || failed+=("templates")

echo "== cargo check"
# --tests so #[test] and #[cfg(test)] items in the docs are type-checked too.
cargo check --manifest-path "$crate/Cargo.toml" --tests --color never 2>&1 | python3 "$tool" annotate --out "$crate"
[ "${PIPESTATUS[0]}" -eq 0 ] || failed+=("compile")

echo "== verbatim lines and core excerpts"
python3 "$tool" verify --docs "$docs" --out "$crate" || failed+=("verify")

if [ ${#failed[@]} -ne 0 ]; then
    echo "docs-check FAILED: ${failed[*]}"
    exit 1
fi
echo "docs-check OK"
