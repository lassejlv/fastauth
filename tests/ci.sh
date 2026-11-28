#!/usr/bin/env bash
# Local CI for fastauth: one command that runs every check the project has.
#
#   tests/ci.sh                 everything
#   tests/ci.sh --quick         fmt, clippy, tests, audit and deny only
#   tests/ci.sh --only compat   one group (or several: --only fmt,clippy)
#   tests/ci.sh --skip website,fuzz
#
# Groups, in order: fmt clippy test compat audit deny docs website fuzz.
# `test` and the MySQL compat runs start throwaway Postgres 17 and MySQL 8.4 containers, and
# `test` Redis 7 and Valkey 8 ones (Docker), on free local ports, and remove them on exit.
# Exits non-zero when any step fails, after printing a summary table. See CONTRIBUTING.md for what each group needs.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

groups=(fmt clippy test compat audit deny docs website fuzz)
quick_groups=(fmt clippy test audit deny)
only=""
skip=""
fuzz_seconds="${FUZZ_SECONDS:-30}"

usage() {
  sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  cat <<EOF

Options:
  --quick             only $(IFS=,; echo "${quick_groups[*]}")
  --only a,b          only these groups
  --skip a,b          every group but these
  --fuzz-seconds N    how long each fuzz target runs (default $fuzz_seconds, or FUZZ_SECONDS)
  -h, --help          this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) only="$(IFS=,; echo "${quick_groups[*]}")" ;;
    --only) only="${2:?--only needs a list}"; shift ;;
    --skip) skip="${2:?--skip needs a list}"; shift ;;
    --fuzz-seconds) fuzz_seconds="${2:?--fuzz-seconds needs a number}"; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
for list in "$only" "$skip"; do
  for g in ${list//,/ }; do
    [[ " ${groups[*]} " == *" $g "* ]] || { echo "unknown group: $g (groups: ${groups[*]})" >&2; exit 2; }
  done
done

wanted() {
  local group="$1"
  if [[ -n "$only" && ",$only," != *",$group,"* ]]; then return 1; fi
  if [[ ",$skip," == *",$group,"* ]]; then return 1; fi
  return 0
}

names=()
results=()
times=()
failed=0

# run <group> <name> <command...>: runs one step and records its result.
run() {
  local group="$1" name="$2"
  shift 2
  wanted "$group" || return 0
  printf '\n\033[1m==> %s\033[0m\n' "$name"
  local start=$SECONDS
  if "$@"; then
    results+=(pass)
  else
    results+=(FAIL)
    failed=1
  fi
  names+=("$name")
  times+=($((SECONDS - start)))
}

# record <name> <result>: a step that didn't run, with why.
record() {
  names+=("$1")
  results+=("$2")
  times+=(0)
  [[ "$2" == FAIL* ]] && failed=1
  return 0
}

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

# ---------------------------------------------------------------- databases

pg_container=""
mysql_container=""
redis_container=""
valkey_container=""
database_url=""
mysql_url=""
redis_url=""
valkey_url=""

cleanup() {
  for c in "$pg_container" "$mysql_container" "$redis_container" "$valkey_container"; do
    [[ -n "$c" ]] && docker rm -f "$c" >/dev/null 2>&1
  done
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT TERM

start_databases() {
  command -v docker >/dev/null || { echo "docker is not installed" >&2; return 1; }
  pg_container="fastauth-ci-pg-$$"
  mysql_container="fastauth-ci-mysql-$$"
  docker run -d --rm --name "$pg_container" -e POSTGRES_PASSWORD=ci -p 127.0.0.1::5432 postgres:17 >/dev/null || return 1
  docker run -d --rm --name "$mysql_container" -e MYSQL_ROOT_PASSWORD=ci -e MYSQL_DATABASE=fastauth \
    -p 127.0.0.1::3306 mysql:8.4 >/dev/null || return 1
  local pg_port mysql_port
  pg_port="$(docker port "$pg_container" 5432/tcp | head -1 | cut -d: -f2)"
  mysql_port="$(docker port "$mysql_container" 3306/tcp | head -1 | cut -d: -f2)"
  echo "waiting for Postgres on $pg_port and MySQL on $mysql_port"
  local i
  for i in $(seq 1 120); do
    docker exec "$pg_container" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break
    sleep 1
  done
  # TCP only answers once MySQL's init server (which has networking off) has finished.
  for i in $(seq 1 180); do
    docker exec "$mysql_container" mysql --protocol=tcp -h127.0.0.1 -uroot -pci -e 'SELECT 1' >/dev/null 2>&1 && break
    sleep 1
  done
  docker exec "$pg_container" pg_isready -h 127.0.0.1 -U postgres >/dev/null || { echo "Postgres didn't start" >&2; return 1; }
  docker exec "$mysql_container" mysql --protocol=tcp -h127.0.0.1 -uroot -pci -e 'SELECT 1' >/dev/null 2>&1 \
    || { echo "MySQL didn't start" >&2; return 1; }
  database_url="postgres://postgres:ci@127.0.0.1:$pg_port/postgres"
  if wanted test; then
    start_redis || return 1
  fi
  mysql_url="mysql://root:ci@127.0.0.1:$mysql_port/fastauth"
  mysql_base="mysql://root:ci@127.0.0.1:$mysql_port"
}

# Redis 7 and Valkey 8, for fastauth-redis's tests.
start_redis() {
  redis_container="fastauth-ci-redis-$$"
  valkey_container="fastauth-ci-valkey-$$"
  docker run -d --rm --name "$redis_container" -p 127.0.0.1::6379 redis:7 >/dev/null || return 1
  docker run -d --rm --name "$valkey_container" -p 127.0.0.1::6379 valkey/valkey:8 >/dev/null || return 1
  local i
  for i in $(seq 1 60); do
    docker exec "$redis_container" redis-cli ping 2>/dev/null | grep -q PONG \
      && docker exec "$valkey_container" valkey-cli ping 2>/dev/null | grep -q PONG && break
    sleep 1
  done
  docker exec "$redis_container" redis-cli ping 2>/dev/null | grep -q PONG || { echo "Redis didn't start" >&2; return 1; }
  docker exec "$valkey_container" valkey-cli ping 2>/dev/null | grep -q PONG || { echo "Valkey didn't start" >&2; return 1; }
  redis_url="redis://127.0.0.1:$(docker port "$redis_container" 6379/tcp | head -1 | cut -d: -f2)"
  valkey_url="redis://127.0.0.1:$(docker port "$valkey_container" 6379/tcp | head -1 | cut -d: -f2)"
  echo "Redis 7 at $redis_url, Valkey 8 at $valkey_url"
}

# A new, empty Postgres database for one compat run.
fresh_pg() {
  local name="compat_$1_$$"
  docker exec "$pg_container" psql -U postgres -q -c "DROP DATABASE IF EXISTS \"$name\"" -c "CREATE DATABASE \"$name\"" \
    >/dev/null 2>&1 || return 1
  echo "${database_url%/*}/$name"
}

# A new, empty MySQL database for one compat run.
fresh_mysql() {
  local name="compat_$1_$$"
  docker exec "$mysql_container" mysql --protocol=tcp -h127.0.0.1 -uroot -pci \
    -e "DROP DATABASE IF EXISTS \`$name\`; CREATE DATABASE \`$name\`" >/dev/null 2>&1 || return 1
  echo "$mysql_base/$name"
}

needs_databases=0
wanted test && needs_databases=1
wanted compat && needs_databases=1
databases_ok=0
if [[ $needs_databases == 1 ]]; then
  printf '\n\033[1m==> databases\033[0m\n'
  if start_databases; then databases_ok=1; else record "databases (Postgres 17, MySQL 8.4, Redis 7, Valkey 8)" FAIL; fi
fi

# ---------------------------------------------------------------- steps

fmt() {
  cargo fmt --all -- --check && cargo fmt --all --manifest-path tests/fuzz/Cargo.toml -- --check
}
run fmt "fmt --check" fmt

run clippy "clippy -D warnings" cargo clippy --workspace --all-targets --all-features -- -D warnings

if wanted test; then
  if [[ $databases_ok == 1 ]]; then
    run test "test --workspace --all-features (Redis 7)" \
      env DATABASE_URL="$database_url" MYSQL_DATABASE_URL="$mysql_url" REDIS_URL="$redis_url" \
      REDIS_CONTAINER="$redis_container" \
      cargo test --workspace --all-features --no-fail-fast
    run test "test fastauth-redis (Valkey 8)" \
      env DATABASE_URL="$database_url" REDIS_URL="$valkey_url" REDIS_CONTAINER="$valkey_container" \
      cargo test -p fastauth-redis --all-features --no-fail-fast
  else
    record "test --workspace --all-features" "FAIL (no databases)"
  fi
fi

compat() {
  local script="$1"
  shift
  env -u DATABASE_URL PORT="$(free_port)" "$@" "tests/compat/better-auth/$script"
}
compat_mysql() {
  local script="$1" url
  url="$(fresh_mysql "${script//[^a-z]/_}")" || return 1
  env DATABASE_URL="$url" PORT="$(free_port)" "tests/compat/better-auth/$script"
}
compat_dual() {
  local url
  url="$(fresh_pg dual)" || return 1
  env DATABASE_URL="$url" tests/compat/better-auth-dual/run-dual.sh
}
if wanted compat; then
  run compat "compat run.sh (axum)" compat run.sh
  run compat "compat run.sh (SERVER=actix)" compat run.sh SERVER=actix
  run compat "compat run-vectors.sh (golden vectors)" compat run-vectors.sh
  for script in run-organization.sh run-admin.sh run-magic-link.sh run-email-otp.sh run-bearer.sh \
    run-jwt.sh run-passkey.sh run-username.sh run-anonymous.sh run-multi-session.sh; do
    run compat "compat $script" compat "$script"
  done
  if [[ $databases_ok == 1 ]]; then
    run compat "compat better-auth-dual/run-dual.sh (Better Auth 1.7.8 + fastauth, one Postgres 17)" compat_dual
  else
    record "compat better-auth-dual/run-dual.sh" "FAIL (no databases)"
  fi
  for script in run.sh run-organization.sh run-passkey.sh; do
    if [[ $databases_ok == 1 ]]; then
      run compat "compat $script (MySQL)" compat_mysql "$script"
    else
      record "compat $script (MySQL)" "FAIL (no databases)"
    fi
  done
fi

run audit "cargo audit" cargo audit
run deny "cargo deny check licenses advisories" cargo deny --config tests/deny.toml check licenses advisories
run docs "docs rust blocks" tests/check-docs.sh

website() {
  (cd website && npm ci --no-audit --no-fund && npm run build && npm run check:markdown)
}
run website "website build" website

if wanted fuzz; then
  if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
    record "fuzz (needs nightly and cargo-fuzz)" FAIL
  else
    fuzz_tmp="$(mktemp -d)"
    run fuzz "fuzz build" cargo +nightly fuzz build --fuzz-dir tests/fuzz -s none
    if [[ "${results[-1]}" == pass ]]; then
      for target in $(cargo +nightly fuzz list --fuzz-dir tests/fuzz); do
        mkdir -p "$fuzz_tmp/$target"
        seeds=()
        [[ -d "tests/fuzz/corpus/$target" ]] && seeds=("tests/fuzz/corpus/$target")
        run fuzz "fuzz $target (${fuzz_seconds}s)" bash -c \
          "cargo +nightly fuzz run --fuzz-dir tests/fuzz -s none $target '$fuzz_tmp/$target' ${seeds[*]} -- -max_total_time=$fuzz_seconds -artifact_prefix='$fuzz_tmp/$target/crash-'"
      done
    fi
    rm -rf "$fuzz_tmp"
  fi
fi

# ---------------------------------------------------------------- summary

printf '\n\033[1mSummary\033[0m\n'
width=4
for name in "${names[@]}"; do (( ${#name} > width )) && width=${#name}; done
printf "%-${width}s  %-20s  %s\n" Step Result Time
printf "%-${width}s  %-20s  %s\n" "$(printf '%*s' "$width" '' | tr ' ' -)" "--------------------" "----"
for i in "${!names[@]}"; do
  printf "%-${width}s  %-20s  %ss\n" "${names[$i]}" "${results[$i]}" "${times[$i]}"
done
if [[ $failed == 1 ]]; then
  printf '\n\033[31mFAILED\033[0m\n'
  exit 1
fi
printf '\n\033[32mOK\033[0m (%s steps)\n' "${#names[@]}"
