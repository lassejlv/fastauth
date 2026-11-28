# Contributing to fastauth

fastauth has no hosted CI. Every check runs locally through one script, and a pull request
should say that `tests/ci.sh` passed on it.

## Layout

| Path | What it holds |
|---|---|
| `crates/` | the published crates: `fastauth` (the facade), `core`, `macros`, `axum`, `actix`, `sqlx`, `redis`, `oauth`, `cli`, and the plugins in `plugins/<name>`. Folder names drop the `fastauth-` prefix, package names keep it: `crates/plugins/jwt` is `fastauth-plugin-jwt` |
| `docs/` | the documentation, also built into the website |
| `examples/fullstack/` | an axum and React app using most plugins, with `e2e.sh` |
| `skills/use-fastauth/` | the agent skill |
| `tests/` | the checks beyond each crate's own tests: `ci.sh` (local CI), `compat/` (the Better Auth client and cross-app suites), `fuzz/` (cargo-fuzz targets), `check-docs.sh` and `docs-check/` (docs code blocks), `upgrade-0.5-fixtures/` (rebuilds the 0.5 databases the upgrade test loads) and `deny.toml` (cargo-deny's licence and advisory policy) |
| `website/` | the docs site (Astro) |

## What you need

| For | Install |
|---|---|
| Building and testing | Rust stable (MSRV 1.94; the workspace uses edition 2024) |
| `test`, MySQL compat runs | Docker, able to pull `postgres:17` and `mysql:8.4` |
| `compat` | [bun](https://bun.sh), Node.js and npm for `run-vectors.sh`, and Chrome or Chromium for `run-passkey.sh` (`CHROME_PATH`, else `google-chrome`, `chromium` or `chromium-browser` on PATH) |
| `audit`, `deny` | `cargo install cargo-audit cargo-deny` |
| `docs` | Python 3 |
| `website` | Node.js and npm |
| `fuzz` | `rustup toolchain install nightly` and `cargo install cargo-fuzz` |

## Running the checks

```sh
tests/ci.sh            # everything, about 30 to 45 minutes from a warm target/
tests/ci.sh --quick    # fmt, clippy, tests, audit and deny
tests/ci.sh --only compat
tests/ci.sh --skip website,fuzz --fuzz-seconds 10
```

The script runs these groups in order, keeps going after a failure, prints a table of every
step with its result and time, and exits non-zero if any step failed.

| Group | What it runs |
|---|---|
| `fmt` | `cargo fmt --check` on the workspace and on `tests/fuzz/` |
| `clippy` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| `test` | `cargo test --workspace --all-features --no-fail-fast` against throwaway Postgres 17, MySQL 8.4 and Redis 7 containers, then `fastauth-redis`'s tests again against Valkey 8 |
| `compat` | every Better Auth 1.7.28 client script in `tests/compat/better-auth/` on the default backends, `run.sh` with `SERVER=actix`, `run-vectors.sh` (the Better Auth golden vectors, both directions), `tests/compat/better-auth-dual/run-dual.sh` (a Better Auth 1.7.8 app and a fastauth app on one Postgres 17, each accepting the other's sign-ins), and `run.sh`, `run-organization.sh` and `run-passkey.sh` on MySQL |
| `audit` | `cargo audit` (RustSec advisories against `Cargo.lock`) |
| `deny` | `cargo deny --config tests/deny.toml check licenses advisories` |
| `docs` | `tests/check-docs.sh`: every Rust block in `docs/` compiles against the current code (see `tests/docs-check/README.md`) |
| `website` | `npm ci`, `npm run build` and `npm run check:markdown` in `website/` |
| `fuzz` | builds every target in `tests/fuzz/` and runs each for `--fuzz-seconds` (default 30) from its committed corpus |

The script starts its database containers on free local ports and removes them when it
exits, including on Ctrl-C. Each compat script gets its own free port, and each MySQL compat run
gets its own empty database.

To run the database tests by hand, point `DATABASE_URL` at a Postgres database,
`MYSQL_DATABASE_URL` at a MySQL database and `REDIS_URL` at Redis or Valkey
(`redis://127.0.0.1:6379`). Each test creates and drops its own schema or database, and the
Redis tests use random keys. Without them, the Postgres, MySQL and Redis tests print a skip
notice and pass; the two-instance test in `fastauth-redis` needs both `DATABASE_URL` and
`REDIS_URL`.

On a machine several people build on, keep `target/` small:

```sh
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
```

`tests/ci.sh` sets `CARGO_INCREMENTAL=0` unless you set it yourself.

## Tests

- Unit and integration tests live next to each crate. Security regressions are named after
  the review that found them (`security_fast31_*.rs`, `security_fast46.rs`). A regression test
  for a bug that isn't fixed yet is `#[ignore]`d with the finding's id in its reason, and the
  fix removes the `#[ignore]`.
- Property tests use [proptest](https://docs.rs/proptest): `crates/core/tests/properties.rs`
  and `crates/sqlx/tests/properties_ids.rs`. When one fails, proptest writes the
  minimal input to a `*.proptest-regressions` file next to the test. Commit that file with
  the fix, so the case runs first from then on.
- Fuzz targets live in `tests/fuzz/`; see `tests/fuzz/README.md` for running them longer and for what
  each one checks.

## Pull requests

- Run `tests/ci.sh` and paste its summary table into the PR.
- Don't add GitHub workflows (`.github/workflows/`).
- New dependencies must pass `tests/deny.toml`'s licence list: MIT and MIT-compatible licences,
  plus MPL-2.0 for the webauthn-rs crates the passkey plugin uses. Anything else needs a
  discussion first.
- fastauth is MIT licensed, and contributions are accepted under the same licence.
