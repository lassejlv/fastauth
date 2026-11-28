# fastauth fuzz targets

cargo-fuzz targets for the parsers that see request input. `tests/fuzz/` is its own Cargo
workspace, so the root workspace never builds, tests or publishes it.

Needs nightly and cargo-fuzz. From the repo root, pass `--fuzz-dir tests/fuzz`:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz list --fuzz-dir tests/fuzz
cargo +nightly fuzz run --fuzz-dir tests/fuzz json_body -- -max_total_time=300
```

| Target | What it feeds | What must hold |
|---|---|---|
| `signed_cookie` | the `Cookie` header: raw, a forged `session_token`, the real cookie with junk appended, and junk `session_data` caches | no panic; a session only comes back when the header carries the genuine signed cookie |
| `bearer_token` | the `Authorization` header through the bearer resolver | no panic; a session only comes back for the real token |
| `jwt_header` | `JwksVerifier::verify` with raw tokens and tokens built around a fuzzed header | no panic; nothing verifies, since the fuzzer holds no private key (the JWKS includes an `oct` key to catch algorithm confusion) |
| `json_body` | `Auth::handle` on every core, email-otp, magic-link, two-factor, organization, admin, api-key and jwt route, signed in or not, with a fuzzed query string and body | no panic and no 500 |
| `email_normalize` | `routes::normalize_email` | no panic; accepted emails are at most 254 bytes, have a local part and a dotted domain, and normalize to themselves |
| `callback_url` | `CoreConfig::is_safe_redirect` | whatever it accepts resolves (WHATWG URL parsing, as browsers do) to the app's origin or a trusted origin |
| `cookie_cache` | the `session_data` cookie cache behind a *valid* signature (the target holds the secret): raw payloads, one field or column replaced with arbitrary JSON, `s`/`u` cut or padded | no panic; a cache entry written for another token, schema fingerprint or an expired time never stands in for the session, so the request falls back to the database and the cookie's real user |
| `multi_session_cookies` | a Cookie header mixing genuine, forged, renamed and tampered `*_multi-*` device cookies, then `list-device-sessions`, `set-active`, `revoke` and `/sign-out` | no 500; a browser only lists or switches to sessions whose signed cookies it holds, and never revokes one it doesn't hold |
| `oauth_callback` | `/callback/{provider}` with fuzzed `code`, `state`, `error` and junk parameters, a fuzzed or missing state cookie, and fuzzed token and userinfo answers from the provider | no 500; always a redirect to the app's origin or a trusted one; a sign-in only with the state and state cookie this browser started |
| `otp_verify` | sequences of password sign-in, TOTP, emailed two-factor codes, backup codes and email-OTP sign-in and checks, with live, padded and arbitrary codes, next to a model of which codes are live | no 500; a verify succeeds only for a code live at that moment: an unused TOTP step, the latest unspent emailed code, an unused backup code, an email OTP with guesses left |
| `passkey_json` | raw bodies to `verify-registration` and `verify-authentication`, and WebAuthn responses around a real P-256 credential with the client data, attestation object, authenticator data, credential id and signature fuzzed one part at a time (signed with the real key when asked) | no 500; registration needs the issued challenge, the app's origin and `webauthn.create`; sign-in needs the real key's signature over the issued challenge, the app's origin, `webauthn.get`, the RP id hash, user presence and the registered credential |
| `api_key_header` | `x-api-key` through the session resolver, and `/api-key/verify`: arbitrary values, the real key with junk before or after, one letter's case flipped, truncated, padded | no 500; a session or `valid: true` only for the exact issued key |
| `username` | `Username::normalize` and `validate` under fuzzed lengths, validation order and normalization, then `/sign-in/username` and `/is-username-available` | what `validate` accepts meets the length bounds and the default character set; a username sign-in or "taken" answer only for the stored username |
| `like_filter` | `contains`, `starts_with` and `ends_with` on `user.name` through fastauth-sqlx on in-process SQLite, over fuzzed names and needles | the SQL returns exactly the rows a plain Rust filter returns. Inputs with a NUL are skipped while SQLX-1 is open (see `crates/sqlx/tests/security_fast46.rs`) |
| `jwt_verify` | the jwt plugin's `verify` and `JwksVerifier` (with the plugin's JWKS) on raw tokens, on tokens the server signs with fuzzed `exp`/`nbf`/`iat`/`iss`/`aud`/`sub`, and on genuine tokens with one byte changed | raw tokens never verify; accepted claims always have a future `exp`, a past `nbf`, the issuer and the audience; a changed token never verifies with other claims |

`callback_url` failed on 0.3.0: `/\t/evil.example` passed the check and a browser opened it
as `http://evil.example/`. That was finding CORE-1 of the FAST-31 security review; the target
is the regression check for its fix, and the inputs it found are replayed by
`crates/core/tests/security_fast31_redirect.rs`.

Most targets that drive several requests build a fresh auth instance per input, so a crash
replays on its own. `tests/fuzz/corpus/<target>/` holds the corpus from the last long run (FAST-53, 61 minutes per
target, minimised with `-merge=1`: about 17,800 files, 1.8 MB); libFuzzer
adds to the first corpus directory it is given, so keep the committed one read-only by passing
a scratch directory first: `cargo +nightly fuzz run --fuzz-dir tests/fuzz -s none <target> /tmp/<target> tests/fuzz/corpus/<target>`.
`-s none` skips AddressSanitizer, which buys nothing in a crate that forbids `unsafe` and
doubles the speed. `tests/ci.sh` runs every target for 30 seconds this way.

For a long run, fork mode keeps going past known crashes and records each in
`tests/fuzz/artifacts/<target>/`:

```sh
cargo +nightly fuzz build --fuzz-dir tests/fuzz -s none
nice tests/fuzz/target/x86_64-unknown-linux-gnu/release/<target> tests/fuzz/corpus/<target> \
  -max_total_time=3600 -fork=1 -ignore_crashes=1 -ignore_ooms=1 -ignore_timeouts=1 \
  -rss_limit_mb=2560 -artifact_prefix=tests/fuzz/artifacts/<target>/
```

Crashes land in `tests/fuzz/artifacts/<target>/`; replay one with
`cargo +nightly fuzz run --fuzz-dir tests/fuzz <target> tests/fuzz/artifacts/<target>/<file>`. To keep going past a known
crash, add `-fork=1 -ignore_crashes=1`.
