# fastauth fuzz targets

cargo-fuzz targets for the parsers that see request input. `fuzz/` is its own Cargo
workspace, so the root workspace never builds, tests or publishes it.

Needs nightly and cargo-fuzz:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run json_body -- -max_total_time=300
```

| Target | What it feeds | What must hold |
|---|---|---|
| `signed_cookie` | the `Cookie` header: raw, a forged `session_token`, the real cookie with junk appended, and junk `session_data` caches | no panic; a session only comes back when the header carries the genuine signed cookie |
| `bearer_token` | the `Authorization` header through the bearer resolver | no panic; a session only comes back for the real token |
| `jwt_header` | `JwksVerifier::verify` with raw tokens and tokens built around a fuzzed header | no panic; nothing verifies, since the fuzzer holds no private key (the JWKS includes an `oct` key to catch algorithm confusion) |
| `json_body` | `Auth::handle` on every core, email-otp, magic-link, two-factor, organization, admin, api-key and jwt route, signed in or not, with a fuzzed query string and body | no panic and no 500 |
| `email_normalize` | `routes::normalize_email` | no panic; accepted emails are at most 254 bytes, have a local part and a dotted domain, and normalize to themselves |
| `callback_url` | `CoreConfig::is_safe_redirect` | whatever it accepts resolves (WHATWG URL parsing, as browsers do) to the app's origin or a trusted origin |

`callback_url` fails on 0.3.0: `/\t/evil.example` passes the check and a browser opens it as
`http://evil.example/`. That is finding CORE-1 of the FAST-31 security review; the target is
the regression check for its fix.

Crashes land in `fuzz/artifacts/<target>/`; replay one with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`. To keep going past a known
crash, add `-fork=1 -ignore_crashes=1`.
