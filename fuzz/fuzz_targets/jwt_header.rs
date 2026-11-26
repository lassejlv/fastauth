//! JwksVerifier on hostile tokens: JWT header parsing, kid lookup and the algorithm a key
//! allows. The fuzzer holds no private key, so no token may ever verify.

#![no_main]

use std::sync::LazyLock;

use fastauth_core::crypto::base64url;
use fastauth_plugin_jwt::verify::JwksVerifier;
use libfuzzer_sys::fuzz_target;

/// RFC 8037's Ed25519 key, RFC 7517's P-256 key, one without kid or alg, and a symmetric
/// key that must never be accepted for verification.
const JWKS: &str = r#"{"keys":[
  {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"ed","alg":"EdDSA"},
  {"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","kid":"ec","alg":"ES256"},
  {"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","kid":"noalg"},
  {"kty":"oct","k":"c2VjcmV0","kid":"hmac","alg":"HS256"}
]}"#;

static VERIFIER: LazyLock<JwksVerifier> = LazyLock::new(|| {
    JwksVerifier::from_json(JWKS, "http://localhost:3000", "http://localhost:3000")
        .expect("valid JWKS")
});

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let token = if mode % 2 == 0 {
        String::from_utf8_lossy(rest).into_owned()
    } else {
        let claims = r#"{"sub":"u","iss":"http://localhost:3000","aud":"http://localhost:3000","exp":99999999999}"#;
        format!(
            "{}.{}.{}",
            base64url(rest),
            base64url(claims.as_bytes()),
            base64url(b"not a signature")
        )
    };
    let verified = VERIFIER.verify::<serde_json::Value>(&token);
    assert!(verified.is_err(), "a forged token verified: {token:?}");
});
