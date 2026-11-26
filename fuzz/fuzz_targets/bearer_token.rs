//! The Authorization header through the bearer resolver: scheme parsing, percent-decoding
//! and the signature check. A session may only come back for the real token.

#![no_main]

use fastauth_fuzz::{FIXTURE, session_user};
use http::{HeaderMap, HeaderValue, header};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let fixture = &*FIXTURE;
    let rest = String::from_utf8_lossy(rest);
    let authorization = match mode % 4 {
        0 => rest.into_owned(),
        1 => format!("Bearer {rest}"),
        2 => format!("Bearer {}{rest}", fixture.signed_token),
        _ => format!("Bearer {}{rest}", fixture.token),
    };
    let Ok(value) = HeaderValue::from_str(&authorization) else {
        return;
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, value);
    if session_user(&headers).is_some() {
        let decoded = percent_encoding::percent_decode_str(&authorization).decode_utf8_lossy();
        assert!(
            decoded.contains(&fixture.token),
            "a session came back for a bearer value without the token: {authorization:?}"
        );
    }
});
