//! The Cookie header: cookie parsing, the session cookie's HMAC check, and the signed cookie
//! cache. A session may only come back when the header carries the genuine signed cookie.

#![no_main]

use fastauth_core::cookies;
use fastauth_fuzz::{FIXTURE, session_user};
use http::{HeaderMap, HeaderValue, header};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let fixture = &*FIXTURE;
    let rest = String::from_utf8_lossy(rest);
    let cookie = match mode % 5 {
        0 => rest.into_owned(),
        1 => format!("fastauth.session_token={rest}"),
        2 => format!("{}{rest}", fixture.session_cookie),
        3 => format!("{}; fastauth.session_data={rest}", fixture.session_cookie),
        _ => format!(
            "{}; {}{rest}",
            fixture.session_cookie,
            fixture.cache_cookie.as_deref().unwrap_or_default()
        ),
    };
    let Ok(value) = HeaderValue::from_str(&cookie) else {
        return;
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, value);
    let _ = cookies::read(&headers, "fastauth.session_token");
    if session_user(&headers).is_some() {
        assert!(
            cookie.contains(&fixture.signed_token),
            "a session came back without the genuine signed cookie: {cookie:?}"
        );
    }
});
