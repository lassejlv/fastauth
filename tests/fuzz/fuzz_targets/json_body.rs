//! Every JSON or query-string input through Auth::handle: routing, the Origin check, body and
//! query decoding, and the endpoint itself, signed in or not. Must never panic or answer 500.

#![no_main]

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use arbitrary::Arbitrary;
use bytes::Bytes;
use fastauth_fuzz::{BASE_URL, FIXTURE, send, sign_up};
use http::{Method, Request, StatusCode, header};
use libfuzzer_sys::fuzz_target;

const ROUTES: &[(&str, &str)] = &[
    ("POST", "/sign-up/email"),
    ("POST", "/sign-in/email"),
    ("POST", "/sign-out"),
    ("GET", "/get-session"),
    ("GET", "/list-sessions"),
    ("POST", "/revoke-session"),
    ("POST", "/revoke-other-sessions"),
    ("POST", "/update-user"),
    ("POST", "/change-password"),
    ("POST", "/send-verification-email"),
    ("GET", "/verify-email"),
    ("POST", "/request-password-reset"),
    ("POST", "/forget-password"),
    ("GET", "/reset-password/x"),
    ("POST", "/reset-password"),
    ("POST", "/email-otp/send-verification-otp"),
    ("POST", "/email-otp/check-verification-otp"),
    ("POST", "/email-otp/verify-email"),
    ("POST", "/sign-in/email-otp"),
    ("POST", "/email-otp/request-password-reset"),
    ("POST", "/email-otp/reset-password"),
    ("POST", "/sign-in/magic-link"),
    ("GET", "/magic-link/verify"),
    ("POST", "/two-factor/enable"),
    ("POST", "/two-factor/disable"),
    ("POST", "/two-factor/get-totp-uri"),
    ("POST", "/two-factor/verify-totp"),
    ("POST", "/two-factor/send-otp"),
    ("POST", "/two-factor/verify-otp"),
    ("POST", "/two-factor/generate-backup-codes"),
    ("POST", "/two-factor/verify-backup-code"),
    ("POST", "/organization/create"),
    ("POST", "/organization/update"),
    ("POST", "/organization/delete"),
    ("POST", "/organization/set-active"),
    ("GET", "/organization/get-full-organization"),
    ("GET", "/organization/list"),
    ("POST", "/organization/check-slug"),
    ("POST", "/organization/invite-member"),
    ("POST", "/organization/accept-invitation"),
    ("POST", "/organization/reject-invitation"),
    ("POST", "/organization/cancel-invitation"),
    ("GET", "/organization/get-invitation"),
    ("GET", "/organization/list-invitations"),
    ("GET", "/organization/list-user-invitations"),
    ("POST", "/organization/add-member"),
    ("POST", "/organization/remove-member"),
    ("POST", "/organization/update-member-role"),
    ("GET", "/organization/get-active-member"),
    ("GET", "/organization/list-members"),
    ("POST", "/organization/leave"),
    ("POST", "/organization/has-permission"),
    ("GET", "/admin/list-users"),
    ("GET", "/admin/get-user"),
    ("POST", "/admin/create-user"),
    ("POST", "/admin/update-user"),
    ("POST", "/admin/set-role"),
    ("POST", "/admin/ban-user"),
    ("POST", "/admin/unban-user"),
    ("POST", "/admin/impersonate-user"),
    ("POST", "/admin/stop-impersonating"),
    ("POST", "/admin/has-permission"),
    ("POST", "/api-key/create"),
    ("GET", "/api-key/get"),
    ("POST", "/api-key/update"),
    ("POST", "/api-key/delete"),
    ("GET", "/api-key/list"),
    ("POST", "/api-key/verify"),
    ("GET", "/jwks"),
    ("GET", "/token"),
    ("POST", "/sign-jwt"),
    ("POST", "/verify-jwt"),
];

#[derive(Arbitrary, Debug)]
struct Input {
    route: u8,
    signed_in: bool,
    origin: bool,
    query: String,
    body: Vec<u8>,
}

/// The session cookie the signed-in inputs carry, recreated when an input signed it out.
static SESSION: Mutex<Option<String>> = Mutex::new(None);
static USERS: AtomicU64 = AtomicU64::new(0);

fn session_cookie() -> String {
    let mut session = SESSION.lock().unwrap();
    let auth = &FIXTURE.auth;
    let alive = session.as_ref().is_some_and(|cookie| {
        let response = send(
            auth,
            Request::get("/api/auth/get-session")
                .header(header::COOKIE, cookie.as_str())
                .body(Bytes::new())
                .unwrap(),
        );
        response.body().as_ref() != b"null"
    });
    if !alive {
        let email = format!("fuzz-{}@acme.dk", USERS.fetch_add(1, Ordering::Relaxed));
        let (_, cookie) = sign_up(auth, &email);
        *session = Some(cookie);
    }
    session.clone().unwrap()
}

fn encode_query(query: &str) -> String {
    const KEEP: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~')
        .remove(b'=')
        .remove(b'&')
        .remove(b'%')
        .remove(b'+')
        .remove(b'/');
    percent_encoding::utf8_percent_encode(query, KEEP).to_string()
}

fuzz_target!(|input: Input| {
    let (method, path) = ROUTES[usize::from(input.route) % ROUTES.len()];
    let method = Method::from_bytes(method.as_bytes()).unwrap();
    let mut uri = format!("/api/auth{path}");
    if !input.query.is_empty() {
        uri.push('?');
        uri.push_str(&encode_query(&input.query));
    }
    let mut request = Request::builder().method(method).uri(uri);
    if input.origin {
        request = request.header(header::ORIGIN, BASE_URL);
    }
    if input.signed_in {
        request = request.header(header::COOKIE, session_cookie());
    }
    let Ok(request) = request.body(Bytes::from(input.body)) else {
        return;
    };
    let response = send(&FIXTURE.auth, request);
    assert_ne!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "500 from request input: {}",
        String::from_utf8_lossy(response.body())
    );
});
