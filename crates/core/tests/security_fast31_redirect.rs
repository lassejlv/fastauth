//! FAST-31 security review evidence for CORE-1 (open redirects through callback URLs). Every
//! `sec_*` test asserts the secure behaviour, failed on 0.3.0, and is the regression test for
//! the fix.

mod common;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::mail::{AuthEmail, Mailer, MemoryMailer};
use fastauth_core::prelude::*;
use http::StatusCode;
use serde_json::json;

fn fast_hasher() -> EmailPassword {
    EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1))
}

fn auth_with(
    email_password: EmailPassword,
    mailer: impl Mailer,
    rate_limit: RateLimit,
) -> Auth<MemoryAdapter> {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(email_password)
        .mailer(mailer)
        .rate_limit(rate_limit)
        .build()
        .expect("valid config")
}

/// Where a browser goes for a Location header or a JSON "url" served by the app.
fn resolve(location: &str) -> url::Url {
    url::Url::parse("http://localhost:3000/")
        .unwrap()
        .join(location)
        .unwrap()
}

const PAYLOADS: [&str; 4] = [
    "/\t/evil.example/steal",
    "/\n/evil.example/steal",
    "/\r/evil.example/steal",
    "/\t\\evil.example/steal",
];

/// CORE-1: relative callback URLs with an ASCII tab/newline after the first slash pass
/// is_safe_redirect, but WHATWG URL parsing (browsers, the url crate) strips those
/// characters and lands on another host.
#[test]
fn sec_safe_redirect_rejects_tab_and_newline_tricks() {
    let auth = auth_with(fast_hasher(), MemoryMailer::new(), RateLimit::disabled());
    let mut accepted = Vec::new();
    for payload in PAYLOADS {
        let resolved = resolve(payload);
        assert_eq!(resolved.host_str(), Some("evil.example"), "{payload:?}");
        if auth.config().is_safe_redirect(payload) {
            accepted.push(format!("{payload:?} -> {resolved}"));
        }
    }
    assert!(
        accepted.is_empty(),
        "is_safe_redirect accepted off-origin targets:\n{}",
        accepted.join("\n")
    );
}

/// CORE-1 (impact): an attacker requests a reset for the victim with a tab-trick redirectTo.
/// The genuine reset email's link then 302s the victim's browser, reset token attached, to
/// the attacker's host.
#[tokio::test]
async fn sec_reset_email_link_cannot_send_token_off_origin() {
    let mailer = MemoryMailer::new();
    let auth = auth_with(fast_hasher(), mailer.clone(), RateLimit::disabled());
    let mut victim = Client::new(auth.clone());
    assert_eq!(
        victim
            .sign_up("victim@acme.dk", "correct horse")
            .await
            .status,
        StatusCode::OK
    );

    let mut attacker = Client::new(auth.clone());
    let requested = attacker
        .post(
            "/request-password-reset",
            json!({ "email": "victim@acme.dk", "redirectTo": "/\t/evil.example/steal" }),
        )
        .await;
    let Some(AuthEmail::ResetPassword(email)) = mailer.last() else {
        assert_eq!(requested.status, StatusCode::FORBIDDEN);
        return;
    };
    let link = email
        .url
        .strip_prefix("http://localhost:3000/api/auth")
        .unwrap()
        .to_owned();
    let mut victim_browser = Client::new(auth);
    let clicked = victim_browser.get(&link).await;
    let location = clicked.location().unwrap_or_default().to_owned();
    let landed = resolve(&location);
    assert!(
        landed.host_str() != Some("evil.example"),
        "request-password-reset answered {} and the emailed link {} redirected to {location:?}, \
         which a browser opens as {landed}: the reset token {} reaches the attacker",
        requested.status,
        email.url,
        email.token
    );
}

/// CORE-1 (unauthenticated variant): the GET callback routes redirect to the error target
/// without any valid token, so a crafted link on the app's own domain bounces anywhere.
#[tokio::test]
async fn sec_get_callbacks_do_not_open_redirect() {
    let auth = auth_with(fast_hasher(), MemoryMailer::new(), RateLimit::disabled());
    let mut browser = Client::new(auth);
    let mut open = Vec::new();
    for path in [
        "/verify-email?token=bogus&callbackURL=%2F%09%2Fevil.example%2F",
        "/reset-password/bogus?callbackURL=%2F%09%2Fevil.example%2F",
    ] {
        let res = browser.get(path).await;
        if let Some(location) = res.location() {
            let landed = resolve(location);
            if landed.host_str() == Some("evil.example") {
                open.push(format!(
                    "GET {path} -> {} {location:?} -> {landed}",
                    res.status
                ));
            }
        }
    }
    assert!(open.is_empty(), "open redirects:\n{}", open.join("\n"));
}

/// Inputs the `callback_url` fuzz target (tests/fuzz/fuzz_targets/callback_url.rs) found against
/// 0.3.0. Whatever `is_safe_redirect` accepts must stay on the app's origin once a browser
/// resolves it.
const FUZZ_REGRESSIONS: &[&str] = &[
    "/\r/Aww",
    "/\n/xe",
    "/\t/l//\u{7}A",
    "/\t/x/\t/",
    "/\t/l/\t/l",
    "/\r/s/\u{0}/w\u{0}/:",
    "/\t/l+o\u{8}\u{0}",
    "/\n\\v\n\nv#",
    "/\n/kZv",
    "/\t\t/w$:00000/\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}0\t\t<",
    "/\n/+/?\n(~..e\u{0}\u{2}\u{0}@[}/?\n(~..e\u{0}\u{2}\u{0}@\u{13}",
    "/\r/x",
    "/\n/+bp",
    "/\n\t/*\u{0}\n",
    "/\r/-P\u{f}",
    "/\t/lA",
    "/\t/o\u{7}\u{0}",
    "/\r/v:/.!x]\u{c}.\r",
    "/\n/x:/",
    "/\n/,",
    "/\r/h://t@",
    "/\r\r/=M\r\r\r\r\r\r\r\rM\t\r\r\r/",
    "/\t\t/\t\tv",
    "/\n\n/.*",
    "/\t/lo/\u{7}A",
    "/\n/\nA\tA\t",
    "/\r/rol\u{0}\u{8}",
    "/\n/xp\tbloFFF(p",
    "/\n\n/O/\u{3}*",
    "/\t/'",
    "/\n/\n~//",
    "/\r\r/P/",
    "/\n/@\n\n\n*\nvs",
    "/\r/x\\*]X\u{1d}&:\r\ry_:",
    "/\t/l",
    "/\n/0",
    "/\t/A",
    "/\t/2\u{17}",
    "/\r/e-",
    "/\t\t/\t\t\t\t~==",
    "/\r/l+o/$",
    "/\n/){\u{0}",
    "/\r/ws:",
    "/\r/\r3#\u{8}\u{0}",
    "/\n/S/",
    "/\t/l/",
    "/\n/n\n,",
    "/\t/0",
    "/\n/+v:/\u{0}",
    "/\t\t\n/'9\t\t\n*",
    "/\n/v//\u{0}/",
    "/\n/(le?\n\n",
    "/\n/\ts($",
    "/\n/v://?",
    "/\r\\-\u{f}",
    "/\t/llA",
    "/\t/.\n/",
    "/\n/c\u{0}\u{0}\u{0}",
    "/\t/o\u{7}@2E.A",
    "/\n/){*",
    "/\n\n/d*",
    "/\r/G\\-",
    "/\n/1",
    "/\t\t/\t\t\t\t+\t\t",
    "/\n/h",
];

/// CORE-1: the fuzzer's crashing inputs, kept as a regression test.
#[test]
fn sec_fuzz_callback_url_regressions_stay_on_origin() {
    let auth = auth_with(fast_hasher(), MemoryMailer::new(), RateLimit::disabled());
    let config = auth.config();
    let mut escaped = Vec::new();
    for target in FUZZ_REGRESSIONS {
        if !config.is_safe_redirect(target) {
            continue;
        }
        let landed = resolve(target);
        if landed.origin() != config.base_url.origin() {
            escaped.push(format!("{target:?} -> {landed}"));
        }
    }
    assert!(
        escaped.is_empty(),
        "accepted off-origin targets:\n{}",
        escaped.join("\n")
    );
}
