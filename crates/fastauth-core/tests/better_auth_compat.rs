//! Better Auth database compatibility, end to end on the memory adapter: the cookie format,
//! the session refresh and the scrypt hasher, through `BetterAuthCompat` and its knobs. The
//! golden vectors are in `fastauth_core::compat`'s unit tests.

mod common;

use common::Client;
use fastauth_core::crypto::Secret;
use fastauth_core::prelude::*;
use serde_json::json;
use time::OffsetDateTime;

const BETTER_AUTH_SECRET: &str = "Zp1n3pXcQ3gyq0z0r1f8m2Kq4bVw9tYvJ6cL5dHs7uE=";

fn builder(
    base_url: &str,
) -> fastauth_core::Builder<
    MemoryAdapter,
    (),
    fastauth_core::Nil,
    fastauth_core::Present,
    fastauth_core::Present,
> {
    FastAuth::builder()
        .secret(Secret::from_base64(&Secret::generate()))
        .base_url(base_url)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default())
        .trusted_origins([common::ORIGIN])
        .rate_limit(RateLimit::disabled())
}

fn compat() -> BetterAuthCompat {
    BetterAuthCompat::new(BETTER_AUTH_SECRET).cookie_prefix("vt")
}

fn auth() -> Auth<MemoryAdapter> {
    builder("http://localhost:3000")
        .better_auth_compat(compat())
        .build()
        .unwrap()
}

/// The cookie better-call would read: percent-decoded, so `token.signature=`.
fn unencoded(cookie: &str) -> String {
    cookie
        .replace("%2B", "+")
        .replace("%2F", "/")
        .replace("%3D", "=")
}

#[tokio::test]
async fn session_cookies_use_better_auths_name_and_format() {
    let auth = builder("https://acme.dk")
        .better_auth_compat(compat())
        .build()
        .unwrap();
    let mut client = Client::new(auth);
    let res = client.sign_up("ba@acme.dk", "correct horse").await;
    assert_eq!(res.status, 200, "{}", res.json);
    let token = res.json["token"].as_str().unwrap().to_owned();
    let cookie = client.jar["__Secure-vt.session_token"].clone();
    let (value, signature) = cookie.rsplit_once('.').unwrap();
    assert_eq!(value, token);
    assert!(signature.ends_with("%3D"), "{cookie}");
    assert_eq!(unencoded(signature).len(), 44, "{cookie}");
    assert!(
        res.set_cookies().iter().all(|c| c.contains("; HttpOnly")
            && c.contains("; Secure")
            && c.contains("SameSite=Lax"))
    );

    client
        .jar
        .insert("__Secure-vt.session_token".into(), unencoded(&cookie));
    let session = client.get("/get-session").await;
    assert_eq!(session.json["user"]["email"], "ba@acme.dk");

    client.jar.insert(
        "__Secure-vt.session_token".into(),
        format!("{value}x.{signature}"),
    );
    assert_eq!(
        client.get("/get-session").await.json,
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn the_dont_remember_marker_is_signed_like_better_auth() {
    let mut client = Client::new(auth());
    client
        .post(
            "/sign-up/email",
            json!({ "email": "m@acme.dk", "password": "correct horse", "name": "M", "rememberMe": false }),
        )
        .await;
    client.jar.clear();
    let res = client
        .post(
            "/sign-in/email",
            json!({ "email": "m@acme.dk", "password": "correct horse", "rememberMe": false }),
        )
        .await;
    assert_eq!(res.status, 200, "{}", res.json);
    let marker = &client.jar["vt.dont_remember"];
    assert!(
        marker.starts_with("true.") && marker.ends_with("%3D"),
        "{marker}"
    );
}

#[tokio::test]
async fn passwords_are_better_auth_scrypt_hashes() {
    let auth = auth();
    let mut client = Client::new(auth.clone());
    client.sign_up("p@acme.dk", "\u{fb01}sh and chips").await;
    let account = auth
        .api()
        .db()
        .find::<Account>(Account::PROVIDER_ID.eq("credential"))
        .one()
        .await
        .unwrap()
        .unwrap();
    let hash = account.password_hash.unwrap();
    let (salt, key) = hash.split_once(':').unwrap();
    assert_eq!((salt.len(), key.len()), (32, 128), "{hash}");
    assert!(
        hash.bytes()
            .all(|b| b == b':' || b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );

    client.jar.clear();
    let res = client
        .post(
            "/sign-in/email",
            json!({ "email": "p@acme.dk", "password": "fish and chips" }),
        )
        .await;
    assert_eq!(res.status, 200, "NFKC-equal password: {}", res.json);
    let after = auth
        .api()
        .db()
        .find::<Account>(Account::PROVIDER_ID.eq("credential"))
        .one()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after.password_hash.as_deref(),
        Some(hash.as_str()),
        "never rehashed"
    );
}

/// Signs up and returns the client and the session's id.
async fn signed_in(
    auth: &Auth<MemoryAdapter>,
) -> (Client<MemoryAdapter, (), fastauth_core::Nil>, Id) {
    let mut client = Client::new(auth.clone());
    client.sign_up("s@acme.dk", "correct horse").await;
    let session = client.get("/get-session").await;
    let id = Id::from(session.json["session"]["id"].as_str().unwrap().to_owned());
    (client, id)
}

async fn set_times(
    auth: &Auth<MemoryAdapter>,
    id: &Id,
    created: OffsetDateTime,
    updated: OffsetDateTime,
    expires: OffsetDateTime,
) {
    auth.api()
        .db()
        .update::<Session>(Session::ID.eq(id))
        .set(Session::CREATED_AT, created)
        .set(Session::UPDATED_AT, updated)
        .set(Session::EXPIRES_AT, expires)
        .exec()
        .await
        .unwrap();
}

async fn expiry(auth: &Auth<MemoryAdapter>, id: &Id) -> OffsetDateTime {
    auth.api()
        .db()
        .find::<Session>(Session::ID.eq(id))
        .one()
        .await
        .unwrap()
        .unwrap()
        .expires_at
}

#[tokio::test]
async fn refresh_follows_better_auths_rule() {
    let auth = auth();
    let (mut client, id) = signed_in(&auth).await;
    let now = OffsetDateTime::now_utc();
    let fourteen = Duration::days(14);

    // Extended two days ago, then touched (Better Auth moves updatedAt on any update): due.
    let created = now - Duration::days(5);
    set_times(&auth, &id, created, now, now - Duration::days(2) + fourteen).await;
    let res = client.get("/get-session").await;
    assert!(
        res.set_cookies()
            .iter()
            .any(|c| c.starts_with("vt.session_token="))
    );
    let extended = expiry(&auth, &id).await;
    assert!(
        (extended - (now + fourteen)).abs() < Duration::minutes(1),
        "{extended}"
    );

    // Extended an hour ago: not due yet, whatever updatedAt says.
    let earlier = now - Duration::days(3);
    set_times(
        &auth,
        &id,
        created,
        earlier,
        now - Duration::hours(1) + fourteen,
    )
    .await;
    client.get("/get-session").await;
    assert_eq!(
        expiry(&auth, &id).await,
        now - Duration::hours(1) + fourteen
    );

    // Created to last a day (rememberMe: false), used without its marker: never extended.
    let short = now - Duration::hours(2);
    set_times(&auth, &id, short, short, short + Duration::days(1)).await;
    client.get("/get-session").await;
    assert_eq!(expiry(&auth, &id).await, short + Duration::days(1));
}

#[tokio::test]
async fn the_default_rule_still_reads_updated_at() {
    let auth = builder("http://localhost:3000")
        .session(SessionConfig::default().expires_in(Duration::days(14)))
        .build()
        .unwrap();
    let (mut client, id) = signed_in(&auth).await;
    let now = OffsetDateTime::now_utc();
    let expires = now - Duration::days(2) + Duration::days(14);
    set_times(&auth, &id, now - Duration::days(5), now, expires).await;
    client.get("/get-session").await;
    assert_eq!(expiry(&auth, &id).await, expires);
}

#[test]
fn the_cookie_cache_is_refused() {
    let err = builder("http://localhost:3000")
        .session(SessionConfig::default().cookie_cache(Duration::minutes(5)))
        .better_auth_compat(compat())
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("cookie cache"), "{err}");

    let err = builder("http://localhost:3000")
        .session(SessionConfig::default().cookie_cache(Duration::minutes(5)))
        .cookies(CookieConfig::default().signing(CookieSigning::better_auth(BETTER_AUTH_SECRET)))
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("cookie cache"), "{err}");
}

#[test]
fn a_weak_better_auth_secret_is_refused_in_production() {
    let weak = || BetterAuthCompat::new("changeme");
    let err = builder("https://acme.dk")
        .better_auth_compat(weak())
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("Better Auth secret"), "{err}");
    assert!(
        builder("https://acme.dk")
            .better_auth_compat(weak())
            .allow_insecure_config(true)
            .build()
            .is_ok()
    );
    assert!(
        builder("http://localhost:3000")
            .better_auth_compat(weak())
            .build()
            .is_ok()
    );
    let err = builder("http://localhost:3000")
        .better_auth_compat(BetterAuthCompat::new(""))
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("empty"), "{err}");
}
