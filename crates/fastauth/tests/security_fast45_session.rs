//! FAST-45 security review, area "session" (prefix SESS): session lifecycle across plugins.
//! These need several plugins at once, so they live in the umbrella crate and run with
//! `--all-features`. Tests named `sec_*` assert the secure behaviour and fail on 0.5.0
//! (7cd9718) on purpose; tests named `guard_*` pass and pin behaviour that was checked.
//!
//! cargo +stable test -p fastauth --all-features --test security_fast45_session -- --nocapture --test-threads=1
#![cfg(all(
    feature = "admin",
    feature = "api-key",
    feature = "two-factor",
    feature = "jwt",
    feature = "bearer",
    feature = "multi-session",
    feature = "macros"
))]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Bytes;
use axum::http::{HeaderMap, Request, header};
use fastauth::crypto::{Argon2id, Secret, base64url_decode};
use fastauth::mail::{AuthEmail, MemoryMailer};
use fastauth::models::Session as SessionRow;
use fastauth::plugins::admin::{
    Admin, AdminExt, AdminSession, AdminUser, BanUserInput, Permissions,
};
use fastauth::plugins::api_key::{ApiKeys, ApiKeysExt, CreateApiKeyInput, ListApiKeysInput};
use fastauth::plugins::bearer::Bearer;
use fastauth::plugins::jwt::Jwt;
use fastauth::plugins::multi_session::MultiSession;
use fastauth::plugins::two_factor::TwoFactor;
use fastauth::prelude::*;
use fastauth::query::Db;
use serde_json::{Value, json};
use time::OffsetDateTime;

/// An app column the app marked "never serialized to clients".
#[derive(Fields, Clone, Debug)]
pub struct Profile {
    #[field(returned = false)]
    pub internal_note: Option<String>,
}

type AppAuth =
    Auth<MemoryAdapter, Profile, plugins![Admin, ApiKeys, TwoFactor, Jwt, Bearer, MultiSession]>;

type SqlAuth<D> = Auth<D, (), plugins![Admin, ApiKeys, TwoFactor]>;

const ORIGIN: &str = "http://localhost:3000";
const PASSWORD: &str = "correct horse";

#[derive(Default)]
struct Opts {
    /// `SessionConfig::cookie_cache(5 min)`; off by default in fastauth.
    cookie_cache: bool,
    /// `update_age(0)`: every request may refresh the session.
    refresh_always: bool,
    /// An app `on_session_created` hook that fails while the flag is set.
    failing_hook: Option<Arc<AtomicBool>>,
    impersonation: Option<Duration>,
    mailer: Option<MemoryMailer>,
    /// An app session gate that, while the flag is set, deletes the user's sessions: a
    /// revocation that lands between the session lookup and its refresh.
    revoking_gate: Option<Arc<AtomicBool>>,
}

fn build(opts: Opts) -> AppAuth {
    let mut session = SessionConfig::default();
    if opts.cookie_cache {
        session = session.cookie_cache(Duration::minutes(5));
    }
    if opts.refresh_always {
        session = session.update_age(Duration::ZERO);
    }
    let mut admin = Admin::new().role("support", Permissions::new().allow("user", ["impersonate"]));
    if let Some(duration) = opts.impersonation {
        admin = admin.impersonation_session_duration(duration);
    }
    let mut builder = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .session(session)
        .rate_limit(RateLimit::disabled())
        .user_fields::<Profile>()
        .plugin(admin)
        .plugin(ApiKeys::new().sessions(true))
        .plugin(TwoFactor::new().skip_verification_on_enable(true))
        .plugin(Jwt::new())
        .plugin(Bearer::new())
        .plugin(MultiSession::new());
    if let Some(mailer) = opts.mailer {
        builder = builder.mailer(mailer);
    }
    if let Some(flag) = opts.failing_hook {
        builder = builder.configure(move |app| {
            app.on_session_created(move |_ctx, _session| {
                let flag = flag.clone();
                async move {
                    if flag.load(Ordering::SeqCst) {
                        Err(AuthError::bad_request(
                            "SESSION_LIMIT",
                            "this account has too many sessions",
                        ))
                    } else {
                        Ok(())
                    }
                }
            });
        });
    }
    if let Some(flag) = opts.revoking_gate {
        builder = builder.configure(move |app| {
            app.session_gate(move |ctx, session, _usage| {
                let flag = flag.clone();
                async move {
                    if flag.swap(false, Ordering::SeqCst) {
                        ctx.db()
                            .delete::<SessionRow>(SessionRow::USER_ID.eq(&session.user.id))
                            .await?;
                    }
                    Ok(())
                }
            });
        });
    }
    builder.build().expect("valid config")
}

/// Speaks HTTP to `Auth::handle` with a cookie jar.
struct Browser {
    auth: AppAuth,
    jar: HashMap<String, String>,
    /// The `Set-Cookie` values and headers of the last response.
    set_cookies: Vec<String>,
    headers: HeaderMap,
}

impl Browser {
    fn new(auth: &AppAuth) -> Self {
        Self {
            auth: auth.clone(),
            jar: HashMap::new(),
            set_cookies: Vec::new(),
            headers: HeaderMap::new(),
        }
    }

    async fn send(&mut self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        self.send_with(method, path, body, &[], true).await
    }

    async fn send_with(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
        extra: &[(&str, &str)],
        origin: bool,
    ) -> (u16, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("/api/auth{path}"))
            .header(header::CONTENT_TYPE, "application/json");
        if origin {
            builder = builder.header(header::ORIGIN, ORIGIN);
        }
        if !self.jar.is_empty() {
            let cookies = self
                .jar
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            builder = builder.header(header::COOKIE, cookies);
        }
        for (name, value) in extra {
            builder = builder.header(*name, *value);
        }
        let body = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
        let response = self.auth.handle(builder.body(body).unwrap()).await;
        self.set_cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();
        self.headers = response.headers().clone();
        for cookie in &self.set_cookies {
            let (pair, attrs) = cookie.split_once(';').unwrap_or((cookie, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if attrs.contains("Max-Age=0") {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.to_owned(), value.to_owned());
            }
        }
        let json = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
        (response.status().as_u16(), json)
    }

    /// The session cookie the last response set (not cleared), if any.
    fn new_session_cookie(&self) -> Option<&String> {
        self.set_cookies.iter().find(|c| {
            c.starts_with("fastauth.session_token=")
                && !c.starts_with("fastauth.session_token=;")
                && !c.contains("Max-Age=0")
        })
    }
}

fn db(auth: &AppAuth) -> Db<'_, MemoryAdapter> {
    Db::new(auth.adapter(), auth.schema())
}

async fn signed_up(auth: &AppAuth, email: &str) -> (Browser, Id) {
    let mut browser = Browser::new(auth);
    let (status, json) = browser
        .send(
            "POST",
            "/sign-up/email",
            Some(json!({ "email": email, "password": PASSWORD, "name": "Test User" })),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let user = db(auth)
        .find::<User>(User::EMAIL.eq(email))
        .one()
        .await
        .unwrap()
        .unwrap();
    (browser, user.id)
}

async fn signed_in(auth: &AppAuth, email: &str, remember_me: bool) -> Browser {
    let mut browser = Browser::new(auth);
    let (status, json) = browser
        .send(
            "POST",
            "/sign-in/email",
            Some(json!({ "email": email, "password": PASSWORD, "rememberMe": remember_me })),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    browser
}

async fn sessions_of(auth: &AppAuth, user: &Id) -> Vec<SessionRow> {
    db(auth)
        .find::<SessionRow>(SessionRow::USER_ID.eq(user))
        .all()
        .await
        .unwrap()
}

/// An admin whose browser holds a session cookie and a cookie-cache cookie written while
/// they were an admin.
async fn cached_admin(auth: &AppAuth) -> (Browser, Id) {
    let (mut admin, id) = signed_up(auth, "root@acme.dk").await;
    auth.admin().set_role(&id, "admin").await.unwrap();
    let (status, session) = admin.send("GET", "/get-session", None).await;
    assert_eq!(status, 200);
    assert_eq!(session["user"]["role"], "admin", "{session}");
    assert!(
        admin.jar.contains_key("fastauth.session_data"),
        "baseline: the cookie cache is written: {:?}",
        admin.jar.keys()
    );
    (admin, id)
}

/// A user with two-factor on whose browser holds a cookie-cache cookie, and whose
/// sessions were then all revoked (what `/revoke-sessions` from another device, a password
/// reset or an admin does).
async fn revoked_but_cached(auth: &AppAuth, email: &str) -> (Browser, Id) {
    let (mut user, id) = signed_up(auth, email).await;
    let (status, enabled) = user
        .send(
            "POST",
            "/two-factor/enable",
            Some(json!({ "password": PASSWORD })),
        )
        .await;
    assert_eq!(status, 200, "{enabled}");
    let (status, session) = user.send("GET", "/get-session", None).await;
    assert_eq!(status, 200);
    assert_eq!(session["user"]["twoFactorEnabled"], true, "{session}");
    assert!(user.jar.contains_key("fastauth.session_data"));
    db(auth)
        .delete::<SessionRow>(SessionRow::USER_ID.eq(&id))
        .await
        .unwrap();
    assert!(sessions_of(auth, &id).await.is_empty());
    (user, id)
}

// ------------------------------------------------------------------------------ SESS-1

/// SESS-1: with the cookie cache on, `/admin/*` authorizes from the cached session. An
/// admin whose sessions were revoked (a stolen cookie, an offboarded employee) can still
/// create a new admin account with a password of their choosing, which outlives the cache.
#[tokio::test]
async fn sec_revoked_admin_session_in_the_cookie_cache_cannot_create_an_admin() {
    let auth = build(Opts {
        cookie_cache: true,
        ..Opts::default()
    });
    let (mut admin, id) = cached_admin(&auth).await;
    auth.admin().revoke_user_sessions(&id).await.unwrap();
    assert!(sessions_of(&auth, &id).await.is_empty());

    let (status, json) = admin
        .send(
            "POST",
            "/admin/create-user",
            Some(json!({
                "email": "backdoor@evil.test",
                "password": "backdoor password",
                "name": "Backdoor",
                "role": "admin",
            })),
        )
        .await;
    let created = db(&auth)
        .find::<User>(User::EMAIL.eq("backdoor@evil.test"))
        .one()
        .await
        .unwrap();
    assert!(
        created.is_none(),
        "a revoked admin session created a new admin: {status} {json}"
    );
    assert!(matches!(status, 401 | 403), "{status} {json}");
}

/// SESS-1: a demoted admin's cached session still passes the `user:set-role` check, so
/// they give themselves the role back, for good.
#[tokio::test]
async fn sec_demoted_admin_in_the_cookie_cache_cannot_promote_themselves_again() {
    let auth = build(Opts {
        cookie_cache: true,
        ..Opts::default()
    });
    let (mut admin, id) = cached_admin(&auth).await;
    auth.admin().set_role(&id, "user").await.unwrap();

    let (status, json) = admin
        .send(
            "POST",
            "/admin/set-role",
            Some(json!({ "userId": id, "role": "admin" })),
        )
        .await;
    let row = db(&auth)
        .find::<User>(User::ID.eq(&id))
        .one_row()
        .await
        .unwrap()
        .unwrap();
    let role = AdminUser::decode(&row).unwrap().role;
    assert_eq!(
        role.as_deref(),
        Some("user"),
        "the demoted admin is an admin again: {status} {json}"
    );
    assert!(matches!(status, 401 | 403), "{status} {json}");
}

/// SESS-1: a banned admin's cached session (the ban revoked the stored one) still
/// impersonates another user, which mints a new stored session for that user.
#[tokio::test]
async fn sec_banned_admin_in_the_cookie_cache_cannot_impersonate() {
    let auth = build(Opts {
        cookie_cache: true,
        ..Opts::default()
    });
    let (mut admin, id) = cached_admin(&auth).await;
    let (_, bob) = signed_up(&auth, "bob@acme.dk").await;
    let before = sessions_of(&auth, &bob).await.len();
    auth.admin()
        .ban(BanUserInput::new(id.clone()))
        .await
        .unwrap();

    let (status, json) = admin
        .send(
            "POST",
            "/admin/impersonate-user",
            Some(json!({ "userId": bob })),
        )
        .await;
    assert_eq!(
        sessions_of(&auth, &bob).await.len(),
        before,
        "a banned admin got a session for bob: {status} {json}"
    );
    assert!(matches!(status, 401 | 403), "{status} {json}");
}

// ------------------------------------------------------------------------------ SESS-2

/// SESS-2: `/two-factor/generate-backup-codes` mints second factors from the cached
/// session. Someone who has the password and a revoked session's cookies gets working
/// backup codes, so two-factor no longer protects the account.
#[tokio::test]
async fn sec_revoked_session_in_the_cookie_cache_cannot_mint_backup_codes() {
    let auth = build(Opts {
        cookie_cache: true,
        ..Opts::default()
    });
    let (mut stale, _) = revoked_but_cached(&auth, "ada@acme.dk").await;
    let (status, json) = stale
        .send(
            "POST",
            "/two-factor/generate-backup-codes",
            Some(json!({ "password": PASSWORD })),
        )
        .await;
    assert!(
        json.get("backupCodes").is_none(),
        "a revoked session minted backup codes: {json}"
    );
    assert_eq!(status, 401, "{json}");
}

/// SESS-2: `/two-factor/get-totp-uri` hands the TOTP secret to the cached session.
#[tokio::test]
async fn sec_revoked_session_in_the_cookie_cache_cannot_read_the_totp_secret() {
    let auth = build(Opts {
        cookie_cache: true,
        ..Opts::default()
    });
    let (mut stale, _) = revoked_but_cached(&auth, "ada@acme.dk").await;
    let (status, json) = stale
        .send(
            "POST",
            "/two-factor/get-totp-uri",
            Some(json!({ "password": PASSWORD })),
        )
        .await;
    assert!(
        json.get("totpURI").is_none(),
        "a revoked session read the TOTP secret: {json}"
    );
    assert_eq!(status, 401, "{json}");
}

/// SESS-2: an API key's session (ephemeral, never a stored session) mints backup codes and
/// reads the TOTP secret, though the plugin docs say key sessions can't change two-factor.
/// Anyone holding a key and the password gets a second factor for the account.
#[tokio::test]
async fn sec_api_key_session_cannot_mint_backup_codes() {
    let auth = build(Opts::default());
    let (mut ada, id) = signed_up(&auth, "ada@acme.dk").await;
    let (status, json) = ada
        .send(
            "POST",
            "/two-factor/enable",
            Some(json!({ "password": PASSWORD })),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let key = auth
        .api_keys()
        .create(CreateApiKeyInput {
            user_id: Some(id.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    for path in [
        "/two-factor/generate-backup-codes",
        "/two-factor/get-totp-uri",
    ] {
        let (status, json) = Browser::new(&auth)
            .send_with(
                "POST",
                path,
                Some(json!({ "password": PASSWORD })),
                &[("x-api-key", key.key.as_str())],
                true,
            )
            .await;
        assert!(
            json.get("backupCodes").is_none() && json.get("totpURI").is_none(),
            "{path}: an API key session got a second factor: {json}"
        );
        assert!(matches!(status, 401 | 403), "{path}: {status} {json}");
    }
}

/// SESS-2: `/change-password` accepts the cached session (Better Auth reads the session
/// from the database here).
#[tokio::test]
async fn sec_revoked_session_in_the_cookie_cache_cannot_change_the_password() {
    let auth = build(Opts {
        cookie_cache: true,
        ..Opts::default()
    });
    let (mut stale, _) = revoked_but_cached(&auth, "ada@acme.dk").await;
    let (status, json) = stale
        .send(
            "POST",
            "/change-password",
            Some(json!({ "currentPassword": PASSWORD, "newPassword": "attacker's choice" })),
        )
        .await;
    assert_eq!(
        status, 401,
        "a revoked session changed the password: {json}"
    );
}

/// SESS-2: `/revoke-sessions` accepts the cached session, so a revoked session signs
/// the real user out of the sessions they opened since (Better Auth reads the session from
/// the database here).
#[tokio::test]
async fn sec_revoked_session_in_the_cookie_cache_cannot_revoke_the_users_new_sessions() {
    let auth = build(Opts {
        cookie_cache: true,
        ..Opts::default()
    });
    let (mut stale, id) = signed_up(&auth, "ada@acme.dk").await;
    stale.send("GET", "/get-session", None).await;
    assert!(stale.jar.contains_key("fastauth.session_data"));
    db(&auth)
        .delete::<SessionRow>(SessionRow::USER_ID.eq(&id))
        .await
        .unwrap();
    // The real user signs in again on their own device.
    let _fresh = signed_in(&auth, "ada@acme.dk", true).await;
    assert_eq!(sessions_of(&auth, &id).await.len(), 1);

    let (status, json) = stale.send("POST", "/revoke-sessions", None).await;
    assert_eq!(
        sessions_of(&auth, &id).await.len(),
        1,
        "a revoked session signed the user out everywhere: {status} {json}"
    );
    assert_eq!(status, 401, "{json}");
}

/// SESS-2: `/api-key/delete` reads `ctx.session()`, unlike create and update.
#[tokio::test]
async fn sec_revoked_session_in_the_cookie_cache_cannot_delete_api_keys() {
    let auth = build(Opts {
        cookie_cache: true,
        ..Opts::default()
    });
    let (mut stale, id) = signed_up(&auth, "ada@acme.dk").await;
    let key = auth
        .api_keys()
        .create(CreateApiKeyInput {
            user_id: Some(id.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    stale.send("GET", "/get-session", None).await;
    db(&auth)
        .delete::<SessionRow>(SessionRow::USER_ID.eq(&id))
        .await
        .unwrap();
    let (status, json) = stale
        .send(
            "POST",
            "/api-key/delete",
            Some(json!({ "keyId": key.api_key.id })),
        )
        .await;
    assert!(
        auth.api_keys().verify(&key.key, None).await.unwrap().valid,
        "a revoked session deleted the user's API key: {status} {json}"
    );
    assert_eq!(status, 401, "{json}");
}

// ------------------------------------------------------------------------------ SESS-3

/// SESS-3: an impersonation session can't create or update the user's API keys (FAST-31
/// AUTHZ-7), but it can delete them: `/api-key/delete` never asks for the sensitive session.
#[tokio::test]
async fn sec_impersonation_session_cannot_delete_the_users_api_keys() {
    let auth = build(Opts::default());
    let (mut admin, admin_id) = signed_up(&auth, "root@acme.dk").await;
    auth.admin().set_role(&admin_id, "support").await.unwrap();
    let (_, bob) = signed_up(&auth, "bob@acme.dk").await;
    let key = auth
        .api_keys()
        .create(CreateApiKeyInput {
            user_id: Some(bob.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    let (status, json) = admin
        .send(
            "POST",
            "/admin/impersonate-user",
            Some(json!({ "userId": bob })),
        )
        .await;
    assert_eq!(status, 200, "{json}");

    let (status, json) = admin
        .send(
            "POST",
            "/api-key/delete",
            Some(json!({ "keyId": key.api_key.id })),
        )
        .await;
    assert!(
        auth.api_keys().verify(&key.key, None).await.unwrap().valid,
        "an impersonation session deleted bob's API key: {status} {json}"
    );
    assert!(matches!(status, 401 | 403), "{status} {json}");
}

/// SESS-3: an API key's own session can't create or update keys (FAST-31 AUTHZ-3), but it
/// can delete every other key of its owner.
#[tokio::test]
async fn sec_api_key_session_cannot_delete_other_api_keys() {
    let auth = build(Opts::default());
    let (_, bob) = signed_up(&auth, "bob@acme.dk").await;
    let mut keys = Vec::new();
    for _ in 0..2 {
        keys.push(
            auth.api_keys()
                .create(CreateApiKeyInput {
                    user_id: Some(bob.clone()),
                    ..Default::default()
                })
                .await
                .unwrap(),
        );
    }
    let (status, json) = Browser::new(&auth)
        .send_with(
            "POST",
            "/api-key/delete",
            Some(json!({ "keyId": keys[1].api_key.id })),
            &[("x-api-key", keys[0].key.as_str())],
            true,
        )
        .await;
    assert!(
        auth.api_keys()
            .verify(&keys[1].key, None)
            .await
            .unwrap()
            .valid,
        "one API key deleted another: {status} {json}"
    );
    assert!(matches!(status, 401 | 403), "{status} {json}");
}

// ------------------------------------------------------------------------------ SESS-4

/// SESS-4: `rememberMe: false` only changes the cookie. The stored session gets the full
/// `expires_in` (7 days), where Better Auth gives such a session one day.
#[tokio::test]
async fn sec_dont_remember_session_expires_within_a_day() {
    let auth = build(Opts::default());
    let (_, id) = signed_up(&auth, "ada@acme.dk").await;
    db(&auth)
        .delete::<SessionRow>(SessionRow::USER_ID.eq(&id))
        .await
        .unwrap();
    let browser = signed_in(&auth, "ada@acme.dk", false).await;
    assert!(
        browser.jar.contains_key("fastauth.dont_remember"),
        "baseline: the sign-in was a don't-remember one"
    );
    let session = sessions_of(&auth, &id).await.remove(0);
    let lifetime = session.expires_at - OffsetDateTime::now_utc();
    assert!(
        lifetime <= Duration::days(1) + Duration::minutes(1),
        "a don't-remember session lives for {lifetime}"
    );
}

/// SESS-4: the sliding refresh extends a don't-remember session like any other, so it
/// never expires while its token is used. Better Auth never refreshes one.
#[tokio::test]
async fn sec_dont_remember_session_is_not_extended_by_refresh() {
    let auth = build(Opts {
        refresh_always: true,
        ..Opts::default()
    });
    let (_, id) = signed_up(&auth, "ada@acme.dk").await;
    db(&auth)
        .delete::<SessionRow>(SessionRow::USER_ID.eq(&id))
        .await
        .unwrap();
    let mut browser = signed_in(&auth, "ada@acme.dk", false).await;
    let before = sessions_of(&auth, &id).await.remove(0).expires_at;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (status, _) = browser.send("GET", "/get-session", None).await;
    assert_eq!(status, 200);
    let after = sessions_of(&auth, &id).await.remove(0).expires_at;
    assert_eq!(
        after, before,
        "the refresh extended a don't-remember session"
    );
}

/// SESS-4: with multi-session, a don't-remember sign-in still leaves a persistent
/// device-session cookie (`Max-Age` of the full session lifetime) holding the token, so
/// closing the browser doesn't end the session: `/multi-session/set-active` brings it back.
#[tokio::test]
async fn sec_dont_remember_sign_in_leaves_no_persistent_device_cookie() {
    let auth = build(Opts::default());
    let (_, _) = signed_up(&auth, "ada@acme.dk").await;
    let browser = signed_in(&auth, "ada@acme.dk", false).await;
    let session_cookie = browser.new_session_cookie().expect("a session cookie");
    assert!(
        !session_cookie.contains("Max-Age"),
        "baseline: the session cookie lasts for the browser session: {session_cookie}"
    );
    let device = browser
        .set_cookies
        .iter()
        .find(|c| c.contains("_multi-"))
        .expect("a device-session cookie");
    assert!(
        !device.contains("Max-Age"),
        "the device-session cookie outlives the browser session: {device}"
    );
}

// ------------------------------------------------------------------------------ SESS-5

/// SESS-5: `create_session` stores the session and queues its cookie before the session
/// hooks run, and an error response still carries queued cookies. When a hook refuses the
/// sign-in, the browser is signed in anyway.
#[tokio::test]
async fn sec_sign_in_a_session_hook_refused_sets_no_session_cookie() {
    let flag = Arc::new(AtomicBool::new(false));
    let auth = build(Opts {
        failing_hook: Some(flag.clone()),
        ..Opts::default()
    });
    let (_, id) = signed_up(&auth, "ada@acme.dk").await;
    db(&auth)
        .delete::<SessionRow>(SessionRow::USER_ID.eq(&id))
        .await
        .unwrap();
    flag.store(true, Ordering::SeqCst);
    let mut browser = Browser::new(&auth);
    let (status, json) = browser
        .send(
            "POST",
            "/sign-in/email",
            Some(json!({ "email": "ada@acme.dk", "password": PASSWORD })),
        )
        .await;
    assert_eq!(status, 400, "baseline: the hook failed the sign-in: {json}");
    assert_eq!(json["code"], "SESSION_LIMIT");
    flag.store(false, Ordering::SeqCst);
    let cookie = browser.new_session_cookie().cloned();
    let (_, session) = browser.send("GET", "/get-session", None).await;
    assert!(
        cookie.is_none() && session.is_null(),
        "the refused sign-in signed the browser in: cookie {cookie:?}, session {session}"
    );
}

/// SESS-5: `/admin/impersonate-user` creates an ordinary session for the target and marks it
/// `impersonatedBy` (and shortens it) in a second step. When a session hook fails in
/// between, the admin's browser holds a full, unmarked session for the target: 7 days,
/// refreshed, hidden from nothing, and allowed to mint credentials.
#[tokio::test]
async fn sec_failed_impersonation_leaves_no_unmarked_session_for_the_target() {
    let flag = Arc::new(AtomicBool::new(false));
    let auth = build(Opts {
        failing_hook: Some(flag.clone()),
        ..Opts::default()
    });
    let (mut admin, admin_id) = signed_up(&auth, "root@acme.dk").await;
    auth.admin().set_role(&admin_id, "support").await.unwrap();
    let (_, bob) = signed_up(&auth, "bob@acme.dk").await;
    db(&auth)
        .delete::<SessionRow>(SessionRow::USER_ID.eq(&bob))
        .await
        .unwrap();

    flag.store(true, Ordering::SeqCst);
    let (status, json) = admin
        .send(
            "POST",
            "/admin/impersonate-user",
            Some(json!({ "userId": bob })),
        )
        .await;
    flag.store(false, Ordering::SeqCst);
    assert_eq!(status, 400, "baseline: the hook failed the request: {json}");

    let rows = db(&auth)
        .find::<SessionRow>(SessionRow::USER_ID.eq(&bob))
        .all_rows()
        .await
        .unwrap();
    let unmarked = rows
        .iter()
        .filter(|row| AdminSession::decode(row).unwrap().impersonated_by.is_none())
        .count();
    let (_, session) = admin.send("GET", "/get-session", None).await;
    assert_eq!(
        unmarked, 0,
        "bob has a session that isn't marked as impersonation; the admin's browser now is {}",
        session["user"]["email"]
    );
    // And it must not be able to mint credentials for bob. The browser is still the admin's
    // (FAST-49 amendment: a correct fix leaves it signed in as root, as in Better Auth, so a
    // key it creates is root's own, and bob ends up with none).
    assert_eq!(session["user"]["email"], "root@acme.dk", "{session}");
    let (status, created) = admin
        .send("POST", "/api-key/create", Some(json!({ "name": "kept" })))
        .await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["userId"], admin_id.as_str(), "{created}");
    let bobs = auth
        .api_keys()
        .list(ListApiKeysInput {
            user_id: Some(bob.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(bobs.total, 0, "bob got an API key");
}

// ------------------------------------------------------------------------------ SESS-6

/// SESS-6: the cookie cache serializes the whole user and session rows into a cookie that
/// is signed, not encrypted, so columns marked `returned = false` ("never serialized to
/// clients") reach the browser.
#[tokio::test]
async fn sec_cookie_cache_holds_no_column_hidden_from_clients() {
    let auth = build(Opts {
        cookie_cache: true,
        ..Opts::default()
    });
    let (mut browser, id) = signed_up(&auth, "ada@acme.dk").await;
    db(&auth)
        .update::<User>(User::ID.eq(&id))
        .set(
            Profile::INTERNAL_NOTE,
            Some("chargeback-risk:high".to_owned()),
        )
        .exec()
        .await
        .unwrap();
    let (status, session) = browser.send("GET", "/get-session", None).await;
    assert_eq!(status, 200);
    assert!(
        !session.to_string().contains("chargeback-risk"),
        "baseline: /get-session hides the column: {session}"
    );
    let cookie = browser
        .jar
        .get("fastauth.session_data")
        .expect("the cookie cache");
    let (payload, _signature) = cookie.rsplit_once('.').unwrap();
    let decoded = String::from_utf8(base64url_decode(payload).unwrap()).unwrap();
    assert!(
        !decoded.contains("chargeback-risk"),
        "the cookie cache carries the hidden column: {decoded}"
    );
}

// ------------------------------------------------------------------------------ SESS-7

fn jwt_claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&base64url_decode(payload).unwrap()).unwrap()
}

/// SESS-7: `/token` signs a JWT valid for `expiration_time` (15 minutes) whatever the
/// session it came from. A one-minute impersonation session yields a token for the target
/// user that outlives it by 14 minutes, with nothing in it saying it is an impersonation.
#[tokio::test]
async fn sec_jwt_does_not_outlive_the_session_it_was_issued_for() {
    let auth = build(Opts {
        impersonation: Some(Duration::minutes(1)),
        ..Opts::default()
    });
    let (mut admin, admin_id) = signed_up(&auth, "root@acme.dk").await;
    auth.admin().set_role(&admin_id, "support").await.unwrap();
    let (_, bob) = signed_up(&auth, "bob@acme.dk").await;
    let (status, json) = admin
        .send(
            "POST",
            "/admin/impersonate-user",
            Some(json!({ "userId": bob })),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let (status, json) = admin.send("GET", "/token", None).await;
    assert_eq!(status, 200, "{json}");
    let claims = jwt_claims(json["token"].as_str().unwrap());
    assert_eq!(claims["sub"], bob.as_str());
    let session_end = (OffsetDateTime::now_utc() + Duration::minutes(1)).unix_timestamp();
    let exp = claims["exp"].as_i64().unwrap();
    assert!(
        exp <= session_end + 5,
        "the JWT of a one-minute impersonation session is valid for {} more seconds; claims: {claims}",
        exp - OffsetDateTime::now_utc().unix_timestamp()
    );
}

// ------------------------------------------------------------------------------ SESS-8

/// SESS-8: the sliding refresh ignores the row count of its conditional update. When the
/// session is revoked between the lookup and the refresh (another device's
/// `/revoke-sessions`, an admin ban), the response still sets a refreshed session cookie and,
/// with the cookie cache on, a fresh cache cookie for the revoked session, which then keeps
/// it alive for the cache's max age.
#[tokio::test]
async fn sec_refresh_of_a_concurrently_revoked_session_does_not_recache_it() {
    let flag = Arc::new(AtomicBool::new(false));
    let auth = build(Opts {
        cookie_cache: true,
        refresh_always: true,
        revoking_gate: Some(flag.clone()),
        ..Opts::default()
    });
    let (mut ada, id) = signed_up(&auth, "ada@acme.dk").await;
    // No cache cookie yet, so the next request looks the session up and refreshes it.
    ada.jar.remove("fastauth.session_data");
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    flag.store(true, Ordering::SeqCst);
    let (status, _) = ada.send("GET", "/get-session", None).await;
    assert_eq!(status, 200);
    assert!(
        sessions_of(&auth, &id).await.is_empty(),
        "baseline: the session was revoked mid-request"
    );
    let cached = ada
        .set_cookies
        .iter()
        .any(|c| c.starts_with("fastauth.session_data=") && !c.contains("Max-Age=0"));
    let (_, session) = ada.send("GET", "/get-session", None).await;
    assert!(
        !cached && session.is_null(),
        "the revoked session was re-cached (cache cookie set: {cached}) and still answers: {session}"
    );
}

// ------------------------------------------------------------------------------ guards

/// Checked: impersonation is marked, can't nest, can't mint credentials, and
/// `stop-impersonating` ends it and restores the admin.
#[tokio::test]
async fn guard_impersonation_is_marked_bounded_and_ends_cleanly() {
    let auth = build(Opts {
        refresh_always: true,
        ..Opts::default()
    });
    let (mut admin, admin_id) = signed_up(&auth, "root@acme.dk").await;
    auth.admin().set_role(&admin_id, "admin").await.unwrap();
    let (_, bob) = signed_up(&auth, "bob@acme.dk").await;
    let (_, carol) = signed_up(&auth, "carol@acme.dk").await;

    let (status, json) = admin
        .send(
            "POST",
            "/admin/impersonate-user",
            Some(json!({ "userId": bob })),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let token = json["session"]["token"].as_str().unwrap().to_owned();
    let (_, session) = admin.send("GET", "/get-session", None).await;
    assert_eq!(session["user"]["email"], "bob@acme.dk");
    assert_eq!(session["session"]["impersonatedBy"], admin_id.as_str());

    // The refresh (update_age = 0) doesn't extend it past the hour.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    admin.send("GET", "/get-session", None).await;
    let stored = sessions_of(&auth, &bob)
        .await
        .into_iter()
        .max_by_key(|s| s.created_at)
        .unwrap();
    assert!(stored.expires_at - OffsetDateTime::now_utc() <= Duration::hours(1));

    // No nesting, even though bob's session would have to be an admin's for it anyway.
    let (status, _) = admin
        .send(
            "POST",
            "/admin/impersonate-user",
            Some(json!({ "userId": carol })),
        )
        .await;
    assert_eq!(status, 403);
    // No credentials for bob.
    for (path, body) in [
        ("/api-key/create", json!({ "name": "x" })),
        ("/two-factor/enable", json!({ "password": PASSWORD })),
    ] {
        let (status, json) = admin.send("POST", path, Some(body)).await;
        assert_eq!(status, 403, "{path}: {json}");
    }
    // The user doesn't see the impersonation session in their own list... but the admin can stop.
    let (status, json) = admin.send("POST", "/admin/stop-impersonating", None).await;
    assert_eq!(status, 200, "{json}");
    let (_, session) = admin.send("GET", "/get-session", None).await;
    assert_eq!(session["user"]["email"], "root@acme.dk");
    assert!(!admin.jar.contains_key("fastauth.admin_session"));
    // The impersonation token is dead, as a cookie-less bearer token too.
    let (status, session) = Browser::new(&auth)
        .send_with(
            "GET",
            "/get-session",
            None,
            &[("authorization", &format!("Bearer {token}"))],
            true,
        )
        .await;
    assert_eq!(status, 200);
    assert!(session.is_null(), "{session}");
}

/// Checked: an admin's API key (an ephemeral session) can't impersonate, and a banned
/// admin's stored session is refused at once without the cookie cache.
#[tokio::test]
async fn guard_api_key_and_banned_admin_cannot_impersonate() {
    let auth = build(Opts::default());
    let (mut admin, admin_id) = signed_up(&auth, "root@acme.dk").await;
    auth.admin().set_role(&admin_id, "admin").await.unwrap();
    let (_, bob) = signed_up(&auth, "bob@acme.dk").await;
    let key = auth
        .api_keys()
        .create(CreateApiKeyInput {
            user_id: Some(admin_id.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    let (status, json) = Browser::new(&auth)
        .send_with(
            "POST",
            "/admin/impersonate-user",
            Some(json!({ "userId": bob })),
            &[("x-api-key", key.key.as_str())],
            true,
        )
        .await;
    assert_eq!(status, 403, "{json}");

    auth.admin()
        .ban(BanUserInput::new(admin_id.clone()))
        .await
        .unwrap();
    let (status, json) = admin
        .send(
            "POST",
            "/admin/impersonate-user",
            Some(json!({ "userId": bob })),
        )
        .await;
    assert_eq!(status, 401, "{json}");
}

/// Checked: bearer tokens. The raw and the signed token both resolve; a token with a bad
/// signature doesn't; a session cookie wins over a bearer header; a bad cookie isn't rescued
/// by a good bearer token; and a cookie-less bearer POST needs no Origin while a cookie POST
/// does.
#[tokio::test]
async fn guard_bearer_tokens_and_cookies_do_not_mix_identities() {
    let auth = build(Opts::default());
    let (mut ada, _) = signed_up(&auth, "ada@acme.dk").await;
    let signed = ada
        .headers
        .get("set-auth-token")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let (_, session) = ada.send("GET", "/get-session", None).await;
    let raw = session["session"]["token"].as_str().unwrap().to_owned();
    let (bob, _) = signed_up(&auth, "bob@acme.dk").await;

    for token in [raw.clone(), signed.clone()] {
        let (_, session) = Browser::new(&auth)
            .send_with(
                "GET",
                "/get-session",
                None,
                &[("authorization", &format!("Bearer {token}"))],
                false,
            )
            .await;
        assert_eq!(session["user"]["email"], "ada@acme.dk", "{token}");
    }
    let forged = format!("{raw}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let (_, session) = Browser::new(&auth)
        .send_with(
            "GET",
            "/get-session",
            None,
            &[("authorization", &format!("Bearer {forged}"))],
            false,
        )
        .await;
    assert!(session.is_null(), "{session}");

    // bob's cookie plus ada's bearer token: the cookie decides.
    let mut mixed = Browser::new(&auth);
    mixed.jar = bob.jar.clone();
    let bearer = format!("Bearer {raw}");
    let (_, session) = mixed
        .send_with(
            "GET",
            "/get-session",
            None,
            &[("authorization", &bearer)],
            true,
        )
        .await;
    assert_eq!(session["user"]["email"], "bob@acme.dk");

    // A cookie that doesn't verify plus a valid bearer token: signed out, not ada.
    let mut broken = Browser::new(&auth);
    broken
        .jar
        .insert("fastauth.session_token".into(), "nonsense.signature".into());
    let (_, session) = broken
        .send_with(
            "GET",
            "/get-session",
            None,
            &[("authorization", &bearer)],
            true,
        )
        .await;
    assert!(session.is_null(), "{session}");

    // CSRF: bearer without cookies needs no Origin; cookies without Origin are refused,
    // also when a bearer header is sent along.
    let (status, json) = Browser::new(&auth)
        .send_with(
            "POST",
            "/update-user",
            Some(json!({ "name": "Ada B" })),
            &[("authorization", &bearer)],
            false,
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let mut cookie_only = Browser::new(&auth);
    cookie_only.jar = bob.jar.clone();
    let (status, json) = cookie_only
        .send_with(
            "POST",
            "/update-user",
            Some(json!({ "name": "Mallory" })),
            &[("authorization", &bearer)],
            false,
        )
        .await;
    assert_eq!(status, 403, "{json}");
    assert_eq!(json["code"], "MISSING_OR_NULL_ORIGIN");
    // An untrusted Origin is refused for bearer requests too.
    let (status, _) = Browser::new(&auth)
        .send_with(
            "POST",
            "/update-user",
            Some(json!({ "name": "Mallory" })),
            &[
                ("authorization", &bearer),
                ("origin", "https://evil.example"),
            ],
            false,
        )
        .await;
    assert_eq!(status, 403);
}

/// Checked: multi-session. `/sign-out` revokes every device session; a revoked device
/// session can't be listed or switched to; another browser can't switch to a token it
/// doesn't hold a device cookie for.
#[tokio::test]
async fn guard_device_sessions_die_with_their_sessions() {
    let auth = build(Opts::default());
    let (mut browser, ada) = signed_up(&auth, "ada@acme.dk").await;
    let (_, bob) = signed_up(&auth, "bob@acme.dk").await;
    db(&auth)
        .delete::<SessionRow>(SessionRow::USER_ID.eq(&bob))
        .await
        .unwrap();
    // The same browser signs in as bob too.
    let (status, json) = browser
        .send(
            "POST",
            "/sign-in/email",
            Some(json!({ "email": "bob@acme.dk", "password": PASSWORD })),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let (_, list) = browser
        .send("GET", "/multi-session/list-device-sessions", None)
        .await;
    assert_eq!(list.as_array().unwrap().len(), 2, "{list}");
    let ada_token = list
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["user"]["email"] == "ada@acme.dk")
        .unwrap()["session"]["token"]
        .as_str()
        .unwrap()
        .to_owned();

    // A browser without the device cookie can't switch to ada's session by its token.
    let (status, _) = Browser::new(&auth)
        .send(
            "POST",
            "/multi-session/set-active",
            Some(json!({ "sessionToken": ada_token })),
        )
        .await;
    assert_eq!(status, 401);

    // ada's session is revoked elsewhere: the device cookie no longer lists or switches.
    db(&auth)
        .delete::<SessionRow>(SessionRow::USER_ID.eq(&ada))
        .await
        .unwrap();
    let (_, list) = browser
        .send("GET", "/multi-session/list-device-sessions", None)
        .await;
    assert_eq!(list.as_array().unwrap().len(), 1, "{list}");
    let (status, _) = browser
        .send(
            "POST",
            "/multi-session/set-active",
            Some(json!({ "sessionToken": ada_token })),
        )
        .await;
    assert_eq!(status, 401);

    // Sign-out ends bob's device session too.
    let (status, _) = browser.send("POST", "/sign-out", None).await;
    assert_eq!(status, 200);
    assert!(sessions_of(&auth, &bob).await.is_empty());
    assert!(
        !browser.jar.keys().any(|k| k.contains("_multi-")),
        "{:?}",
        browser.jar.keys()
    );
}

/// Checked (FAST-31 AUTHZ-5 fix): with the cookie cache on, a revoked session can't create
/// an API key or enable two-factor, because those read the session from the database.
#[tokio::test]
async fn guard_revoked_session_in_the_cookie_cache_cannot_create_credentials() {
    let auth = build(Opts {
        cookie_cache: true,
        ..Opts::default()
    });
    let (mut stale, id) = signed_up(&auth, "ada@acme.dk").await;
    stale.send("GET", "/get-session", None).await;
    db(&auth)
        .delete::<SessionRow>(SessionRow::USER_ID.eq(&id))
        .await
        .unwrap();
    for (path, body) in [
        ("/api-key/create", json!({ "name": "x" })),
        ("/two-factor/enable", json!({ "password": PASSWORD })),
    ] {
        let mut browser = Browser::new(&auth);
        browser.jar = stale.jar.clone();
        let (status, json) = browser.send("POST", path, Some(body)).await;
        assert_eq!(status, 401, "{path}: {json}");
    }
}

/// Checked: a password reset revokes every session by default, the bearer token of one
/// included, and the reset token works once.
#[tokio::test]
async fn guard_password_reset_revokes_sessions_and_bearer_tokens() {
    let mailer = MemoryMailer::new();
    let auth = build(Opts {
        mailer: Some(mailer.clone()),
        ..Opts::default()
    });
    let (mut ada, id) = signed_up(&auth, "ada@acme.dk").await;
    let (_, session) = ada.send("GET", "/get-session", None).await;
    let raw = session["session"]["token"].as_str().unwrap().to_owned();
    let (status, _) = Browser::new(&auth)
        .send(
            "POST",
            "/request-password-reset",
            Some(json!({ "email": "ada@acme.dk" })),
        )
        .await;
    assert_eq!(status, 200);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let token = mailer
        .sent()
        .into_iter()
        .find_map(|email| match email {
            AuthEmail::ResetPassword(reset) => Some(reset.token),
            _ => None,
        })
        .expect("a reset email");
    let body = json!({ "token": token, "newPassword": "a brand new password" });
    let (status, json) = Browser::new(&auth)
        .send("POST", "/reset-password", Some(body.clone()))
        .await;
    assert_eq!(status, 200, "{json}");
    assert!(sessions_of(&auth, &id).await.is_empty());
    let (_, session) = Browser::new(&auth)
        .send_with(
            "GET",
            "/get-session",
            None,
            &[("authorization", &format!("Bearer {raw}"))],
            false,
        )
        .await;
    assert!(session.is_null());
    let (status, _) = Browser::new(&auth)
        .send("POST", "/reset-password", Some(body))
        .await;
    assert_eq!(status, 400);
}

/// Checked on SQLite (foreign keys on, as the sqlx adapter connects): `/admin/remove-user`
/// takes the user's sessions, API keys and two-factor row with it, so nothing the user held
/// authenticates afterwards (a JWT already issued still runs to its `exp`; see SESS-7).
#[tokio::test]
async fn guard_removed_users_credentials_die_with_them_on_sqlite() {
    use fastauth::adapter::Adapter;
    use fastauth::prelude::{SqlitePool, Sqlx};

    async fn run<D: Adapter>(db: D) {
        let auth: SqlAuth<D> = FastAuth::builder()
            .secret(Secret::from_bytes(vec![42u8; 32]))
            .base_url(ORIGIN)
            .database(db)
            .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
            .rate_limit(RateLimit::disabled())
            .plugin(Admin::new())
            .plugin(ApiKeys::new().sessions(true))
            .plugin(TwoFactor::new().skip_verification_on_enable(true))
            .build()
            .expect("valid config");
        auth.migrator().run().await.expect("migrations");
        let user = auth
            .api()
            .create_user(fastauth::routes::CreateUserInput {
                email: "gone@acme.dk".into(),
                name: "Gone".into(),
                password: Some(PASSWORD.into()),
                ..Default::default()
            })
            .await
            .unwrap();
        let key = auth
            .api_keys()
            .create(CreateApiKeyInput {
                user_id: Some(user.id.clone()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(auth.api_keys().verify(&key.key, None).await.unwrap().valid);
        auth.admin().remove_user(&user.id).await.unwrap();
        let verified = auth.api_keys().verify(&key.key, None).await.unwrap();
        assert!(!verified.valid, "a removed user's API key still verifies");
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", key.key.parse().unwrap());
        assert!(auth.get_session(&headers).await.unwrap_or(None).is_none());
    }

    let path = std::env::temp_dir().join(format!("fastauth-fast45-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let pool = SqlitePool::connect(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .expect("SQLite file");
    run(Sqlx::new(pool)).await;
    let _ = std::fs::remove_file(path);
}
