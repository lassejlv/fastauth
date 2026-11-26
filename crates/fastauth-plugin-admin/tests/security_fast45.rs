//! FAST-45 security review (area: identity, prefix ATO): what the admin user-management
//! routes may write. Each `sec_*` test asserts the secure behaviour and fails on fastauth
//! 0.5.0 (7cd9718); `guard_*` tests pass.
//!
//! Run: cargo +stable test -p fastauth-plugin-admin --all-features --test security_fast45 -- --nocapture --test-threads=1

mod common;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_plugin_admin::{Admin, AdminExt, Permissions};
use fastauth_plugin_two_factor::TwoFactor;
use http::StatusCode;
use serde_json::json;

type Plugins = plugins![Admin, TwoFactor];
type AppAuth = Auth<MemoryAdapter, (), Plugins>;
type Browser = Client<MemoryAdapter, (), Plugins>;

const PASSWORD: &str = "correct horse";

fn build(admin: Admin) -> AppAuth {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(admin)
        .plugin(TwoFactor::new())
        .build()
        .expect("valid config")
}

async fn signed_up(auth: &AppAuth, email: &str) -> (Browser, Id) {
    let mut browser = Client::new(auth.clone());
    let res = browser.sign_up(email, PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let id = Id::from(res.json["user"]["id"].as_str().unwrap());
    (browser, id)
}

/// ATO-9: `/admin/update-user` needs `user:set-email` to write `emailVerified`, but
/// `/admin/create-user` takes it in `data` with `user:create` alone. A role that may only
/// create users makes a verified user for any address, with a password it chose.
#[tokio::test]
async fn sec_create_user_needs_set_email_to_mark_the_email_verified() {
    let auth = build(Admin::new().role(
        "onboarding",
        Permissions::new().allow("user", ["create", "update"]),
    ));
    let (mut helper, helper_id) = signed_up(&auth, "helper@acme.dk").await;
    auth.admin()
        .set_role(&helper_id, "onboarding")
        .await
        .unwrap();
    let (_, other_id) = signed_up(&auth, "other@acme.dk").await;

    let res = helper
        .post(
            "/admin/update-user",
            json!({ "userId": other_id, "data": { "emailVerified": true } }),
        )
        .await;
    assert_eq!(
        res.status,
        StatusCode::FORBIDDEN,
        "baseline, update refuses: {}",
        res.json
    );

    let res = helper
        .post(
            "/admin/create-user",
            json!({
                "email": "ceo@acme.dk",
                "name": "CEO",
                "password": "helper knows this",
                "data": { "emailVerified": true },
            }),
        )
        .await;
    println!(
        "[create-user with data.emailVerified and only user:create] status={} body={}",
        res.status, res.json
    );
    assert!(
        res.status != StatusCode::OK || res.json["user"]["emailVerified"] != true,
        "a role without user:set-email created a verified user: {}",
        res.json
    );
}

/// ATO-9: `/admin/update-user` writes any returned user column with `user:update` alone, so a
/// role that can't set passwords, emails or impersonate can still switch a user's two-factor
/// off by writing the plugin's flag.
#[tokio::test]
async fn sec_update_user_cannot_switch_off_two_factor() {
    let auth = build(Admin::new().role("support", Permissions::new().allow("user", ["update"])));
    let (mut support, support_id) = signed_up(&auth, "support@acme.dk").await;
    auth.admin().set_role(&support_id, "support").await.unwrap();
    let (mut ada, ada_id) = signed_up(&auth, "ada@acme.dk").await;
    auth.api()
        .db()
        .update::<User>(User::ID.eq(&ada_id))
        .set(
            fastauth_plugin_two_factor::TwoFactorUser::TWO_FACTOR_ENABLED,
            true,
        )
        .exec()
        .await
        .unwrap();
    assert_eq!(
        ada.get("/get-session").await.json["user"]["twoFactorEnabled"],
        true
    );

    let res = support
        .post(
            "/admin/update-user",
            json!({ "userId": ada_id, "data": { "twoFactorEnabled": false } }),
        )
        .await;
    let now = ada.get("/get-session").await.json["user"]["twoFactorEnabled"].clone();
    println!(
        "[update-user data.twoFactorEnabled=false with only user:update] status={} twoFactorEnabled now={now}",
        res.status
    );
    assert_eq!(
        now, true,
        "a role with only user:update switched Ada's two-factor off: {}",
        res.json
    );
}

/// The email itself is guarded on both routes: create refuses a taken address, and update
/// needs `user:set-email`.
#[tokio::test]
async fn guard_admin_email_writes_need_set_email_and_a_free_address() {
    let auth = build(Admin::new().role(
        "onboarding",
        Permissions::new().allow("user", ["create", "update"]),
    ));
    let (mut helper, helper_id) = signed_up(&auth, "helper@acme.dk").await;
    auth.admin()
        .set_role(&helper_id, "onboarding")
        .await
        .unwrap();
    let (_, other_id) = signed_up(&auth, "other@acme.dk").await;
    let res = helper
        .post(
            "/admin/update-user",
            json!({ "userId": other_id, "data": { "email": "ceo@acme.dk" } }),
        )
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.json);
    let res = helper
        .post(
            "/admin/create-user",
            json!({ "email": " OTHER@acme.dk ", "name": "Dup", "password": PASSWORD }),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.json);
    let res = helper
        .post(
            "/admin/create-user",
            json!({ "email": "x@acme.dk", "name": "X", "data": { "email": "ceo@acme.dk" } }),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.json);
}
