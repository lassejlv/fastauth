//! FAST-31 security review (area: authz). Each test asserts the secure behaviour, so the
//! ones covering a finding fail on 0.3.0 and pass once it is fixed.

mod common;

use common::{Client, Res, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_core::query::Db;
use fastauth_plugin_admin::{Admin, AdminExt};
use http::StatusCode;
use serde_json::json;
use time::OffsetDateTime;

type Plugins = plugins![Admin];
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
        .build()
        .expect("valid config")
}

fn db(auth: &AppAuth) -> Db<'_, MemoryAdapter> {
    Db::new(auth.adapter(), auth.schema())
}

async fn signed_up(auth: &AppAuth, email: &str) -> (Browser, Id) {
    let mut browser = Client::new(auth.clone());
    let res = browser.sign_up(email, PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let id = Id::from(res.json["user"]["id"].as_str().unwrap());
    (browser, id)
}

/// Two users with the built-in `admin` role, which lacks `user:impersonate-admins`.
async fn two_admins(auth: &AppAuth) -> (Browser, Browser, Id) {
    let (root, root_id) = signed_up(auth, "root@acme.dk").await;
    auth.admin().set_role(&root_id, "admin").await.unwrap();
    let (ops, ops_id) = signed_up(auth, "ops@acme.dk").await;
    auth.admin().set_role(&ops_id, "admin").await.unwrap();
    (root, ops, ops_id)
}

fn report(name: &str, res: &Res) {
    println!("[{name}] status={} body={}", res.status, res.json);
}

/// AUTHZ-4: the default `admin` role may not impersonate another admin, so it must not be
/// able to take the account over by setting that admin's password either.
#[tokio::test]
async fn sec_admin_cannot_set_another_admins_password() {
    let auth = build(Admin::new());
    let (mut root, _ops, ops_id) = two_admins(&auth).await;

    let res = root
        .post("/admin/impersonate-user", json!({ "userId": ops_id }))
        .await;
    report("impersonate other admin", &res);
    assert_eq!(
        res.status,
        StatusCode::FORBIDDEN,
        "baseline: impersonation is refused"
    );

    let res = root
        .post(
            "/admin/set-user-password",
            json!({ "userId": ops_id, "newPassword": "attacker chosen pw" }),
        )
        .await;
    report("set other admin's password", &res);
    let mut attacker = Client::new(auth.clone());
    let signed_in = attacker
        .post(
            "/sign-in/email",
            json!({ "email": "ops@acme.dk", "password": "attacker chosen pw" }),
        )
        .await;
    report("sign in as other admin with the new password", &signed_in);
    assert_eq!(
        res.status,
        StatusCode::FORBIDDEN,
        "an admin without user:impersonate-admins set another admin's password: {}",
        res.json
    );
    assert_ne!(signed_in.status, StatusCode::OK);
}

/// AUTHZ-4: changing another admin's email (then resetting its password) is the same
/// takeover through `/admin/update-user`.
#[tokio::test]
async fn sec_admin_cannot_change_another_admins_email() {
    let auth = build(Admin::new());
    let (mut root, _ops, ops_id) = two_admins(&auth).await;
    let res = root
        .post(
            "/admin/update-user",
            json!({ "userId": ops_id, "data": { "email": "evil@attacker.dk", "emailVerified": true } }),
        )
        .await;
    report("update other admin's email", &res);
    assert_eq!(
        res.status,
        StatusCode::FORBIDDEN,
        "an admin without user:impersonate-admins changed another admin's email: {}",
        res.json
    );
}

/// AUTHZ-4: `admin_user_ids` are admins whatever their role; a role admin must not be able to
/// set their password.
#[tokio::test]
async fn sec_role_admin_cannot_set_password_of_admin_user_ids() {
    let db_auth = build(Admin::new());
    let (_, super_id) = signed_up(&db_auth, "super@acme.dk").await;
    let auth = {
        let adapter = db_auth.adapter().clone();
        FastAuth::builder()
            .secret(secret())
            .base_url("http://localhost:3000")
            .database(adapter)
            .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
            .rate_limit(RateLimit::disabled())
            .plugin(Admin::new().admin_user_ids([super_id.clone()]))
            .build()
            .expect("valid config")
    };
    let (mut root, root_id) = signed_up(&auth, "root@acme.dk").await;
    auth.admin().set_role(&root_id, "admin").await.unwrap();
    let res = root
        .post(
            "/admin/set-user-password",
            json!({ "userId": super_id, "newPassword": "attacker chosen pw" }),
        )
        .await;
    report("role admin sets admin_user_ids user's password", &res);
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.json);
}

/// AUTHZ-6: an impersonation session lasts `impersonation_session_duration`; the regular
/// session refresh must not stretch it to the full `expires_in`.
#[tokio::test]
async fn sec_impersonation_session_is_not_extended_by_refresh() {
    let auth = build(Admin::new().impersonation_session_duration(Duration::days(2)));
    let (mut admin, admin_id) = signed_up(&auth, "root@acme.dk").await;
    auth.admin().set_role(&admin_id, "admin").await.unwrap();
    let (_, bob) = signed_up(&auth, "bob@acme.dk").await;

    let res = admin
        .post("/admin/impersonate-user", json!({ "userId": bob }))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let session_id = Id::from(res.json["session"]["id"].as_str().unwrap());
    let before = db(&auth)
        .find::<Session>(Session::ID.eq(&session_id))
        .one()
        .await
        .unwrap()
        .unwrap();

    // The session was last touched more than `update_age` (1 day) ago.
    db(&auth)
        .update::<Session>(Session::ID.eq(&session_id))
        .set(
            Session::UPDATED_AT,
            OffsetDateTime::now_utc() - Duration::hours(25),
        )
        .exec()
        .await
        .unwrap();
    let res = admin.get("/get-session").await;
    assert_eq!(res.json["user"]["email"], "bob@acme.dk");
    let after = db(&auth)
        .find::<Session>(Session::ID.eq(&session_id))
        .one()
        .await
        .unwrap()
        .unwrap();
    println!(
        "[impersonation refresh] expires_at before={} after={} (impersonation duration 2 days, expires_in 7 days)",
        before.expires_at, after.expires_at
    );
    assert!(
        after.expires_at <= before.expires_at,
        "the impersonation session was extended from {} to {}",
        before.expires_at,
        after.expires_at
    );
}

/// Coverage: every admin endpoint refuses a plain user and an anonymous caller.
#[tokio::test]
async fn sec_admin_endpoints_refuse_plain_users_and_anonymous() {
    let auth = build(Admin::new());
    let (mut user, user_id) = signed_up(&auth, "bob@acme.dk").await;
    let (_, other) = signed_up(&auth, "eve@acme.dk").await;
    let mut anonymous: Browser = Client::new(auth.clone());
    let calls = [
        (
            "/admin/create-user",
            json!({ "email": "x@acme.dk", "name": "X", "password": PASSWORD }),
        ),
        (
            "/admin/set-role",
            json!({ "userId": user_id, "role": "admin" }),
        ),
        ("/admin/ban-user", json!({ "userId": other })),
        ("/admin/unban-user", json!({ "userId": other })),
        (
            "/admin/update-user",
            json!({ "userId": other, "data": { "name": "pwned" } }),
        ),
        (
            "/admin/set-user-password",
            json!({ "userId": other, "newPassword": "attacker chosen pw" }),
        ),
        ("/admin/remove-user", json!({ "userId": other })),
        ("/admin/list-user-sessions", json!({ "userId": other })),
        ("/admin/revoke-user-session", json!({ "sessionToken": "x" })),
        ("/admin/revoke-user-sessions", json!({ "userId": other })),
        ("/admin/impersonate-user", json!({ "userId": other })),
    ];
    for (path, body) in calls {
        let res = user.post(path, body.clone()).await;
        assert_eq!(
            res.status,
            StatusCode::FORBIDDEN,
            "{path} as user: {}",
            res.json
        );
        let res = anonymous.post(path, body).await;
        assert_eq!(
            res.status,
            StatusCode::UNAUTHORIZED,
            "{path} anonymous: {}",
            res.json
        );
    }
    for path in ["/admin/list-users", &format!("/admin/get-user?id={other}")] {
        let res = user.get(path).await;
        assert_eq!(
            res.status,
            StatusCode::FORBIDDEN,
            "{path} as user: {}",
            res.json
        );
        let res = anonymous.get(path).await;
        assert_eq!(
            res.status,
            StatusCode::UNAUTHORIZED,
            "{path} anonymous: {}",
            res.json
        );
    }
    let still = auth.admin().get_user(&other).await.unwrap();
    assert_eq!(still.name, "Test User");
}
