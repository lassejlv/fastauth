#![cfg(feature = "axum")]

mod common;

use axum::Router;
use axum::body::Body;
use axum::routing::get;
use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_plugin_admin::{Admin, AdminExt, Permissions, RequireRole, role};
use http::{Request, StatusCode, header};
use tower::ServiceExt;

type AppAuth = Auth<MemoryAdapter, (), plugins![Admin]>;

role!(Support = "support");

async fn admin_only(admin: RequireRole<AppAuth, role::Admin>) -> String {
    admin.user.email.clone()
}

async fn support_only(support: RequireRole<AppAuth, Support>) -> String {
    support.user.email.clone()
}

fn app(auth: &AppAuth) -> Router {
    Router::new()
        .route("/admin", get(admin_only))
        .route("/support", get(support_only))
        .with_state(auth.clone())
}

async fn status(auth: &AppAuth, path: &str, cookies: Option<String>) -> StatusCode {
    let mut request = Request::get(path);
    if let Some(cookies) = cookies {
        request = request.header(header::COOKIE, cookies);
    }
    app(auth)
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn require_role_answers_401_403_or_lets_the_role_in() {
    let db = MemoryAdapter::new();
    let build = |admin: Admin| -> AppAuth {
        FastAuth::builder()
            .secret(secret())
            .base_url("http://localhost:3000")
            .database(db.clone())
            .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
            .rate_limit(RateLimit::disabled())
            .plugin(admin.role("support", Permissions::new().allow("user", ["list"])))
            .build()
            .unwrap()
    };
    let auth = build(Admin::new());
    let mut bob = Client::new(auth.clone());
    let id = Id::from(
        bob.sign_up("bob@acme.dk", "correct horse").await.json["user"]["id"]
            .as_str()
            .unwrap(),
    );

    assert_eq!(
        status(&auth, "/admin", None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(&auth, "/admin", bob.cookie_header()).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(&auth, "/support", bob.cookie_header()).await,
        StatusCode::FORBIDDEN
    );

    auth.admin()
        .set_role(&id, ["support", "user"])
        .await
        .unwrap();
    assert_eq!(
        status(&auth, "/support", bob.cookie_header()).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&auth, "/admin", bob.cookie_header()).await,
        StatusCode::FORBIDDEN
    );

    auth.admin().set_role(&id, "admin").await.unwrap();
    assert_eq!(
        status(&auth, "/admin", bob.cookie_header()).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&auth, "/support", bob.cookie_header()).await,
        StatusCode::FORBIDDEN
    );

    auth.admin().set_role(&id, "user").await.unwrap();
    let listed = build(Admin::new().admin_user_ids([id.clone()]));
    assert_eq!(
        status(&listed, "/admin", bob.cookie_header()).await,
        StatusCode::OK
    );
    let superadmins = build(
        Admin::new()
            .role("superadmin", Permissions::admin())
            .admin_roles(["admin", "superadmin"]),
    );
    superadmins
        .admin()
        .set_role(&id, "superadmin")
        .await
        .unwrap();
    assert_eq!(
        status(&superadmins, "/admin", bob.cookie_header()).await,
        StatusCode::OK
    );
}
