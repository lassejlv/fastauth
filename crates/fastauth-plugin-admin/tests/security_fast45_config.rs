//! FAST-45 security review evidence (7cd9718), admin plugin: unbounded list responses.
//! sec_ tests assert the secure behaviour and fail on 7cd9718 on purpose.
//!
//! Run: cargo test -p fastauth-plugin-admin --test security_fast45_config -- --nocapture --test-threads=1

mod common;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_core::routes::CreateUserInput;
use fastauth_plugin_admin::{Admin, AdminExt};
use http::StatusCode;

type Plugins = plugins![Admin];

/// DOS-5: /admin/list-users without limit returns every user in one response (and loads them
/// all into memory first). Better Auth defaults to 100 (plugins/admin/routes: limit || 100).
#[tokio::test]
async fn sec_list_users_has_a_default_page_size() {
    let auth: Auth<MemoryAdapter, (), Plugins> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Admin::new())
        .build()
        .expect("valid config");
    let mut root = Client::new(auth.clone());
    let res = root.sign_up("root@acme.dk", "correct horse").await;
    let root_id = Id::from(res.json["user"]["id"].as_str().unwrap());
    auth.admin().set_role(&root_id, "admin").await.unwrap();
    for n in 0..300 {
        auth.api()
            .create_user(CreateUserInput {
                email: format!("user{n}@acme.dk"),
                name: format!("User {n}"),
                ..CreateUserInput::default()
            })
            .await
            .unwrap();
    }
    let res = root.get("/admin/list-users").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let returned = res.json["users"].as_array().map_or(0, Vec::len);
    println!("[/admin/list-users with no limit, 301 users] returned={returned}");
    assert!(
        returned <= 100,
        "/admin/list-users returned all {returned} users in one response"
    );
}
