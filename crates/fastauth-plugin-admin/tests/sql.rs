//! The admin plugin on SQLite and, with `MYSQL_DATABASE_URL` set, MySQL: the role, ban and
//! impersonation columns migrate, list-users searches case-sensitively in SQL, and bans and
//! impersonation round-trip.

mod common;

use common::{Client, Res, secret};
use fastauth_core::adapter::Adapter;
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_plugin_admin::{Admin, AdminExt, CreateUserInput};
use fastauth_sqlx::sqlx::sqlite::SqlitePoolOptions;
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{MySqlPool, Sqlx};
use http::StatusCode;
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse";

fn emails(res: &Res) -> Vec<String> {
    res.json["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["email"].as_str().unwrap().to_owned())
        .collect()
}

async fn flow<D: Adapter>(db: D) {
    let auth: Auth<D, (), plugins![Admin]> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Admin::new())
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");
    assert!(auth.migrator().plan().await.unwrap().is_empty());

    let mut admin = Client::new(auth.clone());
    let res = admin.sign_up("root@acme.dk", PASSWORD).await;
    let root = Id::from(res.json["user"]["id"].as_str().unwrap());
    auth.admin().set_role(&root, "admin").await.unwrap();
    let mut bob_browser = Client::new(auth.clone());
    let res = bob_browser.sign_up("bob@acme.dk", PASSWORD).await;
    let bob = res.json["user"]["id"].as_str().unwrap().to_owned();
    for (email, name) in [
        ("ann@acme.dk", "Ann"),
        ("cat@other.io", "Cat"),
        ("d_t@acme.dk", "Dot"),
    ] {
        auth.admin()
            .create_user(CreateUserInput {
                email: email.into(),
                name: name.into(),
                ..CreateUserInput::default()
            })
            .await
            .unwrap();
    }

    let res = admin
        .get("/admin/list-users?searchValue=acme&sortBy=email&sortDirection=desc&limit=2&offset=1")
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["total"], 4);
    assert_eq!(emails(&res), ["d_t@acme.dk", "bob@acme.dk"]);
    let res = admin
        .get("/admin/list-users?searchValue=C&searchField=name&searchOperator=starts_with")
        .await;
    assert_eq!(emails(&res), ["cat@other.io"]);
    let res = admin
        .get("/admin/list-users?searchValue=.io&searchOperator=ends_with")
        .await;
    assert_eq!(emails(&res), ["cat@other.io"]);
    let res = admin.get("/admin/list-users?searchValue=_").await;
    assert_eq!(emails(&res), ["d_t@acme.dk"], "_ is not a wildcard");
    let res = admin.get("/admin/list-users?searchValue=ACME").await;
    assert_eq!(res.json["total"], 0, "search is case-sensitive");

    let res = admin
        .post(
            "/admin/ban-user",
            json!({ "userId": bob, "banReason": "spamming" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["banned"], true);
    assert_eq!(bob_browser.get("/get-session").await.json, Value::Null);
    let res = admin
        .get("/admin/list-users?filterField=banned&filterValue=true")
        .await;
    assert_eq!(emails(&res), ["bob@acme.dk"]);
    let res = bob_browser
        .post(
            "/sign-in/email",
            json!({ "email": "bob@acme.dk", "password": PASSWORD }),
        )
        .await;
    assert_eq!(res.json["code"], "BANNED_USER", "{}", res.json);
    let res = admin
        .post("/admin/unban-user", json!({ "userId": bob }))
        .await;
    assert_eq!(res.json["user"]["banned"], false, "{}", res.json);

    let res = admin
        .post("/admin/impersonate-user", json!({ "userId": bob }))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let session = admin.get("/get-session").await.json;
    assert_eq!(session["user"]["email"], "bob@acme.dk");
    assert_eq!(session["session"]["impersonatedBy"], root.as_str());
    let res = admin.post("/admin/stop-impersonating", json!({})).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(
        admin.get("/get-session").await.json["user"]["email"],
        "root@acme.dk"
    );
}

#[tokio::test]
async fn admin_on_sqlite() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite");
    flow(Sqlx::new(pool)).await;
}

#[tokio::test]
async fn admin_on_mysql() {
    let Ok(url) = std::env::var("MYSQL_DATABASE_URL") else {
        eprintln!("MYSQL_DATABASE_URL is not set; skipping the MySQL test");
        return;
    };
    let pool = MySqlPool::connect(&url)
        .await
        .expect("connect to MYSQL_DATABASE_URL");
    let database = format!("fastauth_admin_{}", Id::new_v7().as_str().replace('-', ""));
    flow(Sqlx::new(pool.clone()).schema(database.clone())).await;
    pool.execute(AssertSqlSafe(format!("DROP DATABASE `{database}`")))
        .await
        .expect("drop the test database");
}
