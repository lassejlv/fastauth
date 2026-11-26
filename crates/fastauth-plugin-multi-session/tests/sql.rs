//! The multi-session flow on SQLite and, with `DATABASE_URL` set, Postgres.

mod common;

use common::{Client, secret};
use fastauth_core::adapter::Adapter;
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_core::value::Id;
use fastauth_plugin_multi_session::MultiSession;
use fastauth_sqlx::sqlx::sqlite::SqlitePoolOptions;
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{PgPool, Sqlx};
use http::StatusCode;
use serde_json::{Value, json};

async fn flow<D: Adapter>(db: D) {
    let auth: Auth<D, (), plugins![MultiSession]> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(MultiSession::new())
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");

    let mut browser = Client::new(auth.clone());
    let mut tokens = Vec::new();
    for email in ["ada@acme.dk", "bob@acme.dk"] {
        browser.sign_up(email, "correct horse").await;
        tokens.push(browser.get("/get-session").await.json["session"]["token"].clone());
    }
    let listed = browser
        .get("/multi-session/list-device-sessions")
        .await
        .json;
    assert_eq!(listed.as_array().unwrap().len(), 2, "{listed}");

    let res = browser
        .post(
            "/multi-session/set-active",
            json!({ "sessionToken": tokens[0] }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(
        browser.get("/get-session").await.json["user"]["email"],
        "ada@acme.dk"
    );

    let res = browser
        .post(
            "/multi-session/revoke",
            json!({ "sessionToken": tokens[0] }),
        )
        .await;
    assert_eq!(res.json, json!({ "status": true }));
    assert_eq!(
        browser.get("/get-session").await.json["user"]["email"],
        "bob@acme.dk"
    );

    browser.post("/sign-out", json!({})).await;
    assert_eq!(browser.get("/get-session").await.json, Value::Null);
    let left = browser
        .get("/multi-session/list-device-sessions")
        .await
        .json;
    assert_eq!(left, json!([]));
}

#[tokio::test]
async fn multi_session_on_sqlite() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite");
    flow(Sqlx::new(pool)).await;
}

#[tokio::test]
async fn multi_session_on_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL is not set; skipping the Postgres test");
        return;
    };
    let pool = PgPool::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    let schema = format!(
        "fastauth_multi_session_{}",
        Id::new_v7().as_str().replace('-', "")
    );
    flow(Sqlx::new(pool.clone()).schema(schema.clone())).await;
    pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .expect("drop the test schema");
}
