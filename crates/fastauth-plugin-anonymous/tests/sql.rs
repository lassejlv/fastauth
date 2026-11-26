//! The anonymous flow on SQLite and, with `DATABASE_URL` set, Postgres.

mod common;

use common::{Client, secret};
use fastauth_core::adapter::Adapter;
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_core::value::Id;
use fastauth_plugin_anonymous::{Anonymous, AnonymousUser};
use fastauth_sqlx::sqlx::sqlite::SqlitePoolOptions;
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{PgPool, Sqlx};
use http::StatusCode;
use serde_json::{Value, json};

async fn flow<D: Adapter>(db: D) {
    let auth: Auth<D, (), plugins![Anonymous]> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Anonymous::new())
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");
    let anonymous_users = || async {
        auth.api()
            .db()
            .find::<User>(AnonymousUser::IS_ANONYMOUS.eq(true))
            .all()
            .await
            .unwrap()
            .len()
    };

    let mut app = Client::new(auth.clone());
    let res = app.post("/sign-in/anonymous", json!({})).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["isAnonymous"], true);
    assert_eq!(anonymous_users().await, 1);

    let res = app.sign_up("ada@acme.dk", "correct horse").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["isAnonymous"], false);
    assert_eq!(anonymous_users().await, 0, "linked and deleted");
    assert_eq!(
        app.get("/get-session").await.json["user"]["email"],
        "ada@acme.dk"
    );

    let mut guest = Client::new(auth.clone());
    guest.post("/sign-in/anonymous", json!({})).await;
    assert_eq!(anonymous_users().await, 1);
    let res = guest.post("/delete-anonymous-user", json!({})).await;
    assert_eq!(res.json, json!({ "success": true }));
    assert_eq!(anonymous_users().await, 0);
    assert_eq!(guest.get("/get-session").await.json, Value::Null);
}

#[tokio::test]
async fn anonymous_on_sqlite() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite");
    flow(Sqlx::new(pool)).await;
}

#[tokio::test]
async fn anonymous_on_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL is not set; skipping the Postgres test");
        return;
    };
    let pool = PgPool::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    let schema = format!(
        "fastauth_anonymous_{}",
        Id::new_v7().as_str().replace('-', "")
    );
    flow(Sqlx::new(pool.clone()).schema(schema.clone())).await;
    pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .expect("drop the test schema");
}
