//! The username flow on SQLite and, with `DATABASE_URL` set, Postgres.

mod common;

use common::{Client, secret};
use fastauth_core::adapter::Adapter;
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_core::value::Id;
use fastauth_plugin_username::{Username, UsernameExt};
use fastauth_sqlx::sqlx::sqlite::SqlitePoolOptions;
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{PgPool, Sqlx};
use http::StatusCode;
use serde_json::{Value, json};

async fn flow<D: Adapter>(db: D) {
    let auth: Auth<D, (), plugins![Username]> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Username::new())
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");

    let sign_up = |email: &str, extra: Value| {
        let mut body = json!({ "email": email, "password": "correct horse", "name": "Test" });
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        body
    };
    let mut ada = Client::new(auth.clone());
    let res = ada
        .post(
            "/sign-up/email",
            sign_up("ada@acme.dk", json!({ "username": "Ada" })),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["username"], "ada");
    assert_eq!(res.json["user"]["displayUsername"], "Ada");

    for email in ["a@acme.dk", "b@acme.dk"] {
        let res = Client::new(auth.clone())
            .post("/sign-up/email", sign_up(email, json!({})))
            .await;
        assert_eq!(
            res.status,
            StatusCode::OK,
            "users without a username: {}",
            res.json
        );
    }
    let taken = Client::new(auth.clone())
        .post(
            "/sign-up/email",
            sign_up("c@acme.dk", json!({ "username": "ADA" })),
        )
        .await;
    assert_eq!(taken.json["code"], "USERNAME_IS_ALREADY_TAKEN");

    let mut again = Client::new(auth.clone());
    let res = again
        .post(
            "/sign-in/username",
            json!({ "username": "ADA", "password": "correct horse" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(
        again.get("/get-session").await.json["user"]["username"],
        "ada"
    );

    let res = again
        .post("/update-user", json!({ "username": "Countess" }))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert!(
        auth.username()
            .find_user("countess")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        auth.username()
            .is_available("ada")
            .await
            .unwrap()
            .data
            .available
    );
    assert!(
        !auth
            .username()
            .is_available("COUNTESS")
            .await
            .unwrap()
            .data
            .available
    );
}

#[tokio::test]
async fn username_on_sqlite() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite");
    flow(Sqlx::new(pool)).await;
}

#[tokio::test]
async fn username_on_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL is not set; skipping the Postgres test");
        return;
    };
    let pool = PgPool::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    let schema = format!(
        "fastauth_username_{}",
        Id::new_v7().as_str().replace('-', "")
    );
    flow(Sqlx::new(pool.clone()).schema(schema.clone())).await;
    pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .expect("drop the test schema");
}
