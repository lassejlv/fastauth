//! The magic link flow on SQLite and, with `DATABASE_URL` or
//! `MYSQL_DATABASE_URL` set, Postgres or MySQL.

mod common;

use common::{Client, auth_path, plugin_emails, secret};
use fastauth_core::adapter::Adapter;
use fastauth_core::crypto::Argon2id;
use fastauth_core::mail::MemoryMailer;
use fastauth_core::models::Verification;
use fastauth_core::prelude::*;
use fastauth_core::query::Where;
use fastauth_core::value::Id;
use fastauth_plugin_magic_link::MagicLink;
use fastauth_sqlx::sqlx::sqlite::SqlitePoolOptions;
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{MySqlPool, PgPool, Sqlx};
use http::StatusCode;
use serde_json::json;

async fn flow<D: Adapter>(db: D) {
    let mailer = MemoryMailer::new();
    let auth: Auth<D, (), plugins![MagicLink]> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .mailer(mailer.clone())
        .plugin(MagicLink::new())
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");

    let mut squatter = Client::new(auth.clone());
    squatter.sign_up("ada@acme.dk", "squatter password").await;

    let mut ada = Client::new(auth.clone());
    let sent = ada
        .post(
            "/sign-in/magic-link",
            json!({ "email": "ada@acme.dk", "name": "Ada", "callbackURL": "/app" }),
        )
        .await;
    assert_eq!(sent.json, json!({ "status": true }));
    let link = auth_path(
        plugin_emails(&mailer)
            .pop()
            .unwrap()
            .url
            .as_deref()
            .unwrap(),
    );
    let res = ada.get(&link).await;
    assert_eq!(res.status, StatusCode::FOUND);
    assert_eq!(res.location(), Some("http://localhost:3000/app"));
    let session = ada.get("/get-session").await.json;
    assert_eq!(session["user"]["email"], "ada@acme.dk");
    assert_eq!(session["user"]["emailVerified"], true);
    assert_eq!(squatter.get("/get-session").await.json, json!(null));

    let reused = Client::new(auth.clone()).get(&link).await;
    assert_eq!(
        reused.location(),
        Some("http://localhost:3000/app?error=INVALID_TOKEN")
    );

    let mut newcomer = Client::new(auth.clone());
    newcomer
        .post(
            "/sign-in/magic-link",
            json!({ "email": "new@acme.dk", "name": "New" }),
        )
        .await;
    let link = auth_path(
        plugin_emails(&mailer)
            .pop()
            .unwrap()
            .url
            .as_deref()
            .unwrap(),
    );
    let token = link
        .split(['?', '&'])
        .find_map(|p| p.strip_prefix("token="))
        .unwrap();
    let res = newcomer
        .get(&format!("/magic-link/verify?token={token}"))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["name"], "New");
    assert_eq!(res.json["user"]["emailVerified"], true);

    let left = auth
        .api()
        .db()
        .find::<Verification>(Where::all())
        .all()
        .await
        .unwrap();
    assert!(
        left.iter().all(|v| v.identifier != "magic-link"),
        "used links are gone: {left:?}"
    );
}

#[tokio::test]
async fn magic_link_on_sqlite() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite");
    flow(Sqlx::new(pool)).await;
}

#[tokio::test]
async fn magic_link_on_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL is not set; skipping the Postgres test");
        return;
    };
    let pool = PgPool::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    let schema = format!(
        "fastauth_magic_link_{}",
        Id::new_v7().as_str().replace('-', "")
    );
    flow(Sqlx::new(pool.clone()).schema(schema.clone())).await;
    pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .expect("drop the test schema");
}

#[tokio::test]
async fn magic_link_on_mysql() {
    let Ok(url) = std::env::var("MYSQL_DATABASE_URL") else {
        eprintln!("MYSQL_DATABASE_URL is not set; skipping the MySQL test");
        return;
    };
    let pool = MySqlPool::connect(&url)
        .await
        .expect("connect to MYSQL_DATABASE_URL");
    let database = format!(
        "fastauth_magic_link_{}",
        Id::new_v7().as_str().replace('-', "")
    );
    flow(Sqlx::new(pool.clone()).schema(database.clone())).await;
    pool.execute(AssertSqlSafe(format!("DROP DATABASE `{database}`")))
        .await
        .expect("drop the test database");
}
