//! Register, sign in, rename and delete on SQLite and, with `DATABASE_URL` or
//! `MYSQL_DATABASE_URL` set, Postgres or MySQL.

mod common;

use common::authenticator::Authenticator;
use common::{Client, ORIGIN, secret};
use fastauth_core::adapter::Adapter;
use fastauth_core::crypto::Argon2id;
use fastauth_core::models::Verification;
use fastauth_core::prelude::*;
use fastauth_core::query::Where;
use fastauth_core::value::Id;
use fastauth_plugin_passkey::{Passkey, PasskeyRow};
use fastauth_sqlx::sqlx::sqlite::SqlitePoolOptions;
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{MySqlPool, PgPool, Sqlx};
use http::StatusCode;
use serde_json::json;

async fn flow<D: Adapter>(db: D) {
    let auth: Auth<D, (), plugins![Passkey]> = FastAuth::builder()
        .secret(secret())
        .base_url(ORIGIN)
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Passkey::new())
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");

    let mut ada = Client::new(auth.clone());
    assert_eq!(ada.sign_up("ada@acme.dk").await.status, StatusCode::OK);
    let mut key = Authenticator::new();
    let added = ada.add_passkey(&mut key, Some("Laptop")).await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.json);
    let id = added.json["id"].clone();
    assert_eq!(added.json["credentialID"], key.credential_id());
    assert_eq!(added.json["backedUp"], false);

    let mut phone = Client::new(auth.clone());
    let signed_in = phone.sign_in_with_passkey(&mut key).await;
    assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.json);
    assert_eq!(signed_in.json["user"]["email"], "ada@acme.dk");
    assert_eq!(
        phone.get("/get-session").await.json["user"]["email"],
        "ada@acme.dk"
    );

    let mut thief = Client::new(auth.clone());
    let mut clone = key.clone();
    phone.sign_in_with_passkey(&mut key).await;
    let res = thief.sign_in_with_passkey(&mut clone).await;
    assert_eq!(res.json["code"], "AUTHENTICATION_FAILED", "a stale counter");

    let rows = auth
        .api()
        .db()
        .find::<PasskeyRow>(Where::all())
        .all()
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].counter, 3);

    let renamed = ada
        .post(
            "/passkey/update-passkey",
            json!({ "id": id, "name": "Work" }),
        )
        .await;
    assert_eq!(renamed.json["passkey"]["name"], "Work");
    let listed = ada.get("/passkey/list-user-passkeys").await.json;
    assert_eq!(listed[0]["name"], "Work");
    assert_eq!(listed[0]["counter"], 3);

    let left = auth
        .api()
        .db()
        .find::<Verification>(Where::all())
        .all()
        .await
        .unwrap();
    assert!(
        left.iter().all(|v| v.identifier != "passkey"),
        "used challenges are gone: {left:?}"
    );

    let deleted = ada
        .post("/passkey/delete-passkey", json!({ "id": id }))
        .await;
    assert_eq!(deleted.json, json!({ "status": true }));
    let res = Client::new(auth.clone())
        .sign_in_with_passkey(&mut key)
        .await;
    assert_eq!(res.json["code"], "PASSKEY_NOT_FOUND");
}

#[tokio::test]
async fn passkey_on_sqlite() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite");
    flow(Sqlx::new(pool)).await;
}

#[tokio::test]
async fn passkey_on_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL is not set; skipping the Postgres test");
        return;
    };
    let pool = PgPool::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    let schema = format!(
        "fastauth_passkey_{}",
        Id::new_v7().as_str().replace('-', "")
    );
    flow(Sqlx::new(pool.clone()).schema(schema.clone())).await;
    pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .expect("drop the test schema");
}

#[tokio::test]
async fn passkey_on_mysql() {
    let Ok(url) = std::env::var("MYSQL_DATABASE_URL") else {
        eprintln!("MYSQL_DATABASE_URL is not set; skipping the MySQL test");
        return;
    };
    let pool = MySqlPool::connect(&url)
        .await
        .expect("connect to MYSQL_DATABASE_URL");
    let database = format!(
        "fastauth_passkey_{}",
        Id::new_v7().as_str().replace('-', "")
    );
    flow(Sqlx::new(pool.clone()).schema(database.clone())).await;
    pool.execute(AssertSqlSafe(format!("DROP DATABASE `{database}`")))
        .await
        .expect("drop the test database");
}
