//! Two-factor sign-in through backup codes on SQLite and, with `MYSQL_DATABASE_URL` set,
//! MySQL: the plugin's table and user column migrate, and the pending sign-in, backup codes
//! and disabling round-trip.

mod common;

use common::{Client, secret};
use fastauth_core::adapter::Adapter;
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_core::value::Id;
use fastauth_plugin_two_factor::TwoFactor;
use fastauth_sqlx::sqlx::sqlite::SqlitePoolOptions;
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{MySqlPool, Sqlx};
use http::StatusCode;
use serde_json::{Value, json};

const EMAIL: &str = "ada@acme.dk";
const PASSWORD: &str = "correct horse";

async fn flow<D: Adapter>(db: D) {
    let auth: Auth<D, (), plugins![TwoFactor]> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(TwoFactor::new().skip_verification_on_enable(true))
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");
    assert!(auth.migrator().plan().await.unwrap().is_empty());

    let mut ada = Client::new(auth.clone());
    ada.sign_up(EMAIL, PASSWORD).await;
    let enabled = ada
        .post("/two-factor/enable", json!({ "password": PASSWORD }))
        .await;
    assert_eq!(enabled.status, StatusCode::OK, "{}", enabled.json);
    let codes: Vec<String> = serde_json::from_value(enabled.json["backupCodes"].clone()).unwrap();
    assert_eq!(codes.len(), 10);
    assert_eq!(
        ada.get("/get-session").await.json["user"]["twoFactorEnabled"],
        true
    );

    let sign_in = json!({ "email": EMAIL, "password": PASSWORD });
    ada.post("/sign-out", json!({})).await;
    let challenged = ada.post("/sign-in/email", sign_in.clone()).await;
    assert_eq!(
        challenged.json["twoFactorRedirect"], true,
        "{}",
        challenged.json
    );
    assert_eq!(ada.get("/get-session").await.json, Value::Null);
    let res = ada
        .post(
            "/two-factor/verify-backup-code",
            json!({ "code": codes[0] }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(ada.get("/get-session").await.json["user"]["email"], EMAIL);

    ada.post("/sign-out", json!({})).await;
    ada.post("/sign-in/email", sign_in.clone()).await;
    let reused = ada
        .post(
            "/two-factor/verify-backup-code",
            json!({ "code": codes[0] }),
        )
        .await;
    assert_eq!(
        reused.json["code"], "INVALID_BACKUP_CODE",
        "{}",
        reused.json
    );
    let res = ada
        .post(
            "/two-factor/verify-backup-code",
            json!({ "code": codes[1] }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);

    let res = ada
        .post("/two-factor/disable", json!({ "password": PASSWORD }))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    ada.post("/sign-out", json!({})).await;
    let res = ada.post("/sign-in/email", sign_in).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["twoFactorEnabled"], false, "{}", res.json);
}

#[tokio::test]
async fn two_factor_on_sqlite() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite");
    flow(Sqlx::new(pool)).await;
}

#[tokio::test]
async fn two_factor_on_mysql() {
    let Ok(url) = std::env::var("MYSQL_DATABASE_URL") else {
        eprintln!("MYSQL_DATABASE_URL is not set; skipping the MySQL test");
        return;
    };
    let pool = MySqlPool::connect(&url)
        .await
        .expect("connect to MYSQL_DATABASE_URL");
    let database = format!(
        "fastauth_two_factor_{}",
        Id::new_v7().as_str().replace('-', "")
    );
    flow(Sqlx::new(pool.clone()).schema(database.clone())).await;
    pool.execute(AssertSqlSafe(format!("DROP DATABASE `{database}`")))
        .await
        .expect("drop the test database");
}
