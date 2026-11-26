//! Email OTP on SQLite and, with `DATABASE_URL` set, Postgres: sign-up by code, attempt
//! counting and a password reset.

mod common;

use common::{Client, plugin_emails, secret};
use fastauth_core::adapter::Adapter;
use fastauth_core::crypto::Argon2id;
use fastauth_core::mail::MemoryMailer;
use fastauth_core::models::Verification;
use fastauth_core::prelude::*;
use fastauth_core::query::Where;
use fastauth_core::value::Id;
use fastauth_plugin_email_otp::EmailOtp;
use fastauth_sqlx::sqlx::sqlite::SqlitePoolOptions;
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{PgPool, Sqlx};
use http::StatusCode;
use serde_json::json;

fn last_code(mailer: &MemoryMailer) -> String {
    plugin_emails(mailer).pop().unwrap().code.unwrap()
}

async fn flow<D: Adapter>(db: D) {
    let mailer = MemoryMailer::new();
    let auth: Auth<D, (), plugins![EmailOtp]> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .email_verification(EmailVerification::default().send_on_sign_up(false))
        .rate_limit(RateLimit::disabled())
        .mailer(mailer.clone())
        .plugin(EmailOtp::new())
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");
    let mut ada = Client::new(auth.clone());

    ada.post(
        "/email-otp/send-verification-otp",
        json!({ "email": "ada@acme.dk", "type": "sign-in" }),
    )
    .await;
    let code = last_code(&mailer);
    let wrong = ada
        .post(
            "/sign-in/email-otp",
            json!({ "email": "ada@acme.dk", "otp": "000000x" }),
        )
        .await;
    assert_eq!(wrong.json["code"], "INVALID_OTP");
    let row = auth
        .api()
        .db()
        .find::<Verification>(Where::all())
        .one()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.data.as_deref(), Some("1"));
    let signed_in = ada
        .post(
            "/sign-in/email-otp",
            json!({ "email": "ada@acme.dk", "otp": code, "name": "Ada" }),
        )
        .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.json);
    assert_eq!(signed_in.json["user"]["emailVerified"], true);
    assert_eq!(ada.get("/get-session").await.json["user"]["name"], "Ada");

    ada.post(
        "/email-otp/request-password-reset",
        json!({ "email": "ada@acme.dk" }),
    )
    .await;
    let code = last_code(&mailer);
    let check = ada
        .post(
            "/email-otp/check-verification-otp",
            json!({ "email": "ada@acme.dk", "type": "forget-password", "otp": code }),
        )
        .await;
    assert_eq!(check.json, json!({ "success": true }));
    let reset = ada
        .post(
            "/email-otp/reset-password",
            json!({ "email": "ada@acme.dk", "otp": code, "password": "battery staple" }),
        )
        .await;
    assert_eq!(reset.json, json!({ "success": true }), "{}", reset.json);
    let password = Client::new(auth.clone())
        .post(
            "/sign-in/email",
            json!({ "email": "ada@acme.dk", "password": "battery staple" }),
        )
        .await;
    assert_eq!(password.status, StatusCode::OK, "{}", password.json);

    for _ in 0..3 {
        ada.post(
            "/email-otp/send-verification-otp",
            json!({ "email": "ada@acme.dk", "type": "email-verification" }),
        )
        .await;
    }
    let code = last_code(&mailer);
    for _ in 0..3 {
        ada.post(
            "/email-otp/verify-email",
            json!({ "email": "ada@acme.dk", "otp": "nope" }),
        )
        .await;
    }
    let burnt = ada
        .post(
            "/email-otp/verify-email",
            json!({ "email": "ada@acme.dk", "otp": code }),
        )
        .await;
    assert_eq!(burnt.status, StatusCode::FORBIDDEN);
    assert_eq!(burnt.json["code"], "TOO_MANY_ATTEMPTS");
    let left = auth
        .api()
        .db()
        .count::<Verification>(Where::all())
        .await
        .unwrap();
    assert_eq!(left, 0, "used and burnt codes are gone");
}

#[tokio::test]
async fn email_otp_on_sqlite() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite");
    flow(Sqlx::new(pool)).await;
}

#[tokio::test]
async fn email_otp_on_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL is not set; skipping the Postgres test");
        return;
    };
    let pool = PgPool::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    let schema = format!(
        "fastauth_email_otp_{}",
        Id::new_v7().as_str().replace('-', "")
    );
    flow(Sqlx::new(pool.clone()).schema(schema.clone())).await;
    pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .expect("drop the test schema");
}
