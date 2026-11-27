//! The storage knobs Better Auth database compatibility uses, on the memory adapter: raw
//! session tokens, foreign account rows, review-only migrations and verification pruning.
//! The better_auth_schema tests in fastauth-sqlx run the same knobs on Better Auth's tables.

mod common;

use common::{Client, secret};
use fastauth_core::adapter::DbError;
use fastauth_core::config::SessionTokens;
use fastauth_core::crypto::{Argon2id, Hash};
use fastauth_core::mail::AuthEmail;
use fastauth_core::migrate::{Migrations, ReviewOnly};
use fastauth_core::model::Model;
use fastauth_core::models::Verification;
use fastauth_core::prelude::*;
use fastauth_core::query::{Db, Where};
use fastauth_core::schema::ColumnNaming;
use fastauth_core::value::Value;
use fastauth_core::{Builder, Nil, Present};
use serde_json::json;
use time::OffsetDateTime;

fn builder() -> Builder<MemoryAdapter, (), Nil, Present, Present> {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
}

fn db(auth: &Auth<MemoryAdapter>) -> Db<'_, MemoryAdapter> {
    Db::new(auth.adapter(), auth.schema())
}

#[test]
fn camel_case_naming() {
    for (declared, stored) in [
        ("id", "id"),
        ("email_verified", "emailVerified"),
        ("access_token_expires_at", "accessTokenExpiresAt"),
        ("user_id", "userId"),
        ("customer_id", "customerId"),
    ] {
        assert_eq!(ColumnNaming::CamelCase.apply(declared), stored);
        assert_eq!(ColumnNaming::SnakeCase.apply(declared), declared);
    }
}

#[test]
fn storage_mistakes_fail_the_build() {
    let err = builder()
        .rename_column("user", "nickname", "nick")
        .bytes_as_hex_text("user", "email")
        .rename_column("account", "password_hash", "scope")
        .build()
        .unwrap_err();
    let problems = format!("{err:?}");
    for expected in [
        "rename_column names `user.nickname`, which is not in the schema",
        "bytes_as_hex_text names `user.email`, which is Text, not Bytes",
        "two columns of `account` are stored as `scope`",
    ] {
        assert!(problems.contains(expected), "{expected:?} in {problems}");
    }
}

#[test]
fn stored_names_follow_the_strategy_and_renames() {
    let auth = builder()
        .column_naming(ColumnNaming::CamelCase)
        .rename_column("account", "password_hash", "password")
        .bytes_as_hex_text("account", "access_token")
        .session_tokens(SessionTokens::Raw)
        .build()
        .unwrap();
    let account = auth.schema().expect("account");
    assert_eq!(account.stored_column("password_hash"), Some("password"));
    assert_eq!(account.stored_column("provider_id"), Some("providerId"));
    assert!(account.is_hex_text(account.position("access_token").unwrap()));
    assert!(!account.is_hex_text(account.position("refresh_token").unwrap()));
    let session = auth.schema().expect("session");
    assert_eq!(session.stored_column("token"), Some("token"));
    assert_eq!(session.stored_column("token_hash"), None);
    assert_eq!(session.stored_column("user_id"), Some("userId"));
    assert_eq!(
        session.stored_reference(session.position("user_id").unwrap()),
        Some("id")
    );
}

#[tokio::test]
async fn raw_session_tokens_are_stored_and_looked_up_as_they_are() {
    let auth = builder()
        .session_tokens(SessionTokens::Raw)
        .build()
        .unwrap();
    let mut client = Client::new(auth.clone());
    let signed_up = client.sign_up("raw@acme.dk", "correct horse").await;
    let token = signed_up.json["token"].as_str().unwrap().to_owned();

    let row = db(&auth)
        .find::<Session>(Session::TOKEN.eq(token.clone()))
        .one_row()
        .await
        .unwrap()
        .expect("the session row holds the token itself");
    assert!(row.table().position("token_hash").is_none());
    assert_eq!(
        Session::decode(&row).unwrap().token_hash,
        Hash::sha256(&token)
    );

    let me = client.get("/get-session").await;
    assert_eq!(me.json["user"]["email"], "raw@acme.dk", "{}", me.json);

    // A session row another app wrote the way Better Auth does: the token in `token`.
    let user_id = Value::Text(me.json["user"]["id"].as_str().unwrap().to_owned());
    let now = OffsetDateTime::now_utc();
    db(&auth)
        .insert_row::<Session>(vec![
            ("id", Value::Text("ba-session".into())),
            ("token", Value::Text("written-by-better-auth".into())),
            ("user_id", user_id),
            (
                "expires_at",
                Value::Timestamp(now + time::Duration::days(7)),
            ),
            ("created_at", Value::Timestamp(now)),
            ("updated_at", Value::Timestamp(now)),
        ])
        .await
        .unwrap();
    let found = auth
        .get_session_by_token("written-by-better-auth")
        .await
        .unwrap()
        .expect("fastauth resolves the other app's session");
    assert_eq!(found.user.email, "raw@acme.dk");
    assert!(
        auth.get_session_by_token("written-by-better-aut")
            .await
            .unwrap()
            .is_none()
    );

    let revoked = client
        .post(
            "/revoke-session",
            json!({ "token": "written-by-better-auth" }),
        )
        .await;
    assert_eq!(revoked.json["status"], true, "{}", revoked.json);
    assert!(
        auth.get_session_by_token("written-by-better-auth")
            .await
            .unwrap()
            .is_none()
    );

    client.post("/sign-out", json!({})).await;
    let left = db(&auth)
        .count::<Session>(Session::TOKEN.eq(token))
        .await
        .unwrap();
    assert_eq!(left, 0, "sign-out deletes the row");
}

#[tokio::test]
async fn hashed_session_tokens_stay_the_default() {
    let auth = builder().build().unwrap();
    let session = auth.schema().expect("session");
    assert!(session.position("token_hash").is_some());
    assert!(session.position("token").is_none());
    assert_eq!(auth.config().session_tokens(), SessionTokens::Hashed);
}

/// Signs up a user and gives it an `oidc` account another app owns.
async fn user_with_foreign_account(
    auth: &Auth<MemoryAdapter>,
) -> (Client<MemoryAdapter, (), Nil>, String) {
    let mut client = Client::new(auth.clone());
    let signed_up = client.sign_up("sso@acme.dk", "correct horse").await;
    let user_id = signed_up.json["user"]["id"].as_str().unwrap().to_owned();
    let now = OffsetDateTime::now_utc();
    db(auth)
        .insert_row::<Account>(vec![
            ("id", Value::Text("oidc-row".into())),
            ("user_id", Value::Text(user_id.clone())),
            ("provider_id", Value::Text("oidc".into())),
            ("account_id", Value::Text("sso-subject-1".into())),
            (
                "access_token",
                Value::Bytes(b"the sso app's token".to_vec()),
            ),
            ("created_at", Value::Timestamp(now)),
            ("updated_at", Value::Timestamp(now)),
        ])
        .await
        .unwrap();
    (client, user_id)
}

async fn providers(auth: &Auth<MemoryAdapter>, user_id: &str) -> Vec<String> {
    let mut providers: Vec<String> = db(auth)
        .find::<Account>(Account::USER_ID.eq(Id::from(user_id)))
        .all()
        .await
        .unwrap()
        .into_iter()
        .map(|a| a.provider_id)
        .collect();
    providers.sort();
    providers
}

async fn claim_by_verification_link(auth: &Auth<MemoryAdapter>, mailer: &MemoryMailer) {
    let mut client = Client::new(auth.clone());
    client
        .post(
            "/send-verification-email",
            json!({ "email": "sso@acme.dk" }),
        )
        .await;
    let Some(AuthEmail::VerifyEmail(email)) = mailer.last() else {
        panic!("no verification email")
    };
    // A browser that never knew the password, so the link claims the user.
    let verified = client
        .get(&format!("/verify-email?token={}", email.token))
        .await;
    assert!(verified.status.is_success(), "{}", verified.json);
}

#[tokio::test]
async fn a_claim_by_email_verification_leaves_foreign_accounts_alone() {
    let mailer = MemoryMailer::new();
    let auth = builder()
        .mailer(mailer.clone())
        .only_owned_accounts(true)
        .build()
        .unwrap();
    assert_eq!(
        auth.config().owned_account_providers(),
        Some(&["credential".to_owned()][..])
    );
    assert!(!auth.config().owns_account_provider("oidc"));
    let (_, user_id) = user_with_foreign_account(&auth).await;
    claim_by_verification_link(&auth, &mailer).await;
    assert_eq!(
        providers(&auth, &user_id).await,
        ["oidc"],
        "the claim deleted the password and left the oidc row"
    );
    let oidc = db(&auth)
        .find::<Account>(Account::ID.eq(Id::from("oidc-row")))
        .one()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        oidc.access_token.as_deref(),
        Some(&b"the sso app's token"[..])
    );
    assert_eq!(oidc.account_id, "sso-subject-1");
}

#[tokio::test]
async fn without_the_knob_a_claim_deletes_every_account_as_before() {
    let mailer = MemoryMailer::new();
    let auth = builder().mailer(mailer.clone()).build().unwrap();
    assert_eq!(auth.config().owned_account_providers(), None);
    let (_, user_id) = user_with_foreign_account(&auth).await;
    claim_by_verification_link(&auth, &mailer).await;
    assert!(providers(&auth, &user_id).await.is_empty());
}

#[tokio::test]
async fn a_password_reset_leaves_foreign_accounts_alone() {
    let mailer = MemoryMailer::new();
    let auth = builder()
        .mailer(mailer.clone())
        .only_owned_accounts(true)
        .build()
        .unwrap();
    let (mut client, user_id) = user_with_foreign_account(&auth).await;
    client
        .post("/request-password-reset", json!({ "email": "sso@acme.dk" }))
        .await;
    let Some(AuthEmail::ResetPassword(email)) = mailer.last() else {
        panic!("no reset email")
    };
    let reset = client
        .post(
            "/reset-password",
            json!({ "newPassword": "battery staple", "token": email.token }),
        )
        .await;
    assert_eq!(reset.json["status"], true, "{}", reset.json);
    assert_eq!(providers(&auth, &user_id).await, ["credential", "oidc"]);
    let signed_in = client
        .post(
            "/sign-in/email",
            json!({ "email": "sso@acme.dk", "password": "battery staple" }),
        )
        .await;
    assert_eq!(signed_in.status, http::StatusCode::OK, "{}", signed_in.json);
}

#[tokio::test]
async fn review_only_migrations_refuse_to_change_the_database() {
    let auth = builder()
        .migrations(Migrations::ReviewOnly)
        .build()
        .unwrap();
    let migrator = auth.migrator();
    assert_eq!(migrator.mode(), Migrations::ReviewOnly);
    let plan = migrator.plan().await.unwrap();
    assert!(!plan.is_empty());
    for result in [
        migrator.apply(&plan).await,
        migrator.run().await.map(|_| ()),
    ] {
        match result {
            Err(DbError::Other(err)) => {
                assert!(err.is::<ReviewOnly>(), "{err}");
                assert!(err.to_string().contains("fastauth generate"), "{err}");
            }
            other => panic!("expected the review-only refusal, got {other:?}"),
        }
    }
    assert_eq!(migrator.plan().await.unwrap(), plan, "nothing was applied");
}

async fn verification(auth: &Auth<MemoryAdapter>, id: &str, expires_in: time::Duration) {
    let now = OffsetDateTime::now_utc();
    db(auth)
        .insert(&Verification {
            id: Id::from(id),
            identifier: format!("test:{id}"),
            value_hash: Hash::sha256(id),
            data: None,
            expires_at: now + expires_in,
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
}

async fn verification_ids(auth: &Auth<MemoryAdapter>) -> Vec<String> {
    let mut ids: Vec<String> = db(auth)
        .find::<Verification>(Where::all())
        .all()
        .await
        .unwrap()
        .into_iter()
        .map(|v| v.id.to_string())
        .collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn pruning_deletes_only_expired_verifications() {
    let auth = builder().build().unwrap();
    verification(&auth, "expired-1", -time::Duration::minutes(1)).await;
    verification(&auth, "expired-2", -time::Duration::days(3)).await;
    verification(&auth, "live", time::Duration::minutes(15)).await;
    assert_eq!(auth.prune_verifications().await.unwrap(), 2);
    assert_eq!(verification_ids(&auth).await, ["live"]);
    assert_eq!(auth.prune_verifications().await.unwrap(), 0);
}

#[tokio::test]
async fn background_pruning_runs_on_its_interval_and_stops_with_the_auth() {
    let auth = builder().build().unwrap();
    let handle = auth.prune_verifications_every(std::time::Duration::from_millis(20));
    verification(&auth, "expired", -time::Duration::minutes(1)).await;
    verification(&auth, "live", time::Duration::minutes(15)).await;
    for _ in 0..200 {
        if verification_ids(&auth).await == ["live"] {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(verification_ids(&auth).await, ["live"]);
    drop(auth);
    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("the task ends once the auth is dropped")
        .unwrap();
}
