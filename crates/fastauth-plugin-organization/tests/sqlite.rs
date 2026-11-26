//! The organization flow on SQLite and, with `MYSQL_DATABASE_URL` set, MySQL: the derived
//! tables migrate, foreign keys hold, JSON metadata and the invitation status round-trip, and
//! deleting an organization clears its members and invitations.

mod common;

use common::{Client, secret};
use fastauth_core::adapter::Adapter;
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_core::query::Db;
use fastauth_core::value::Id;
use fastauth_plugin_organization::Organization;
use fastauth_sqlx::sqlx::sqlite::SqlitePoolOptions;
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{MySqlPool, Sqlx};
use http::StatusCode;
use serde_json::json;

type App<D> = Client<D, (), plugins![Organization]>;

#[tokio::test]
async fn organization_flow_on_sqlite() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite");
    flow(Sqlx::new(pool)).await;
}

#[tokio::test]
async fn organization_flow_on_mysql() {
    let Ok(url) = std::env::var("MYSQL_DATABASE_URL") else {
        eprintln!("MYSQL_DATABASE_URL is not set; skipping the MySQL test");
        return;
    };
    let pool = MySqlPool::connect(&url)
        .await
        .expect("connect to MYSQL_DATABASE_URL");
    let database = format!(
        "fastauth_organization_{}",
        Id::new_v7().as_str().replace('-', "")
    );
    flow(Sqlx::new(pool.clone()).schema(database.clone())).await;
    pool.execute(AssertSqlSafe(format!("DROP DATABASE `{database}`")))
        .await
        .expect("drop the test database");
}

async fn flow<D: Adapter>(db: D) {
    let auth: Auth<D, (), plugins![Organization]> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Organization::default())
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");

    let mut owner: App<D> = Client::new(auth.clone());
    owner.sign_up("owner@acme.dk", "correct horse").await;
    let org = owner
        .post(
            "/organization/create",
            json!({ "name": "Acme", "slug": "acme", "metadata": { "plan": "pro", "seats": 5 } }),
        )
        .await;
    assert_eq!(org.status, StatusCode::OK, "{}", org.json);
    assert_eq!(org.json["metadata"], json!({ "plan": "pro", "seats": 5 }));
    let org_id = org.json["id"].as_str().unwrap().to_owned();
    let session = owner.get("/get-session").await.json;
    assert_eq!(session["session"]["activeOrganizationId"], json!(org_id));

    let invitation = owner
        .post(
            "/organization/invite-member",
            json!({ "email": "ada@acme.dk", "role": "admin" }),
        )
        .await;
    assert_eq!(invitation.status, StatusCode::OK, "{}", invitation.json);
    let mut ada: App<D> = Client::new(auth.clone());
    ada.sign_up("ada@acme.dk", "correct horse").await;
    Db::new(auth.adapter(), auth.schema())
        .update::<User>(User::EMAIL.eq("ada@acme.dk"))
        .set(User::EMAIL_VERIFIED, true)
        .exec()
        .await
        .unwrap();
    let accepted = ada
        .post(
            "/organization/accept-invitation",
            json!({ "invitationId": invitation.json["id"] }),
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.json);
    assert_eq!(accepted.json["invitation"]["status"], "accepted");

    let full = owner.get("/organization/get-full-organization").await.json;
    assert_eq!(full["members"].as_array().unwrap().len(), 2);
    assert_eq!(full["invitations"][0]["status"], "accepted");

    let deleted = owner
        .post("/organization/delete", json!({ "organizationId": org_id }))
        .await;
    assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.json);
    assert_eq!(ada.get("/organization/list").await.json, json!([]));
    let session = ada.get("/get-session").await.json;
    assert_eq!(session["session"]["activeOrganizationId"], json!(null));
}
