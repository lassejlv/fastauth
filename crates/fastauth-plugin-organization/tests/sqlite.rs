//! The organization flow on SQLite: the derived tables migrate, foreign keys hold, JSON
//! metadata and the invitation status round-trip, and deleting an organization clears its
//! members and invitations.

mod common;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_plugin_organization::Organization;
use fastauth_sqlx::sqlx::sqlite::SqlitePoolOptions;
use fastauth_sqlx::{Sqlite, Sqlx};
use http::StatusCode;
use serde_json::json;

type App = Client<Sqlx<Sqlite>, (), plugins![Organization]>;

#[tokio::test]
async fn organization_flow_on_sqlite() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite");
    let auth: Auth<Sqlx<Sqlite>, (), plugins![Organization]> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Organization::default())
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");

    let mut owner: App = Client::new(auth.clone());
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
    let mut ada: App = Client::new(auth.clone());
    ada.sign_up("ada@acme.dk", "correct horse").await;
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
