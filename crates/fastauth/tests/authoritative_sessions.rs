//! FAST-49: authorization decisions read the session from the database, never from the
//! cookie cache, and the cookie cache keeps hidden columns out of the browser without losing
//! them on the server.
//!
//! cargo test -p fastauth --all-features --test authoritative_sessions
#![cfg(all(feature = "organization", feature = "macros"))]

use std::collections::HashMap;

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, Request, header};
use fastauth::crypto::{Argon2id, Secret};
use fastauth::models::Session as SessionRow;
use fastauth::plugins::organization::{Invitation, Organization, OrganizationRow};
use fastauth::prelude::*;
use fastauth::query::Db;
use serde_json::{Value, json};

#[derive(Fields, Clone, Debug)]
pub struct Profile {
    #[field(returned = false)]
    pub internal_note: Option<String>,
}

type AppAuth = Auth<MemoryAdapter, Profile, plugins![Organization]>;

const ORIGIN: &str = "http://localhost:3000";
const PASSWORD: &str = "correct horse";

fn build() -> AppAuth {
    FastAuth::builder()
        .secret(Secret::from_bytes(vec![7u8; 32]))
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .session(SessionConfig::default().cookie_cache(Duration::minutes(5)))
        .rate_limit(RateLimit::disabled())
        .user_fields::<Profile>()
        .plugin(Organization::default())
        .build()
        .expect("valid config")
}

#[derive(Clone)]
struct Browser {
    auth: AppAuth,
    jar: HashMap<String, String>,
}

impl Browser {
    fn new(auth: &AppAuth) -> Self {
        Self {
            auth: auth.clone(),
            jar: HashMap::new(),
        }
    }

    fn cookie_header(&self) -> String {
        self.jar
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    async fn send(&mut self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("/api/auth{path}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, ORIGIN);
        if !self.jar.is_empty() {
            builder = builder.header(header::COOKIE, self.cookie_header());
        }
        let body = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
        let response = self.auth.handle(builder.body(body).unwrap()).await;
        for cookie in response.headers().get_all(header::SET_COOKIE) {
            let cookie = cookie.to_str().unwrap();
            let (pair, attrs) = cookie.split_once(';').unwrap_or((cookie, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if attrs.contains("Max-Age=0") {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.to_owned(), value.to_owned());
            }
        }
        let json = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
        (response.status().as_u16(), json)
    }
}

fn db(auth: &AppAuth) -> Db<'_, MemoryAdapter> {
    Db::new(auth.adapter(), auth.schema())
}

/// An organization owner whose browser holds a fresh cookie-cache cookie.
async fn cached_owner(auth: &AppAuth) -> (Browser, Id, String) {
    let mut owner = Browser::new(auth);
    let (status, json) = owner
        .send(
            "POST",
            "/sign-up/email",
            Some(json!({ "email": "owner@acme.dk", "password": PASSWORD, "name": "Owner" })),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let id = Id::from(json["user"]["id"].as_str().unwrap());
    let (status, json) = owner
        .send(
            "POST",
            "/organization/create",
            Some(json!({ "name": "Acme", "slug": "acme" })),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let org = json["id"].as_str().unwrap().to_owned();
    let (status, _) = owner.send("GET", "/get-session", None).await;
    assert_eq!(status, 200);
    assert!(owner.jar.contains_key("fastauth.session_data"));
    (owner, id, org)
}

async fn invitations(auth: &AppAuth, org: &str) -> usize {
    db(auth)
        .find::<Invitation>(Invitation::ORGANIZATION_ID.eq(Id::from(org)))
        .all()
        .await
        .unwrap()
        .len()
}

/// A live session the cookie cache answers still passes the organization's checks.
#[tokio::test]
async fn cached_session_of_a_live_owner_still_manages_the_organization() {
    let auth = build();
    let (mut owner, _, org) = cached_owner(&auth).await;
    let (status, json) = owner
        .send(
            "POST",
            "/organization/invite-member",
            Some(json!({ "email": "new@acme.dk", "role": "member", "organizationId": org })),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(invitations(&auth, &org).await, 1);
}

/// A revoked owner session in the cookie cache can't invite anyone or delete the
/// organization.
#[tokio::test]
async fn revoked_owner_session_in_the_cookie_cache_cannot_manage_the_organization() {
    let auth = build();
    let (owner, id, org) = cached_owner(&auth).await;
    db(&auth)
        .delete::<SessionRow>(SessionRow::USER_ID.eq(&id))
        .await
        .unwrap();

    let (status, json) = owner
        .clone()
        .send(
            "POST",
            "/organization/invite-member",
            Some(json!({ "email": "mallory@evil.test", "role": "owner", "organizationId": org })),
        )
        .await;
    assert_eq!(status, 401, "{json}");
    assert_eq!(invitations(&auth, &org).await, 0);

    let (status, json) = owner
        .clone()
        .send(
            "POST",
            "/organization/delete",
            Some(json!({ "organizationId": org })),
        )
        .await;
    assert_eq!(status, 401, "{json}");
    let kept = db(&auth)
        .find::<OrganizationRow>(OrganizationRow::ID.eq(Id::from(org.as_str())))
        .one()
        .await
        .unwrap();
    assert!(kept.is_some(), "a revoked session deleted the organization");
}

/// The cookie cache hides `returned = false` columns from the browser, and a session the
/// cache answers still carries them on the server.
#[tokio::test]
async fn cookie_cache_keeps_hidden_columns_on_the_server() {
    let auth = build();
    let (mut browser, id, _) = cached_owner(&auth).await;
    db(&auth)
        .update::<User>(User::ID.eq(&id))
        .set(Profile::INTERNAL_NOTE, Some("vip".to_owned()))
        .exec()
        .await
        .unwrap();
    browser.jar.remove("fastauth.session_data");
    let (status, _) = browser.send("GET", "/get-session", None).await;
    assert_eq!(status, 200);
    assert!(browser.jar.contains_key("fastauth.session_data"));
    // Only the cache can answer once the stored session is gone.
    db(&auth)
        .delete::<SessionRow>(SessionRow::USER_ID.eq(&id))
        .await
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&browser.cookie_header()).unwrap(),
    );
    let session = auth
        .get_session(&headers)
        .await
        .unwrap()
        .expect("the cache answers");
    assert_eq!(session.user.fields.internal_note.as_deref(), Some("vip"));
}
