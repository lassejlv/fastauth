//! Two instances of one app behind a load balancer, sharing one Postgres database and one
//! Redis: the sign-in limit holds across both, a session revoked through one is refused by the
//! other, and so is a banned admin. Needs `DATABASE_URL` (Postgres) and `REDIS_URL`; skipped
//! without them.

use std::collections::BTreeMap;
use std::net::IpAddr;

use bytes::Bytes;
use fastauth_core::crypto::{Argon2id, random_string};
use fastauth_core::prelude::*;
use fastauth_core::{ClientAddr, plugins};
use fastauth_plugin_admin::{Admin, AdminExt, BanUserInput};
use fastauth_redis::RedisStorage;
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{PgPool, Postgres, Sqlx};
use http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};

type App = Auth<Sqlx<Postgres>, (), plugins![Admin]>;

const PASSWORD: &str = "correct horse battery";

fn unique(len: usize) -> String {
    random_string(len, b"abcdefghijklmnopqrstuvwxyz0123456789")
}

/// One Postgres schema and one Redis, and a way to start instances on them. Every instance gets
/// its own connection pool and its own Redis connection, like separate processes.
struct Deployment {
    url: String,
    redis_url: String,
    schema: String,
}

impl Deployment {
    async fn new() -> Option<Self> {
        let (Ok(url), Ok(redis_url)) = (std::env::var("DATABASE_URL"), std::env::var("REDIS_URL"))
        else {
            eprintln!("DATABASE_URL or REDIS_URL is not set; skipping the two-instance test");
            return None;
        };
        let deployment = Self {
            url,
            redis_url,
            schema: format!("fastauth_two_{}", unique(12)),
        };
        deployment
            .instance(true, SessionConfig::default())
            .await
            .migrator()
            .run()
            .await
            .expect("migrates");
        Some(deployment)
    }

    async fn instance(&self, shared_storage: bool, session: SessionConfig) -> App {
        let pool = PgPool::connect(&self.url)
            .await
            .expect("connect to DATABASE_URL");
        let builder = FastAuth::builder()
            .secret(Secret::from_bytes(
                b"two instances, one secret, 32 bytes!".to_vec(),
            ))
            .base_url("http://localhost:3000")
            .database(Sqlx::new(pool).schema(self.schema.as_str()))
            .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
            .session(session)
            .multi_instance(true)
            .plugin(Admin::new());
        let builder = if shared_storage {
            builder.secondary_storage(RedisStorage::connect(&self.redis_url).await.unwrap())
        } else {
            builder
        };
        builder.build().expect("valid config")
    }

    async fn pair(&self, session: SessionConfig) -> (App, App) {
        (
            self.instance(true, session.clone()).await,
            self.instance(true, session).await,
        )
    }

    async fn drop(self) {
        let pool = PgPool::connect(&self.url).await.unwrap();
        pool.execute(AssertSqlSafe(format!(
            "DROP SCHEMA \"{}\" CASCADE",
            self.schema
        )))
        .await
        .expect("drop test schema");
    }
}

/// A browser: a cookie jar and a client IP. Each request goes to the instance the test names,
/// the way a load balancer would pick one.
struct Browser {
    ip: IpAddr,
    cookies: BTreeMap<String, String>,
}

impl Browser {
    fn new() -> Self {
        let n = random_string(3, b"0123456789abcdef");
        let bytes = u32::from_str_radix(&n, 16).unwrap();
        Self {
            ip: IpAddr::from([198, 18, (bytes >> 8) as u8, bytes as u8]),
            cookies: BTreeMap::new(),
        }
    }

    async fn send(
        &mut self,
        auth: &App,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("/api/auth{path}"))
            .header(header::ORIGIN, "http://localhost:3000")
            .header(header::CONTENT_TYPE, "application/json");
        if !self.cookies.is_empty() {
            let jar = self
                .cookies
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            request = request.header(header::COOKIE, jar);
        }
        let body = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
        let mut request = request.body(body).unwrap();
        request.extensions_mut().insert(ClientAddr(self.ip));
        let response = auth.handle(request).await;
        for cookie in response.headers().get_all(header::SET_COOKIE) {
            let cookie = cookie.to_str().unwrap();
            let (pair, attrs) = cookie.split_once(';').unwrap_or((cookie, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if value.is_empty() || attrs.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_owned(), value.to_owned());
            }
        }
        let json = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
        (response.status(), json)
    }

    async fn post(&mut self, auth: &App, path: &str, body: Value) -> (StatusCode, Value) {
        self.send(auth, Method::POST, path, Some(body)).await
    }

    async fn get(&mut self, auth: &App, path: &str) -> (StatusCode, Value) {
        self.send(auth, Method::GET, path, None).await
    }

    async fn sign_up(&mut self, auth: &App, email: &str) -> Id {
        let (status, body) = self
            .post(
                auth,
                "/sign-up/email",
                json!({ "email": email, "password": PASSWORD, "name": "Test" }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        Id::from(body["user"]["id"].as_str().unwrap())
    }

    async fn sign_in(&mut self, auth: &App, email: &str) -> (StatusCode, Value) {
        self.post(
            auth,
            "/sign-in/email",
            json!({ "email": email, "password": PASSWORD }),
        )
        .await
    }

    /// The signed-in user's email on `auth`, or `None` when the instance refuses the session.
    async fn signed_in_as(&mut self, auth: &App) -> Option<String> {
        let (status, body) = self.get(auth, "/get-session").await;
        if status != StatusCode::OK {
            return None;
        }
        body["user"]["email"].as_str().map(str::to_owned)
    }
}

/// Wrong-password sign-ins for one email from one client, sent to `instances` in turn: the
/// statuses each one got.
async fn guesses(instances: &[&App], count: usize) -> Vec<StatusCode> {
    let email = format!("{}@acme.dk", unique(10));
    let mut browser = Browser::new();
    let mut statuses = Vec::new();
    for n in 0..count {
        let (status, _) = browser
            .post(
                instances[n % instances.len()],
                "/sign-in/email",
                json!({ "email": email, "password": "wrong" }),
            )
            .await;
        statuses.push(status);
    }
    statuses
}

#[tokio::test]
async fn the_sign_in_limit_holds_across_instances() {
    let Some(deployment) = Deployment::new().await else {
        return;
    };
    let (a, b) = deployment.pair(SessionConfig::default()).await;
    let statuses = guesses(&[&a, &b], 6).await;
    assert_eq!(
        statuses,
        [
            StatusCode::UNAUTHORIZED,
            StatusCode::UNAUTHORIZED,
            StatusCode::UNAUTHORIZED,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS,
        ],
        "3 sign-ins per 10 seconds per client, whichever instance answers"
    );

    let alone_a = deployment.instance(false, SessionConfig::default()).await;
    let alone_b = deployment.instance(false, SessionConfig::default()).await;
    let statuses = guesses(&[&alone_a, &alone_b], 7).await;
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::UNAUTHORIZED)
            .count(),
        6,
        "without secondary storage, each instance allows the limit: {statuses:?}"
    );
    deployment.drop().await;
}

#[tokio::test]
async fn a_session_revoked_through_one_instance_is_refused_by_the_other() {
    let Some(deployment) = Deployment::new().await else {
        return;
    };
    let (a, b) = deployment.pair(SessionConfig::default()).await;
    let email = format!("{}@acme.dk", unique(10));
    let mut phone = Browser::new();
    let mut laptop = Browser::new();
    phone.sign_up(&b, &email).await;
    assert_eq!(laptop.sign_in(&a, &email).await.0, StatusCode::OK);
    assert_eq!(
        phone.signed_in_as(&b).await.as_deref(),
        Some(email.as_str())
    );

    let (status, body) = laptop.post(&a, "/revoke-other-sessions", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(phone.signed_in_as(&b).await, None, "B refuses it at once");
    assert_eq!(phone.signed_in_as(&a).await, None);
    assert_eq!(
        laptop.signed_in_as(&b).await.as_deref(),
        Some(email.as_str())
    );
    deployment.drop().await;
}

#[tokio::test]
async fn with_the_cookie_cache_a_revoked_session_ends_within_the_window() {
    let Some(deployment) = Deployment::new().await else {
        return;
    };
    let window = SessionConfig::default().cookie_cache(Duration::seconds(2));
    let (a, b) = deployment.pair(window).await;
    let email = format!("{}@acme.dk", unique(10));
    let mut phone = Browser::new();
    let mut laptop = Browser::new();
    phone.sign_up(&b, &email).await;
    assert_eq!(laptop.sign_in(&a, &email).await.0, StatusCode::OK);
    assert_eq!(
        phone.signed_in_as(&b).await.as_deref(),
        Some(email.as_str())
    );
    assert!(
        phone
            .cookies
            .keys()
            .any(|name| name.ends_with("session_data")),
        "the phone holds a cookie cache: {:?}",
        phone.cookies.keys()
    );

    let (status, _) = laptop.post(&a, "/revoke-other-sessions", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        phone.signed_in_as(&b).await.as_deref(),
        Some(email.as_str()),
        "inside the window, the cookie cache answers, as in Better Auth"
    );
    tokio::time::sleep(std::time::Duration::from_millis(3100)).await;
    assert_eq!(
        phone.signed_in_as(&b).await,
        None,
        "after the window, B refuses it"
    );
    deployment.drop().await;
}

#[tokio::test]
async fn an_admin_banned_through_one_instance_is_refused_by_the_other() {
    let Some(deployment) = Deployment::new().await else {
        return;
    };
    let window = SessionConfig::default().cookie_cache(Duration::minutes(5));
    let (a, b) = deployment.pair(window).await;
    let mut root = Browser::new();
    let root_email = format!("root-{}@acme.dk", unique(8));
    let root_id = root.sign_up(&a, &root_email).await;
    a.admin().set_role(&root_id, "admin").await.unwrap();
    let mut mallory = Browser::new();
    let mallory_email = format!("mallory-{}@acme.dk", unique(8));
    let mallory_id = mallory.sign_up(&b, &mallory_email).await;
    a.admin().set_role(&mallory_id, "admin").await.unwrap();
    assert_eq!(
        mallory.get(&b, "/admin/list-users").await.0,
        StatusCode::OK,
        "mallory is an admin on B"
    );
    assert_eq!(
        mallory.signed_in_as(&b).await.as_deref(),
        Some(mallory_email.as_str())
    );

    a.admin()
        .ban(BanUserInput::new(mallory_id.clone()))
        .await
        .unwrap();

    let (status, body) = mallory.get(&b, "/admin/list-users").await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "admin routes read the database, so B refuses the banned admin at once: {status} {body}"
    );
    let (status, body) = mallory
        .post(&b, "/admin/ban-user", json!({ "userId": root_id.as_str() }))
        .await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "{status} {body}"
    );
    let (status, body) = mallory.sign_in(&b, &mallory_email).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "BANNED_USER");
    assert_eq!(
        root.signed_in_as(&b).await.as_deref(),
        Some(root_email.as_str())
    );
    deployment.drop().await;
}
