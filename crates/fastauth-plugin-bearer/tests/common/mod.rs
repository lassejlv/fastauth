#![allow(dead_code)]

use bytes::Bytes;
use fastauth_core::adapter::Adapter;
use fastauth_core::value::Id;
use fastauth_core::{Auth, PluginSet, model::Fields};
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{PgPool, Postgres, Sqlite, SqlitePool, Sqlx};
use http::{HeaderMap, Method, Request, StatusCode, header};
use serde_json::Value;

pub const ORIGIN: &str = "http://localhost:3000";

pub fn secret() -> fastauth_core::crypto::Secret {
    fastauth_core::crypto::Secret::from_bytes(vec![42u8; 32])
}

pub struct Res {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub json: Value,
}

impl Res {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The value of the session cookie this response sets, if it sets one.
    pub fn session_cookie(&self) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| c.strip_prefix("fastauth.session_token="))
            .map(|c| c.split(';').next().unwrap().to_owned())
    }
}

/// Sends one request to `Auth::handle`, with no cookies: only `Origin` and `extra`.
pub async fn send<D: Adapter, U: Fields, P: PluginSet>(
    auth: &Auth<D, U, P>,
    method: Method,
    path: &str,
    extra: &[(&str, &str)],
    body: Option<Value>,
) -> Res {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("/api/auth{path}"))
        .header(header::ORIGIN, ORIGIN);
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let body = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
    let response = auth.handle(builder.body(body).unwrap()).await;
    Res {
        status: response.status(),
        headers: response.headers().clone(),
        json: serde_json::from_slice(response.body()).unwrap_or(Value::Null),
    }
}

pub fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

pub async fn sqlite() -> Sqlx<Sqlite> {
    let pool = SqlitePool::connect("sqlite::memory:")
        .await
        .expect("SQLite");
    Sqlx::new(pool)
}

/// A fresh schema on `DATABASE_URL`, or `None` (the test skips) when it isn't set.
pub async fn postgres() -> Option<(Sqlx<Postgres>, PgDrop)> {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL is not set; skipping the Postgres run");
        return None;
    };
    let pool = PgPool::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    let schema = format!("fastauth_bearer_{}", Id::new_v7().as_str().replace('-', ""));
    let db = Sqlx::new(pool.clone()).schema(schema.clone());
    Some((db, PgDrop { pool, schema }))
}

pub struct PgDrop {
    pool: PgPool,
    schema: String,
}

impl PgDrop {
    pub async fn drop_schema(self) {
        self.pool
            .execute(AssertSqlSafe(format!(
                "DROP SCHEMA \"{}\" CASCADE",
                self.schema
            )))
            .await
            .expect("drop test schema");
    }
}
