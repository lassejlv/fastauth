//! fastauth on the tables Better Auth 1.7.8's own migration creates (better-auth/schema.*.sql,
//! from its CLI; see better-auth/generate.sh), with the storage knobs Better Auth database
//! compatibility uses: camelCase columns, the `password` rename, hex text OAuth tokens, raw
//! session tokens, foreign account rows left alone and review-only migrations.

use std::str::FromStr;

use bytes::Bytes;
use fastauth_core::adapter::{Adapter, DbError};
use fastauth_core::config::SessionTokens;
use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::migrate::{Migrations, ReviewOnly};
use fastauth_core::model::Fields;
use fastauth_core::prelude::*;
use fastauth_core::query::Db;
use fastauth_core::schema::{ColumnDef, ColumnNaming, ColumnType};
use fastauth_core::value::{DecodeError, Id, Row, Value};
use fastauth_sqlx::sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use fastauth_sqlx::sqlx::postgres::PgPoolOptions;
use fastauth_sqlx::sqlx::{self, AssertSqlSafe, Executor};
use fastauth_sqlx::{Dialect, MySqlPool, PgPool, SqlitePool, Sqlx};
use http::{Method, Request, StatusCode, header};
use serde_json::json;

const POSTGRES: &str = include_str!("better-auth/schema.postgres.sql");
const MYSQL: &str = include_str!("better-auth/schema.mysql.sql");
const SQLITE: &str = include_str!("better-auth/schema.sqlite.sql");

/// The app's `customerId` field, declared the Rust way.
#[derive(Clone, Debug, PartialEq)]
struct Customer {
    customer_id: Option<String>,
}

impl Fields for Customer {
    fn columns() -> &'static [ColumnDef] {
        const COLUMNS: &[ColumnDef] = &[ColumnDef::new("customer_id", ColumnType::Text).nullable()];
        COLUMNS
    }

    fn decode(row: &Row) -> Result<Self, DecodeError> {
        Ok(Self {
            customer_id: row.get("customer_id")?,
        })
    }
}

fn compat<DB: Dialect>(db: Sqlx<DB>) -> Auth<Sqlx<DB>, Customer> {
    compat_tokens(db, false)
}

fn compat_tokens<DB: Dialect>(db: Sqlx<DB>, plaintext: bool) -> Auth<Sqlx<DB>, Customer> {
    FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url("http://localhost:3000")
        .database(db.rename("verification", "fastauth_verification"))
        .user_fields::<Customer>()
        .column_naming(ColumnNaming::CamelCase)
        .rename_column("account", "password_hash", "password")
        .bytes_as_hex_text("account", "access_token")
        .bytes_as_hex_text("account", "refresh_token")
        .session_tokens(SessionTokens::Raw)
        .only_owned_accounts(true)
        .migrations(Migrations::ReviewOnly)
        .store_oauth_tokens_in_plaintext(plaintext)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .build()
        .expect("valid config")
}

struct Res {
    status: StatusCode,
    json: serde_json::Value,
    cookies: String,
}

async fn send<D: Adapter>(
    auth: &Auth<D, Customer>,
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
    cookies: &str,
) -> Res {
    let mut request = Request::builder()
        .method(method)
        .uri(format!("/api/auth{path}"))
        .header(header::ORIGIN, "http://localhost:3000");
    if !cookies.is_empty() {
        request = request.header(header::COOKIE, cookies);
    }
    let body = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
    let response = auth.handle(request.body(body).unwrap()).await;
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok()?.split(';').next().map(str::to_owned))
        .filter(|c| c.starts_with("fastauth.session_token="))
        .collect::<Vec<_>>()
        .join("; ");
    Res {
        status: response.status(),
        json: serde_json::from_slice(response.body()).unwrap_or_default(),
        cookies,
    }
}

/// Better Auth's schema, then fastauth's reviewed migrations, then a sign-up, sign-in,
/// session lookup and sign-out on them. Answers the auth and the signed-in user's id.
async fn on_better_auth_tables<DB: Dialect>(
    db: Sqlx<DB>,
    better_auth_schema: &str,
    run: impl AsyncFn(String),
) -> (Auth<Sqlx<DB>, Customer>, String) {
    run(better_auth_schema.to_owned()).await;
    let auth = compat(db);
    let migrator = auth.migrator();
    match migrator.run().await {
        Err(DbError::Other(err)) if err.is::<ReviewOnly>() => {}
        other => panic!("migrate must refuse in review-only mode, got {other:?}"),
    }
    let plan = migrator.plan().await.unwrap();
    assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
    let migrations = migrator.sql_steps().await.unwrap();
    let names: Vec<&str> = migrations.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "add_user_securityStamp",
            "index_account_accountId",
            "unique_account_providerId_accountId",
            "create_verification",
        ],
        "fastauth adds only these to Better Auth's tables"
    );
    for migration in &migrations {
        run(migration.sql.clone()).await;
    }
    let after = migrator.plan().await.unwrap();
    assert!(after.is_empty(), "{after:?}");

    let signed_up = send(
        &auth,
        Method::POST,
        "/sign-up/email",
        Some(json!({ "email": "Lasse@Acme.dk", "password": "correct horse", "name": "Lasse" })),
        "",
    )
    .await;
    assert_eq!(signed_up.status, StatusCode::OK, "{}", signed_up.json);
    let user_id = signed_up.json["user"]["id"].as_str().unwrap().to_owned();

    Db::new(auth.adapter(), auth.schema())
        .update::<User>(User::ID.eq(Id::from(user_id.as_str())))
        .set_raw("customer_id", Value::Text("cus_123".into()))
        .exec()
        .await
        .unwrap();

    let signed_in = send(
        &auth,
        Method::POST,
        "/sign-in/email",
        Some(json!({ "email": "lasse@acme.dk", "password": "correct horse" })),
        "",
    )
    .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.json);
    let token = signed_in.json["token"].as_str().unwrap().to_owned();
    let me = send(&auth, Method::GET, "/get-session", None, &signed_in.cookies).await;
    assert_eq!(me.json["user"]["email"], "lasse@acme.dk", "{}", me.json);
    assert_eq!(me.json["session"]["token"], token.as_str());
    let session = auth.get_session_by_token(&token).await.unwrap().unwrap();
    assert_eq!(session.user.fields.customer_id.as_deref(), Some("cus_123"));

    let out = send(
        &auth,
        Method::POST,
        "/sign-out",
        Some(json!({})),
        &signed_in.cookies,
    )
    .await;
    assert_eq!(out.json, json!({ "success": true }));
    assert!(auth.get_session_by_token(&token).await.unwrap().is_none());
    (auth, user_id)
}

fn fresh_name() -> String {
    format!("fastauth_ba_{}", Id::new_v7().as_str().replace('-', ""))
}

#[tokio::test]
async fn postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL is not set; skipping the Postgres test");
        return;
    };
    let admin = PgPool::connect(&url).await.unwrap();
    let schema = fresh_name();
    admin
        .execute(AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .await
        .unwrap();
    let search_path = format!("SET search_path TO \"{schema}\"");
    let pool = PgPoolOptions::new()
        .after_connect(move |conn, _| {
            let search_path = search_path.clone();
            Box::pin(async move {
                conn.execute(AssertSqlSafe(search_path)).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let run = async |sql: String| {
        sqlx::raw_sql(AssertSqlSafe(sql))
            .execute(&pool)
            .await
            .unwrap();
    };

    let (auth, user_id) = on_better_auth_tables(Sqlx::new(pool.clone()), POSTGRES, run).await;

    let (stamp, verified, customer): (i64, bool, Option<String>) = sqlx::query_as(
        "SELECT \"securityStamp\", \"emailVerified\", \"customerId\" FROM \"user\" WHERE id = $1",
    )
    .bind(&user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stamp, 0, "a new user's stamp is the column default");
    assert!(!verified);
    assert_eq!(customer.as_deref(), Some("cus_123"));
    let (provider, account_id, password): (String, String, Option<String>) = sqlx::query_as(
        "SELECT \"providerId\", \"accountId\", password FROM account WHERE \"userId\" = $1",
    )
    .bind(&user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (provider.as_str(), account_id.as_str()),
        ("credential", user_id.as_str())
    );
    assert!(password.unwrap().starts_with("$argon2id$"));

    // A session Better Auth created: the token itself in session.token.
    sqlx::query(
        "INSERT INTO session (id, token, \"userId\", \"expiresAt\", \"createdAt\", \"updatedAt\") \
         VALUES ('ba-session', 'better-auth-token', $1, now() + interval '7 days', now(), now())",
    )
    .bind(&user_id)
    .execute(&pool)
    .await
    .unwrap();
    let found = auth
        .get_session_by_token("better-auth-token")
        .await
        .unwrap();
    assert_eq!(found.unwrap().user.id.as_str(), user_id);

    // A session fastauth created holds the token Better Auth looks up.
    let signed_in = send(
        &auth,
        Method::POST,
        "/sign-in/email",
        Some(json!({ "email": "lasse@acme.dk", "password": "correct horse" })),
        "",
    )
    .await;
    let token = signed_in.json["token"].as_str().unwrap();
    let (stored,): (String,) = sqlx::query_as("SELECT token FROM session WHERE token = $1")
        .bind(token)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, token);

    // OAuth tokens are text in Better Auth's table; fastauth stores its sealed bytes as hex.
    sqlx::query(
        "INSERT INTO account (id, \"accountId\", \"providerId\", \"userId\", \"accessToken\", \
         \"createdAt\", \"updatedAt\") VALUES ('oidc-row', 'sso-1', 'oidc', $1, 'plain-sso-token', now(), now())",
    )
    .bind(&user_id)
    .execute(&pool)
    .await
    .unwrap();
    let oidc = Db::new(auth.adapter(), auth.schema())
        .find::<Account>(Account::ID.eq(Id::from("oidc-row")))
        .one()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        oidc.access_token.as_deref(),
        Some(&b"plain-sso-token"[..]),
        "text that isn't hex reads as its bytes"
    );
    Db::new(auth.adapter(), auth.schema())
        .update::<Account>(Account::ID.eq(Id::from("oidc-row")))
        .set(Account::REFRESH_TOKEN, Some(vec![0xde, 0xad, 0xbe, 0xef]))
        .exec()
        .await
        .unwrap();
    let (refresh,): (Option<String>,) =
        sqlx::query_as("SELECT \"refreshToken\" FROM account WHERE id = 'oidc-row'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(refresh.as_deref(), Some("deadbeef"));

    // With plain-text OAuth tokens the text columns hold the tokens themselves, as Better
    // Auth's do, and fastauth still reads a token it stored encrypted before.
    let plain = compat_tokens(Sqlx::new(pool.clone()), true);
    Db::new(auth.adapter(), auth.schema())
        .update::<Account>(Account::ID.eq(Id::from("oidc-row")))
        .set(
            Account::ACCESS_TOKEN,
            Some(auth.keys().encrypt(b"sealed-token")),
        )
        .set(Account::REFRESH_TOKEN, Some(b"deadbeef".to_vec()))
        .exec()
        .await
        .unwrap();
    Db::new(plain.adapter(), plain.schema())
        .update::<Account>(Account::ID.eq(Id::from("oidc-row")))
        .set(Account::REFRESH_TOKEN, Some(b"1//plain-refresh".to_vec()))
        .exec()
        .await
        .unwrap();
    let (refresh,): (Option<String>,) =
        sqlx::query_as("SELECT \"refreshToken\" FROM account WHERE id = 'oidc-row'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(refresh.as_deref(), Some("1//plain-refresh"));
    let row = Db::new(plain.adapter(), plain.schema())
        .find::<Account>(Account::ID.eq(Id::from("oidc-row")))
        .one()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.read_access_token(plain.keys()).as_deref(),
        Some("sealed-token")
    );
    assert_eq!(
        row.read_refresh_token(plain.keys()).as_deref(),
        Some("1//plain-refresh")
    );

    // The unique migration explains how to check for duplicates first.
    let check = compat(Sqlx::new(pool.clone()));
    sqlx::raw_sql(AssertSqlSafe(
        "DROP INDEX \"account_providerId_accountId_key\"".to_owned(),
    ))
    .execute(&pool)
    .await
    .unwrap();
    let unique = check.migrator().sql_steps().await.unwrap().remove(0);
    assert_eq!(unique.name, "unique_account_providerId_accountId");
    assert!(
        unique.sql.contains("-- It must return no rows")
            && unique.sql.contains("GROUP BY \"providerId\", \"accountId\" HAVING COUNT(*) > 1")
            && unique.sql.contains(
                "CREATE UNIQUE INDEX \"account_providerId_accountId_key\" ON \"account\" (\"providerId\", \"accountId\");"
            ),
        "{}",
        unique.sql
    );

    // Pruning deletes fastauth's expired rows and nothing in Better Auth's table.
    sqlx::raw_sql(AssertSqlSafe(
        "INSERT INTO verification (id, identifier, value, \"expiresAt\") \
         VALUES ('ba-expired', 'reset-password:x', 'user', now() - interval '1 day'); \
         INSERT INTO fastauth_verification (id, identifier, \"valueHash\", \"expiresAt\") \
         VALUES ('fa-expired', 'test', '\\x00', now() - interval '1 day'), \
                ('fa-live', 'test', '\\x01', now() + interval '1 day');"
            .to_owned(),
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(auth.prune_verifications().await.unwrap(), 1);
    let (left,): (i64,) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM verification) + (SELECT count(*) FROM fastauth_verification)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        left, 2,
        "Better Auth's row and fastauth's live row are left"
    );

    drop(pool);
    admin
        .execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .unwrap();
}

#[tokio::test]
async fn mysql() {
    let Ok(url) = std::env::var("MYSQL_DATABASE_URL") else {
        eprintln!("MYSQL_DATABASE_URL is not set; skipping the MySQL test");
        return;
    };
    let server = MySqlPool::connect(&url).await.unwrap();
    let name = fresh_name();
    server
        .execute(AssertSqlSafe(format!("CREATE DATABASE `{name}`")))
        .await
        .unwrap();
    let options = MySqlConnectOptions::from_str(&url).unwrap().database(&name);
    let pool = MySqlPoolOptions::new().connect_with(options).await.unwrap();
    let run = async |sql: String| {
        for statement in sql.split(';').filter(|s| {
            !s.lines()
                .all(|l| l.trim().is_empty() || l.trim_start().starts_with("--"))
        }) {
            sqlx::raw_sql(AssertSqlSafe(statement.to_owned()))
                .execute(&pool)
                .await
                .unwrap_or_else(|err| panic!("{err}: {statement}"));
        }
    };
    on_better_auth_tables(Sqlx::new(pool.clone()), MYSQL, run).await;
    drop(pool);
    server
        .execute(AssertSqlSafe(format!("DROP DATABASE `{name}`")))
        .await
        .unwrap();
}

#[tokio::test]
async fn sqlite() {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    let run = async |sql: String| {
        sqlx::raw_sql(AssertSqlSafe(sql))
            .execute(&pool)
            .await
            .unwrap();
    };
    on_better_auth_tables(Sqlx::new(pool.clone()), SQLITE, run).await;
}
