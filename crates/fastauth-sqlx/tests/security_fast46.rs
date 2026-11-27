//! FAST-46 fuzzing findings in the sqlx adapter, kept as regression tests. FAST-58 fixed
//! both: SQLite matches text filters byte by byte, Postgres binds a needle with a NUL as
//! NULL (it can't store one, so the filter matches nothing), and core refuses request text
//! with a NUL with 400 `INVALID_REQUEST_BODY`.
//!
//! SQLX-1: a NUL character in a `contains`, `starts_with` or `ends_with` needle. SQLite's GLOB
//! reads the pattern as a C string, so everything after the NUL is dropped and `*\0*`
//! matches every row. Found by the `like_filter` fuzz target (input: contains "\0" over
//! [""]). Postgres can't store NUL in text at all and rejects the parameter, so the same
//! search is a database error there. The same truncation works the other way on SQLite: a
//! stored name with a NUL is cut there too, so a needle that only matches after the NUL
//! misses the row (found by FAST-53's long `like_filter` run: contains ">" over ["=\0>"]).
//!
//! SQLX-2: Postgres rejects a NUL anywhere in a text parameter, so request input carrying
//! `\u0000` (a sign-up name, an email) is a database error and a 500 instead of a 400. SQLite
//! and MySQL store it.

use std::str::FromStr;

use bytes::Bytes;
use fastauth_core::adapter::Adapter;
use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::models::User;
use fastauth_core::prelude::*;
use fastauth_core::query::Where;
use fastauth_sqlx::sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{MySqlPool, PgPool, SqlitePool, Sqlx};

const NAMES: [&str; 3] = ["", "alice", "bob"];

/// Every needle holds a NUL, and no name does, so each must match nothing.
async fn nul_needles_match_nothing<D: Adapter>(db: D) {
    let auth: Auth<D> = FastAuth::builder()
        .secret(Secret::from_bytes(vec![5u8; 32]))
        .base_url("http://localhost:3000")
        .database(db)
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrations");
    let api = auth.api();
    let now = time::OffsetDateTime::now_utc();
    for (i, name) in NAMES.iter().enumerate() {
        api.db()
            .insert(&User {
                id: Id::from(format!("u{i}")),
                email: format!("u{i}@acme.dk"),
                email_verified: false,
                name: (*name).to_owned(),
                image: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("insert");
    }
    let cases: [(&str, Where<User>); 4] = [
        ("contains \\0", User::NAME.contains("\0")),
        ("contains a\\0", User::NAME.contains("a\0")),
        ("starts_with al\\0x", User::NAME.starts_with("al\0x")),
        ("ends_with \\0b", User::NAME.ends_with("\0b")),
    ];
    for (label, filter) in cases {
        let found = api.db().find::<User>(filter).all().await;
        let names: Vec<String> = found
            .unwrap_or_else(|err| panic!("{label}: the query failed: {err}"))
            .into_iter()
            .map(|u| u.name)
            .collect();
        assert!(names.is_empty(), "{label} matched {names:?}");
    }
    api.db()
        .delete::<User>(Where::all())
        .await
        .expect("clean up");
}

#[tokio::test]
async fn sqlx_1_nul_in_a_pattern_on_sqlite() {
    let pool = SqlitePool::connect("sqlite::memory:")
        .await
        .expect("SQLite");
    nul_needles_match_nothing(Sqlx::new(pool)).await;
}

#[tokio::test]
async fn sqlx_1_nul_in_a_stored_name_on_sqlite() {
    let pool = SqlitePool::connect("sqlite::memory:")
        .await
        .expect("SQLite");
    let auth: Auth<Sqlx<fastauth_sqlx::Sqlite>> = FastAuth::builder()
        .secret(Secret::from_bytes(vec![5u8; 32]))
        .base_url("http://localhost:3000")
        .database(Sqlx::new(pool))
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrations");
    let api = auth.api();
    let now = time::OffsetDateTime::now_utc();
    api.db()
        .insert(&User {
            id: Id::from("u0".to_owned()),
            email: "u0@acme.dk".to_owned(),
            email_verified: false,
            name: "=\0>".to_owned(),
            image: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("insert");
    let cases: [(&str, Where<User>); 2] = [
        ("contains >", User::NAME.contains(">")),
        ("ends_with >", User::NAME.ends_with(">")),
    ];
    for (label, filter) in cases {
        let found = api.db().find::<User>(filter).all().await.expect(label);
        assert_eq!(found.len(), 1, "{label} missed the name \"=\\0>\"");
    }
}

#[tokio::test]
async fn sqlx_1_nul_in_a_pattern_on_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL is not set; skipping the Postgres run");
        return;
    };
    let pool = PgPool::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    let schema = format!("fastauth_fast46_{}", Id::new_v7().as_str().replace('-', ""));
    nul_needles_match_nothing(Sqlx::new(pool.clone()).schema(schema.clone())).await;
    pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .expect("drop test schema");
}

#[tokio::test]
async fn sqlx_1_nul_in_a_pattern_on_mysql() {
    let Ok(url) = std::env::var("MYSQL_DATABASE_URL") else {
        eprintln!("MYSQL_DATABASE_URL is not set; skipping the MySQL run");
        return;
    };
    let server = MySqlPool::connect(&url)
        .await
        .expect("connect to MYSQL_DATABASE_URL");
    let name = format!("fastauth_fast46_{}", Id::new_v7().as_str().replace('-', ""));
    server
        .execute(AssertSqlSafe(format!("CREATE DATABASE `{name}`")))
        .await
        .expect("create");
    let options = MySqlConnectOptions::from_str(&url).unwrap().database(&name);
    let pool = MySqlPoolOptions::new().connect_with(options).await.unwrap();
    nul_needles_match_nothing(Sqlx::new(pool.clone())).await;
    pool.close().await;
    server
        .execute(AssertSqlSafe(format!("DROP DATABASE `{name}`")))
        .await
        .expect("drop");
}

#[tokio::test]
async fn sqlx_2_nul_in_request_text_on_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL is not set; skipping the Postgres run");
        return;
    };
    let pool = PgPool::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    let schema = format!("fastauth_fast46_{}", Id::new_v7().as_str().replace('-', ""));
    let auth: Auth<Sqlx<fastauth_sqlx::Postgres>> = FastAuth::builder()
        .secret(Secret::from_bytes(vec![5u8; 32]))
        .base_url("http://localhost:3000")
        .database(Sqlx::new(pool.clone()).schema(schema.clone()))
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(256, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrations");
    let mut statuses = Vec::new();
    for body in [
        r#"{"email":"nul@acme.dk","password":"correct horse","name":"a\u0000b"}"#,
        r#"{"email":"n\u0000ul@acme.dk","password":"correct horse","name":"Nul"}"#,
    ] {
        let response = auth
            .handle(
                http::Request::post("/api/auth/sign-up/email")
                    .header(http::header::ORIGIN, "http://localhost:3000")
                    .body(Bytes::from(body))
                    .unwrap(),
            )
            .await;
        statuses.push((body, response.status()));
    }
    pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .expect("drop test schema");
    let failed: Vec<_> = statuses
        .iter()
        .filter(|(_, s)| s.is_server_error())
        .collect();
    assert!(
        failed.is_empty(),
        "a NUL in request text answered 5xx: {failed:?}"
    );
}
