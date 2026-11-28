//! Property: ids from every `IdStrategy` round-trip through each sqlx backend. A user signed up
//! on a fresh schema comes back by its id with the same id, email and session, whatever the
//! strategy (ULID, UUIDv7, UUIDv4 or a custom generator returning arbitrary Unicode).
//! SQLite always runs; Postgres runs with `DATABASE_URL` and MySQL with `MYSQL_DATABASE_URL`.

use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use fastauth_core::adapter::Adapter;
use fastauth_core::config::IdStrategy;
use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::prelude::*;
use fastauth_sqlx::sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{MySqlPool, PgPool, SqlitePool, Sqlx};
use http::{Request, StatusCode, header};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use serde_json::{Value, json};

static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
});

#[derive(Clone, Debug)]
enum Choice {
    Ulid,
    UuidV7,
    UuidV4,
    /// A counter, then this text: unique, and still any Unicode the generator may return.
    Custom(String),
}

fn choice() -> impl Strategy<Value = Choice> {
    prop_oneof![
        Just(Choice::Ulid),
        Just(Choice::UuidV7),
        Just(Choice::UuidV4),
        "\\PC{0,60}".prop_map(Choice::Custom),
    ]
}

fn strategy(choice: &Choice) -> IdStrategy {
    match choice {
        Choice::Ulid => IdStrategy::Ulid,
        Choice::UuidV7 => IdStrategy::UuidV7,
        Choice::UuidV4 => IdStrategy::UuidV4,
        Choice::Custom(text) => {
            let text = text.clone();
            let counter = Arc::new(AtomicUsize::new(0));
            IdStrategy::custom(move || format!("{}{text}", counter.fetch_add(1, Ordering::Relaxed)))
        }
    }
}

fn shaped(choice: &Choice, id: &str) -> bool {
    match choice {
        Choice::Ulid => {
            id.len() == 26
                && id
                    .bytes()
                    .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
        }
        Choice::UuidV7 => {
            uuid::Uuid::parse_str(id).is_ok_and(|u| u.get_version_num() == 7 && u.to_string() == id)
        }
        Choice::UuidV4 => {
            uuid::Uuid::parse_str(id).is_ok_and(|u| u.get_version_num() == 4 && u.to_string() == id)
        }
        Choice::Custom(text) => {
            id.ends_with(text.as_str()) && id[..id.len() - text.len()].parse::<usize>().is_ok()
        }
    }
}

async fn send<D: Adapter>(auth: &Auth<D>, request: Request<Bytes>) -> (StatusCode, Value) {
    let response = auth.handle(request).await;
    let cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("fastauth.session_token="))
        .map(|c| c.split(';').next().unwrap().to_owned());
    let mut json: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
    if let Some(cookie) = cookie {
        json["__cookie"] = json!(cookie);
    }
    (response.status(), json)
}

/// Signs `users` users up on `db` with `choice`'s ids and checks each one reads back.
async fn round_trip<D: Adapter>(db: D, choice: &Choice, users: usize) -> Result<(), TestCaseError> {
    let auth: Auth<D> = FastAuth::builder()
        .secret(Secret::from_bytes(vec![5u8; 32]))
        .base_url("http://localhost:3000")
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(256, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .ids(strategy(choice))
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrations");
    for n in 0..users {
        let email = format!("user{n}@acme.dk");
        let body = json!({ "email": email, "password": "correct horse", "name": "Ids" });
        let (status, signed_up) = send(
            &auth,
            Request::post("/api/auth/sign-up/email")
                .header(header::ORIGIN, "http://localhost:3000")
                .body(Bytes::from(body.to_string()))
                .unwrap(),
        )
        .await;
        prop_assert_eq!(status, StatusCode::OK, "{}", signed_up);
        let id = signed_up["user"]["id"].as_str().expect("an id").to_owned();
        prop_assert!(shaped(choice, &id), "{:?} generated {:?}", choice, id);

        let api = auth.api();
        let found = api
            .db()
            .find::<User>(User::ID.eq(Id::from(id.as_str())))
            .all()
            .await
            .expect("find");
        prop_assert_eq!(found.len(), 1, "{:?} finds {} users", id, found.len());
        prop_assert_eq!(found[0].id.as_str(), id.as_str());
        prop_assert_eq!(&found[0].email, &email);

        let (status, session) = send(
            &auth,
            Request::get("/api/auth/get-session")
                .header(
                    header::COOKIE,
                    signed_up["__cookie"].as_str().expect("a cookie"),
                )
                .body(Bytes::new())
                .unwrap(),
        )
        .await;
        prop_assert_eq!(status, StatusCode::OK);
        prop_assert_eq!(
            session["user"]["id"].as_str(),
            Some(id.as_str()),
            "{}",
            session
        );
        prop_assert_eq!(
            session["session"]["userId"].as_str(),
            Some(id.as_str()),
            "{}",
            session
        );
        let session_id = session["session"]["id"].as_str().expect("a session id");
        prop_assert!(
            shaped(choice, session_id),
            "{:?} generated session id {:?}",
            choice,
            session_id
        );
        let sessions = api
            .db()
            .find::<Session>(Session::ID.eq(Id::from(session_id)))
            .all()
            .await
            .expect("find");
        prop_assert_eq!(sessions.len(), 1);
        prop_assert_eq!(sessions[0].user_id.as_str(), id.as_str());
    }
    Ok(())
}

fn fresh_name() -> String {
    format!("fastauth_ids_{}", Id::new_v7().as_str().replace('-', ""))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn ids_round_trip_on_sqlite(choice in choice(), users in 1usize..4) {
        RUNTIME.block_on(async {
            let pool = SqlitePool::connect("sqlite::memory:").await.expect("SQLite");
            round_trip(Sqlx::new(pool), &choice, users).await
        })?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    #[test]
    fn ids_round_trip_on_postgres(choice in choice(), users in 1usize..4) {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("DATABASE_URL is not set; skipping the Postgres run");
            return Ok(());
        };
        RUNTIME.block_on(async {
            let pool = PgPool::connect(&url).await.expect("connect to DATABASE_URL");
            let schema = fresh_name();
            let result = round_trip(Sqlx::new(pool.clone()).schema(schema.clone()), &choice, users).await;
            pool.execute(AssertSqlSafe(format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE")))
                .await
                .expect("drop test schema");
            result
        })?;
    }

    #[test]
    fn ids_round_trip_on_mysql(choice in choice(), users in 1usize..4) {
        let Ok(url) = std::env::var("MYSQL_DATABASE_URL") else {
            eprintln!("MYSQL_DATABASE_URL is not set; skipping the MySQL run");
            return Ok(());
        };
        RUNTIME.block_on(async {
            let server = MySqlPool::connect(&url).await.expect("connect to MYSQL_DATABASE_URL");
            let name = fresh_name();
            server.execute(AssertSqlSafe(format!("CREATE DATABASE `{name}`"))).await.expect("create");
            let options = MySqlConnectOptions::from_str(&url).unwrap().database(&name);
            let pool = MySqlPoolOptions::new().connect_with(options).await.unwrap();
            let result = round_trip(Sqlx::new(pool.clone()), &choice, users).await;
            pool.close().await;
            server.execute(AssertSqlSafe(format!("DROP DATABASE `{name}`"))).await.expect("drop");
            result
        })?;
    }
}
