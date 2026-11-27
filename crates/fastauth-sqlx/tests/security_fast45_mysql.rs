//! FAST-45, area C: the MySQL adapter (new in 0.5) against Postgres and SQLite.
//!
//! Needs `MYSQL_DATABASE_URL` (each test makes and drops its own database) and, for the
//! cross-backend cases, `DATABASE_URL` (a fresh schema). A backend whose URL isn't set is
//! skipped, not failed, and every line of output names the backend it ran on.
//!
//! `sec_*` tests fail on 7cd9718 (0.5.0) on purpose and are the regression tests for the
//! fix; `guard_*` tests pass and pin behaviour that was checked and found right.
#![cfg(all(feature = "mysql", feature = "postgres", feature = "sqlite"))]

use std::str::FromStr;

use fastauth_core::adapter::Adapter;
use fastauth_core::config::IdStrategy;
use fastauth_core::migrate::MigrationPlan;
use fastauth_core::models::User;
use fastauth_core::query::{Db, Where};
use fastauth_core::schema::Schema;
use fastauth_core::testing::conformance_schema;
use fastauth_core::value::Id;
use fastauth_sqlx::sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use fastauth_sqlx::sqlx::postgres::PgPoolOptions;
use fastauth_sqlx::sqlx::sqlite::SqlitePoolOptions;
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{MySqlPool, Sqlx};
use time::OffsetDateTime;

fn fresh_name() -> String {
    format!("fast45_mysql_{}", Id::new_v7().as_str().replace('-', ""))
}

/// A pool on a new, empty MySQL database with `sql_mode` set as given (`None`: the server's),
/// or `None` when `MYSQL_DATABASE_URL` isn't set.
async fn mysql(
    sql_mode: Option<&'static str>,
    found_rows: bool,
) -> Option<(MySqlPool, String, MySqlPool)> {
    let Ok(url) = std::env::var("MYSQL_DATABASE_URL") else {
        println!("[mysql] skipped: MYSQL_DATABASE_URL is not set");
        return None;
    };
    let server = MySqlPool::connect(&url)
        .await
        .expect("connect to MYSQL_DATABASE_URL");
    let name = fresh_name();
    server
        .execute(AssertSqlSafe(format!("CREATE DATABASE `{name}`")))
        .await
        .unwrap();
    let options = MySqlConnectOptions::from_str(&url)
        .unwrap()
        .database(&name)
        .found_rows(found_rows);
    let pool = MySqlPoolOptions::new()
        .max_connections(4)
        .after_connect(move |conn, _| {
            Box::pin(async move {
                if let Some(mode) = sql_mode {
                    conn.execute(AssertSqlSafe(format!("SET SESSION sql_mode = '{mode}'")))
                        .await?;
                }
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .unwrap();
    Some((pool, name, server))
}

async fn drop_mysql(name: String, server: MySqlPool) {
    server
        .execute(AssertSqlSafe(format!("DROP DATABASE `{name}`")))
        .await
        .unwrap();
}

async fn migrate<D: Adapter>(db: &D, schema: &Schema) {
    let plan = MigrationPlan::diff(schema, &db.introspect().await.unwrap());
    db.apply(&plan).await.unwrap();
}

fn user(email: &str, name: &str) -> User {
    let now = OffsetDateTime::now_utc();
    User {
        id: Id::new_v7(),
        email: email.to_owned(),
        email_verified: false,
        name: name.to_owned(),
        image: None,
        created_at: now,
        updated_at: now,
    }
}

// ---------------------------------------------------------------------- LIKE escaping

const NAMES: &[&str] = &[
    "50%_off!",
    "50xoff",
    "a\\b",
    "a\\\\b",
    "ab",
    "x!%y",
    "x!y",
    "under_score",
    "underXscore",
    "Ada",
    "ada",
    "a'b",
    "%",
    "_",
    "!",
    "\\",
];
const NEEDLES: &[&str] = &[
    "%", "_", "!", "\\", "!%", "\\%", "\\_", "%_", "a\\", "\\b", "!y", "Ada", "'", "!!", "\\\\",
];

/// Every needle as Contains, StartsWith and EndsWith on `user.name`; answers the mismatches
/// against matching the needle literally.
async fn literal_matching<D: Adapter>(db: D) -> Vec<String> {
    let schema = conformance_schema(&IdStrategy::UuidV7, false);
    migrate(&db, &schema).await;
    let typed = Db::new(&db, &schema);
    for (i, name) in NAMES.iter().enumerate() {
        typed
            .insert(&user(&format!("u{i}@acme.dk"), name))
            .await
            .unwrap();
    }
    let mut wrong = Vec::new();
    for needle in NEEDLES {
        type Case = (
            &'static str,
            fn(&str) -> Where<User>,
            fn(&str, &str) -> bool,
        );
        let cases: [Case; 3] = [
            ("contains", |n| User::NAME.contains(n), |s, n| s.contains(n)),
            (
                "starts_with",
                |n| User::NAME.starts_with(n),
                |s, n| s.starts_with(n),
            ),
            (
                "ends_with",
                |n| User::NAME.ends_with(n),
                |s, n| s.ends_with(n),
            ),
        ];
        for (op, filter, expect) in cases {
            let mut got: Vec<String> = typed
                .find::<User>(filter(needle))
                .all()
                .await
                .unwrap_or_else(|err| panic!("{op}({needle:?}) failed: {err}"))
                .into_iter()
                .map(|u| u.name)
                .collect();
            got.sort();
            let mut want: Vec<String> = NAMES
                .iter()
                .filter(|n| expect(n, needle))
                .map(|n| (*n).to_owned())
                .collect();
            want.sort();
            if got != want {
                wrong.push(format!(
                    "{op}({needle:?}) matched {got:?}, literal match is {want:?}"
                ));
            }
        }
    }
    wrong
}

/// Checked: Contains/StartsWith/EndsWith (admin list-users search) match `% _ ! \ '` literally
/// and case-sensitively on SQLite (byte comparison), Postgres (LIKE ESCAPE '\\') and MySQL
/// (LIKE ESCAPE '!'), the last both in the default sql_mode and with NO_BACKSLASH_ESCAPES.
#[tokio::test]
async fn guard_text_filters_match_literally_on_every_backend_and_sql_mode() {
    let mut failures = Vec::new();
    let mut report = |backend: &str, wrong: Vec<String>| {
        if wrong.is_empty() {
            println!(
                "[{backend}] {} patterns x 3 operators matched literally",
                NEEDLES.len()
            );
        } else {
            println!("[{backend}] WRONG: {wrong:#?}");
            failures.push(format!("[{backend}] {wrong:?}"));
        }
    };
    let sqlite = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    report("sqlite", literal_matching(Sqlx::new(sqlite)).await);
    match std::env::var("DATABASE_URL") {
        Ok(url) => {
            let pool = PgPoolOptions::new().connect(&url).await.unwrap();
            let schema = fresh_name();
            report(
                "postgres",
                literal_matching(Sqlx::new(pool.clone()).schema(schema.clone())).await,
            );
            pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
                .await
                .unwrap();
        }
        Err(_) => println!("[postgres] skipped: DATABASE_URL is not set"),
    }
    for (label, mode) in [
        ("mysql, server sql_mode", None),
        (
            "mysql, NO_BACKSLASH_ESCAPES",
            Some(
                "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION,NO_BACKSLASH_ESCAPES",
            ),
        ),
        ("mysql, ANSI", Some("ANSI")),
    ] {
        let Some((pool, name, server)) = mysql(mode, true).await else {
            break;
        };
        let modes: (String,) = sqlx_mode(&pool).await;
        println!("[{label}] @@sql_mode = {}", modes.0);
        report(label, literal_matching(Sqlx::new(pool)).await);
        drop_mysql(name, server).await;
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

async fn sqlx_mode(pool: &MySqlPool) -> (String,) {
    fastauth_sqlx::sqlx::query_as("SELECT CAST(@@SESSION.sql_mode AS CHAR)")
        .fetch_one(pool)
        .await
        .unwrap()
}

// ---------------------------------------------------------------------- identity of text keys

/// Checked: the stored-key comparison is the same on all three backends, so an app that moves
/// between them keeps the same identities. `user.email` compares byte for byte: case, a trailing
/// space (utf8mb4_0900_bin is NO PAD) and NFC vs NFD are all different keys, on MySQL as on
/// Postgres and SQLite. (Core trims and lowercases before every write and lookup; it doesn't
/// apply Unicode normalization on any backend, so "josé" in NFC and NFD are two accounts
/// everywhere, as in Better Auth.)
#[tokio::test]
async fn guard_text_keys_compare_byte_for_byte_on_every_backend() {
    async fn probe<D: Adapter>(db: D) -> Vec<(String, usize, bool)> {
        let schema = conformance_schema(&IdStrategy::UuidV7, false);
        migrate(&db, &schema).await;
        let typed = Db::new(&db, &schema);
        typed.insert(&user("ada@acme.dk", "Ada")).await.unwrap();
        typed
            .insert(&user("jos\u{e9}@acme.dk", "NFC"))
            .await
            .unwrap();
        let mut out = Vec::new();
        for probe in [
            "ada@acme.dk",
            "Ada@acme.dk",
            "ada@acme.dk ",
            "ada@acme.dk\u{a0}",
            "jos\u{e9}@acme.dk",
            "jose\u{301}@acme.dk",
        ] {
            let found = typed.count::<User>(User::EMAIL.eq(probe)).await.unwrap() as usize;
            let inserted = typed.insert(&user(probe, "probe")).await.is_ok();
            out.push((format!("{probe:?}"), found, inserted));
        }
        out
    }
    let sqlite = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let reference = probe(Sqlx::new(sqlite)).await;
    println!("[sqlite] (probe, rows that equal it, a new row with it is accepted): {reference:?}");
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pool = PgPoolOptions::new().connect(&url).await.unwrap();
        let schema = fresh_name();
        let got = probe(Sqlx::new(pool.clone()).schema(schema.clone())).await;
        println!("[postgres] {got:?}");
        pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
            .await
            .unwrap();
        assert_eq!(got, reference, "postgres differs from sqlite");
    }
    if let Some((pool, name, server)) = mysql(None, true).await {
        let got = probe(Sqlx::new(pool)).await;
        println!("[mysql] {got:?}");
        drop_mysql(name, server).await;
        assert_eq!(got, reference, "mysql differs from sqlite");
    }
    assert_eq!(reference[0], ("\"ada@acme.dk\"".into(), 1, false));
}

// ---------------------------------------------------------------------- UUID ids

/// Checked: under a UUID id strategy MySQL stores ids as binary(16). A client id that isn't a
/// UUID matches nothing (no error, no 500, no wrong row) in eq and IN filters, as on Postgres.
/// Repro (info): other textual forms of the same UUID (upper case, no hyphens, braces, urn:)
/// find the same row on MySQL and Postgres but not on SQLite (text), so code that compares
/// a client id with a stored one as strings sees a mismatch where the database sees a match.
#[tokio::test]
async fn guard_malformed_uuid_ids_match_nothing() {
    async fn probe<D: Adapter>(db: D) -> Vec<(String, Result<usize, String>)> {
        let schema = conformance_schema(&IdStrategy::UuidV7, false);
        migrate(&db, &schema).await;
        let typed = Db::new(&db, &schema);
        let ada = user("ada@acme.dk", "Ada");
        let id = ada.id.as_str().to_owned();
        typed.insert(&ada).await.unwrap();
        let forms = [
            id.clone(),
            "not-a-uuid".to_owned(),
            "' OR 1=1 --".to_owned(),
            String::new(),
            id.to_uppercase(),
            id.replace('-', ""),
            format!("{{{id}}}"),
            format!("urn:uuid:{id}"),
        ];
        let mut out = Vec::new();
        for form in forms {
            let eq = typed
                .count::<User>(User::ID.eq(Id::from(form.as_str())))
                .await;
            let in_ = typed
                .find::<User>(User::ID.in_([Id::from(form.as_str()), Id::from("bogus")]))
                .all()
                .await
                .map(|rows| rows.len());
            let result = match (eq, in_) {
                (Ok(a), Ok(b)) if a as usize == b => Ok(b),
                (a, b) => Err(format!("eq {a:?}, in {b:?}")),
            };
            out.push((form, result));
        }
        out
    }
    let sqlite = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut all = vec![("sqlite", probe(Sqlx::new(sqlite)).await)];
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pool = PgPoolOptions::new().connect(&url).await.unwrap();
        let schema = fresh_name();
        all.push((
            "postgres",
            probe(Sqlx::new(pool.clone()).schema(schema.clone())).await,
        ));
        pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
            .await
            .unwrap();
    }
    if let Some((pool, name, server)) = mysql(None, true).await {
        all.push(("mysql", probe(Sqlx::new(pool)).await));
        drop_mysql(name, server).await;
    }
    for (backend, results) in &all {
        println!("[{backend}] (id form, rows matched): {results:?}");
        assert_eq!(results[0].1, Ok(1), "[{backend}] canonical id");
        for (form, result) in &results[1..4] {
            assert_eq!(
                result,
                &Ok(0),
                "[{backend}] {form:?} must match nothing, cleanly"
            );
        }
    }
}

// ---------------------------------------------------------------------- affected rows

/// Checked: sqlx connects to MySQL with CLIENT_FOUND_ROWS (`found_rows` defaults to true), so an
/// UPDATE that matches a row without changing it reports 1, as Postgres and SQLite do. The
/// plugins' compare-and-swaps rely on that: passkey sign-in writes the same counter back for
/// authenticators that always report 0 and fails when the update reports 0. The test also
/// builds a pool with `.found_rows(false)` and prints what that update reports.
#[tokio::test]
async fn guard_mysql_counts_matched_rows_for_an_unchanged_update() {
    for found_rows in [true, false] {
        let Some((pool, name, server)) = mysql(None, found_rows).await else {
            return;
        };
        let schema = conformance_schema(&IdStrategy::UuidV7, false);
        let db = Sqlx::new(pool);
        migrate(&db, &schema).await;
        let typed = Db::new(&db, &schema);
        typed.insert(&user("ada@acme.dk", "Ada")).await.unwrap();
        let same = typed
            .update::<User>(User::EMAIL.eq("ada@acme.dk").and(User::NAME.eq("Ada")))
            .set(User::NAME, "Ada")
            .exec()
            .await
            .unwrap();
        println!(
            "[mysql, found_rows({found_rows})] an UPDATE matching 1 row and changing nothing reports {same}"
        );
        drop_mysql(name, server).await;
        if found_rows {
            assert_eq!(same, 1);
        }
    }
}

// ---------------------------------------------------------------------- migrations

/// DB-1. MySQL commits each DDL statement by itself, and the migrator adds a unique (or
/// foreign-key) column to an existing table with two statements: `ADD COLUMN` and then
/// `ADD CONSTRAINT`. When it stops between them (killed, connection dropped, lock wait
/// timeout, a failing constraint), the column exists without its constraint, and the
/// introspection only looks at column names and `idx_` index names, so the next run plans
/// nothing and `fastauth status` reports the database up to date. Uniqueness is then gone
/// for good (on a username column: two users with one username).
#[tokio::test]
async fn sec_mysql_migrator_finishes_a_unique_column_it_stopped_halfway() {
    let Some((pool, name, server)) = mysql(None, true).await else {
        return;
    };
    let db = Sqlx::new(pool.clone());
    migrate(&db, &conformance_schema(&IdStrategy::Ulid, false)).await;

    let v2 = conformance_schema(&IdStrategy::Ulid, true);
    let plan = MigrationPlan::diff(&v2, &db.introspect().await.unwrap());
    let script = db.render_sql(&plan).unwrap();
    let statements: Vec<&str> = script
        .split(";\n")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    println!(
        "[mysql] the v2 migration is {} statements:\n{}",
        statements.len(),
        statements.join(";\n")
    );
    // Every statement commits except `ADD CONSTRAINT item_nickname_key UNIQUE`, the one right
    // after `ADD COLUMN nickname`: the run that failed there (or was killed there) is then
    // finished by hand or by a second run, which is what the docs say to do.
    let constraint = statements
        .iter()
        .position(|s| s.contains("UNIQUE (`nickname`)"))
        .expect("an ADD CONSTRAINT for nickname");
    assert!(statements[constraint - 1].contains("ADD COLUMN `nickname`"));
    for (i, statement) in statements.iter().enumerate() {
        if i != constraint {
            pool.execute(AssertSqlSafe(statement.to_string()))
                .await
                .unwrap();
        }
    }

    let rerun = MigrationPlan::diff(&v2, &db.introspect().await.unwrap());
    let planned: Vec<String> = rerun
        .steps
        .iter()
        .map(|step| match step {
            fastauth_core::migrate::Step::CreateTable(t) => format!("create {}", t.name),
            fastauth_core::migrate::Step::AddColumn { table, column } => {
                format!("add {}.{}", table.name, column.name)
            }
            fastauth_core::migrate::Step::CreateIndex { table, column } => {
                format!("index {}.{}", table.name, column.name)
            }
            #[allow(unreachable_patterns)]
            other => format!("{other:?}"),
        })
        .collect();
    println!(
        "[mysql] with every statement but the nickname UNIQUE applied, the migrator plans: {planned:?}"
    );
    db.apply(&rerun).await.unwrap();
    for _ in 0..2 {
        pool.execute(AssertSqlSafe(
            "INSERT INTO item (id, name, `rank`, `at`, nickname) VALUES (UUID(), UUID(), 1, NOW(6), 'same')".to_owned(),
        ))
        .await
        .map(|_| ())
        .unwrap_or_else(|err| println!("[mysql] second duplicate refused: {err}"));
    }
    let (dupes,): (i64,) =
        fastauth_sqlx::sqlx::query_as("SELECT COUNT(*) FROM item WHERE nickname = 'same'")
            .fetch_one(&pool)
            .await
            .unwrap();
    println!("[mysql] rows with nickname 'same' after the migrator said it was done: {dupes}");
    drop_mysql(name, server).await;
    assert!(
        dupes <= 1,
        "the migrator planned {planned:?} for a unique column without its constraint, and the \"unique\" column holds {dupes} equal values"
    );
}

// ---------------------------------------------------------------------- key length

/// Repro (info, DB-3): key text columns are varchar(768). Under MySQL's default strict mode a
/// longer value is an error (a 500 for the request that wrote it). Under a non-strict
/// sql_mode (some managed servers, `sql_mode=''`) it's cut to 768 characters with a warning, so
/// two values that differ after character 768 are the same key, and the full value never
/// finds the stored one. Postgres (text) and SQLite keep any length.
#[tokio::test]
async fn guard_long_key_text_is_refused_not_truncated_in_strict_mode() {
    let long = |tail: &str| format!("{}{tail}@acme.dk", "a".repeat(800));
    for (label, mode) in [
        ("strict (server default)", None),
        ("non-strict sql_mode=''", Some("")),
    ] {
        let Some((pool, name, server)) = mysql(mode, true).await else {
            return;
        };
        let schema = conformance_schema(&IdStrategy::UuidV7, false);
        let db = Sqlx::new(pool);
        migrate(&db, &schema).await;
        let typed = Db::new(&db, &schema);
        let first = typed
            .insert(&user(&long("x"), "first"))
            .await
            .map(|_| ())
            .map_err(|e| e.to_string());
        let second = typed
            .insert(&user(&long("y"), "second"))
            .await
            .map(|_| ())
            .map_err(|e| e.to_string());
        let found = typed
            .count::<User>(User::EMAIL.eq(long("x")))
            .await
            .unwrap();
        println!(
            "[mysql, {label}] insert 808-char email: {first:?}; a second one differing at char 801: {second:?}; lookups of the first find {found}"
        );
        drop_mysql(name, server).await;
        if mode.is_none() {
            assert!(first.is_err(), "strict mode refuses the long value");
        }
    }
}
