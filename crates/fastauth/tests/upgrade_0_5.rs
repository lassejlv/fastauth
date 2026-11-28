//! A real fastauth 0.5 database upgraded by this version, on SQLite, Postgres and MySQL.
//!
//! The databases in fixtures/upgrade_0_5/ were made by fastauth 0.5.0 itself: its migrator
//! created the schema and its HTTP API seeded users with passwords (verified and not),
//! sessions, social links, an organization with members and a pending invitation,
//! two-factor, an API key, a username and a guest. tests/upgrade-0.5-fixtures/generate.sh
//! regenerates them. Each <backend>.json holds what the test needs to act as those users.
//!
//! The test loads a dump, adds the duplicates 0.5 allowed and 0.6's unique constraints
//! forbid, and checks that the migrator refuses them before any DDL, naming the rows; that
//! the fix-up queries from docs/concepts/02-database.md work; that the migration then
//! finishes; and that the 0.5 users, sessions, keys and second factors still work, while
//! links 0.5 mailed don't (CHANGELOG, "Upgrading from 0.5").
//!
//! SQLite always runs. Postgres runs with DATABASE_URL (a fresh schema) and MySQL with
//! MYSQL_DATABASE_URL (a fresh database); a backend without its URL is skipped.
#![cfg(all(
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "two-factor",
    feature = "organization",
    feature = "admin",
    feature = "api-key",
    feature = "magic-link",
    feature = "email-otp",
    feature = "bearer",
    feature = "jwt",
    feature = "passkey",
    feature = "username",
    feature = "anonymous",
    feature = "multi-session"
))]

use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;

use axum::body::Bytes;
use axum::http::{Request, header};
use fastauth::adapter::Adapter;
use fastauth::crypto::Argon2id;
use fastauth::mail::MemoryMailer;
use fastauth::models::User;
use fastauth::plugins::admin::Admin;
use fastauth::plugins::anonymous::Anonymous;
use fastauth::plugins::api_key::ApiKeys;
use fastauth::plugins::bearer::Bearer;
use fastauth::plugins::email_otp::EmailOtp;
use fastauth::plugins::jwt::Jwt;
use fastauth::plugins::magic_link::MagicLink;
use fastauth::plugins::multi_session::MultiSession;
use fastauth::plugins::organization::Organization;
use fastauth::plugins::passkey::Passkey;
use fastauth::plugins::two_factor::TwoFactor;
use fastauth::plugins::username::Username;
use fastauth::prelude::*;
use fastauth::sqlx::sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use fastauth::sqlx::sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use fastauth::sqlx::sqlx::sqlite::SqlitePoolOptions;
use fastauth::sqlx::sqlx::{self, AssertSqlSafe, Executor};
use serde_json::{Value, json};

type Everything = plugins![
    TwoFactor,
    Organization,
    Admin,
    ApiKeys,
    MagicLink,
    EmailOtp,
    Bearer,
    Jwt,
    Passkey,
    Username,
    Anonymous,
    MultiSession,
];
type AppAuth<D> = Auth<D, (), Everything>;

const ORIGIN: &str = "http://localhost:3000";
const DOCS: &str = include_str!("../../../docs/concepts/02-database.md");

/// The same configuration the generator gave 0.5, so the secret, the hasher and the plugin
/// tables match what the dump holds.
fn build<D: Adapter>(db: D, manifest: &Value) -> AppAuth<D> {
    let secret = manifest["secret"].as_str().unwrap().as_bytes().to_vec();
    FastAuth::builder()
        .secret(Secret::from_bytes(secret))
        .base_url(ORIGIN)
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .mailer(MemoryMailer::new())
        .plugin(TwoFactor::new().skip_verification_on_enable(true))
        .plugin(Organization::default())
        .plugin(Admin::new())
        .plugin(ApiKeys::new().sessions(true))
        .plugin(MagicLink::new())
        .plugin(EmailOtp::new())
        .plugin(Bearer::new())
        .plugin(Jwt::new())
        .plugin(Passkey::new())
        .plugin(Username::new())
        .plugin(Anonymous::new())
        .plugin(MultiSession::new())
        .build()
        .expect("valid config")
}

type Exec = Box<dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>>;

/// Raw SQL on the database under test, several statements at once, with the
/// backend's quoting of the `user` table.
struct Raw {
    backend: &'static str,
    exec: Exec,
}

impl Raw {
    fn new<DB>(backend: &'static str, pool: sqlx::Pool<DB>) -> Self
    where
        DB: sqlx::Database,
        for<'c> &'c sqlx::Pool<DB>: Executor<'c, Database = DB>,
    {
        Self {
            backend,
            exec: Box::new(move |sql| {
                let pool = pool.clone();
                Box::pin(async move {
                    sqlx::raw_sql(AssertSqlSafe(sql))
                        .execute(&pool)
                        .await
                        .map(|_| ())
                        .map_err(|err| err.to_string())
                })
            }),
        }
    }

    async fn run(&self, sql: impl Into<String>) -> Result<(), String> {
        (self.exec)(sql.into()).await
    }

    /// `sql` with `"user"` written the way this backend quotes it.
    fn dialect(&self, sql: &str) -> String {
        if self.backend == "mysql" {
            sql.replace("\"user\"", "`user`")
        } else {
            sql.to_owned()
        }
    }
}

/// The statements of the SQL block in the docs' "Unique constraints on an existing
/// database" section, finding queries included: what an operator pastes to fix the
/// duplicates.
fn docs_fix_ups() -> Vec<String> {
    let section = DOCS
        .split_once("### Unique constraints on an existing database")
        .expect("the docs section exists")
        .1;
    let block = section
        .split_once("```sql")
        .expect("the section has a SQL block")
        .1
        .split_once("```")
        .unwrap()
        .0;
    let code: String = block
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    code.split(';')
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
        .map(str::to_owned)
        .collect()
}

fn manifest(backend: &str) -> Value {
    let json = match backend {
        "sqlite" => include_str!("fixtures/upgrade_0_5/sqlite.json"),
        "postgres" => include_str!("fixtures/upgrade_0_5/postgres.json"),
        _ => include_str!("fixtures/upgrade_0_5/mysql.json"),
    };
    serde_json::from_str(json).expect("manifest")
}

fn dump(backend: &str) -> &'static str {
    match backend {
        "sqlite" => include_str!("fixtures/upgrade_0_5/sqlite.sql"),
        "postgres" => include_str!("fixtures/upgrade_0_5/postgres.sql"),
        _ => include_str!("fixtures/upgrade_0_5/mysql.sql"),
    }
}

fn fresh_name() -> String {
    format!("upgrade_0_5_{}", Id::new_v7().as_str().replace('-', ""))
}

/// A browser: a cookie jar in front of `Auth::handle`.
struct Browser<'a, D: Adapter> {
    auth: &'a AppAuth<D>,
    jar: Vec<(String, String)>,
    headers: Vec<(&'static str, String)>,
}

impl<'a, D: Adapter> Browser<'a, D> {
    fn new(auth: &'a AppAuth<D>) -> Self {
        Self {
            auth,
            jar: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// A browser that holds a cookie 0.5 set, as `name=value`.
    fn with_cookie(auth: &'a AppAuth<D>, cookie: &Value) -> Self {
        let (name, value) = cookie.as_str().unwrap().split_once('=').unwrap();
        let mut browser = Self::new(auth);
        browser.jar.push((name.to_owned(), value.to_owned()));
        browser
    }

    async fn send(&mut self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("/api/auth{path}"))
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json");
        for (name, value) in &self.headers {
            builder = builder.header(*name, value);
        }
        if !self.jar.is_empty() {
            let cookies = self
                .jar
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            builder = builder.header(header::COOKIE, cookies);
        }
        let body = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
        let response = self.auth.handle(builder.body(body).unwrap()).await;
        for cookie in response.headers().get_all(header::SET_COOKIE) {
            let cookie = cookie.to_str().unwrap();
            let (pair, attrs) = cookie.split_once(';').unwrap_or((cookie, ""));
            let (name, value) = pair.split_once('=').unwrap();
            self.jar.retain(|(k, _)| k != name);
            if !attrs.contains("Max-Age=0") {
                self.jar.push((name.to_owned(), value.to_owned()));
            }
        }
        let status = response.status().as_u16();
        let json = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
        (status, json)
    }

    async fn post(&mut self, path: &str, body: Value) -> (u16, Value) {
        self.send("POST", path, Some(body)).await
    }

    async fn whoami(&mut self) -> Option<String> {
        let (_, json) = self.send("GET", "/get-session", None).await;
        json["user"]["email"].as_str().map(str::to_owned)
    }
}

/// The steps the 0.5 database needs, as the migrator prints them.
async fn pending<D: Adapter>(auth: &AppAuth<D>) -> Vec<String> {
    let mut steps: Vec<String> = auth
        .migrator()
        .plan()
        .await
        .expect("plans")
        .steps
        .iter()
        .map(ToString::to_string)
        .collect();
    steps.sort();
    steps
}

const UPGRADE_STEPS: [&str; 4] = [
    "add column user.security_stamp (Int, owner core)",
    "add unique (organization_id, user_id) on member",
    "add unique (provider_id, account_id) on account",
    "add unique (user_id) on two_factor",
];

/// What 0.5 let in and 0.6's constraints forbid: Alice's GitHub account linked to Bob too,
/// Carol in the organization twice (the copy as owner), and a second TOTP secret for
/// `two_factor_user`.
fn duplicates(m: &Value, two_factor_user: &str) -> [String; 3] {
    let (bob, carol, two_factor_user) = (&m["bob_id"], &m["carol_id"], &m[two_factor_user]);
    [
        format!(
            "INSERT INTO account (id, user_id, provider_id, account_id, scope, created_at, updated_at) \
             SELECT 'dup-account', {bob}, provider_id, account_id, scope, created_at, updated_at \
             FROM account WHERE id = 'acct-github-1001'"
        ),
        format!(
            "INSERT INTO member (id, organization_id, user_id, role, created_at) \
             SELECT 'dup-member', organization_id, user_id, 'owner', created_at \
             FROM member WHERE user_id = {carol}"
        ),
        format!(
            "INSERT INTO two_factor (id, user_id, secret, backup_codes, last_used_step) \
             SELECT 'dup-two-factor', user_id, secret, backup_codes, last_used_step \
             FROM two_factor WHERE user_id = {two_factor_user}"
        ),
    ]
    .map(|sql| sql.replace('"', "'"))
}

async fn expect_refusal<D: Adapter>(auth: &AppAuth<D>, table: &str, rows: &[&str]) {
    let err = auth
        .migrator()
        .run()
        .await
        .expect_err("the migrator refuses duplicates")
        .to_string();
    assert!(
        err.contains(&format!("to `{table}`")),
        "refusal names {table}: {err}"
    );
    for row in rows {
        assert!(err.contains(row), "refusal names row {row}: {err}");
    }
    let mut expected = UPGRADE_STEPS.map(str::to_owned).to_vec();
    expected.sort();
    assert_eq!(pending(auth).await, expected, "nothing was applied");
}

async fn upgrade<D: Adapter>(db: D, raw: Raw) {
    let backend = raw.backend;
    let m = manifest(backend);
    raw.run(dump(backend)).await.expect("load the 0.5 dump");
    let auth = build(db, &m);

    let mut expected = UPGRADE_STEPS.map(str::to_owned).to_vec();
    expected.sort();
    assert_eq!(pending(&auth).await, expected, "[{backend}] plan for 0.5");

    for sql in duplicates(&m, "carol_id") {
        raw.run(sql).await.expect("0.5 allowed the duplicate");
    }
    let carol = m["carol_id"].as_str().unwrap();
    expect_refusal(&auth, "account", &["dup-account", "acct-github-1001"]).await;
    raw.run("DELETE FROM account WHERE id = 'dup-account'")
        .await
        .unwrap();
    expect_refusal(&auth, "two_factor", &["dup-two-factor", carol]).await;
    for statement in docs_fix_ups() {
        raw.run(raw.dialect(&statement))
            .await
            .unwrap_or_else(|err| panic!("[{backend}] docs fix-up failed: {statement}\n{err}"));
    }
    auth.migrator()
        .run()
        .await
        .expect("migrates after the fix-ups");
    assert!(pending(&auth).await.is_empty(), "[{backend}] up to date");

    for sql in duplicates(&m, "frank_id") {
        assert!(
            raw.run(&sql).await.is_err(),
            "[{backend}] the new constraint refuses: {sql}"
        );
    }
    let api = auth.api();
    let db = api.db();
    assert_eq!(
        db.count::<User>(User::SECURITY_STAMP.ne(0)).await.unwrap(),
        0,
        "[{backend}] existing users get security_stamp 0"
    );

    let password = m["password"].as_str().unwrap();
    let sign_in = |email: &str| json!({"email": email, "password": password});

    // 0.5 sessions resolve, on both of Alice's devices, and so do the guest's and Dave's.
    for (cookie, email) in [
        ("alice_session_cookie", Some("alice@example.com")),
        ("alice_phone_session_cookie", Some("alice@example.com")),
        ("dave_session_cookie", Some("dave@example.com")),
        ("bob_session_cookie", Some("bob@example.com")),
    ] {
        let mut browser = Browser::with_cookie(&auth, &m[cookie]);
        assert_eq!(
            browser.whoami().await.as_deref(),
            email,
            "[{backend}] {cookie}"
        );
    }
    let mut guest = Browser::with_cookie(&auth, &m["guest_session_cookie"]);
    let (status, session) = guest.send("GET", "/get-session", None).await;
    assert_eq!(status, 200, "[{backend}] guest session: {session}");
    assert_eq!(
        session["user"]["isAnonymous"], true,
        "[{backend}] {session}"
    );

    // 0.5 passwords sign in.
    let mut alice = Browser::new(&auth);
    let (status, out) = alice
        .post("/sign-in/email", sign_in("alice@example.com"))
        .await;
    assert_eq!(status, 200, "[{backend}] alice signs in: {out}");
    let (status, out) = Browser::new(&auth)
        .post(
            "/sign-in/username",
            json!({"username": "dave_dev", "password": password}),
        )
        .await;
    assert_eq!(status, 200, "[{backend}] dave signs in by username: {out}");

    // A 0.5 API key still authenticates.
    let mut key = Browser::new(&auth);
    key.headers
        .push(("x-api-key", m["alice_api_key"].as_str().unwrap().to_owned()));
    assert_eq!(
        key.whoami().await.as_deref(),
        Some("alice@example.com"),
        "[{backend}] 0.5 API key"
    );

    // Frank's second factor from 0.5 still challenges, and a 0.5 backup code answers it.
    let mut frank = Browser::new(&auth);
    let (status, out) = frank
        .post("/sign-in/email", sign_in("frank@example.com"))
        .await;
    assert_eq!(status, 200, "[{backend}] frank: {out}");
    assert_eq!(out["twoFactorRedirect"], true, "[{backend}] frank: {out}");
    let code = m["frank_backup_codes"][0].clone();
    let (status, out) = frank
        .post("/two-factor/verify-backup-code", json!({"code": code}))
        .await;
    assert_eq!(status, 200, "[{backend}] backup code: {out}");
    assert_eq!(frank.whoami().await.as_deref(), Some("frank@example.com"));

    // The docs' fix-up turned Carol's two-factor off: she signs in with her password alone.
    let mut carol_browser = Browser::new(&auth);
    let (status, out) = carol_browser
        .post("/sign-in/email", sign_in("carol@example.com"))
        .await;
    assert_eq!(status, 200, "[{backend}] carol: {out}");
    assert_ne!(out["twoFactorRedirect"], true, "[{backend}] carol: {out}");

    // The fix-up kept Carol's original membership, as a member, not the owner copy.
    let org = m["organization_id"].as_str().unwrap();
    let (status, members) = alice
        .send(
            "GET",
            &format!("/organization/list-members?organizationId={org}"),
            None,
        )
        .await;
    assert_eq!(status, 200, "[{backend}] list members: {members}");
    let roles: Vec<(&str, &str)> = members["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| {
            (
                member["user"]["email"].as_str().unwrap(),
                member["role"].as_str().unwrap(),
            )
        })
        .collect();
    let mut roles = roles;
    roles.sort();
    assert_eq!(
        roles,
        [
            ("alice@example.com", "owner"),
            ("carol@example.com", "member"),
            ("frank@example.com", "member"),
        ],
        "[{backend}]"
    );
    let (status, invitations) = alice
        .send(
            "GET",
            &format!("/organization/list-invitations?organizationId={org}"),
            None,
        )
        .await;
    assert_eq!(status, 200, "[{backend}] {invitations}");
    assert!(
        invitations.to_string().contains("bob@example.com"),
        "[{backend}] Bob's 0.5 invitation is still pending: {invitations}"
    );

    // Links 0.5 mailed stop working (CHANGELOG: users request a new one), and using one
    // changes nothing: Bob is still unverified and his password still signs in.
    let (status, out) = Browser::new(&auth)
        .post(
            "/reset-password",
            json!({"token": m["bob_reset_token"], "newPassword": "a brand new password"}),
        )
        .await;
    assert_eq!(status, 400, "[{backend}] 0.5 reset link: {out}");
    let token = m["bob_verify_token"].as_str().unwrap();
    let (status, out) = Browser::new(&auth)
        .send("GET", &format!("/verify-email?token={token}"), None)
        .await;
    assert!(
        status >= 400,
        "[{backend}] 0.5 verification link: {status} {out}"
    );
    let mut bob = Browser::new(&auth);
    let (status, out) = bob.post("/sign-in/email", sign_in("bob@example.com")).await;
    assert_eq!(status, 200, "[{backend}] bob keeps his password: {out}");
    assert_eq!(out["user"]["emailVerified"], false, "[{backend}] {out}");
}

#[tokio::test]
async fn a_0_5_database_upgrades_on_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("upgrade.db").display()
    );
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    upgrade(Sqlx::new(pool.clone()), Raw::new("sqlite", pool)).await;
}

#[tokio::test]
async fn a_0_5_database_upgrades_on_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        println!("[postgres] skipped, DATABASE_URL is not set");
        return;
    };
    let server = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = fresh_name();
    server
        .execute(AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .await
        .unwrap();
    let options = PgConnectOptions::from_str(&url)
        .unwrap()
        .options([("search_path", schema.as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .unwrap();
    upgrade(Sqlx::new(pool.clone()), Raw::new("postgres", pool)).await;
    server
        .execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_0_5_database_upgrades_on_mysql() {
    let Ok(url) = std::env::var("MYSQL_DATABASE_URL") else {
        println!("[mysql] skipped, MYSQL_DATABASE_URL is not set");
        return;
    };
    let server = MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let database = fresh_name();
    server
        .execute(AssertSqlSafe(format!("CREATE DATABASE `{database}`")))
        .await
        .unwrap();
    let options = MySqlConnectOptions::from_str(&url)
        .unwrap()
        .database(&database);
    let pool = MySqlPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .unwrap();
    upgrade(Sqlx::new(pool.clone()), Raw::new("mysql", pool)).await;
    server
        .execute(AssertSqlSafe(format!("DROP DATABASE `{database}`")))
        .await
        .unwrap();
}
