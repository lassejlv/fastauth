//! The claim model (ATO-1..8, RACE-1) on real databases: a claim is one transaction on
//! SQLite, Postgres and MySQL, a failing plugin cleanup rolls all of it back, and a 0.5
//! database gets `user.security_stamp` from the migrator.
//!
//! Every test runs on a SQLite file and, when the URLs are set, on Postgres (`DATABASE_URL`,
//! a fresh schema) and MySQL (`MYSQL_DATABASE_URL`, a fresh database). A backend without its
//! URL is skipped.
#![cfg(all(
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "two-factor",
    feature = "api-key",
    feature = "magic-link"
))]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration as StdDuration;

use axum::body::Bytes;
use axum::http::{Request, header};
use fastauth::adapter::Adapter;
use fastauth::crypto::{Argon2id, Secret};
use fastauth::mail::{AuthEmail, MemoryMailer};
use fastauth::migrate::Step;
use fastauth::plugin_prelude::{AuthError, Plugin, PluginBuilder};
use fastauth::plugins::api_key::{ApiKeys, ApiKeysExt, CreateApiKeyInput};
use fastauth::plugins::magic_link::MagicLink;
use fastauth::plugins::two_factor::{TwoFactor, TwoFactorRow};
use fastauth::prelude::*;
use fastauth::query::Db;
use fastauth::sqlx::sqlx::mysql::MySqlPoolOptions;
use fastauth::sqlx::sqlx::postgres::PgPoolOptions;
use fastauth::sqlx::sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use fastauth::sqlx::sqlx::{AssertSqlSafe, Executor};
use serde_json::{Value, json};

/// A plugin whose claim cleanup fails while it is armed.
#[derive(Default)]
struct Tripwire {
    armed: Arc<AtomicBool>,
}

impl Plugin for Tripwire {
    const ID: &'static str = "tripwire";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        let armed = self.armed.clone();
        app.on_claim(move |_claim| {
            let armed = armed.load(Ordering::SeqCst);
            Box::pin(async move {
                if armed {
                    return Err(AuthError::internal("tripwire"));
                }
                Ok(())
            })
        });
    }
}

type Plugins = plugins![TwoFactor, ApiKeys, MagicLink, Tripwire];
type AppAuth<D> = Auth<D, (), Plugins>;

const ORIGIN: &str = "http://localhost:3000";
const PASSWORD: &str = "correct horse battery";

struct App<D: Adapter> {
    auth: AppAuth<D>,
    mail: MemoryMailer,
    armed: Arc<AtomicBool>,
}

type Exec = Box<dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Raw SQL on the backend under test: the quoted name of the `user` table and a way to run
/// a statement.
struct Raw {
    user_table: String,
    exec: Exec,
}

fn raw<DB>(pool: fastauth::sqlx::sqlx::Pool<DB>, user_table: String) -> Raw
where
    DB: fastauth::sqlx::sqlx::Database,
    for<'c> &'c fastauth::sqlx::sqlx::Pool<DB>: Executor<'c, Database = DB>,
{
    Raw {
        user_table,
        exec: Box::new(move |sql| {
            let pool = pool.clone();
            Box::pin(async move {
                pool.execute(AssertSqlSafe(sql)).await.expect("raw SQL");
            })
        }),
    }
}

type Outcome = Result<String, String>;

async fn app<D: Adapter>(db: D) -> App<D> {
    let mail = MemoryMailer::new();
    let tripwire = Tripwire::default();
    let armed = tripwire.armed.clone();
    let auth: AppAuth<D> = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .email_verification(EmailVerification::default().send_on_sign_up(false))
        .rate_limit(RateLimit::disabled())
        .mailer(mail.clone())
        .plugin(TwoFactor::new().skip_verification_on_enable(true))
        .plugin(ApiKeys::new())
        .plugin(MagicLink::new())
        .plugin(tripwire)
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");
    App { auth, mail, armed }
}

fn fresh_name() -> String {
    format!("claim_model_{}", Id::new_v7().as_str().replace('-', ""))
}

macro_rules! on_every_backend {
    ($what:expr, $scenario:ident) => {{
        let mut violations: Vec<String> = Vec::new();
        let mut record = |backend: &str, outcome: Outcome| match outcome {
            Ok(note) => println!("[{backend}] {}: holds. {note}", $what),
            Err(violation) => {
                println!("[{backend}] {}: VIOLATED. {violation}", $what);
                violations.push(format!("[{backend}] {violation}"));
            }
        };
        {
            let dir = tempfile::tempdir().unwrap();
            let options = SqliteConnectOptions::new()
                .filename(dir.path().join("claim.db"))
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .busy_timeout(StdDuration::from_secs(10));
            let pool = SqlitePoolOptions::new()
                .max_connections(8)
                .connect_with(options)
                .await
                .expect("SQLite file");
            let raw = raw(pool.clone(), "\"user\"".into());
            record("sqlite", $scenario(app(Sqlx::new(pool)).await, raw).await);
        }
        match std::env::var("DATABASE_URL") {
            Ok(url) => {
                let pool = PgPoolOptions::new()
                    .max_connections(16)
                    .connect(&url)
                    .await
                    .expect("connect to DATABASE_URL");
                let schema = fresh_name();
                let raw = raw(pool.clone(), format!("\"{schema}\".\"user\""));
                let db = Sqlx::new(pool.clone()).schema(schema.clone());
                record("postgres", $scenario(app(db).await, raw).await);
                pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
                    .await
                    .expect("drop the test schema");
            }
            Err(_) => println!("[postgres] {}: skipped, DATABASE_URL is not set", $what),
        }
        match std::env::var("MYSQL_DATABASE_URL") {
            Ok(url) => {
                let pool = MySqlPoolOptions::new()
                    .max_connections(16)
                    .connect(&url)
                    .await
                    .expect("connect to MYSQL_DATABASE_URL");
                let database = fresh_name();
                let raw = raw(pool.clone(), format!("`{database}`.`user`"));
                let db = Sqlx::new(pool.clone()).schema(database.clone());
                record("mysql", $scenario(app(db).await, raw).await);
                pool.execute(AssertSqlSafe(format!("DROP DATABASE `{database}`")))
                    .await
                    .expect("drop the test database");
            }
            Err(_) => println!("[mysql] {}: skipped, MYSQL_DATABASE_URL is not set", $what),
        }
        assert!(violations.is_empty(), "{}", violations.join("\n"));
    }};
}

/// A browser: the app and a cookie jar.
struct Browser<'a, D: Adapter> {
    app: &'a App<D>,
    jar: Vec<(String, String)>,
}

impl<'a, D: Adapter> Browser<'a, D> {
    fn new(app: &'a App<D>) -> Self {
        Self {
            app,
            jar: Vec::new(),
        }
    }

    async fn send(&mut self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("/api/auth{path}"))
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json");
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
        let response = self.app.auth.handle(builder.body(body).unwrap()).await;
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

    async fn whoami(&mut self) -> Option<Value> {
        let (_, json) = self.send("GET", "/get-session", None).await;
        json.get("user").cloned().filter(|user| !user.is_null())
    }

    /// Asks for a magic link for `email` and opens it in this browser.
    async fn open_magic_link(&mut self, email: &str) -> (u16, Value) {
        let before = self.app.mail.sent().len();
        let (status, json) = self
            .post("/sign-in/magic-link", json!({ "email": email }))
            .await;
        assert_eq!(status, 200, "{json}");
        let url = magic_link(self.app, email, before).await;
        let path = url
            .strip_prefix("http://localhost:3000/api/auth")
            .unwrap_or_else(|| panic!("not an auth URL: {url}"))
            .to_owned();
        self.send("GET", &path, None).await
    }
}

fn db<D: Adapter>(app: &App<D>) -> Db<'_, D> {
    Db::new(app.auth.adapter(), app.auth.schema())
}

/// Emails are sent in the background: waits for a magic link to `to` sent after the first
/// `before` emails.
async fn magic_link<D: Adapter>(app: &App<D>, to: &str, before: usize) -> String {
    for _ in 0..400 {
        let found = app
            .mail
            .sent()
            .iter()
            .skip(before)
            .find_map(|email| match email {
                AuthEmail::Plugin(e) if e.kind == "magic-link" && e.to == to => e.url.clone(),
                _ => None,
            });
        if let Some(url) = found {
            return url;
        }
        tokio::time::sleep(StdDuration::from_millis(5)).await;
    }
    panic!("the magic link never arrived: {:?}", app.mail.sent());
}

async fn user<D: Adapter>(app: &App<D>, email: &str) -> User {
    db(app)
        .find::<User>(User::EMAIL.eq(email))
        .one()
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("no user {email}"))
}

/// Mallory signs up with Ada's address, enables two-factor and makes an API key. Answers
/// her signed-in browser and the key.
async fn squat<'a, D: Adapter>(app: &'a App<D>, email: &str) -> (Browser<'a, D>, String) {
    let mut mallory = Browser::new(app);
    let (status, json) = mallory
        .post(
            "/sign-up/email",
            json!({ "email": email, "password": PASSWORD, "name": "Mallory" }),
        )
        .await;
    assert_eq!(status, 200, "sign-up: {json}");
    let (status, json) = mallory
        .post("/two-factor/enable", json!({ "password": PASSWORD }))
        .await;
    assert_eq!(status, 200, "two-factor/enable: {json}");
    let owner = user(app, email).await.id;
    let key = app
        .auth
        .api_keys()
        .create(CreateApiKeyInput {
            user_id: Some(owner),
            ..Default::default()
        })
        .await
        .unwrap()
        .key;
    (mallory, key)
}

/// What the squatter left on `email`'s user: whether the key still verifies, how many
/// two-factor rows there are, and whether the email is verified.
async fn leftovers<D: Adapter>(app: &App<D>, email: &str, key: &str) -> (bool, u64, bool) {
    let user = user(app, email).await;
    let key_valid = app.auth.api_keys().verify(key, None).await.unwrap().valid;
    let two_factor = db(app)
        .count::<TwoFactorRow>(TwoFactorRow::USER_ID.eq(&user.id))
        .await
        .unwrap();
    (key_valid, two_factor, user.email_verified)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_removes_every_credential_in_one_transaction() {
    on_every_backend!("claim on a real database", claim_removes_everything);
}

async fn claim_removes_everything<D: Adapter>(app: App<D>, _raw: Raw) -> Outcome {
    let email = "ada@acme.dk";
    let (mut mallory, key) = squat(&app, email).await;
    let mut ada = Browser::new(&app);
    let (status, json) = ada.open_magic_link(email).await;
    if status >= 400 {
        return Err(format!("the magic link failed: {status} {json}"));
    }
    let (key_valid, two_factor, verified) = leftovers(&app, email, &key).await;
    let mallory_signed_in = mallory.whoami().await.is_some();
    let (password_status, _) = Browser::new(&app)
        .post(
            "/sign-in/email",
            json!({ "email": email, "password": PASSWORD }),
        )
        .await;
    if key_valid || two_factor != 0 || !verified || mallory_signed_in || password_status == 200 {
        return Err(format!(
            "after the claim: key valid {key_valid}, two_factor rows {two_factor}, verified \
             {verified}, Mallory's session alive {mallory_signed_in}, her password answers \
             {password_status}"
        ));
    }
    if ada.whoami().await.is_none() {
        return Err("Ada isn't signed in after the claim".into());
    }
    Ok("key, two-factor, session and password gone; Ada signed in".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failing_cleanup_rolls_the_whole_claim_back() {
    on_every_backend!("failing cleanup rolls back", failing_cleanup_rolls_back);
}

async fn failing_cleanup_rolls_back<D: Adapter>(app: App<D>, _raw: Raw) -> Outcome {
    let email = "ada@acme.dk";
    let (mut mallory, key) = squat(&app, email).await;

    app.armed.store(true, Ordering::SeqCst);
    let mut ada = Browser::new(&app);
    let (status, _) = ada.open_magic_link(email).await;
    let (key_valid, two_factor, verified) = leftovers(&app, email, &key).await;
    let mallory_signed_in = mallory.whoami().await.is_some();
    if status < 400 || ada.whoami().await.is_some() {
        return Err(format!(
            "the claim answered {status} with a failing cleanup"
        ));
    }
    if !key_valid || two_factor != 1 || verified || !mallory_signed_in {
        return Err(format!(
            "a failed claim committed part of itself: key valid {key_valid}, two_factor rows \
             {two_factor}, verified {verified}, Mallory's session alive {mallory_signed_in}"
        ));
    }

    app.armed.store(false, Ordering::SeqCst);
    let (retry, json) = ada.open_magic_link(email).await;
    if retry >= 400 {
        return Err(format!("the retried claim failed: {retry} {json}"));
    }
    let (key_valid, two_factor, verified) = leftovers(&app, email, &key).await;
    if key_valid || two_factor != 0 || !verified || mallory.whoami().await.is_some() {
        return Err(format!(
            "the retried claim left: key valid {key_valid}, two_factor rows {two_factor}, \
             verified {verified}"
        ));
    }
    Ok(format!(
        "the failed claim answered {status} and changed nothing; the retry claimed"
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_migrator_adds_the_security_stamp_to_a_0_5_database() {
    on_every_backend!("0.5 upgrade", upgrade_from_0_5);
}

async fn upgrade_from_0_5<D: Adapter>(app: App<D>, raw: Raw) -> Outcome {
    let (status, json) = Browser::new(&app)
        .post(
            "/sign-up/email",
            json!({ "email": "old@acme.dk", "password": PASSWORD, "name": "Old" }),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    (raw.exec)(format!(
        "ALTER TABLE {} DROP COLUMN security_stamp",
        raw.user_table
    ))
    .await;

    let plan = app.auth.migrator().plan().await.unwrap();
    let adds_stamp = plan.steps.iter().any(|step| {
        matches!(step, Step::AddColumn { table, column }
            if table.name == "user" && column.name == "security_stamp")
    });
    if !adds_stamp || plan.steps.len() != 1 {
        return Err(format!("the plan for a 0.5 database is {plan:?}"));
    }
    app.auth.migrator().run().await.unwrap();
    if !app.auth.migrator().plan().await.unwrap().is_empty() {
        return Err("the migrator has more to do after running".into());
    }

    let mut old = Browser::new(&app);
    let (status, json) = old
        .post(
            "/sign-in/email",
            json!({ "email": "old@acme.dk", "password": PASSWORD }),
        )
        .await;
    if status != 200 {
        return Err(format!("an existing user can't sign in: {status} {json}"));
    }
    let mut ada = Browser::new(&app);
    let (status, json) = ada.open_magic_link("old@acme.dk").await;
    if status >= 400 || old.whoami().await.is_some() {
        return Err(format!(
            "the claim of an upgraded user answered {status} {json} or left its session"
        ));
    }
    Ok("one AddColumn step; existing users sign in and are claimed".into())
}
