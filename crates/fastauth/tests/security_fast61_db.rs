//! FAST-61, #46 slice: the unique constraints 0.6 adds, how the migrator plans and checks
//! them, and the row-lock transactions around them, on SQLite, Postgres and MySQL.
//!
//! Every scenario runs on a SQLite file and, when the URLs are set, on Postgres
//! (DATABASE_URL, a fresh schema) and MySQL (MYSQL_DATABASE_URL, a fresh database). A
//! backend without its URL is skipped. Scenarios about one database's catalog say so and
//! pass on the others.
//!
//! sec_* tests assert the secure or correct behaviour and fail on e1c00a33 (0.6.0). guard_*
//! tests pass and pin behaviour that was checked and holds.
#![cfg(all(
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "two-factor",
    feature = "organization",
    feature = "magic-link"
))]

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration as StdDuration;

use axum::body::Bytes;
use axum::http::{Request, header};
use fastauth::adapter::Adapter;
use fastauth::crypto::{Argon2id, PasswordHasher, Secret};
use fastauth::mail::{AuthEmail, MemoryMailer};
use fastauth::migrate::Step;
use fastauth::models::{Account, User};
use fastauth::plugin_prelude as pp;
use fastauth::plugins::magic_link::MagicLink;
use fastauth::plugins::organization::{Member, Organization};
use fastauth::plugins::two_factor::{TwoFactor, TwoFactorRow};
use fastauth::prelude::*;
use fastauth::query::Db;
use fastauth::sqlx::sqlx::mysql::MySqlPoolOptions;
use fastauth::sqlx::sqlx::postgres::PgPoolOptions;
use fastauth::sqlx::sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use fastauth::sqlx::sqlx::{self, AssertSqlSafe, Executor};
use serde_json::{Value, json};

/// What a verified social sign-in does for an unverified local user with that address
/// (fastauth-oauth routes.rs): claim it and link the provider account in the claim's
/// transaction. An endpoint, so the test needs no OAuth provider.
struct SocialClaim;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SocialClaimInput {
    email: String,
    account_id: String,
}

struct ClaimWithLink;

impl<D: Adapter> pp::Endpoint<D> for ClaimWithLink {
    const METHOD: pp::Method = pp::Method::POST;
    const PATH: &'static str = "/test/social-claim";
    type Access = pp::Public;
    type Input = SocialClaimInput;
    type Output = Value;

    async fn call(
        &self,
        ctx: pp::Ctx<D, pp::Public>,
        input: SocialClaimInput,
    ) -> Result<Value, pp::AuthError> {
        let internal = ctx.internal();
        let user = internal
            .find_user_by_email(&input.email)
            .await?
            .expect("the user exists");
        let user = internal
            .claim_user(
                user,
                Some(pp::NewAccount::oauth("github", input.account_id)),
            )
            .await?;
        Ok(json!({ "emailVerified": user.email_verified }))
    }
}

impl pp::Plugin for SocialClaim {
    const ID: &'static str = "social-claim";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut pp::PluginBuilder<'_, D>) {
        app.endpoint(ClaimWithLink);
    }
}

type Plugins = plugins![TwoFactor, Organization, MagicLink, SocialClaim];
type AppAuth<D> = Auth<D, (), Plugins>;

const ORIGIN: &str = "http://localhost:3000";
const PASSWORD: &str = "correct horse battery";

type Outcome = Result<String, String>;

#[derive(Default)]
struct GateState {
    armed: bool,
    entered: bool,
    released: bool,
    rehash: bool,
}

/// A hasher that can hold the next hash until the test lets it go, so a request can be
/// paused between reading the database and writing the password.
#[derive(Clone, Default)]
struct Gate(Arc<(Mutex<GateState>, Condvar)>);

impl Gate {
    fn arm(&self) {
        let mut state = self.0.0.lock().unwrap();
        *state = GateState {
            armed: true,
            rehash: state.rehash,
            ..GateState::default()
        };
    }

    fn set_rehash(&self, rehash: bool) {
        self.0.0.lock().unwrap().rehash = rehash;
    }

    /// Waits until an armed hash started; false after 10 s.
    async fn entered(&self) -> bool {
        for _ in 0..1000 {
            if self.0.0.lock().unwrap().entered {
                return true;
            }
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
        false
    }

    fn release(&self) {
        let mut state = self.0.0.lock().unwrap();
        state.released = true;
        state.armed = false;
        self.0.1.notify_all();
    }
}

struct GatedHasher {
    gate: Gate,
    inner: Argon2id,
}

impl PasswordHasher for GatedHasher {
    fn hash(&self, password: &str) -> Result<String, String> {
        let (lock, wake) = &*self.gate.0;
        let mut state = lock.lock().unwrap();
        if state.armed && !state.entered {
            state.entered = true;
            while !state.released {
                state = wake.wait(state).unwrap();
            }
        }
        drop(state);
        self.inner.hash(password)
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, String> {
        self.inner.verify(password, hash)
    }

    fn needs_rehash(&self, _hash: &str) -> bool {
        self.gate.0.0.lock().unwrap().rehash
    }
}

struct App<D: Adapter> {
    auth: AppAuth<D>,
    mail: MemoryMailer,
    gate: Gate,
}

async fn app<D: Adapter>(db: D) -> App<D> {
    let mail = MemoryMailer::new();
    let gate = Gate::default();
    let hasher = GatedHasher {
        gate: gate.clone(),
        inner: Argon2id::with_params(1024, 1, 1),
    };
    let auth: AppAuth<D> = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .database(db)
        .email_password(EmailPassword::default().hasher(hasher))
        .email_verification(EmailVerification::default().send_on_sign_up(false))
        .rate_limit(RateLimit::disabled())
        .mailer(mail.clone())
        .plugin(TwoFactor::new().skip_verification_on_enable(true))
        .plugin(Organization::default().organization_limit(3))
        .plugin(MagicLink::new())
        .plugin(SocialClaim)
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");
    App { auth, mail, gate }
}

type Exec = Box<dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>>;

/// Raw SQL on the backend under test, with its table names.
struct Raw {
    backend: &'static str,
    /// The schema (Postgres) or database (MySQL) the app's tables are in.
    namespace: Option<String>,
    exec: Exec,
}

impl Raw {
    fn new<DB>(backend: &'static str, namespace: Option<String>, pool: sqlx::Pool<DB>) -> Self
    where
        DB: sqlx::Database,
        for<'c> &'c sqlx::Pool<DB>: Executor<'c, Database = DB>,
    {
        Self {
            backend,
            namespace,
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

    fn quote(&self, name: &str) -> String {
        if self.backend == "mysql" {
            format!("`{name}`")
        } else {
            format!("\"{name}\"")
        }
    }

    /// `table`, qualified and quoted.
    fn t(&self, table: &str) -> String {
        match &self.namespace {
            Some(ns) => format!("{}.{}", self.quote(ns), self.quote(table)),
            None => self.quote(table),
        }
    }

    async fn drop_index(&self, table: &str, index: &str) -> Result<(), String> {
        let sql = match (self.backend, &self.namespace) {
            ("mysql", _) => format!("DROP INDEX {} ON {}", self.quote(index), self.t(table)),
            (_, Some(ns)) => format!("DROP INDEX {}.{}", self.quote(ns), self.quote(index)),
            _ => format!("DROP INDEX {}", self.quote(index)),
        };
        self.run(sql).await
    }

    /// An index on `columns` of `table`; text columns get a prefix on MySQL, where
    /// two varchar(768) columns exceed the key size.
    async fn create_index(
        &self,
        unique: bool,
        table: &str,
        index: &str,
        columns: &[&str],
    ) -> Result<(), String> {
        let columns: Vec<String> = columns
            .iter()
            .map(|c| {
                if self.backend == "mysql" {
                    format!("{}(300)", self.quote(c))
                } else {
                    self.quote(c)
                }
            })
            .collect();
        self.run(format!(
            "CREATE {}INDEX {} ON {} ({})",
            if unique { "UNIQUE " } else { "" },
            self.quote(index),
            self.t(table),
            columns.join(", ")
        ))
        .await
    }

    async fn insert_account(
        &self,
        id: &str,
        user: &Id,
        provider: &str,
        account_id: &str,
    ) -> Result<(), String> {
        self.run(format!(
            "INSERT INTO {} (id, user_id, provider_id, account_id) VALUES ('{id}', '{}', '{provider}', '{account_id}')",
            self.t("account"),
            user.as_str()
        ))
        .await
    }
}

fn fresh_name() -> String {
    format!("fast61_db_{}", Id::new_v7().as_str().replace('-', ""))
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
                .filename(dir.path().join("fast61.db"))
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .busy_timeout(StdDuration::from_secs(10));
            let pool = SqlitePoolOptions::new()
                .max_connections(8)
                .connect_with(options)
                .await
                .expect("SQLite file");
            let raw = Raw::new("sqlite", None, pool.clone());
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
                let raw = Raw::new("postgres", Some(schema.clone()), pool.clone());
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
                let raw = Raw::new("mysql", Some(database.clone()), pool.clone());
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

/// A browser: a cookie jar and the app. Cloning it copies the jar.
struct Browser<D: Adapter> {
    auth: AppAuth<D>,
    mail: MemoryMailer,
    jar: Vec<(String, String)>,
}

impl<D: Adapter> Clone for Browser<D> {
    fn clone(&self) -> Self {
        Self {
            auth: self.auth.clone(),
            mail: self.mail.clone(),
            jar: self.jar.clone(),
        }
    }
}

impl<D: Adapter + 'static> Browser<D> {
    fn new(app: &App<D>) -> Self {
        Self {
            auth: app.auth.clone(),
            mail: app.mail.clone(),
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

    fn spawn_post(&self, path: &'static str, body: Value) -> tokio::task::JoinHandle<(u16, Value)> {
        let mut browser = self.clone();
        tokio::spawn(async move { browser.post(path, body).await })
    }

    async fn sign_up(&mut self, email: &str) -> (u16, Value) {
        self.post(
            "/sign-up/email",
            json!({"email": email, "name": "Someone", "password": PASSWORD}),
        )
        .await
    }

    async fn sign_in(&mut self, email: &str, password: &str) -> (u16, Value) {
        self.post(
            "/sign-in/email",
            json!({"email": email, "password": password}),
        )
        .await
    }

    /// Asks for a magic link for `email` and opens it in this browser.
    async fn open_magic_link(&mut self, email: &str) -> (u16, Value) {
        let before = self.mail.sent().len();
        let (status, json) = self
            .post("/sign-in/magic-link", json!({ "email": email }))
            .await;
        assert_eq!(status, 200, "{json}");
        let mut url = None;
        for _ in 0..400 {
            url = self
                .mail
                .sent()
                .iter()
                .skip(before)
                .find_map(|email_| match email_ {
                    AuthEmail::Plugin(e) if e.kind == "magic-link" && e.to == email => {
                        e.url.clone()
                    }
                    _ => None,
                });
            if url.is_some() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        let url = url.expect("the magic link arrived");
        let path = url
            .strip_prefix("http://localhost:3000/api/auth")
            .unwrap()
            .to_owned();
        self.send("GET", &path, None).await
    }
}

fn db<D: Adapter>(app: &App<D>) -> Db<'_, D> {
    Db::new(app.auth.adapter(), app.auth.schema())
}

async fn user_id<D: Adapter>(app: &App<D>, email: &str) -> Id {
    db(app)
        .find::<User>(User::EMAIL.eq(email))
        .one()
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("no user {email}"))
        .id
}

async fn added_uniques<D: Adapter>(app: &App<D>) -> Vec<String> {
    app.auth
        .migrator()
        .plan()
        .await
        .unwrap()
        .steps
        .iter()
        .filter(|step| matches!(step, Step::AddUnique { .. }))
        .map(ToString::to_string)
        .collect()
}

// ------------------------------------------------------------------------ set_password vs claim

/// F61-DB-1. A squatter signed up with the owner's address keeps a /change-password in flight.
/// The owner proves the address (a magic link), which claims the user: every account and
/// session goes. The change-password request had already authenticated, so its
/// set_password finds no credential account to update and links a new one, with the
/// squatter's password, to the now verified user.
#[tokio::test]
async fn sec_a_password_change_in_flight_during_a_claim_gives_the_squatter_nothing() {
    on_every_backend!("change-password vs claim", change_password_vs_claim);
}

async fn change_password_vs_claim<D: Adapter + 'static>(app: App<D>, _raw: Raw) -> Outcome {
    let email = "ada@example.com";
    let mut squatter = Browser::new(&app);
    let (status, out) = squatter.sign_up(email).await;
    assert_eq!(status, 200, "{out}");
    app.gate.arm();
    let change = squatter.spawn_post(
        "/change-password",
        json!({"currentPassword": PASSWORD, "newPassword": "squatter keeps this one"}),
    );
    if !app.gate.entered().await {
        app.gate.release();
        return Err(format!("change-password never hashed: {:?}", change.await));
    }
    let mut owner = Browser::new(&app);
    let (claim_status, claim) = owner.open_magic_link(email).await;
    app.gate.release();
    let (change_status, change) = change.await.unwrap();
    let (status, out) = Browser::new(&app)
        .sign_in(email, "squatter keeps this one")
        .await;
    let user = user_id(&app, email).await;
    let accounts = db(&app)
        .count::<Account>(Account::USER_ID.eq(&user))
        .await
        .unwrap();
    if status == 200 {
        return Err(format!(
            "after the owner's claim (magic link {claim_status} {claim}), the squatter signs in \
             to the verified account with the password its in-flight change-password set \
             (change-password answered {change_status} {change}; sign-in {status}, \
             emailVerified={}; {accounts} account(s))",
            out["user"]["emailVerified"]
        ));
    }
    Ok(format!(
        "change-password answered {change_status}, the squatter's sign-in {status}, {accounts} account(s)"
    ))
}

/// F61-DB-1, second path. Sign-in rehashes a password whose hash has old parameters
/// (needs_rehash) with set_password before it creates the session. A squatter's sign-in in
/// flight during the owner's claim gets a 401 from the security stamp, but its rehash has
/// already linked a credential account with the squatter's password to the claimed user.
#[tokio::test]
async fn sec_a_rehash_in_flight_during_a_claim_does_not_restore_the_squatters_password() {
    on_every_backend!("sign-in rehash vs claim", rehash_vs_claim);
}

async fn rehash_vs_claim<D: Adapter + 'static>(app: App<D>, _raw: Raw) -> Outcome {
    let email = "ada@example.com";
    let squatter = Browser::new(&app);
    let (status, out) = squatter.clone().sign_up(email).await;
    assert_eq!(status, 200, "{out}");
    app.gate.set_rehash(true);
    app.gate.arm();
    let sign_in = squatter.spawn_post(
        "/sign-in/email",
        json!({"email": email, "password": PASSWORD}),
    );
    if !app.gate.entered().await {
        app.gate.release();
        return Err(format!("sign-in never rehashed: {:?}", sign_in.await));
    }
    let (claim_status, _) = Browser::new(&app).open_magic_link(email).await;
    app.gate.release();
    let (first_status, _) = sign_in.await.unwrap();
    app.gate.set_rehash(false);
    let (status, out) = Browser::new(&app).sign_in(email, PASSWORD).await;
    if status == 200 {
        return Err(format!(
            "after the owner's claim (magic link {claim_status}), the squatter's password signs \
             in to the verified account again: the in-flight sign-in ({first_status}) relinked \
             it while rehashing (emailVerified={})",
            out["user"]["emailVerified"]
        ));
    }
    Ok(format!(
        "in-flight sign-in {first_status}, later sign-in {status}"
    ))
}

/// F61-DB-1, third path. The owner takes the address back with a password reset while the
/// squatter's change-password is in flight. The reset claims the user and sets the owner's
/// password; the squatter's set_password then updates that credential row with its own
/// password. A fix that only stops set_password from inserting isn't enough.
#[tokio::test]
async fn sec_a_password_change_in_flight_during_a_reset_does_not_replace_the_owners_password() {
    on_every_backend!("change-password vs reset", change_password_vs_reset);
}

async fn change_password_vs_reset<D: Adapter + 'static>(app: App<D>, _raw: Raw) -> Outcome {
    let email = "ada@example.com";
    let mut squatter = Browser::new(&app);
    let (status, out) = squatter.sign_up(email).await;
    assert_eq!(status, 200, "{out}");
    app.gate.arm();
    let change = squatter.spawn_post(
        "/change-password",
        json!({"currentPassword": PASSWORD, "newPassword": "squatter keeps this one"}),
    );
    if !app.gate.entered().await {
        app.gate.release();
        return Err(format!("change-password never hashed: {:?}", change.await));
    }
    let mut owner = Browser::new(&app);
    let before = app.mail.sent().len();
    let (status, out) = owner
        .post("/request-password-reset", json!({"email": email}))
        .await;
    assert_eq!(status, 200, "{out}");
    let mut token = None;
    for _ in 0..400 {
        token = app
            .mail
            .sent()
            .iter()
            .skip(before)
            .find_map(|mail| match mail {
                AuthEmail::ResetPassword(m) if m.to == email => Some(m.token.clone()),
                _ => None,
            });
        if token.is_some() {
            break;
        }
        tokio::time::sleep(StdDuration::from_millis(5)).await;
    }
    let (reset_status, reset) = owner
        .post(
            "/reset-password",
            json!({"token": token.expect("the reset mail arrived"), "newPassword": "the owner's own password"}),
        )
        .await;
    app.gate.release();
    let (change_status, _) = change.await.unwrap();
    let (owner_status, _) = Browser::new(&app)
        .sign_in(email, "the owner's own password")
        .await;
    let (squatter_status, _) = Browser::new(&app)
        .sign_in(email, "squatter keeps this one")
        .await;
    if squatter_status == 200 || owner_status != 200 {
        return Err(format!(
            "after the owner's reset ({reset_status} {reset}), the squatter's in-flight \
             change-password ({change_status}) decides the password: the owner's sign-in \
             answers {owner_status}, the squatter's {squatter_status}"
        ));
    }
    Ok(format!(
        "change-password {change_status}; owner signs in, squatter gets {squatter_status}"
    ))
}

/// F61-DB-1 without the gate: production Argon2 parameters, a squatter that keeps one
/// change-password in flight at a time, and an owner who opens a magic link at a random
/// moment. Prints how often the squatter ends up with a working password on the claimed
/// user. Ignored: a measurement for the report, not a regression test.
#[tokio::test]
#[ignore]
async fn probe_change_password_vs_claim_without_a_gate() {
    let dir = tempfile::tempdir().unwrap();
    let options = SqliteConnectOptions::new()
        .filename(dir.path().join("probe.db"))
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(StdDuration::from_secs(10));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
        .unwrap();
    let mail = MemoryMailer::new();
    let auth: AppAuth<Sqlx<Sqlite>> = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default().hasher(Argon2id::owasp()))
        .email_verification(EmailVerification::default().send_on_sign_up(false))
        .rate_limit(RateLimit::disabled())
        .mailer(mail.clone())
        .plugin(TwoFactor::new())
        .plugin(Organization::default())
        .plugin(MagicLink::new())
        .plugin(SocialClaim)
        .build()
        .unwrap();
    auth.migrator().run().await.unwrap();
    let app = App {
        auth,
        mail,
        gate: Gate::default(),
    };
    let (trials, mut won) = (20, 0);
    for trial in 0..trials {
        let email = format!("probe{trial}@example.com");
        let mut squatter = Browser::new(&app);
        let (status, _) = squatter.sign_up(&email).await;
        assert_eq!(status, 200);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let looping = {
            let stop = stop.clone();
            let mut squatter = squatter.clone();
            tokio::spawn(async move {
                let passwords = ["squatter password one", "squatter password two"];
                let mut current = PASSWORD.to_owned();
                let mut i = 0;
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    let next = passwords[i % 2];
                    let (status, _) = squatter
                        .post(
                            "/change-password",
                            json!({"currentPassword": current, "newPassword": next}),
                        )
                        .await;
                    if status != 200 {
                        break;
                    }
                    current = next.to_owned();
                    i += 1;
                }
            })
        };
        tokio::time::sleep(StdDuration::from_millis(150 + (trial * 37 % 300) as u64)).await;
        Browser::new(&app).open_magic_link(&email).await;
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        looping.await.unwrap();
        for password in ["squatter password one", "squatter password two"] {
            if Browser::new(&app).sign_in(&email, password).await.0 == 200 {
                won += 1;
            }
        }
    }
    println!("the squatter kept a working password after {won} of {trials} claims");
}

// ------------------------------------------------------------------------------ lock ordering

/// F61-DB-2. Two-factor enable deletes the user's two_factor row and inserts the new one in a
/// transaction. On MySQL (REPEATABLE READ) the DELETE of a row that isn't there takes a gap
/// lock on the unique index, and two users whose ids fall in the same gap (ULIDs made close
/// together sort next to each other) block each other's INSERT: a deadlock, and one of them
/// gets a 500.
#[tokio::test]
async fn sec_parallel_two_factor_enables_for_different_users_all_succeed() {
    on_every_backend!("parallel two-factor enables", parallel_enables);
}

async fn parallel_enables<D: Adapter + 'static>(app: App<D>, _raw: Raw) -> Outcome {
    let mut failures = Vec::new();
    let mut total = 0;
    for round in 0..3 {
        let mut browsers = Vec::new();
        for i in 0..8 {
            let mut browser = Browser::new(&app);
            let (status, out) = browser.sign_up(&format!("u{round}-{i}@example.com")).await;
            assert_eq!(status, 200, "{out}");
            browsers.push(browser);
        }
        let tasks: Vec<_> = browsers
            .iter()
            .map(|b| b.spawn_post("/two-factor/enable", json!({"password": PASSWORD})))
            .collect();
        for task in tasks {
            total += 1;
            let (status, out) = task.await.unwrap();
            if status != 200 {
                failures.push(format!("{status} {out}"));
            }
        }
    }
    let rows = db(&app)
        .count::<TwoFactorRow>(fastauth::query::Where::all())
        .await
        .unwrap();
    if failures.is_empty() {
        Ok(format!("{total} enables, {rows} rows"))
    } else {
        Err(format!(
            "{} of {total} enables for different users failed: {}",
            failures.len(),
            failures.join("; ")
        ))
    }
}

/// A verified social sign-in that claims an unverified user deletes the user's accounts and
/// inserts the provider account in one transaction, the shape that deadlocks two-factor
/// enable on MySQL. It holds: the DELETE finds the user's credential account, so it locks
/// that record rather than a shared gap.
#[tokio::test]
async fn guard_parallel_social_claims_of_different_users_all_succeed() {
    on_every_backend!("parallel social claims", parallel_social_claims);
}

async fn parallel_social_claims<D: Adapter + 'static>(app: App<D>, _raw: Raw) -> Outcome {
    let mut failures = Vec::new();
    let mut total = 0;
    for round in 0..3 {
        let mut emails = Vec::new();
        for i in 0..8 {
            let email = format!("social{round}-{i}@example.com");
            let (status, out) = Browser::new(&app).sign_up(&email).await;
            assert_eq!(status, 200, "{out}");
            emails.push(email);
        }
        let tasks: Vec<_> = emails
            .iter()
            .enumerate()
            .map(|(i, email)| {
                Browser::new(&app).spawn_post(
                    "/test/social-claim",
                    json!({"email": email, "accountId": format!("gh-{round}-{i}")}),
                )
            })
            .collect();
        for task in tasks {
            total += 1;
            let (status, out) = task.await.unwrap();
            if status != 200 {
                failures.push(format!("{status} {out}"));
            }
        }
    }
    if failures.is_empty() {
        Ok(format!("{total} claims with a link, all 200"))
    } else {
        Err(format!(
            "{} of {total} social claims of different users failed: {}",
            failures.len(),
            failures.join("; ")
        ))
    }
}

/// Organization create with a limit locks the user row, counts and inserts in one
/// transaction; creates by different users don't block each other.
#[tokio::test]
async fn guard_parallel_organization_creates_by_different_users_all_succeed() {
    on_every_backend!("parallel organization creates", parallel_creates);
}

async fn parallel_creates<D: Adapter + 'static>(app: App<D>, _raw: Raw) -> Outcome {
    let mut browsers = Vec::new();
    for i in 0..8 {
        let mut browser = Browser::new(&app);
        let (status, out) = browser.sign_up(&format!("owner{i}@example.com")).await;
        assert_eq!(status, 200, "{out}");
        browsers.push(browser);
    }
    let tasks: Vec<_> = browsers
        .iter()
        .enumerate()
        .flat_map(|(i, b)| {
            (0..2).map(move |j| {
                b.spawn_post(
                    "/organization/create",
                    json!({"name": "Org", "slug": format!("org-{i}-{j}")}),
                )
            })
        })
        .collect();
    let mut failures = Vec::new();
    for task in tasks {
        let (status, out) = task.await.unwrap();
        if status != 200 {
            failures.push(format!("{status} {out}"));
        }
    }
    if failures.is_empty() {
        Ok("16 creates by 8 users, all 200".into())
    } else {
        Err(failures.join("; "))
    }
}

/// Claims of different users (magic links opened at once) only delete inside their
/// transactions, so their gap locks don't deadlock.
#[tokio::test]
async fn guard_parallel_claims_of_different_users_all_succeed() {
    on_every_backend!("parallel claims", parallel_claims);
}

async fn parallel_claims<D: Adapter + 'static>(app: App<D>, _raw: Raw) -> Outcome {
    let mut owners = Vec::new();
    for i in 0..8 {
        let email = format!("claimed{i}@example.com");
        let (status, out) = Browser::new(&app).sign_up(&email).await;
        assert_eq!(status, 200, "{out}");
        owners.push(email);
    }
    let tasks: Vec<_> = owners
        .into_iter()
        .map(|email| {
            let mut browser = Browser::new(&app);
            tokio::spawn(async move { browser.open_magic_link(&email).await })
        })
        .collect();
    let mut failures = Vec::new();
    for task in tasks {
        let (status, out) = task.await.unwrap();
        if status >= 400 {
            failures.push(format!("{status} {out}"));
        }
    }
    if failures.is_empty() {
        Ok("8 claims, none failed".into())
    } else {
        Err(failures.join("; "))
    }
}

// ------------------------------------------------------------------ AddUnique planning & checks

/// A 0.5-shaped database: the account unique is missing and the user has no
/// security_stamp, so the migrator plans an ADD COLUMN and then the unique.
async fn without_account_unique<D: Adapter>(app: &App<D>, raw: &Raw) {
    raw.drop_index("account", "account_provider_id_account_id_key")
        .await
        .expect("drop the account unique");
    assert_eq!(
        added_uniques(app).await,
        ["add unique (provider_id, account_id) on account"]
    );
}

/// F61-DB-3. On MySQL the account unique indexes a 384-character prefix of each column, but
/// the duplicate check compares whole values. Two account ids that share their first 384
/// characters pass the check, and CREATE UNIQUE INDEX then fails after the ADD COLUMN before
/// it has committed (MySQL DDL isn't transactional): the migration is half-applied, against
/// the docs' "it changes nothing".
#[tokio::test]
async fn sec_mysql_duplicates_the_check_cannot_see_do_not_half_apply_the_migration() {
    on_every_backend!("prefix duplicates", prefix_duplicates);
}

async fn prefix_duplicates<D: Adapter + 'static>(app: App<D>, raw: Raw) -> Outcome {
    if raw.backend != "mysql" {
        return Ok("MySQL only: full-length keys here".into());
    }
    let (status, out) = Browser::new(&app).sign_up("long@example.com").await;
    assert_eq!(status, 200, "{out}");
    let user = user_id(&app, "long@example.com").await;
    without_account_unique(&app, &raw).await;
    raw.run(format!(
        "ALTER TABLE {} DROP COLUMN security_stamp",
        raw.t("user")
    ))
    .await
    .unwrap();
    let shared = "x".repeat(384);
    raw.insert_account("long-a", &user, "oidc", &format!("{shared}A"))
        .await
        .unwrap();
    raw.insert_account("long-b", &user, "oidc", &format!("{shared}B"))
        .await
        .unwrap();
    let before = app.auth.migrator().plan().await.unwrap();
    let result = app.auth.migrator().run().await;
    let after = app.auth.migrator().plan().await.unwrap();
    let Err(err) = result else {
        return Ok("migrated".into());
    };
    if after.steps.len() != before.steps.len() {
        let rerun = {
            raw.run(format!(
                "DELETE FROM {} WHERE id = 'long-b'",
                raw.t("account")
            ))
            .await
            .unwrap();
            app.auth.migrator().run().await.map(|_| ())
        };
        return Err(format!(
            "the duplicate check passed and the migration failed half-way: {err}. Pending \
             before: {:?}; after: {:?}. A re-run after deleting one row: {rerun:?}",
            before
                .steps
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            after
                .steps
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        ));
    }
    Ok(format!("refused before any DDL: {err}"))
}

/// F61-DB-4. A unique index Postgres marked invalid (a failed CREATE UNIQUE INDEX
/// CONCURRENTLY, the way an operator adds one to a big table) is read as the constraint:
/// the migrator plans nothing, status says up to date, and duplicates go in.
#[tokio::test]
async fn sec_postgres_an_invalid_unique_index_does_not_count_as_the_constraint() {
    on_every_backend!("invalid unique index", invalid_index);
}

async fn invalid_index<D: Adapter + 'static>(app: App<D>, raw: Raw) -> Outcome {
    if raw.backend != "postgres" {
        return Ok("Postgres only".into());
    }
    let mut owner = Browser::new(&app);
    let (status, out) = owner.sign_up("owner@example.com").await;
    assert_eq!(status, 200, "{out}");
    let (status, org) = owner
        .post(
            "/organization/create",
            json!({"name": "Acme", "slug": "acme"}),
        )
        .await;
    assert_eq!(status, 200, "{org}");
    raw.drop_index("member", "member_organization_id_user_id_key")
        .await
        .unwrap();
    let duplicate = format!(
        "INSERT INTO {0} (id, organization_id, user_id, role, created_at) \
         SELECT 'dup-' || id, organization_id, user_id, role, created_at FROM {0}",
        raw.t("member")
    );
    raw.run(&duplicate).await.unwrap();
    let concurrently = raw
        .run(format!(
            "CREATE UNIQUE INDEX CONCURRENTLY member_unique_by_hand ON {} (organization_id, user_id)",
            raw.t("member")
        ))
        .await;
    assert!(concurrently.is_err(), "the duplicates make it fail");
    raw.run(format!(
        "DELETE FROM {} WHERE id LIKE 'dup-%'",
        raw.t("member")
    ))
    .await
    .unwrap();
    let plan = added_uniques(&app).await;
    app.auth.migrator().run().await.unwrap();
    match raw.run(&duplicate).await {
        Ok(()) => Err(format!(
            "after migrate (planned uniques: {plan:?}), member takes a duplicate membership: \
             the invalid index member_unique_by_hand was taken for the constraint"
        )),
        Err(err) => Ok(format!("planned {plan:?}; duplicate refused: {err}")),
    }
}

/// The migrator reads uniques by columns, not by name or column order: an index an operator
/// made under another name counts.
#[tokio::test]
async fn guard_a_unique_index_under_another_name_and_column_order_counts() {
    on_every_backend!("unique under another name", unique_by_another_name);
}

async fn unique_by_another_name<D: Adapter + 'static>(app: App<D>, raw: Raw) -> Outcome {
    without_account_unique(&app, &raw).await;
    raw.create_index(true, "account", "by_hand", &["account_id", "provider_id"])
        .await
        .unwrap();
    match added_uniques(&app).await.as_slice() {
        [] => Ok("nothing planned".into()),
        planned => Err(format!("planned again: {planned:?}")),
    }
}

/// A plain index on the same columns isn't taken for the unique: the unique is planned and
/// enforced after migrate.
#[tokio::test]
async fn guard_a_plain_index_on_the_columns_is_not_taken_for_the_unique() {
    on_every_backend!("plain index", plain_index);
}

async fn plain_index<D: Adapter + 'static>(app: App<D>, raw: Raw) -> Outcome {
    let (status, out) = Browser::new(&app).sign_up("plain@example.com").await;
    assert_eq!(status, 200, "{out}");
    let user = user_id(&app, "plain@example.com").await;
    without_account_unique(&app, &raw).await;
    raw.create_index(
        false,
        "account",
        "plain_by_hand",
        &["provider_id", "account_id"],
    )
    .await
    .unwrap();
    let planned = added_uniques(&app).await;
    app.auth.migrator().run().await.unwrap();
    raw.insert_account("p1", &user, "github", "42")
        .await
        .unwrap();
    match raw.insert_account("p2", &user, "github", "42").await {
        Ok(()) => Err(format!("planned {planned:?} but a duplicate went in")),
        Err(_) => Ok(format!("planned {planned:?}, duplicate refused")),
    }
}

/// Values that differ only in case or a trailing space aren't duplicates on any backend:
/// the check and the index use the same (binary, no-pad) comparison, so the migration
/// succeeds and both rows stay.
#[tokio::test]
async fn guard_case_and_trailing_space_are_not_duplicates() {
    on_every_backend!("case and trailing space", case_and_padding);
}

async fn case_and_padding<D: Adapter + 'static>(app: App<D>, raw: Raw) -> Outcome {
    let (status, out) = Browser::new(&app).sign_up("case@example.com").await;
    assert_eq!(status, 200, "{out}");
    let user = user_id(&app, "case@example.com").await;
    without_account_unique(&app, &raw).await;
    for (id, account_id) in [("c1", "AbC"), ("c2", "abc"), ("c3", "pad"), ("c4", "pad ")] {
        raw.insert_account(id, &user, "github", account_id)
            .await
            .unwrap();
    }
    app.auth
        .migrator()
        .run()
        .await
        .map_err(|err| format!("refused: {err}"))?;
    match added_uniques(&app).await.as_slice() {
        [] => Ok("migrated with all four rows".into()),
        planned => Err(format!("still pending: {planned:?}")),
    }
}

/// The refusal names rows of the first table with duplicates only; the member and
/// two_factor duplicates show up one migration at a time. Pinned so a change is noticed.
#[tokio::test]
async fn guard_the_refusal_names_the_rows_by_id() {
    on_every_backend!("refusal names rows", refusal_names_rows);
}

async fn refusal_names_rows<D: Adapter + 'static>(app: App<D>, raw: Raw) -> Outcome {
    let mut owner = Browser::new(&app);
    let (status, out) = owner.sign_up("rows@example.com").await;
    assert_eq!(status, 200, "{out}");
    let (status, org) = owner
        .post(
            "/organization/create",
            json!({"name": "Rows", "slug": "rows"}),
        )
        .await;
    assert_eq!(status, 200, "{org}");
    raw.drop_index("member", "member_organization_id_user_id_key")
        .await
        .unwrap();
    raw.run(format!(
        "INSERT INTO {0} (id, organization_id, user_id, role, created_at) \
         SELECT 'dup-member', organization_id, user_id, role, created_at FROM {0}",
        raw.t("member")
    ))
    .await
    .unwrap();
    let count = db(&app)
        .count::<Member>(fastauth::query::Where::all())
        .await
        .unwrap();
    let err = app
        .auth
        .migrator()
        .run()
        .await
        .expect_err("refused")
        .to_string();
    if err.contains("dup-member") && err.contains("member") {
        Ok(format!("{count} member rows; {err}"))
    } else {
        Err(format!("the refusal doesn't name the row: {err}"))
    }
}
