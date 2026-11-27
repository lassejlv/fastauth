//! FAST-61 review of the 0.6.0 claim model (#48): writes that a session authorised before a
//! claim and that land after it. `claim_user` deletes every credential and session in one
//! transaction and changes the security stamp, and sign-ins and social links re-check the
//! stamp after their insert (`stamp_holds`). Other session-authorised credential writes don't,
//! so a request the squatter has in flight when the owner proves the email puts a credential
//! back on the claimed, now verified, account.
//!
//! The interleaving is forced, not raced: a gated password hasher stops a request inside
//! `hash`/`verify`, and a gated adapter stops it right before its insert into one table. The
//! claim runs while the request is stopped, then the request is let go.
//!
//! Every scenario runs on a SQLite file and, when the URLs are set, on Postgres
//! (`DATABASE_URL`) and MySQL (`MYSQL_DATABASE_URL`).
//!
//! Run: cargo test -p fastauth --all-features --test fast61_claim_races -- --nocapture --test-threads=1
#![cfg(all(
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "two-factor",
    feature = "api-key",
    feature = "magic-link",
    feature = "email-otp"
))]

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration as StdDuration;

use axum::body::Bytes;
use axum::http::{Request, header};
use fastauth::adapter::{
    Adapter, DbResult, Delete, Insert, Queries, Select, SessionWithUser, Update,
};
use fastauth::crypto::{Argon2id, PasswordHasher, Secret};
use fastauth::mail::{AuthEmail, MemoryMailer};
use fastauth::migrate::{LiveSchema, MigrationPlan};
use fastauth::plugin_prelude::{
    Authenticated, Ctx, Duration, Empty, Endpoint, Hash, Method, Transaction, Verification,
};
use fastauth::plugins::api_key::ApiKeys;
use fastauth::plugins::email_otp::EmailOtp;
use fastauth::plugins::magic_link::MagicLink;
use fastauth::plugins::two_factor::{TwoFactor, TwoFactorRow};
use fastauth::prelude::*;
use fastauth::query::Db;
use fastauth::sqlx::sqlx::mysql::MySqlPoolOptions;
use fastauth::sqlx::sqlx::postgres::PgPoolOptions;
use fastauth::sqlx::sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use fastauth::sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth::value::Row;
use serde_json::{Value, json};

const ORIGIN: &str = "http://localhost:3000";
const ADA: &str = "ada@acme.dk";
const MALLORY_PASSWORD: &str = "mallory signed up first";
const MALLORY_NEW_PASSWORD: &str = "mallory changed it mid-claim";
const ADA_PASSWORD: &str = "ada picked this herself";

// ------------------------------------------------------------------------------- gates

/// Stops the first call that passes it after `arm`, until `release`.
#[derive(Clone, Default)]
struct Gate(Arc<GateState>);

#[derive(Default)]
struct GateState {
    armed: AtomicBool,
    reached: AtomicBool,
    released: AtomicBool,
}

impl Gate {
    fn arm(&self) {
        self.0.reached.store(false, Ordering::SeqCst);
        self.0.released.store(false, Ordering::SeqCst);
        self.0.armed.store(true, Ordering::SeqCst);
    }

    /// For the password hasher, which runs on a blocking thread.
    fn pass_blocking(&self) {
        if self.0.armed.swap(false, Ordering::SeqCst) {
            self.0.reached.store(true, Ordering::SeqCst);
            while !self.0.released.load(Ordering::SeqCst) {
                std::thread::sleep(StdDuration::from_millis(1));
            }
        }
    }

    async fn pass(&self) {
        if self.0.armed.swap(false, Ordering::SeqCst) {
            self.0.reached.store(true, Ordering::SeqCst);
            while !self.0.released.load(Ordering::SeqCst) {
                tokio::time::sleep(StdDuration::from_millis(1)).await;
            }
        }
    }

    async fn wait_reached(&self) {
        for _ in 0..5000 {
            if self.0.reached.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(StdDuration::from_millis(2)).await;
        }
        panic!("the gated request never reached the gate");
    }

    fn release(&self) {
        self.0.released.store(true, Ordering::SeqCst);
    }
}

/// Argon2id with a gate in `hash` and one in `verify`.
struct GatedHasher {
    inner: Argon2id,
    on_hash: Gate,
    on_verify: Gate,
}

impl PasswordHasher for GatedHasher {
    fn hash(&self, password: &str) -> Result<String, String> {
        self.on_hash.pass_blocking();
        self.inner.hash(password)
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, String> {
        self.on_verify.pass_blocking();
        self.inner.verify(password, hash)
    }

    fn needs_rehash(&self, hash: &str) -> bool {
        self.inner.needs_rehash(hash)
    }
}

/// An adapter that stops a non-transactional insert or update on `table`, or the first
/// transaction that begins after `arm` (the one a session-authorised write locks the user row
/// in), at `gate`.
struct GatedDb<D> {
    inner: D,
    table: &'static str,
    gate: Gate,
}

impl<D: Adapter> Queries for GatedDb<D> {
    async fn insert(&self, q: Insert<'_>) -> DbResult<Row> {
        if q.table.name == self.table {
            self.gate.pass().await;
        }
        self.inner.insert(q).await
    }

    async fn find_one(&self, q: Select<'_>) -> DbResult<Option<Row>> {
        self.inner.find_one(q).await
    }

    async fn find_many(&self, q: Select<'_>) -> DbResult<Vec<Row>> {
        self.inner.find_many(q).await
    }

    async fn update(&self, q: Update<'_>) -> DbResult<u64> {
        if q.table.name == self.table {
            self.gate.pass().await;
        }
        self.inner.update(q).await
    }

    async fn delete(&self, q: Delete<'_>) -> DbResult<u64> {
        self.inner.delete(q).await
    }

    async fn count(&self, q: Select<'_>) -> DbResult<u64> {
        self.inner.count(q).await
    }
}

impl<D: Adapter> Adapter for GatedDb<D> {
    type Tx = D::Tx;

    async fn begin(&self) -> DbResult<D::Tx> {
        self.gate.pass().await;
        self.inner.begin().await
    }

    async fn introspect(&self) -> DbResult<LiveSchema> {
        self.inner.introspect().await
    }

    async fn apply(&self, plan: &MigrationPlan) -> DbResult<()> {
        self.inner.apply(plan).await
    }

    fn session_with_user(
        &self,
        q: SessionWithUser<'_>,
    ) -> impl Future<Output = DbResult<Option<(Row, Row)>>> + Send {
        self.inner.session_with_user(q)
    }
}

// ------------------------------------------------------------------------------- app

type Plugins = plugins![TwoFactor, ApiKeys, MagicLink, EmailOtp];
type AppAuth<D> = Auth<GatedDb<D>, (), Plugins>;

struct App<D: Adapter> {
    auth: AppAuth<D>,
    mail: MemoryMailer,
    on_hash: Gate,
    on_verify: Gate,
    on_insert: Gate,
    in_lock: Gate,
}

/// `POST /test/locked-write`: a session-authorised write that stops at its gate while it
/// holds the user row (`lock_user_unless_claimed`), then stores a verification a claim
/// deletes (`email-verification:{user_id}`).
struct LockedWrite(Gate);

impl<D: Adapter> Endpoint<D> for LockedWrite {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/test/locked-write";
    type Access = Authenticated;
    type Input = Empty;
    type Output = Value;

    async fn call(&self, ctx: Ctx<D, Authenticated>, _: Empty) -> Result<Value, AuthError> {
        let session = ctx.sensitive_session().await?;
        let tx = ctx
            .internal()
            .lock_user_unless_claimed(&session.user)
            .await?;
        self.0.pass().await;
        let now = ctx.now();
        ctx.db_on(&tx)
            .insert(&Verification {
                id: ctx.new_id()?,
                identifier: format!("email-verification:{}", session.user.id),
                value_hash: Hash::sha256("locked write"),
                data: None,
                expires_at: now + Duration::hours(1),
                created_at: now,
                updated_at: now,
            })
            .await?;
        tx.commit().await?;
        Ok(json!({ "status": true }))
    }
}

async fn app<D: Adapter>(db: D, gated_table: &'static str) -> App<D> {
    app_with(db, gated_table, Argon2id::with_params(1024, 1, 1)).await
}

async fn app_with<D: Adapter>(db: D, gated_table: &'static str, argon2: Argon2id) -> App<D> {
    let mail = MemoryMailer::new();
    let (on_hash, on_verify, on_insert) = (Gate::default(), Gate::default(), Gate::default());
    let in_lock = Gate::default();
    let locked_write = LockedWrite(in_lock.clone());
    let hasher = GatedHasher {
        inner: argon2,
        on_hash: on_hash.clone(),
        on_verify: on_verify.clone(),
    };
    let db = GatedDb {
        inner: db,
        table: gated_table,
        gate: on_insert.clone(),
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
        .plugin(ApiKeys::new().sessions(true))
        .plugin(MagicLink::new())
        .plugin(EmailOtp::new().change_email(true))
        .configure(move |app| {
            app.endpoint(locked_write);
        })
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");
    App {
        auth,
        mail,
        on_hash,
        on_verify,
        on_insert,
        in_lock,
    }
}

type Outcome = Result<String, String>;

fn fresh_name() -> String {
    format!("fast61_{}", Id::new_v7().as_str().replace('-', ""))
}

/// Runs `$scenario(app)` on SQLite, then Postgres and MySQL when their URLs are set, and fails
/// with every backend's violation.
macro_rules! on_every_backend {
    ($what:expr, $table:expr, $scenario:ident) => {{
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
            record(
                "sqlite",
                $scenario(app(Sqlx::new(pool), $table).await).await,
            );
        }
        match std::env::var("DATABASE_URL") {
            Ok(url) => {
                let pool = PgPoolOptions::new()
                    .max_connections(16)
                    .connect(&url)
                    .await
                    .expect("connect to DATABASE_URL");
                let schema = fresh_name();
                let db = Sqlx::new(pool.clone()).schema(schema.clone());
                record("postgres", $scenario(app(db, $table).await).await);
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
                let db = Sqlx::new(pool.clone()).schema(database.clone());
                record("mysql", $scenario(app(db, $table).await).await);
                pool.execute(AssertSqlSafe(format!("DROP DATABASE `{database}`")))
                    .await
                    .expect("drop the test database");
            }
            Err(_) => println!("[mysql] {}: skipped, MYSQL_DATABASE_URL is not set", $what),
        }
        assert!(violations.is_empty(), "{}", violations.join("\n"));
    }};
}

/// A browser: a clone of `Auth` and a cookie jar, so it can move into a task.
struct Browser<D: Adapter> {
    auth: AppAuth<D>,
    jar: Vec<(String, String)>,
}

impl<D: Adapter> Browser<D> {
    fn new(app: &App<D>) -> Self {
        Self {
            auth: app.auth.clone(),
            jar: Vec::new(),
        }
    }

    async fn send(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
        api_key: Option<&str>,
    ) -> (u16, Value) {
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
        if let Some(key) = api_key {
            builder = builder.header("x-api-key", key);
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
        self.send("POST", path, Some(body), None).await
    }

    async fn sign_in(&mut self, email: &str, password: &str) -> (u16, Value) {
        self.post(
            "/sign-in/email",
            json!({ "email": email, "password": password }),
        )
        .await
    }
}

/// Emails go out in the background: waits for one that `pick` accepts, sent after the first
/// `before`.
async fn mail_to<D: Adapter, T>(
    app: &App<D>,
    before: usize,
    pick: impl Fn(&AuthEmail) -> Option<T>,
) -> T {
    for _ in 0..1000 {
        if let Some(found) = app.mail.sent().iter().skip(before).find_map(&pick) {
            return found;
        }
        tokio::time::sleep(StdDuration::from_millis(5)).await;
    }
    panic!("the email never arrived: {:?}", app.mail.sent());
}

/// Ada proves the mailbox with a magic link in her own browser: the claim.
async fn ada_opens_a_magic_link<D: Adapter>(app: &App<D>) -> Browser<D> {
    let mut ada = Browser::new(app);
    let before = app.mail.sent().len();
    let (status, json) = ada
        .post("/sign-in/magic-link", json!({ "email": ADA }))
        .await;
    assert_eq!(status, 200, "{json}");
    let url = mail_to(app, before, |email| match email {
        AuthEmail::Plugin(e) if e.kind == "magic-link" && e.to == ADA => e.url.clone(),
        _ => None,
    })
    .await;
    let path = url.strip_prefix("http://localhost:3000/api/auth").unwrap();
    let (status, json) = ada.send("GET", path, None, None).await;
    assert!(
        status == 200 || status == 302,
        "magic link: {status} {json}"
    );
    ada
}

/// Ada uses "forgot password" and sets her own password: the claim.
async fn ada_resets_the_password<D: Adapter>(app: &App<D>) {
    let mut ada = Browser::new(app);
    let before = app.mail.sent().len();
    let (status, json) = ada
        .post("/request-password-reset", json!({ "email": ADA }))
        .await;
    assert_eq!(status, 200, "{json}");
    let token = mail_to(app, before, |email| match email {
        AuthEmail::ResetPassword(e) if e.to == ADA => Some(e.token.clone()),
        _ => None,
    })
    .await;
    let (status, json) = ada
        .post(
            "/reset-password",
            json!({ "token": token, "newPassword": ADA_PASSWORD }),
        )
        .await;
    assert_eq!(status, 200, "reset: {json}");
}

/// Mallory signs up with Ada's address (nothing verifies it) and is signed in.
async fn mallory_squats<D: Adapter>(app: &App<D>) -> Browser<D> {
    let mut mallory = Browser::new(app);
    let (status, json) = mallory
        .post(
            "/sign-up/email",
            json!({ "email": ADA, "password": MALLORY_PASSWORD, "name": "Mallory" }),
        )
        .await;
    assert_eq!(status, 200, "sign-up: {json}");
    mallory
}

fn spawn_post<D: Adapter>(
    mut browser: Browser<D>,
    path: &'static str,
    body: Value,
) -> tokio::task::JoinHandle<(u16, Value)> {
    tokio::spawn(async move { browser.post(path, body).await })
}

fn db<D: Adapter>(app: &App<D>) -> Db<'_, GatedDb<D>> {
    Db::new(app.auth.adapter(), app.auth.schema())
}

// ------------------------------------------------------------------------------- tests

/// F61-1: /change-password authorises with the session it read at the start, then spends two
/// password hashes (verify the current one, hash the new one) before `set_password` writes.
/// A claim that commits in that window deletes Mallory's session and credential, and then
/// `set_password` finds no credential row and inserts one with Mallory's new password
/// (its fallback is `link_account`, which checks no stamp). The claimed, verified account then
/// signs in with Mallory's password.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_change_password_in_flight_during_a_magic_link_claim_leaves_no_squatter_password() {
    on_every_backend!(
        "change-password in flight during a magic-link claim",
        "",
        change_password_vs_magic_link
    );
}

async fn change_password_vs_magic_link<D: Adapter>(app: App<D>) -> Outcome {
    let mallory = mallory_squats(&app).await;
    app.on_hash.arm();
    let change = spawn_post(
        mallory,
        "/change-password",
        json!({ "currentPassword": MALLORY_PASSWORD, "newPassword": MALLORY_NEW_PASSWORD }),
    );
    app.on_hash.wait_reached().await;
    let _ada = ada_opens_a_magic_link(&app).await;
    app.on_hash.release();
    let (change_status, change_json) = change.await.unwrap();
    let (status, json) = Browser::new(&app).sign_in(ADA, MALLORY_NEW_PASSWORD).await;
    if status == 200 {
        return Err(format!(
            "Mallory's change-password answered {change_status} after Ada's claim, and her new \
             password now signs in to Ada's verified account as {} (emailVerified={})",
            json["user"]["email"], json["user"]["emailVerified"]
        ));
    }
    Ok(format!(
        "change-password answered {change_status} {change_json}; sign-in with Mallory's new \
         password answered {status}"
    ))
}

/// F61-1 (update path): the same window, but Ada claims with "forgot password" and sets her
/// own password. Mallory's `set_password` then finds Ada's new credential row and overwrites
/// its hash: Mallory's password signs in and Ada's doesn't.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_change_password_in_flight_during_a_reset_claim_keeps_the_owners_password() {
    on_every_backend!(
        "change-password in flight during a reset claim",
        "",
        change_password_vs_reset
    );
}

async fn change_password_vs_reset<D: Adapter>(app: App<D>) -> Outcome {
    let mallory = mallory_squats(&app).await;
    app.on_hash.arm();
    let change = spawn_post(
        mallory,
        "/change-password",
        json!({ "currentPassword": MALLORY_PASSWORD, "newPassword": MALLORY_NEW_PASSWORD }),
    );
    app.on_hash.wait_reached().await;
    ada_resets_the_password(&app).await;
    app.on_hash.release();
    let (change_status, _) = change.await.unwrap();
    let (mallory_status, _) = Browser::new(&app).sign_in(ADA, MALLORY_NEW_PASSWORD).await;
    let (ada_status, _) = Browser::new(&app).sign_in(ADA, ADA_PASSWORD).await;
    if mallory_status == 200 || ada_status != 200 {
        return Err(format!(
            "after Ada's reset, Mallory's in-flight change-password answered {change_status}: \
             Mallory's new password signs in with {mallory_status}, Ada's own with {ada_status}"
        ));
    }
    Ok(format!(
        "change-password answered {change_status}; Mallory {mallory_status}, Ada {ada_status}"
    ))
}

/// F61-2: /api-key/create checks the session (`key_manager`, a fresh database read) and then
/// inserts the key with no stamp check. A claim that commits between the two leaves a key the
/// claim's `on_claim` cleanup never saw, and it resolves to a session on Ada's verified
/// account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_api_key_created_during_a_claim_does_not_survive_it() {
    on_every_backend!(
        "api-key/create in flight during a claim",
        "apikey",
        api_key_vs_claim
    );
}

async fn api_key_vs_claim<D: Adapter>(app: App<D>) -> Outcome {
    let mallory = mallory_squats(&app).await;
    app.on_insert.arm();
    let create = spawn_post(mallory, "/api-key/create", json!({ "name": "ci" }));
    app.on_insert.wait_reached().await;
    let _ada = ada_opens_a_magic_link(&app).await;
    app.on_insert.release();
    let (status, created) = create.await.unwrap();
    let Some(key) = created["key"].as_str() else {
        return Ok(format!("api-key/create answered {status} {created}"));
    };
    let (status, session) = Browser::new(&app)
        .send("GET", "/get-session", None, Some(key))
        .await;
    if status == 200 && session["user"]["email"] == ADA {
        return Err(format!(
            "Mallory's API key, created while Ada's claim ran, signs in as {} (emailVerified={})",
            session["user"]["email"], session["user"]["emailVerified"]
        ));
    }
    Ok(format!("the key resolves to {status} {session}"))
}

/// F61-3: /two-factor/enable checks the session and the password, then replaces the
/// enrollment in a transaction that locks the user row. It waits for a claim in progress but
/// doesn't re-check the session or the stamp, so Mallory's TOTP secret lands on Ada's claimed
/// account; with `skip_verification_on_enable` it is switched on, and Ada is challenged by a
/// factor only Mallory holds (ATO-5's outcome, through a race).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_two_factor_enable_in_flight_during_a_claim_leaves_no_enrollment() {
    on_every_backend!(
        "two-factor/enable in flight during a claim",
        "",
        two_factor_vs_claim
    );
}

async fn two_factor_vs_claim<D: Adapter>(app: App<D>) -> Outcome {
    let mallory = mallory_squats(&app).await;
    app.on_verify.arm();
    let enable = spawn_post(
        mallory,
        "/two-factor/enable",
        json!({ "password": MALLORY_PASSWORD }),
    );
    app.on_verify.wait_reached().await;
    let _ada = ada_opens_a_magic_link(&app).await;
    app.on_verify.release();
    let (status, _) = enable.await.unwrap();
    let user = db(&app)
        .find::<User>(User::EMAIL.eq(ADA))
        .one()
        .await
        .unwrap()
        .expect("Ada's user");
    let rows = db(&app)
        .count::<TwoFactorRow>(TwoFactorRow::USER_ID.eq(&user.id))
        .await
        .unwrap();
    if rows > 0 {
        return Err(format!(
            "Mallory's two-factor/enable answered {status} after Ada's claim and left {rows} \
             enrollment row(s) with her TOTP secret on Ada's verified account"
        ));
    }
    Ok(format!(
        "two-factor/enable answered {status}; no enrollment"
    ))
}

/// Guard (F61-1's lock, the other order): a claim that starts while a session-authorised write
/// holds the user row waits for the write to commit, then runs and removes what it stored.
/// Neither deadlocks on any backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn guard_a_claim_waits_for_a_write_holding_the_user_row_and_then_removes_it() {
    on_every_backend!(
        "a claim while a write holds the user row",
        "",
        claim_waits_for_a_locked_write
    );
}

async fn claim_waits_for_a_locked_write<D: Adapter>(app: App<D>) -> Outcome {
    let mallory = mallory_squats(&app).await;
    app.in_lock.arm();
    let write = spawn_post(mallory, "/test/locked-write", json!({}));
    app.in_lock.wait_reached().await;
    let claimed = AtomicBool::new(false);
    let release = async {
        tokio::time::sleep(StdDuration::from_millis(300)).await;
        let early = claimed.load(Ordering::SeqCst);
        app.in_lock.release();
        early
    };
    let claim = async {
        let ada = ada_opens_a_magic_link(&app).await;
        claimed.store(true, Ordering::SeqCst);
        ada
    };
    let (early, _ada) = tokio::join!(release, claim);
    let (status, json) = write.await.unwrap();
    if early {
        return Err("the claim finished while the write still held the user row".into());
    }
    if status != 200 {
        return Err(format!(
            "the write that held the lock first answered {status} {json}"
        ));
    }
    let user = db(&app)
        .find::<User>(User::EMAIL.eq(ADA))
        .one()
        .await
        .unwrap()
        .expect("Ada's user");
    let left = db(&app)
        .count::<Verification>(
            Verification::IDENTIFIER.eq(format!("email-verification:{}", user.id)),
        )
        .await
        .unwrap();
    if left > 0 || !user.email_verified {
        return Err(format!(
            "after the claim, {left} row(s) the write stored remain (emailVerified={})",
            user.email_verified
        ));
    }
    Ok("the claim waited for the write, then removed what it stored".into())
}

/// Guard: a password sign-in in flight during a claim gets no session. RACE-1 holds through
/// the password verify too, forced here instead of raced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn guard_password_sign_in_in_flight_during_a_claim_gets_no_session() {
    on_every_backend!(
        "password sign-in in flight during a claim",
        "",
        sign_in_vs_claim
    );
}

async fn sign_in_vs_claim<D: Adapter>(app: App<D>) -> Outcome {
    drop(mallory_squats(&app).await);
    app.on_verify.arm();
    let sign_in = spawn_post(
        Browser::new(&app),
        "/sign-in/email",
        json!({ "email": ADA, "password": MALLORY_PASSWORD }),
    );
    app.on_verify.wait_reached().await;
    let _ada = ada_opens_a_magic_link(&app).await;
    app.on_verify.release();
    let (status, json) = sign_in.await.unwrap();
    if status == 200 {
        return Err(format!("the in-flight sign-in got a session: {json}"));
    }
    Ok(format!("the in-flight sign-in answered {status}"))
}

/// Not a regression test: how often the F61-1 race lands without any gate, with the default
/// OWASP Argon2id parameters. Mallory sends change-password requests back to back (alternating
/// two passwords) while Ada opens a magic link; a trial counts when either of Mallory's
/// passwords signs in to Ada's verified account afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "measurement, run by hand"]
async fn measure_change_password_race_without_gates() {
    let trials = 20;
    let mut landed = 0;
    for trial in 0..trials {
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
            .unwrap();
        let app = app_with(Sqlx::new(pool), "", Argon2id::owasp()).await;
        let mut mallory = mallory_squats(&app).await;
        let stop = Arc::new(AtomicBool::new(false));
        let looping = {
            let stop = stop.clone();
            tokio::spawn(async move {
                let passwords = [MALLORY_PASSWORD, MALLORY_NEW_PASSWORD];
                let mut current = 0;
                let mut requests = 0;
                while !stop.load(Ordering::SeqCst) {
                    let (status, _) = mallory
                        .post(
                            "/change-password",
                            json!({
                                "currentPassword": passwords[current],
                                "newPassword": passwords[1 - current],
                            }),
                        )
                        .await;
                    requests += 1;
                    if status != 200 {
                        break;
                    }
                    current = 1 - current;
                }
                requests
            })
        };
        tokio::time::sleep(StdDuration::from_millis(50 + 37 * trial)).await;
        let _ada = ada_opens_a_magic_link(&app).await;
        tokio::time::sleep(StdDuration::from_millis(300)).await;
        stop.store(true, Ordering::SeqCst);
        let requests = looping.await.unwrap();
        let mut signed_in = false;
        for password in [MALLORY_PASSWORD, MALLORY_NEW_PASSWORD] {
            signed_in |= Browser::new(&app).sign_in(ADA, password).await.0 == 200;
        }
        println!(
            "trial {trial}: {requests} change-password requests, Mallory signs in: {signed_in}"
        );
        landed += usize::from(signed_in);
    }
    println!("the race landed in {landed} of {trials} trials");
}

/// F61-1 (email): /email-otp/change-email checks the session, the code and that the address
/// is free, then sets the user's email (verified) by id with no stamp check. In flight during
/// Ada's claim, it moves Ada's claimed, verified account to Mallory's mailbox, so Mallory can
/// reset its password.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_email_change_in_flight_during_a_claim_does_not_move_the_account() {
    on_every_backend!(
        "email-otp/change-email in flight during a claim",
        "user",
        change_email_vs_claim
    );
}

async fn change_email_vs_claim<D: Adapter>(app: App<D>) -> Outcome {
    const MALLORY: &str = "mallory@evil.test";
    let mut mallory = mallory_squats(&app).await;
    let before = app.mail.sent().len();
    let (status, json) = mallory
        .post(
            "/email-otp/request-email-change",
            json!({ "newEmail": MALLORY }),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let code = mail_to(&app, before, |email| match email {
        AuthEmail::Plugin(e) if e.kind == "email-otp-change-email" && e.to == MALLORY => {
            e.code.clone()
        }
        _ => None,
    })
    .await;
    app.on_insert.arm();
    let change = spawn_post(
        mallory,
        "/email-otp/change-email",
        json!({ "newEmail": MALLORY, "otp": code }),
    );
    app.on_insert.wait_reached().await;
    let ada = ada_opens_a_magic_link(&app).await;
    app.on_insert.release();
    let (status, _) = change.await.unwrap();
    let ada_id = ada
        .auth
        .api()
        .db()
        .find::<User>(User::EMAIL.eq(MALLORY))
        .one()
        .await
        .unwrap();
    if let Some(user) = ada_id {
        return Err(format!(
            "Mallory's change-email answered {status} after Ada's claim and moved Ada's verified \
             account {} to {} (emailVerified={})",
            user.id, user.email, user.email_verified
        ));
    }
    Ok(format!(
        "change-email answered {status}; Ada keeps her address"
    ))
}
