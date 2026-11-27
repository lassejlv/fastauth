//! FAST-45, area C: races on every single-use or limited thing, on SQLite, Postgres and MySQL.
//!
//! Every test runs its scenario on a SQLite file (WAL, 8 connections) and, when the URLs are
//! set, on Postgres (`DATABASE_URL`, a fresh schema) and MySQL (`MYSQL_DATABASE_URL`, a fresh
//! database), each with a pool of 16 connections and requests on separate tokio tasks. A
//! backend without its URL is skipped, not failed, and every line of output names the backend.
//!
//! `sec_*` tests assert the secure behaviour and fail on 7cd9718 (0.5.0) on purpose; they are
//! the regression tests for the fix. `guard_*` tests pass: they pin invariants that were
//! checked and hold because the database enforces them (a unique constraint, a conditional
//! update, or a delete whose row count is checked).
//!
//! All scenarios live here, in the facade crate, because it is the one crate that already has
//! every plugin and all three sqlx backends behind features, so no dev-dependency was added.
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
    feature = "username"
))]

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration as StdDuration, Instant};

use axum::body::Bytes;
use axum::http::{Request, header};
use fastauth::adapter::Adapter;
use fastauth::crypto::{Argon2id, Secret};
use fastauth::mail::{AuthEmail, MemoryMailer};
use fastauth::models::Verification;
use fastauth::plugins::admin::Admin;
use fastauth::plugins::api_key::{ApiKeys, ApiKeysExt, CreateApiKeyInput};
use fastauth::plugins::email_otp::EmailOtp;
use fastauth::plugins::magic_link::MagicLink;
use fastauth::plugins::organization::{Invitation, InvitationStatus, Member, Organization};
use fastauth::plugins::two_factor::{TwoFactor, TwoFactorRow, totp};
use fastauth::plugins::username::Username;
use fastauth::prelude::*;
use fastauth::query::Db;
use fastauth::sqlx::sqlx::mysql::MySqlPoolOptions;
use fastauth::sqlx::sqlx::postgres::PgPoolOptions;
use fastauth::sqlx::sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use fastauth::sqlx::sqlx::{AssertSqlSafe, Executor};
use serde_json::{Value, json};
use tokio::task::JoinHandle;

type Plugins = plugins![
    TwoFactor,
    Organization,
    Admin,
    ApiKeys,
    MagicLink,
    EmailOtp,
    Username
];
type AppAuth<D> = Auth<D, (), Plugins>;

const ORIGIN: &str = "http://localhost:3000";
const PASSWORD: &str = "correct horse battery";

/// What a scenario found on one backend: a note when the invariant held, the violation when
/// it didn't.
type Outcome = Result<String, String>;

struct App<D: Adapter> {
    auth: AppAuth<D>,
    mail: MemoryMailer,
}

/// `slow_hash`: a password hash that takes tens of milliseconds, as in production, instead
/// of the test default.
async fn app<D: Adapter>(db: D, slow_hash: bool) -> App<D> {
    let mail = MemoryMailer::new();
    let hasher = if slow_hash {
        Argon2id::with_params(19 * 1024, 2, 1)
    } else {
        Argon2id::with_params(1024, 1, 1)
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
        .plugin(Organization::default().organization_limit(2))
        .plugin(Admin::new())
        .plugin(ApiKeys::new())
        .plugin(MagicLink::new())
        .plugin(EmailOtp::new())
        .plugin(Username::new())
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");
    App { auth, mail }
}

fn fresh_name() -> String {
    format!("fast45_races_{}", Id::new_v7().as_str().replace('-', ""))
}

/// Runs the scenario on every backend that is configured and fails when any of them broke
/// the invariant.
macro_rules! on_every_backend {
    ($what:expr, $slow_hash:expr, $scenario:ident) => {{
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
                .filename(dir.path().join("races.db"))
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .busy_timeout(StdDuration::from_secs(10));
            let pool = SqlitePoolOptions::new()
                .max_connections(8)
                .connect_with(options)
                .await
                .expect("SQLite file");
            let outcome = $scenario(app(Sqlx::new(pool), $slow_hash).await).await;
            record("sqlite", outcome);
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
                let outcome = $scenario(app(db, $slow_hash).await).await;
                record("postgres", outcome);
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
                let outcome = $scenario(app(db, $slow_hash).await).await;
                record("mysql", outcome);
                pool.execute(AssertSqlSafe(format!("DROP DATABASE `{database}`")))
                    .await
                    .expect("drop the test database");
            }
            Err(_) => println!("[mysql] {}: skipped, MYSQL_DATABASE_URL is not set", $what),
        }
        assert!(violations.is_empty(), "{}", violations.join("\n"));
    }};
}

/// A browser: a cookie jar and the app. Cloning it copies the jar, so several requests can
/// go out at once with the same cookies.
struct Browser<D: Adapter> {
    auth: AppAuth<D>,
    jar: HashMap<String, String>,
}

impl<D: Adapter> Clone for Browser<D> {
    fn clone(&self) -> Self {
        Self {
            auth: self.auth.clone(),
            jar: self.jar.clone(),
        }
    }
}

impl<D: Adapter> Browser<D> {
    fn new(app: &App<D>) -> Self {
        Self {
            auth: app.auth.clone(),
            jar: HashMap::new(),
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
            if attrs.contains("Max-Age=0") {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.to_owned(), value.to_owned());
            }
        }
        let status = response.status().as_u16();
        let json = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
        (status, json)
    }

    async fn post(&mut self, path: &str, body: Value) -> (u16, Value) {
        self.send("POST", path, Some(body)).await
    }

    async fn get(&mut self, path: &str) -> (u16, Value) {
        self.send("GET", path, None).await
    }

    /// The same request from a copy of this browser on its own task, after `delay`. Answers
    /// the status, the body and the copy, which holds the cookies the response set.
    fn spawn(
        &self,
        method: &'static str,
        path: impl Into<String>,
        body: Option<Value>,
        delay: StdDuration,
    ) -> JoinHandle<(u16, Value, Browser<D>)> {
        let mut copy = self.clone();
        let path = path.into();
        tokio::spawn(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let (status, json) = copy.send(method, &path, body).await;
            (status, json, copy)
        })
    }

    async fn sign_up(&mut self, email: &str) -> Value {
        let (status, json) = self
            .post(
                "/sign-up/email",
                json!({ "email": email, "password": PASSWORD, "name": "Test" }),
            )
            .await;
        assert_eq!(status, 200, "sign-up of {email}: {json}");
        json
    }

    /// The user of this browser's session, if it has one.
    async fn whoami(&mut self) -> Option<Value> {
        let (_, json) = self.get("/get-session").await;
        json.get("user").cloned()
    }
}

/// Runs every request and collects the answers in order.
async fn join_all<D: Adapter>(
    tasks: Vec<JoinHandle<(u16, Value, Browser<D>)>>,
) -> Vec<(u16, Value, Browser<D>)> {
    let mut out = Vec::with_capacity(tasks.len());
    for task in tasks {
        out.push(task.await.expect("request task"));
    }
    out
}

fn statuses<D: Adapter>(answers: &[(u16, Value, Browser<D>)]) -> BTreeMap<String, usize> {
    let mut seen = BTreeMap::new();
    for (status, json, _) in answers {
        let key = match json["code"].as_str() {
            Some(code) => format!("{status} {code}"),
            None => status.to_string(),
        };
        *seen.entry(key).or_default() += 1;
    }
    seen
}

fn db<D: Adapter>(app: &App<D>) -> Db<'_, D> {
    Db::new(app.auth.adapter(), app.auth.schema())
}

/// Emails are sent in the background: waits for the newest one that matches.
async fn mail<D: Adapter, T>(app: &App<D>, pick: impl Fn(&AuthEmail) -> Option<T>) -> T {
    for _ in 0..400 {
        if let Some(found) = app.mail.sent().iter().rev().find_map(&pick) {
            return found;
        }
        tokio::time::sleep(StdDuration::from_millis(5)).await;
    }
    panic!("the email never arrived: {:?}", app.mail.sent());
}

async fn plugin_mail<D: Adapter>(
    app: &App<D>,
    kind: &str,
    to: &str,
) -> (Option<String>, Option<String>) {
    mail(app, |email| match email {
        AuthEmail::Plugin(e) if e.kind == kind && e.to == to => {
            Some((e.url.clone(), e.code.clone()))
        }
        _ => None,
    })
    .await
}

async fn mark_verified<D: Adapter>(app: &App<D>, email: &str) {
    db(app)
        .update::<User>(User::EMAIL.eq(email))
        .set(User::EMAIL_VERIFIED, true)
        .exec()
        .await
        .unwrap();
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

fn auth_path(url: &str) -> String {
    url.strip_prefix("http://localhost:3000/api/auth")
        .unwrap_or_else(|| panic!("not an auth URL: {url}"))
        .to_owned()
}

// ------------------------------------------------------------------ RACE-1: claim vs sign-in

/// RACE-1. A magic link (or email code, or verified social sign-in) that lands on an
/// unverified user claims it: accounts and sessions from before the proof are deleted and
/// plugins drop their credentials on `UserClaimed` (FAST-43). The claim is several separate
/// statements and nothing ties a sign-in to it, so a password sign-in that read the password
/// hash before the claim deleted it inserts its session after the claim deleted the sessions.
/// Whoever registered the address first keeps a live session on the now verified account.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sec_claim_leaves_no_session_to_a_password_sign_in_in_flight() {
    on_every_backend!("claim vs sign-in in flight", true, claim_vs_sign_in);
}

async fn claim_vs_sign_in<D: Adapter>(app: App<D>) -> Outcome {
    const RUNS: usize = 6;
    const SQUATTERS: u32 = 8;
    let mut hit_runs = 0;
    let mut survivors_total = 0;
    let mut detail = String::new();
    let mut hash_ms = 0;
    for run in 0..RUNS {
        let email = format!("ada{run}@acme.dk");
        // Mallory registers Ada's address first. Nothing verifies it.
        Browser::new(&app).sign_up(&email).await;
        if run == 0 {
            let started = Instant::now();
            let (status, _) = Browser::new(&app)
                .post(
                    "/sign-in/email",
                    json!({ "email": email, "password": PASSWORD }),
                )
                .await;
            assert_eq!(status, 200);
            hash_ms = started.elapsed().as_millis() as u64;
        }
        // Ada asks for a magic link and gets it in her mailbox.
        let mut ada = Browser::new(&app);
        let (status, json) = ada
            .post("/sign-in/magic-link", json!({ "email": email }))
            .await;
        assert_eq!(status, 200, "{json}");
        let (url, _) = plugin_mail(&app, "magic-link", &email).await;
        let link = auth_path(&url.unwrap());

        // Mallory keeps signing in with the password; Ada clicks the link meanwhile.
        let sign_in = json!({ "email": email, "password": PASSWORD });
        let step = (hash_ms * 2 / u64::from(SQUATTERS)).max(1);
        let squatters: Vec<_> = (0..SQUATTERS)
            .map(|i| {
                Browser::new(&app).spawn(
                    "POST",
                    "/sign-in/email",
                    Some(sign_in.clone()),
                    StdDuration::from_millis(step * u64::from(i)),
                )
            })
            .collect();
        let click = ada.spawn("GET", link, None, StdDuration::from_millis(hash_ms));
        let squatters = join_all(squatters).await;
        let (status, json, mut ada) = click.await.unwrap();
        assert!(status < 400, "the magic link failed: {status} {json}");
        let ada_user = ada.whoami().await.expect("Ada is signed in");
        assert_eq!(ada_user["emailVerified"], true, "the link claimed the user");

        let mut survivors = 0;
        for (_, _, mut squatter) in squatters {
            if let Some(user) = squatter.whoami().await {
                assert_eq!(user["id"], ada_user["id"]);
                survivors += 1;
            }
        }
        if survivors > 0 {
            hit_runs += 1;
            survivors_total += survivors;
            detail = format!(
                "e.g. run {run}: {survivors} of {SQUATTERS} password sign-ins that were in flight \
                 when the magic link claimed {email} still read /get-session as that user \
                 (emailVerified: true)"
            );
        }
    }
    let rate = format!(
        "{hit_runs}/{RUNS} runs left the first registrant signed in ({survivors_total} sessions; \
         one password check takes {hash_ms} ms here)"
    );
    if hit_runs > 0 {
        return Err(format!("{rate}; {detail}"));
    }
    Ok(rate)
}

// ------------------------------------------------------------------ RACE-2: organization limit

/// RACE-2. `Organization::organization_limit(n)` counts the user's memberships, then
/// inserts the new organization in a separate statement. Requests that create organizations
/// in parallel all pass the count, so a user ends up in more organizations than the limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sec_organization_limit_holds_under_parallel_creates() {
    on_every_backend!(
        "organization_limit(2) vs 8 parallel creates",
        false,
        org_limit
    );
}

async fn org_limit<D: Adapter>(app: App<D>) -> Outcome {
    const RUNS: usize = 5;
    let mut worst = 0;
    let mut hits = 0;
    for run in 0..RUNS {
        let mut owner = Browser::new(&app);
        let email = format!("limit{run}@acme.dk");
        owner.sign_up(&email).await;
        let tasks = (0..8)
            .map(|i| {
                owner.spawn(
                    "POST",
                    "/organization/create",
                    Some(json!({ "name": "Acme", "slug": format!("acme-{run}-{i}") })),
                    StdDuration::ZERO,
                )
            })
            .collect();
        join_all(tasks).await;
        let memberships = db(&app)
            .count::<Member>(Member::USER_ID.eq(user_id(&app, &email).await))
            .await
            .unwrap();
        worst = worst.max(memberships);
        if memberships > 2 {
            hits += 1;
        }
    }
    let rate =
        format!("{hits}/{RUNS} runs exceeded the limit of 2; worst run: {worst} organizations");
    if hits > 0 { Err(rate) } else { Ok(rate) }
}

// ------------------------------------------------------------------ RACE-3: duplicate membership

/// RACE-3. `member` has no unique (organization_id, user_id): invite-member checks for a
/// pending invitation, and accept-invitation checks for a membership, each with a read before
/// a separate insert. A double-submitted invitation followed by two accepts at once gives the
/// invitee two membership rows. Removing the member then deletes one row; the other keeps them
/// in the organization with the invited role.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sec_a_removed_member_is_not_left_in_the_organization_by_a_duplicate_row() {
    on_every_backend!(
        "one membership per user and organization",
        false,
        duplicate_membership
    );
}

async fn duplicate_membership<D: Adapter>(app: App<D>) -> Outcome {
    const RUNS: usize = 8;
    let (mut dup_invites, mut dup_members, mut survived) = (0, 0, 0);
    let mut detail = String::new();
    for run in 0..RUNS {
        let mut owner = Browser::new(&app);
        owner.sign_up(&format!("owner{run}@acme.dk")).await;
        let (status, org) = owner
            .post(
                "/organization/create",
                json!({ "name": "Acme", "slug": format!("dup-{run}") }),
            )
            .await;
        assert_eq!(status, 200, "{org}");
        let org_id = org["id"].as_str().unwrap().to_owned();
        let invitee = format!("bob{run}@acme.dk");
        let mut bob = Browser::new(&app);
        bob.sign_up(&invitee).await;
        mark_verified(&app, &invitee).await;

        // The owner's "Invite" button fires twice.
        let invite = json!({ "email": invitee, "role": "admin", "organizationId": org_id });
        let invites = join_all(
            (0..2)
                .map(|_| {
                    owner.spawn(
                        "POST",
                        "/organization/invite-member",
                        Some(invite.clone()),
                        StdDuration::ZERO,
                    )
                })
                .collect(),
        )
        .await;
        let ids: Vec<String> = invites
            .iter()
            .filter(|(status, _, _)| *status == 200)
            .map(|(_, json, _)| json["id"].as_str().unwrap().to_owned())
            .collect();
        if ids.len() > 1 {
            dup_invites += 1;
        }
        // Bob accepts every invitation he got, at once.
        let accepts = ids
            .iter()
            .map(|id| {
                bob.spawn(
                    "POST",
                    "/organization/accept-invitation",
                    Some(json!({ "invitationId": id })),
                    StdDuration::ZERO,
                )
            })
            .collect();
        join_all(accepts).await;
        let bob_id = user_id(&app, &invitee).await;
        let org = Id::from(org_id.as_str());
        let rows = db(&app)
            .find::<Member>(
                Member::ORGANIZATION_ID
                    .eq(&org)
                    .and(Member::USER_ID.eq(&bob_id)),
            )
            .all()
            .await
            .unwrap();
        if rows.len() > 1 {
            dup_members += 1;
            // The owner removes Bob.
            let (status, json) = owner
                .post(
                    "/organization/remove-member",
                    json!({ "memberIdOrEmail": rows[0].id.as_str(), "organizationId": org_id }),
                )
                .await;
            assert_eq!(status, 200, "{json}");
            let (status, json) = bob
                .post(
                    "/organization/set-active",
                    json!({ "organizationId": org_id }),
                )
                .await;
            if status == 200 {
                survived += 1;
                detail = format!(
                    "e.g. run {run}: 2 invitations, then {} membership rows for Bob; after \
                     remove-member Bob still set-active the organization: 200 {json}",
                    rows.len()
                );
            }
        }
    }
    let rate = format!(
        "{dup_invites}/{RUNS} double invites made two pending invitations, {dup_members}/{RUNS} \
         runs gave Bob two memberships, {survived}/{RUNS} left him in after remove-member"
    );
    if dup_members > 0 {
        Err(format!("{rate}; {detail}"))
    } else {
        Ok(rate)
    }
}

// ------------------------------------------------------------------ guards

/// Checked: sign-up of one address in several spellings at once makes one user, because
/// emails are trimmed and lowercased before the insert and `user.email` is unique.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn guard_parallel_sign_ups_make_one_user_per_email() {
    on_every_backend!(
        "parallel sign-ups, one email in 8 spellings",
        false,
        parallel_sign_up
    );
}

async fn parallel_sign_up<D: Adapter>(app: App<D>) -> Outcome {
    let spellings = [
        "Ada{}@Acme.dk",
        "ada{}@acme.dk",
        " ada{}@acme.dk",
        "ADA{}@ACME.DK",
        "ada{}@ACME.dk",
        "aDa{}@acme.dk ",
        "Ada{}@acme.DK",
        "ada{}@acme.dk",
    ];
    let mut results = Vec::new();
    for run in 0..5 {
        let browser = Browser::new(&app);
        let tasks = spellings
            .iter()
            .map(|e| {
                let email = e.replace("{}", &run.to_string());
                browser.spawn(
                    "POST",
                    "/sign-up/email",
                    Some(json!({ "email": email, "password": PASSWORD, "name": "Ada" })),
                    StdDuration::ZERO,
                )
            })
            .collect();
        let answers = join_all(tasks).await;
        let ok = answers.iter().filter(|a| a.0 == 200).count();
        let users = db(&app)
            .count::<User>(User::EMAIL.eq(format!("ada{run}@acme.dk")))
            .await
            .unwrap();
        if ok != 1 || users != 1 {
            return Err(format!(
                "run {run}: {ok} sign-ups answered 200, {users} users: {:?}",
                statuses(&answers)
            ));
        }
        results.push(statuses(&answers));
    }
    Ok(format!("5/5 runs: one user; answers {:?}", results[0]))
}

/// Checked: one username claimed by 8 sign-ups at once goes to one user (`user.username` is
/// unique; the losers get 422).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn guard_parallel_sign_ups_claim_a_username_once() {
    on_every_backend!(
        "one username, 8 parallel sign-ups",
        false,
        parallel_username
    );
}

async fn parallel_username<D: Adapter>(app: App<D>) -> Outcome {
    for run in 0..5 {
        let browser = Browser::new(&app);
        let tasks = (0..8)
            .map(|i| {
                browser.spawn(
                    "POST",
                    "/sign-up/email",
                    Some(json!({ "email": format!("u{run}x{i}@acme.dk"), "password": PASSWORD, "name": "U", "username": format!("Taken{run}") })),
                    StdDuration::ZERO,
                )
            })
            .collect();
        let answers = join_all(tasks).await;
        let ok = answers.iter().filter(|a| a.0 == 200).count();
        if ok != 1 {
            return Err(format!(
                "run {run}: {ok} sign-ups got the username: {:?}",
                statuses(&answers)
            ));
        }
    }
    Ok("5/5 runs: one owner".into())
}

/// Checked: a password-reset token redeemed 8 times at once works once
/// (`consume_verification` deletes the row and requires one deleted row).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn guard_a_reset_token_works_once_under_parallel_use() {
    on_every_backend!("reset token, 8 parallel redemptions", false, parallel_reset);
}

async fn parallel_reset<D: Adapter>(app: App<D>) -> Outcome {
    for run in 0..5 {
        let email = format!("reset{run}@acme.dk");
        let mut ada = Browser::new(&app);
        ada.sign_up(&email).await;
        ada.post("/request-password-reset", json!({ "email": email }))
            .await;
        let token = mail(&app, |m| match m {
            AuthEmail::ResetPassword(e) if e.to == email => Some(e.token.clone()),
            _ => None,
        })
        .await;
        let tasks = (0..8)
            .map(|i| {
                ada.spawn(
                    "POST",
                    "/reset-password",
                    Some(json!({ "token": token, "newPassword": format!("new password {i}!") })),
                    StdDuration::ZERO,
                )
            })
            .collect();
        let answers = join_all(tasks).await;
        let ok = answers.iter().filter(|a| a.0 == 200).count();
        if ok != 1 {
            return Err(format!(
                "run {run}: the token worked {ok} times: {:?}",
                statuses(&answers)
            ));
        }
    }
    Ok("5/5 runs: once".into())
}

/// Checked: one magic link opened 8 times at once signs in once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn guard_a_magic_link_signs_in_once_under_parallel_use() {
    on_every_backend!("magic link, 8 parallel clicks", false, parallel_magic_link);
}

async fn parallel_magic_link<D: Adapter>(app: App<D>) -> Outcome {
    for run in 0..5 {
        let email = format!("link{run}@acme.dk");
        let mut ada = Browser::new(&app);
        ada.post("/sign-in/magic-link", json!({ "email": email }))
            .await;
        let (url, _) = plugin_mail(&app, "magic-link", &email).await;
        let link = auth_path(&url.unwrap());
        let answers = join_all(
            (0..8)
                .map(|_| ada.spawn("GET", link.clone(), None, StdDuration::ZERO))
                .collect(),
        )
        .await;
        let mut signed_in = 0;
        for (_, _, mut b) in answers {
            if b.whoami().await.is_some() {
                signed_in += 1;
            }
        }
        if signed_in != 1 {
            return Err(format!(
                "run {run}: {signed_in} browsers signed in with one link"
            ));
        }
    }
    Ok("5/5 runs: once".into())
}

/// Checked: an email OTP sign-in code sent 8 times at once signs in once, and a burst of 30
/// wrong guesses compares at most `allowed_attempts` (3) of them: each guess claims an attempt
/// with a compare-and-swap before the comparison, and a guess that loses the swap answers
/// INVALID_OTP uncompared. So the right code may still work after the burst (only the counted
/// guesses were compared), but the stored counter never exceeds 3 and the code burns after
/// 3 compared guesses in total.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn guard_email_otp_is_single_use_and_its_attempt_limit_holds_in_parallel() {
    on_every_backend!(
        "email OTP single use and attempts",
        false,
        parallel_email_otp
    );
}

async fn parallel_email_otp<D: Adapter>(app: App<D>) -> Outcome {
    for run in 0..3 {
        let email = format!("otp{run}@acme.dk");
        let mut ada = Browser::new(&app);
        ada.post(
            "/email-otp/send-verification-otp",
            json!({ "email": email, "type": "sign-in" }),
        )
        .await;
        let (_, code) = plugin_mail(&app, "email-otp-sign-in", &email).await;
        let code = code.unwrap();
        let answers = join_all(
            (0..8)
                .map(|_| {
                    ada.spawn(
                        "POST",
                        "/sign-in/email-otp",
                        Some(json!({ "email": email, "otp": code })),
                        StdDuration::ZERO,
                    )
                })
                .collect(),
        )
        .await;
        let ok = answers.iter().filter(|a| a.0 == 200).count();
        if ok != 1 {
            return Err(format!(
                "run {run}: one code signed in {ok} times: {:?}",
                statuses(&answers)
            ));
        }

        let other = format!("guess{run}@acme.dk");
        ada.post(
            "/email-otp/send-verification-otp",
            json!({ "email": other, "type": "sign-in" }),
        )
        .await;
        let (_, code) = plugin_mail(&app, "email-otp-sign-in", &other).await;
        let code = code.unwrap();
        let wrong: Vec<String> = (0..30)
            .map(|i| format!("{:06}", (code.parse::<u32>().unwrap() + 1 + i) % 1_000_000))
            .collect();
        let answers = join_all(
            wrong
                .iter()
                .map(|w| {
                    ada.spawn(
                        "POST",
                        "/sign-in/email-otp",
                        Some(json!({ "email": other, "otp": w })),
                        StdDuration::ZERO,
                    )
                })
                .collect(),
        )
        .await;
        let identifier = format!("sign-in-otp-{other}");
        let compared: u32 = db(&app)
            .find::<Verification>(Verification::IDENTIFIER.eq(identifier.as_str()))
            .one()
            .await
            .unwrap()
            .and_then(|v| v.data)
            .map_or(3, |d| d.parse().unwrap());
        if compared > 3 {
            return Err(format!("run {run}: {compared} guesses were compared"));
        }
        for _ in compared..3 {
            ada.post(
                "/sign-in/email-otp",
                json!({ "email": other, "otp": "000000x" }),
            )
            .await;
        }
        let (status, json) = ada
            .post("/sign-in/email-otp", json!({ "email": other, "otp": code }))
            .await;
        if status == 200 {
            return Err(format!(
                "run {run}: the right code signed in after 3 compared wrong guesses ({compared} in the burst of 30: {:?})",
                statuses(&answers)
            ));
        }
        println!(
            "  run {run}: the burst of 30 compared {compared}, {:?}; right code afterwards: {status} {}",
            statuses(&answers),
            json["code"]
        );
    }
    Ok("3/3 runs: one sign-in per code; never more than 3 guesses compared".into())
}

fn base32_decode(input: &str) -> Vec<u8> {
    let mut bits = 0u64;
    let mut count = 0;
    let mut out = Vec::new();
    for c in input.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("not base32: {c}"),
        };
        bits = (bits << 5) | u64::from(v);
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    out
}

/// A user with two-factor on, and 8 browsers each holding a pending sign-in (password done).
async fn two_factor_pending<D: Adapter>(
    app: &App<D>,
    email: &str,
) -> (Vec<u8>, Vec<String>, Vec<Browser<D>>) {
    let mut ada = Browser::new(app);
    ada.sign_up(email).await;
    let (status, enabled) = ada
        .post("/two-factor/enable", json!({ "password": PASSWORD }))
        .await;
    assert_eq!(status, 200, "{enabled}");
    let uri = enabled["totpURI"].as_str().unwrap();
    let secret = base32_decode(
        uri.split(['?', '&'])
            .find_map(|p| p.strip_prefix("secret="))
            .unwrap(),
    );
    let codes = serde_json::from_value(enabled["backupCodes"].clone()).unwrap();
    let mut pending = Vec::new();
    for _ in 0..8 {
        let mut b = Browser::new(app);
        let (_, json) = b
            .post(
                "/sign-in/email",
                json!({ "email": email, "password": PASSWORD }),
            )
            .await;
        assert_eq!(json["twoFactorRedirect"], true, "{json}");
        pending.push(b);
    }
    (secret, codes, pending)
}

/// Checked: one backup code, and one TOTP code, used by 8 pending sign-ins at once finish one
/// of them (compare-and-swap on `two_factor.backup_codes` and on `last_used_step`).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn guard_backup_and_totp_codes_are_single_use_in_parallel() {
    on_every_backend!(
        "2FA backup code and TOTP replay",
        false,
        parallel_two_factor
    );
}

async fn parallel_two_factor<D: Adapter>(app: App<D>) -> Outcome {
    for run in 0..3 {
        let (_, codes, pending) = two_factor_pending(&app, &format!("tf{run}@acme.dk")).await;
        let answers = join_all(
            pending
                .iter()
                .map(|b| {
                    b.spawn(
                        "POST",
                        "/two-factor/verify-backup-code",
                        Some(json!({ "code": codes[0] })),
                        StdDuration::ZERO,
                    )
                })
                .collect(),
        )
        .await;
        let ok = answers.iter().filter(|a| a.0 == 200).count();
        if ok != 1 {
            return Err(format!(
                "run {run}: one backup code finished {ok} sign-ins: {:?}",
                statuses(&answers)
            ));
        }
        let (secret, _, pending) = two_factor_pending(&app, &format!("tt{run}@acme.dk")).await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = totp::totp(&secret, now, 30, 6);
        let answers = join_all(
            pending
                .iter()
                .map(|b| {
                    b.spawn(
                        "POST",
                        "/two-factor/verify-totp",
                        Some(json!({ "code": code })),
                        StdDuration::ZERO,
                    )
                })
                .collect(),
        )
        .await;
        let ok = answers.iter().filter(|a| a.0 == 200).count();
        if ok != 1 {
            return Err(format!(
                "run {run}: one TOTP code finished {ok} sign-ins: {:?}",
                statuses(&answers)
            ));
        }
    }
    Ok("3/3 runs: one backup code and one TOTP code each finished exactly one sign-in".into())
}

/// Checked: 40 wrong two-factor email codes sent at once from one pending sign-in can't be
/// followed by the right one (the guess counter is a compare-and-swap that retries, FAST-31
/// 2FA-1 fix), on every backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn guard_two_factor_otp_attempt_limit_holds_in_parallel() {
    on_every_backend!(
        "2FA email OTP, 40 parallel wrong guesses",
        false,
        parallel_two_factor_otp
    );
}

async fn parallel_two_factor_otp<D: Adapter>(app: App<D>) -> Outcome {
    for run in 0..3 {
        let email = format!("tfo{run}@acme.dk");
        let (_, _, pending) = two_factor_pending(&app, &email).await;
        let mut b = pending[0].clone();
        let (status, json) = b.post("/two-factor/send-otp", json!({})).await;
        assert_eq!(status, 200, "{json}");
        let (_, code) = plugin_mail(&app, "two-factor-otp", &email).await;
        let code = code.unwrap();
        let wrong: Vec<String> = (0..40)
            .map(|i| format!("{:06}", (code.parse::<u32>().unwrap() + 1 + i) % 1_000_000))
            .collect();
        let answers = join_all(
            wrong
                .iter()
                .map(|w| {
                    b.spawn(
                        "POST",
                        "/two-factor/verify-otp",
                        Some(json!({ "code": w })),
                        StdDuration::ZERO,
                    )
                })
                .collect(),
        )
        .await;
        let (status, _) = b
            .post("/two-factor/verify-otp", json!({ "code": code }))
            .await;
        if status == 200 {
            return Err(format!(
                "run {run}: the right code signed in after 40 parallel wrong guesses {:?}",
                statuses(&answers)
            ));
        }
    }
    Ok("3/3 runs: refused after the burst".into())
}

/// Checked: an invitation accepted 8 times at once makes one membership (status
/// compare-and-swap `pending -> accepted`).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn guard_an_invitation_is_accepted_once_in_parallel() {
    on_every_backend!("one invitation, 8 parallel accepts", false, parallel_accept);
}

async fn parallel_accept<D: Adapter>(app: App<D>) -> Outcome {
    for run in 0..5 {
        let mut owner = Browser::new(&app);
        owner.sign_up(&format!("io{run}@acme.dk")).await;
        let (_, org) = owner
            .post(
                "/organization/create",
                json!({ "name": "Acme", "slug": format!("acc-{run}") }),
            )
            .await;
        let org_id = org["id"].as_str().unwrap().to_owned();
        let invitee = format!("ib{run}@acme.dk");
        let (_, invitation) = owner
            .post(
                "/organization/invite-member",
                json!({ "email": invitee, "role": "member", "organizationId": org_id }),
            )
            .await;
        let mut bob = Browser::new(&app);
        bob.sign_up(&invitee).await;
        mark_verified(&app, &invitee).await;
        let body = json!({ "invitationId": invitation["id"] });
        let answers = join_all(
            (0..8)
                .map(|_| {
                    bob.spawn(
                        "POST",
                        "/organization/accept-invitation",
                        Some(body.clone()),
                        StdDuration::ZERO,
                    )
                })
                .collect(),
        )
        .await;
        let rows = db(&app)
            .count::<Member>(Member::USER_ID.eq(user_id(&app, &invitee).await))
            .await
            .unwrap();
        let ok = answers.iter().filter(|a| a.0 == 200).count();
        if ok != 1 || rows != 1 {
            return Err(format!(
                "run {run}: {ok} accepts answered 200, {rows} memberships: {:?}",
                statuses(&answers)
            ));
        }
        let status = db(&app)
            .find::<Invitation>(Invitation::ID.eq(Id::from(invitation["id"].as_str().unwrap())))
            .one()
            .await
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, InvitationStatus::Accepted);
    }
    Ok("5/5 runs: one membership".into())
}

/// Checked: the last two owners leaving at once keep an owner on every backend (the FAST-31
/// AUTHZ-8 fix: each request re-checks after its own delete and puts its row back).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn guard_two_owners_leaving_at_once_keep_an_owner() {
    on_every_backend!("last two owners leave at once", false, owners_leave);
}

async fn owners_leave<D: Adapter>(app: App<D>) -> Outcome {
    const RUNS: usize = 10;
    for run in 0..RUNS {
        let mut a = Browser::new(&app);
        a.sign_up(&format!("oa{run}@acme.dk")).await;
        let (_, org) = a
            .post(
                "/organization/create",
                json!({ "name": "Acme", "slug": format!("own-{run}") }),
            )
            .await;
        let org_id = org["id"].as_str().unwrap().to_owned();
        let b_email = format!("ob{run}@acme.dk");
        let (_, invitation) = a
            .post(
                "/organization/invite-member",
                json!({ "email": b_email, "role": "owner", "organizationId": org_id }),
            )
            .await;
        let mut b = Browser::new(&app);
        b.sign_up(&b_email).await;
        mark_verified(&app, &b_email).await;
        let (status, json) = b
            .post(
                "/organization/accept-invitation",
                json!({ "invitationId": invitation["id"] }),
            )
            .await;
        assert_eq!(status, 200, "{json}");
        let body = json!({ "organizationId": org_id });
        let answers = join_all(vec![
            a.spawn(
                "POST",
                "/organization/leave",
                Some(body.clone()),
                StdDuration::ZERO,
            ),
            b.spawn(
                "POST",
                "/organization/leave",
                Some(body.clone()),
                StdDuration::ZERO,
            ),
        ])
        .await;
        let owners = db(&app)
            .find::<Member>(Member::ORGANIZATION_ID.eq(Id::from(org_id.as_str())))
            .all()
            .await
            .unwrap()
            .iter()
            .filter(|m| m.has_role("owner"))
            .count();
        if owners == 0 {
            return Err(format!(
                "run {run}: no owner left after {:?}",
                statuses(&answers)
            ));
        }
    }
    Ok(format!("{RUNS}/{RUNS} runs kept an owner"))
}

/// Checked: an API key with `remaining: 5` verified 40 times at once is valid 5 times, and
/// one with a rate limit of 3 per minute 3 times (one compare-and-swap over the four usage
/// columns, retried on a lost race).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn guard_api_key_usage_and_rate_limit_hold_in_parallel() {
    on_every_backend!(
        "API key remaining=5 and rate limit 3/min, 40 parallel verifies",
        false,
        parallel_api_key
    );
}

async fn parallel_api_key<D: Adapter>(app: App<D>) -> Outcome {
    let email = "keys@acme.dk";
    Browser::new(&app).sign_up(email).await;
    let owner = user_id(&app, email).await;
    let mut notes = Vec::new();
    for (label, input, expected) in [
        (
            "remaining=5",
            CreateApiKeyInput {
                remaining: Some(5),
                rate_limit_enabled: Some(false),
                ..Default::default()
            },
            5,
        ),
        (
            "rate limit 3/60s",
            CreateApiKeyInput {
                rate_limit_enabled: Some(true),
                rate_limit_max: Some(3),
                rate_limit_time_window: Some(60_000),
                ..Default::default()
            },
            3,
        ),
    ] {
        let created = app
            .auth
            .api_keys()
            .create(CreateApiKeyInput {
                user_id: Some(owner.clone()),
                ..input
            })
            .await
            .unwrap();
        let tasks: Vec<_> = (0..40)
            .map(|_| {
                let auth = app.auth.clone();
                let key = created.key.clone();
                tokio::spawn(async move { auth.api_keys().verify(&key, None).await.unwrap() })
            })
            .collect();
        let mut valid = 0;
        let mut errors = BTreeMap::<String, usize>::new();
        for task in tasks {
            let out = task.await.unwrap();
            if out.valid {
                valid += 1;
            } else {
                *errors
                    .entry(out.error.unwrap().code.to_string())
                    .or_default() += 1;
            }
        }
        if valid != expected {
            return Err(format!(
                "{label}: {valid} of 40 verifies were valid (expected {expected}); refusals {errors:?}"
            ));
        }
        notes.push(format!("{label}: {valid} valid, refusals {errors:?}"));
    }
    Ok(notes.join("; "))
}

// ------------------------------------------------------------------ RACE-4: two-factor enable

/// RACE-4. `two_factor.user_id` isn't unique and `/two-factor/enable` deletes the user's row, then
/// inserts a new one, in separate statements. Two enables at once (a double-clicked button)
/// leave two rows with different secrets and backup codes. Every later lookup takes whichever
/// row the database returns first, so the QR code and backup codes the user saved may belong
/// to the other row: with `skip_verification_on_enable(true)` the user is locked out of their
/// own account at the next sign-in.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sec_two_factor_enable_keeps_one_secret_per_user() {
    on_every_backend!(
        "one two_factor row per user, 2 parallel enables",
        false,
        double_enable
    );
}

async fn double_enable<D: Adapter>(app: App<D>) -> Outcome {
    const RUNS: usize = 10;
    let (mut dup, mut locked_out) = (0, 0);
    let mut detail = String::new();
    for run in 0..RUNS {
        let email = format!("de{run}@acme.dk");
        let mut ada = Browser::new(&app);
        ada.sign_up(&email).await;
        let body = json!({ "password": PASSWORD });
        let answers = join_all(vec![
            ada.spawn(
                "POST",
                "/two-factor/enable",
                Some(body.clone()),
                StdDuration::ZERO,
            ),
            ada.spawn(
                "POST",
                "/two-factor/enable",
                Some(body.clone()),
                StdDuration::ZERO,
            ),
        ])
        .await;
        let rows = db(&app)
            .count::<TwoFactorRow>(TwoFactorRow::USER_ID.eq(user_id(&app, &email).await))
            .await
            .unwrap();
        if rows < 2 {
            continue;
        }
        dup += 1;
        // The page shows the answer that arrived last; the user saves that secret.
        let (_, shown, _) = answers.iter().rev().find(|a| a.0 == 200).unwrap();
        let uri = shown["totpURI"].as_str().unwrap();
        let secret = base32_decode(
            uri.split(['?', '&'])
                .find_map(|p| p.strip_prefix("secret="))
                .unwrap(),
        );
        let backup: Vec<String> = serde_json::from_value(shown["backupCodes"].clone()).unwrap();
        let mut again = Browser::new(&app);
        let (_, json) = again
            .post(
                "/sign-in/email",
                json!({ "email": email, "password": PASSWORD }),
            )
            .await;
        assert_eq!(json["twoFactorRedirect"], true, "{json}");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (totp_status, _) = again
            .post(
                "/two-factor/verify-totp",
                json!({ "code": totp::totp(&secret, now, 30, 6) }),
            )
            .await;
        let (backup_status, _) = again
            .post(
                "/two-factor/verify-backup-code",
                json!({ "code": backup[0] }),
            )
            .await;
        if totp_status != 200 && backup_status != 200 {
            locked_out += 1;
            detail = format!(
                "e.g. run {run}: {rows} two_factor rows; the saved TOTP answered {totp_status} and the saved backup code {backup_status}"
            );
        }
    }
    let rate = format!(
        "{dup}/{RUNS} runs left two two_factor rows, {locked_out}/{RUNS} locked the user out"
    );
    if dup > 0 {
        Err(format!("{rate}; {detail}"))
    } else {
        Ok(rate)
    }
}

// ------------------------------------------------------------------ DB-2: long keys on MySQL

/// DB-2. Organization slugs and invitation emails have no length limit, and on MySQL they are
/// `varchar(768)` key columns. A longer one answers 500 on MySQL (strict mode: "Data too
/// long") where Postgres and SQLite accept it. Anyone who may create an organization or invite
/// can trigger it; under a non-strict sql_mode the value is cut to 768 characters instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sec_long_slugs_and_invitation_emails_get_a_client_error_not_a_500() {
    on_every_backend!("1000-character slug and invitation email", false, long_keys);
}

async fn long_keys<D: Adapter>(app: App<D>) -> Outcome {
    let mut owner = Browser::new(&app);
    owner.sign_up("longkeys@acme.dk").await;
    let slug = "s".repeat(1000);
    let (status, json) = owner
        .post(
            "/organization/create",
            json!({ "name": "Acme", "slug": slug }),
        )
        .await;
    let mut seen = vec![format!(
        "create with a 1000-char slug: {status} {}",
        json["code"]
    )];
    let mut server_errors = usize::from(status >= 500);
    let (_, org) = owner
        .post(
            "/organization/create",
            json!({ "name": "Acme", "slug": "short-slug" }),
        )
        .await;
    let email = format!("{}@acme.dk", "e".repeat(1000));
    let (status, json) = owner
        .post(
            "/organization/invite-member",
            json!({ "email": email, "role": "member", "organizationId": org["id"] }),
        )
        .await;
    seen.push(format!(
        "invite a 1008-char email: {status} {}",
        json["code"]
    ));
    server_errors += usize::from(status >= 500);
    if server_errors > 0 {
        Err(seen.join("; "))
    } else {
        Ok(seen.join("; "))
    }
}
