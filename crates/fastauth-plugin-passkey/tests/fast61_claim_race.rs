//! FAST-61 review of the 0.6.0 claim model (#48): a passkey registration that a squatter has
//! in flight when the owner proves the email. /passkey/verify-registration checks the session
//! (`registering_session`, a fresh database read), verifies the attestation and then inserts the
//! passkey and, with `createSession: true`, creates a session through `create_session`, which
//! skips the security-stamp check. A claim that commits between the session check and the
//! insert leaves the squatter's passkey (and a new session) on the claimed, verified account.
//!
//! The interleaving is forced: an adapter wrapper stops the insert into `passkey` until the
//! claim (a password reset) has committed.
//!
//! Run: cargo test -p fastauth-plugin-passkey --test fast61_claim_race -- --nocapture
mod common;

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration as StdDuration;

use common::authenticator::Authenticator;
use common::{Client, ORIGIN, secret};
use fastauth_core::adapter::{
    Adapter, DbResult, Delete, Insert, Queries, Select, SessionWithUser, Update,
};
use fastauth_core::crypto::Argon2id;
use fastauth_core::mail::{AuthEmail, MemoryMailer};
use fastauth_core::migrate::{LiveSchema, MigrationPlan};
use fastauth_core::prelude::*;
use fastauth_core::query::Where;
use fastauth_core::value::Row;
use fastauth_plugin_passkey::{Passkey, PasskeyRow};
use fastauth_sqlx::Sqlx;
use fastauth_sqlx::sqlx::sqlite::SqlitePoolOptions;
use http::StatusCode;
use serde_json::json;

const ADA: &str = "ada@acme.dk";

#[derive(Clone, Default)]
struct Gate(Arc<(AtomicBool, AtomicBool, AtomicBool)>);

impl Gate {
    fn arm(&self) {
        self.0.0.store(true, Ordering::SeqCst);
    }

    async fn pass(&self) {
        if self.0.0.swap(false, Ordering::SeqCst) {
            self.0.1.store(true, Ordering::SeqCst);
            while !self.0.2.load(Ordering::SeqCst) {
                tokio::time::sleep(StdDuration::from_millis(1)).await;
            }
        }
    }

    async fn wait_reached(&self) {
        for _ in 0..5000 {
            if self.0.1.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(StdDuration::from_millis(2)).await;
        }
        panic!("the gated request never reached the gate");
    }

    fn release(&self) {
        self.0.2.store(true, Ordering::SeqCst);
    }
}

/// Stops a non-transactional insert into `passkey`, or the first transaction that begins after
/// `arm` (the one a registration writes its passkey in), at the gate.
struct GatedDb<D> {
    inner: D,
    gate: Gate,
}

impl<D: Adapter> Queries for GatedDb<D> {
    async fn insert(&self, q: Insert<'_>) -> DbResult<Row> {
        if q.table.name == "passkey" {
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

/// F61-4: a passkey registered with `createSession: true` while the owner's claim runs keeps
/// both the passkey and a new session on the claimed account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_passkey_registered_during_a_claim_does_not_survive_it() {
    let dir = tempfile_dir();
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect(&format!("sqlite://{dir}/fast61.db?mode=rwc"))
        .await
        .expect("SQLite file");
    let gate = Gate::default();
    let mail = MemoryMailer::new();
    let auth: Auth<GatedDb<Sqlx<_>>, (), plugins![Passkey]> = FastAuth::builder()
        .secret(secret())
        .base_url(ORIGIN)
        .database(GatedDb {
            inner: Sqlx::new(pool),
            gate: gate.clone(),
        })
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .email_verification(EmailVerification::default().send_on_sign_up(false))
        .rate_limit(RateLimit::disabled())
        .mailer(mail.clone())
        .plugin(Passkey::new())
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");

    let mut mallory = Client::new(auth.clone());
    assert_eq!(mallory.sign_up(ADA).await.status, StatusCode::OK);
    let options = mallory.get("/passkey/generate-register-options").await;
    assert_eq!(options.status, StatusCode::OK, "{}", options.json);
    let mut key = Authenticator::new();
    let response = key.create(&options.json, ORIGIN).expect("registers");
    gate.arm();
    let register = tokio::spawn(async move {
        mallory
            .post(
                "/passkey/verify-registration",
                json!({ "response": response, "createSession": true }),
            )
            .await
    });
    gate.wait_reached().await;

    let mut ada = Client::new(auth.clone());
    let asked = ada
        .post("/request-password-reset", json!({ "email": ADA }))
        .await;
    assert_eq!(asked.status, StatusCode::OK, "{}", asked.json);
    let mut token = None;
    for _ in 0..1000 {
        token = mail.sent().into_iter().find_map(|email| match email {
            AuthEmail::ResetPassword(e) if e.to == ADA => Some(e.token),
            _ => None,
        });
        if token.is_some() {
            break;
        }
        tokio::time::sleep(StdDuration::from_millis(5)).await;
    }
    let reset = ada
        .post(
            "/reset-password",
            json!({ "token": token.expect("a reset email"), "newPassword": "ada picked this" }),
        )
        .await;
    assert_eq!(reset.status, StatusCode::OK, "{}", reset.json);
    gate.release();
    let registered = register.await.unwrap();
    println!(
        "verify-registration answered {} {}",
        registered.status, registered.json
    );

    let passkeys = auth
        .api()
        .db()
        .find::<PasskeyRow>(Where::all())
        .all()
        .await
        .unwrap()
        .len();
    let mut phone = Client::new(auth.clone());
    let signed_in = phone.sign_in_with_passkey(&mut key).await;
    let session_back = !registered.json["session"].is_null();
    assert!(
        passkeys == 0 && signed_in.status != StatusCode::OK && !session_back,
        "after Ada's reset claimed the account, Mallory's in-flight registration left \
         {passkeys} passkey(s), returned a session: {session_back}, and her passkey signs in \
         with {} as {} (emailVerified={})",
        signed_in.status,
        signed_in.json["user"]["email"],
        signed_in.json["user"]["emailVerified"]
    );
}

fn tempfile_dir() -> String {
    let dir = std::env::temp_dir().join(format!("fast61-passkey-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let _ = std::fs::remove_file(dir.join("fast61.db"));
    dir.display().to_string()
}
