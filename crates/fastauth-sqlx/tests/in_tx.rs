//! Server API calls joining the app's transaction: `auth.api().in_tx(&tx)`.

use std::sync::{Arc, Mutex};

use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::endpoint::After;
use fastauth_core::error::codes;
use fastauth_core::prelude::*;
use fastauth_core::query::{Db, Where};
use fastauth_core::routes::{
    CreateUserInput, SignInEmailInput, SignInOutput, SignUpEmail, SignUpEmailInput,
};
use fastauth_core::value::ColumnValue as _;
use fastauth_sqlx::sqlx::{self, AssertSqlSafe, Executor, Pool};
use fastauth_sqlx::{Dialect, InTx, SharedTx, Sqlx};
use http::StatusCode;

/// The app's own table, written with plain sqlx on the shared transaction.
trait AppDb: Dialect + Sized {
    async fn create_members(pool: &Pool<Self>);
    async fn insert_member(tx: &SharedTx<Self>, user_id: &str) -> Result<(), sqlx::Error>;
    async fn members(pool: &Pool<Self>) -> i64;
}

const MEMBERS: &str = "create table team_member (team_id integer not null, user_id text not null)";

#[cfg(feature = "sqlite")]
impl AppDb for fastauth_sqlx::Sqlite {
    async fn create_members(pool: &Pool<Self>) {
        pool.execute(MEMBERS).await.unwrap();
    }

    async fn insert_member(tx: &SharedTx<Self>, user_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("insert into team_member (team_id, user_id) values (?, ?)")
            .bind(1)
            .bind(user_id)
            .execute(&mut **tx.lock().await)
            .await
            .map(drop)
    }

    async fn members(pool: &Pool<Self>) -> i64 {
        sqlx::query_scalar("select count(*) from team_member")
            .fetch_one(pool)
            .await
            .unwrap()
    }
}

#[cfg(feature = "postgres")]
impl AppDb for fastauth_sqlx::Postgres {
    async fn create_members(pool: &Pool<Self>) {
        pool.execute(MEMBERS).await.unwrap();
    }

    async fn insert_member(tx: &SharedTx<Self>, user_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("insert into team_member (team_id, user_id) values ($1, $2)")
            .bind(1)
            .bind(user_id)
            .execute(&mut **tx.lock().await)
            .await
            .map(drop)
    }

    async fn members(pool: &Pool<Self>) -> i64 {
        sqlx::query_scalar("select count(*) from team_member")
            .fetch_one(pool)
            .await
            .unwrap()
    }
}

/// Emails of `UserCreated` events, with whether the handler could read the user back.
type Fired = Arc<Mutex<Vec<(String, bool)>>>;

struct Fixture<DB: Dialect> {
    auth: Auth<Sqlx<DB>>,
    pool: Pool<DB>,
    fired: Fired,
}

impl<DB: AppDb> Fixture<DB> {
    async fn new(pool: Pool<DB>) -> Self {
        let fired = Fired::default();
        let on_created = fired.clone();
        let auth = FastAuth::builder()
            .secret(Secret::from_bytes(vec![42u8; 32]))
            .base_url("http://localhost:3000")
            .database(Sqlx::new(pool.clone()))
            .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
            .rate_limit(RateLimit::disabled())
            .on(move |event: UserCreated, ctx| {
                let fired = on_created.clone();
                async move {
                    let found = ctx.internal().find_user_by_email(&event.email).await?;
                    fired.lock().unwrap().push((event.email, found.is_some()));
                    Ok(())
                }
            })
            .configure(|app| {
                // Sign-up as "Broken" fails after writing the user, account and session, with
                // a database error (a second user with the same email).
                app.hook::<SignUpEmail>().after(|ctx, output| async move {
                    if output.user.get("name").and_then(|n| n.as_str()) != Some("Broken") {
                        return Ok(After::Continue(output));
                    }
                    let email = output.user["email"].as_str().unwrap_or_default().to_owned();
                    ctx.db()
                        .insert_row::<User>(vec![
                            ("id", Id::new_v7().into_value()),
                            ("email", email.into_value()),
                            ("name", "Twin".to_owned().into_value()),
                        ])
                        .await?;
                    Ok(After::Continue(output))
                });
            })
            .build()
            .expect("valid config");
        auth.migrator().run().await.expect("migrate");
        DB::create_members(&pool).await;
        Self { auth, pool, fired }
    }

    async fn rows(&self) -> (u64, u64, u64, i64) {
        let db = Db::new(self.auth.adapter(), self.auth.schema());
        (
            db.count::<User>(Where::all()).await.unwrap(),
            db.count::<Account>(Where::all()).await.unwrap(),
            db.count::<Session>(Where::all()).await.unwrap(),
            DB::members(&self.pool).await,
        )
    }

    fn fired(&self) -> Vec<(String, bool)> {
        self.fired.lock().unwrap().clone()
    }

    async fn begin(&self) -> SharedTx<DB> {
        SharedTx::new(self.pool.begin().await.unwrap())
    }

    async fn create_user(&self, tx: &SharedTx<DB>, email: &str) -> Result<String, AuthError> {
        let user = self
            .auth
            .api()
            .in_tx(tx)
            .create_user(CreateUserInput {
                email: email.into(),
                name: "Lasse".into(),
                password: Some("correct horse".into()),
                ..Default::default()
            })
            .await?;
        Ok(user.id.as_str().to_owned())
    }
}

/// (a) The user, its account and the app's row all disappear with a rollback.
async fn rollback_discards_everything<DB: AppDb>(pool: Pool<DB>) {
    let f = Fixture::new(pool).await;
    let tx = f.begin().await;
    let id = f.create_user(&tx, "lasse@acme.dk").await.unwrap();
    DB::insert_member(&tx, &id).await.unwrap();
    tx.rollback().await.unwrap();

    assert_eq!(f.rows().await, (0, 0, 0, 0));
    assert_eq!(f.fired(), []);
}

/// (b) Commit keeps both, and `UserCreated` fires after the commit, not before.
async fn commit_keeps_everything_and_fires_after<DB: AppDb>(pool: Pool<DB>) {
    let f = Fixture::new(pool).await;
    let tx = f.begin().await;
    let id = f.create_user(&tx, "Lasse@Acme.dk").await.unwrap();
    DB::insert_member(&tx, &id).await.unwrap();
    assert_eq!(f.fired(), [], "events wait for the commit");
    tx.commit().await.unwrap();

    assert_eq!(f.rows().await, (1, 1, 0, 1));
    assert_eq!(f.fired(), [("lasse@acme.dk".to_owned(), true)]);
}

/// (c) A duplicate email fails the call with 422 and leaves the app's transaction usable:
/// only the failed call's savepoint rolls back.
async fn duplicate_email_leaves_tx_usable<DB: AppDb>(pool: Pool<DB>) {
    let f = Fixture::new(pool).await;
    let tx = f.begin().await;
    let id = f.create_user(&tx, "lasse@acme.dk").await.unwrap();
    DB::insert_member(&tx, &id).await.unwrap();

    let err = f.create_user(&tx, "LASSE@acme.dk").await.unwrap_err();
    assert_eq!(err.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(err.code(), codes::USER_ALREADY_EXISTS);

    DB::insert_member(&tx, &id).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(f.rows().await, (1, 1, 0, 2));
    assert_eq!(f.fired(), [("lasse@acme.dk".to_owned(), true)]);
}

/// A call that fails after several writes, on a database error, rolls back only its own
/// writes: the earlier call's user and the app's rows survive, and the tx stays usable.
async fn failed_call_leaves_tx_as_it_was<DB: AppDb>(pool: Pool<DB>) {
    let f = Fixture::new(pool).await;
    let tx = f.begin().await;
    let id = f.create_user(&tx, "lasse@acme.dk").await.unwrap();
    DB::insert_member(&tx, &id).await.unwrap();

    let err = f
        .auth
        .api()
        .in_tx(&tx)
        .sign_up_email(SignUpEmailInput {
            name: "Broken".into(),
            email: "broken@acme.dk".into(),
            password: "correct horse".into(),
            image: None,
            callback_url: None,
            remember_me: None,
            extra: Default::default(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);

    DB::insert_member(&tx, &id).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(f.rows().await, (1, 1, 0, 2));
    assert_eq!(f.fired(), [("lasse@acme.dk".to_owned(), true)]);
}

/// Sign-in and the session lookup of a later call run on the tx too, and the session
/// commits with it.
async fn session_calls_run_on_the_tx<DB: AppDb>(pool: Pool<DB>) {
    let f = Fixture::new(pool).await;
    let tx = f.begin().await;
    f.create_user(&tx, "lasse@acme.dk").await.unwrap();
    let signed_in = f
        .auth
        .api()
        .in_tx(&tx)
        .sign_in_email(SignInEmailInput {
            email: "lasse@acme.dk".into(),
            password: "correct horse".into(),
            remember_me: None,
            callback_url: None,
        })
        .await
        .unwrap();
    let SignInOutput::SignedIn { token, .. } = signed_in.data else {
        panic!("no session");
    };
    let sessions = f
        .auth
        .api()
        .in_tx(&tx)
        .session_token(&token)
        .list_sessions()
        .await
        .unwrap();
    assert_eq!(sessions.data.len(), 1);
    tx.commit().await.unwrap();
    assert_eq!(f.rows().await, (1, 1, 1, 0));
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use fastauth_sqlx::SqlitePool;

    async fn pool() -> SqlitePool {
        SqlitePool::connect("sqlite::memory:")
            .await
            .expect("in-memory SQLite")
    }

    #[tokio::test]
    async fn rollback_discards_everything() {
        super::rollback_discards_everything(pool().await).await;
    }

    #[tokio::test]
    async fn commit_keeps_everything_and_fires_after() {
        super::commit_keeps_everything_and_fires_after(pool().await).await;
    }

    #[tokio::test]
    async fn duplicate_email_leaves_tx_usable() {
        super::duplicate_email_leaves_tx_usable(pool().await).await;
    }

    #[tokio::test]
    async fn failed_call_leaves_tx_as_it_was() {
        super::failed_call_leaves_tx_as_it_was(pool().await).await;
    }

    #[tokio::test]
    async fn session_calls_run_on_the_tx() {
        super::session_calls_run_on_the_tx(pool().await).await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use fastauth_core::value::Id;
    use fastauth_sqlx::PgPool;
    use fastauth_sqlx::sqlx::postgres::PgPoolOptions;

    use super::{AssertSqlSafe, Executor};

    /// Runs `test` on a pool whose `search_path` is a fresh schema, then drops the schema.
    /// Skipped without `DATABASE_URL`.
    async fn with_schema<F: Future<Output = ()>>(test: impl FnOnce(PgPool) -> F) {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("DATABASE_URL is not set; skipping the Postgres test");
            return;
        };
        let admin = PgPool::connect(&url)
            .await
            .expect("connect to DATABASE_URL");
        let schema = format!("fastauth_tx_{}", Id::new_v7().as_str().replace('-', ""));
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
        test(pool.clone()).await;
        pool.close().await;
        admin
            .execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rollback_discards_everything() {
        with_schema(super::rollback_discards_everything).await;
    }

    #[tokio::test]
    async fn commit_keeps_everything_and_fires_after() {
        with_schema(super::commit_keeps_everything_and_fires_after).await;
    }

    #[tokio::test]
    async fn duplicate_email_leaves_tx_usable() {
        with_schema(super::duplicate_email_leaves_tx_usable).await;
    }

    #[tokio::test]
    async fn failed_call_leaves_tx_as_it_was() {
        with_schema(super::failed_call_leaves_tx_as_it_was).await;
    }

    #[tokio::test]
    async fn session_calls_run_on_the_tx() {
        with_schema(super::session_calls_run_on_the_tx).await;
    }
}
