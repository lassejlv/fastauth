//! Sharing an app's sqlx transaction with fastauth server API calls.
//! See `docs/04-sessions.md`.

use std::sync::Arc;

use fastauth_core::Api;
use fastauth_core::adapter::{DbError, DbResult};
use fastauth_core::events::DeferredEvents;
use sqlx_core::transaction::TransactionManager;
use tokio::sync::{Mutex, MutexGuard};

use crate::{Dialect, SharedConn, Sqlx};

/// An app's sqlx transaction that fastauth server API calls can join with [`InTx::in_tx`].
/// The rows those calls write commit or roll back with the app's own, and their events
/// fire after [`commit`](Self::commit), never on rollback.
///
/// ```no_run
/// # async fn run(auth: fastauth_core::Auth<fastauth_sqlx::Sqlx<fastauth_sqlx::Sqlite>>, pool: fastauth_sqlx::SqlitePool) -> Result<(), Box<dyn std::error::Error>> {
/// use fastauth_core::routes::CreateUserInput;
/// use fastauth_sqlx::{InTx, SharedTx};
///
/// let tx = SharedTx::new(pool.begin().await?);
/// let user = auth
///     .api()
///     .in_tx(&tx)
///     .create_user(CreateUserInput {
///         email: "lasse@acme.dk".into(),
///         name: "Lasse".into(),
///         ..Default::default()
///     })
///     .await?;
/// fastauth_sqlx::sqlx::query("insert into team_member (team_id, user_id) values (?, ?)")
///     .bind(1)
///     .bind(user.id.as_str())
///     .execute(&mut **tx.lock().await)
///     .await?;
/// tx.commit().await?; // UserCreated fires here
/// # Ok(())
/// # }
/// ```
pub struct SharedTx<DB: Dialect> {
    tx: SharedConn<DB>,
    events: DeferredEvents,
}

impl<DB: Dialect> std::fmt::Debug for SharedTx<DB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedTx")
            .field("events", &self.events)
            .finish_non_exhaustive()
    }
}

impl<DB: Dialect> SharedTx<DB> {
    pub fn new(tx: sqlx::Transaction<'static, DB>) -> Self {
        Self {
            tx: Arc::new(Mutex::new(tx)),
            events: DeferredEvents::default(),
        }
    }

    /// The transaction, for the app's own queries: `.execute(&mut **tx.lock().await)`.
    /// Don't hold the guard across a fastauth call; the call waits for it.
    pub async fn lock(&self) -> MutexGuard<'_, sqlx::Transaction<'static, DB>> {
        self.tx.lock().await
    }

    /// Commits, then fires the events of the fastauth calls made in it.
    pub async fn commit(self) -> DbResult<()> {
        let tx = unwrap(self.tx)?;
        if DB::TransactionManager::get_transaction_depth(&*tx) > 1 {
            return Err(DbError::Other(
                "a fastauth savepoint is still open in the transaction".into(),
            ));
        }
        tx.commit().await.map_err(DbError::other)?;
        self.events.fire().await;
        Ok(())
    }

    /// Rolls back and discards the events. Dropping it does the same.
    pub async fn rollback(self) -> DbResult<()> {
        unwrap(self.tx)?.rollback().await.map_err(DbError::other)
    }
}

fn unwrap<DB: Dialect>(tx: SharedConn<DB>) -> DbResult<sqlx::Transaction<'static, DB>> {
    Arc::try_unwrap(tx)
        .map(Mutex::into_inner)
        .map_err(|_| DbError::Other("a fastauth call still holds the transaction".into()))
}

/// `auth.api().in_tx(&tx)`: server API calls on an app's [`SharedTx`].
pub trait InTx<'a, DB: Dialect> {
    /// Runs every call of this `Api` on `tx`, each inside its own savepoint: a call that
    /// fails rolls back its own writes and leaves `tx` as it was. Events wait for
    /// [`SharedTx::commit`].
    fn in_tx(self, tx: &'a SharedTx<DB>) -> Self;
}

impl<'a, DB: Dialect> InTx<'a, DB> for Api<'a, Sqlx<DB>> {
    fn in_tx(self, tx: &'a SharedTx<DB>) -> Self {
        let db = self.adapter().bind(tx.tx.clone());
        self.within(db, &tx.events)
    }
}
