//! The sqlx adapter for [fastauth](https://github.com/lassejlv/fastauth): Postgres and SQLite,
//! with migrations. See `docs/06-database.md`.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use fastauth_sqlx::{Sqlx, SqlitePool};
//!
//! let pool = SqlitePool::connect("sqlite://acme.db?mode=rwc").await?;
//! let db = Sqlx::new(pool).table_prefix("fa_"); // Sqlx<Sqlite>
//! # let _ = db;
//! # Ok(())
//! # }
//! ```

mod driver;
#[cfg(feature = "postgres")]
mod postgres;
mod render;
#[cfg(feature = "sqlite")]
mod sqlite;
mod tx;

use std::collections::HashSet;
use std::sync::Arc;

use fastauth_core::adapter::{
    Adapter, DbError, DbResult, Delete, Filter, Insert, Queries, Select, SessionWithUser,
    Transaction, Update,
};
use fastauth_core::migrate::{LiveSchema, MigrationPlan, index_name};
use fastauth_core::schema::{ColumnType, TableDef};
use fastauth_core::value::{DecodeError, Row, Value};
use sqlx::pool::PoolConnection;
use sqlx_core::transaction::TransactionManager;
use tokio::sync::{Mutex, MutexGuard};

pub use sqlx;
pub use sqlx::Pool;
#[cfg(feature = "postgres")]
pub use sqlx::{PgPool, Postgres};
#[cfg(feature = "sqlite")]
pub use sqlx::{Sqlite, SqlitePool};

use crate::driver::stored_type;
use crate::render::{Names, Sql, Statement};
pub use crate::tx::{InTx, SharedTx};

/// A database this crate supports: [`Postgres`] or [`Sqlite`], each behind the feature of
/// the same name. Sealed.
pub trait Dialect: driver::Driver {}

impl<DB: driver::Driver> Dialect for DB {}

/// The fastauth adapter over a sqlx pool. `Sqlx::new(pool)` infers the database from the
/// pool: a `PgPool` gives `Sqlx<Postgres>`, a `SqlitePool` gives `Sqlx<Sqlite>`.
///
/// Query text is rendered once per query shape and cached; values are always bind
/// parameters. Clones share the pool and the cache.
pub struct Sqlx<DB: Dialect> {
    pool: Pool<DB>,
    sql: Arc<Sql>,
    /// The app transaction this copy is bound to by `InTx::in_tx`: every query runs on it,
    /// and `begin` opens a savepoint in it.
    tx: Option<SharedConn<DB>>,
}

type SharedConn<DB> = Arc<Mutex<sqlx::Transaction<'static, DB>>>;

impl<DB: Dialect> Clone for Sqlx<DB> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            sql: self.sql.clone(),
            tx: self.tx.clone(),
        }
    }
}

impl<DB: Dialect> std::fmt::Debug for Sqlx<DB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sqlx")
            .field("names", &self.sql.names)
            .finish_non_exhaustive()
    }
}

impl<DB: Dialect> Sqlx<DB> {
    /// Wraps a pool. Tables keep their plain names (`user`, `session`, ...).
    pub fn new(pool: Pool<DB>) -> Self {
        Self {
            pool,
            sql: Arc::new(Sql::new(Names::default())),
            tx: None,
        }
    }

    /// Prefixes every table name: `.table_prefix("fa_")` stores `fa_user`, `fa_session`, ...
    pub fn table_prefix(self, prefix: impl Into<String>) -> Self {
        let prefix = prefix.into();
        self.with_names(|names| names.prefix = prefix)
    }

    /// Stores `table` under another name, e.g. `.rename("user", "accounts")` to keep an
    /// existing users table name. The table prefix doesn't apply to a renamed table.
    pub fn rename(self, table: impl Into<String>, to: impl Into<String>) -> Self {
        let (table, to) = (table.into(), to.into());
        self.with_names(|names| {
            names.renames.insert(table, to);
        })
    }

    /// The pool, for the app's own queries.
    pub fn pool(&self) -> &Pool<DB> {
        &self.pool
    }

    fn with_names(self, change: impl FnOnce(&mut Names)) -> Self {
        let mut names = self.sql.names.clone();
        change(&mut names);
        Self {
            pool: self.pool,
            sql: Arc::new(Sql::new(names)),
            tx: self.tx,
        }
    }

    fn bind(&self, tx: SharedConn<DB>) -> Self {
        Self {
            pool: self.pool.clone(),
            sql: self.sql.clone(),
            tx: Some(tx),
        }
    }

    async fn conn(&self) -> DbResult<Conn<'_, DB>> {
        Ok(match &self.tx {
            Some(tx) => Conn::Tx(tx.lock().await),
            None => Conn::Pool(self.pool.acquire().await.map_err(DbError::other)?),
        })
    }
}

/// A connection for one query: from the pool, or the bound app transaction's.
enum Conn<'a, DB: Dialect> {
    Pool(PoolConnection<DB>),
    Tx(MutexGuard<'a, sqlx::Transaction<'static, DB>>),
}

impl<DB: Dialect> std::ops::Deref for Conn<'_, DB> {
    type Target = DB::Connection;

    fn deref(&self) -> &DB::Connection {
        match self {
            Self::Pool(conn) => conn,
            Self::Tx(tx) => tx,
        }
    }
}

impl<DB: Dialect> std::ops::DerefMut for Conn<'_, DB> {
    fn deref_mut(&mut self) -> &mut DB::Connection {
        match self {
            Self::Pool(conn) => conn,
            Self::Tx(tx) => tx,
        }
    }
}

#[cfg(feature = "postgres")]
impl Sqlx<Postgres> {
    /// The Postgres schema for fastauth's tables. Default: the connection's `search_path`.
    /// The migrator creates the schema if it doesn't exist.
    pub fn schema(self, schema: impl Into<String>) -> Self {
        let schema = schema.into();
        self.with_names(|names| names.schema = Some(schema))
    }
}

/// A transaction from [`Adapter::begin`]: a new one on a pool connection, or a savepoint
/// when the adapter is bound to an app transaction. Dropping it without `commit` rolls back.
pub struct SqlxTx<DB: Dialect> {
    kind: TxKind<DB>,
    sql: Arc<Sql>,
}

enum TxKind<DB: Dialect> {
    Owned(Mutex<sqlx::Transaction<'static, DB>>),
    Savepoint(Savepoint<DB>),
}

struct Savepoint<DB: Dialect> {
    tx: SharedConn<DB>,
    open: bool,
}

impl<DB: Dialect> Drop for Savepoint<DB> {
    fn drop(&mut self) {
        if !self.open {
            return;
        }
        if let Ok(mut tx) = self.tx.try_lock() {
            DB::TransactionManager::start_rollback(&mut **tx);
        }
    }
}

impl<DB: Dialect> SqlxTx<DB> {
    async fn lock(&self) -> MutexGuard<'_, sqlx::Transaction<'static, DB>> {
        match &self.kind {
            TxKind::Owned(tx) => tx.lock().await,
            TxKind::Savepoint(savepoint) => savepoint.tx.lock().await,
        }
    }
}

fn db_error<DB: Dialect>(err: sqlx::Error, sql: &Sql, table: &TableDef) -> DbError {
    match err.as_database_error() {
        Some(db) if db.is_unique_violation() => DbError::UniqueViolation {
            table: table.name.to_owned(),
            column: DB::violated_column(db, &sql.names.physical(table.name), table),
        },
        _ => DbError::other(err),
    }
}

fn decode<DB: Dialect>(table: &Arc<TableDef>, row: &DB::Row, offset: usize) -> DbResult<Row> {
    let values = table
        .columns
        .iter()
        .enumerate()
        .map(|(i, column)| {
            DB::decode(row, offset + i, stored_type(table, column.ty))
                .map_err(|m| DecodeError::new(column.name, m))
        })
        .collect::<Result<_, _>>()?;
    Ok(Row::new(table.clone(), values))
}

async fn fetch<DB: Dialect>(
    conn: &mut DB::Connection,
    sql: &Sql,
    statement: Statement,
    table: &TableDef,
) -> DbResult<Vec<DB::Row>> {
    DB::fetch_all(conn, statement.sql, statement.params)
        .await
        .map_err(|err| db_error::<DB>(err, sql, table))
}

async fn execute<DB: Dialect>(
    conn: &mut DB::Connection,
    sql: &Sql,
    statement: Statement,
    table: &TableDef,
) -> DbResult<u64> {
    DB::execute(conn, statement.sql, statement.params)
        .await
        .map_err(|err| db_error::<DB>(err, sql, table))
}

async fn insert<DB: Dialect>(conn: &mut DB::Connection, sql: &Sql, q: Insert<'_>) -> DbResult<Row> {
    let table = q.table;
    let rows = fetch::<DB>(conn, sql, sql.insert::<DB>(q), table).await?;
    let row = rows
        .first()
        .ok_or_else(|| DbError::Schema(format!("insert into `{}` returned no row", table.name)))?;
    decode::<DB>(table, row, 0)
}

async fn find_many<DB: Dialect>(
    conn: &mut DB::Connection,
    sql: &Sql,
    q: Select<'_>,
) -> DbResult<Vec<Row>> {
    render::check_filter(&q.filter)?;
    let table = q.table;
    let rows = fetch::<DB>(conn, sql, sql.select::<DB>(q), table).await?;
    rows.iter().map(|row| decode::<DB>(table, row, 0)).collect()
}

async fn find_one<DB: Dialect>(
    conn: &mut DB::Connection,
    sql: &Sql,
    mut q: Select<'_>,
) -> DbResult<Option<Row>> {
    q.limit = Some(1);
    Ok(find_many::<DB>(conn, sql, q).await?.pop())
}

async fn count<DB: Dialect>(
    conn: &mut DB::Connection,
    sql: &Sql,
    table: &TableDef,
    filter: Filter,
) -> DbResult<u64> {
    render::check_filter(&filter)?;
    let rows = fetch::<DB>(conn, sql, sql.count::<DB>(table, filter), table).await?;
    let value = rows
        .first()
        .map(|row| DB::decode(row, 0, ColumnType::Int))
        .transpose()
        .map_err(|m| DecodeError::new("count", m))?;
    match value {
        Some(Value::Int(n)) => Ok(n.unsigned_abs()),
        other => Err(DbError::Schema(format!("COUNT(*) returned {other:?}"))),
    }
}

async fn update<DB: Dialect>(conn: &mut DB::Connection, sql: &Sql, q: Update<'_>) -> DbResult<u64> {
    if q.set.is_empty() {
        return count::<DB>(conn, sql, q.table, q.filter).await;
    }
    render::check_filter(&q.filter)?;
    let table = q.table;
    execute::<DB>(conn, sql, sql.update::<DB>(q), table).await
}

async fn delete<DB: Dialect>(conn: &mut DB::Connection, sql: &Sql, q: Delete<'_>) -> DbResult<u64> {
    render::check_filter(&q.filter)?;
    let table = q.table;
    execute::<DB>(conn, sql, sql.delete::<DB>(q), table).await
}

async fn session_with_user<DB: Dialect>(
    conn: &mut DB::Connection,
    sql: &Sql,
    q: SessionWithUser<'_>,
) -> DbResult<Option<(Row, Row)>> {
    for (table, column) in [
        (q.session, "token_hash"),
        (q.session, "user_id"),
        (q.user, "id"),
    ] {
        if table.position(column).is_none() {
            return Err(DbError::Schema(format!(
                "`{}.{column}` missing",
                table.name
            )));
        }
    }
    let statement =
        sql.session_with_user::<DB>(q.session, q.user, q.token_hash.as_bytes().to_vec());
    let rows = fetch::<DB>(conn, sql, statement, q.session).await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let session = decode::<DB>(q.session, row, 0)?;
    let user = decode::<DB>(q.user, row, q.session.columns.len())?;
    Ok(Some((session, user)))
}

impl<DB: Dialect> Queries for Sqlx<DB> {
    async fn insert(&self, q: Insert<'_>) -> DbResult<Row> {
        insert::<DB>(&mut *self.conn().await?, &self.sql, q).await
    }

    async fn find_one(&self, q: Select<'_>) -> DbResult<Option<Row>> {
        find_one::<DB>(&mut *self.conn().await?, &self.sql, q).await
    }

    async fn find_many(&self, q: Select<'_>) -> DbResult<Vec<Row>> {
        find_many::<DB>(&mut *self.conn().await?, &self.sql, q).await
    }

    async fn update(&self, q: Update<'_>) -> DbResult<u64> {
        update::<DB>(&mut *self.conn().await?, &self.sql, q).await
    }

    async fn delete(&self, q: Delete<'_>) -> DbResult<u64> {
        delete::<DB>(&mut *self.conn().await?, &self.sql, q).await
    }

    async fn count(&self, q: Select<'_>) -> DbResult<u64> {
        count::<DB>(&mut *self.conn().await?, &self.sql, q.table, q.filter).await
    }
}

impl<DB: Dialect> Queries for SqlxTx<DB> {
    async fn insert(&self, q: Insert<'_>) -> DbResult<Row> {
        insert::<DB>(&mut **self.lock().await, &self.sql, q).await
    }

    async fn find_one(&self, q: Select<'_>) -> DbResult<Option<Row>> {
        find_one::<DB>(&mut **self.lock().await, &self.sql, q).await
    }

    async fn find_many(&self, q: Select<'_>) -> DbResult<Vec<Row>> {
        find_many::<DB>(&mut **self.lock().await, &self.sql, q).await
    }

    async fn update(&self, q: Update<'_>) -> DbResult<u64> {
        update::<DB>(&mut **self.lock().await, &self.sql, q).await
    }

    async fn delete(&self, q: Delete<'_>) -> DbResult<u64> {
        delete::<DB>(&mut **self.lock().await, &self.sql, q).await
    }

    async fn count(&self, q: Select<'_>) -> DbResult<u64> {
        count::<DB>(&mut **self.lock().await, &self.sql, q.table, q.filter).await
    }
}

impl<DB: Dialect> Transaction for SqlxTx<DB> {
    async fn commit(self) -> DbResult<()> {
        match self.kind {
            TxKind::Owned(tx) => tx.into_inner().commit().await.map_err(DbError::other),
            TxKind::Savepoint(mut savepoint) => {
                DB::TransactionManager::commit(&mut **savepoint.tx.lock().await)
                    .await
                    .map_err(DbError::other)?;
                savepoint.open = false;
                Ok(())
            }
        }
    }

    async fn rollback(self) -> DbResult<()> {
        match self.kind {
            TxKind::Owned(tx) => tx.into_inner().rollback().await.map_err(DbError::other),
            TxKind::Savepoint(mut savepoint) => {
                DB::TransactionManager::rollback(&mut **savepoint.tx.lock().await)
                    .await
                    .map_err(DbError::other)?;
                savepoint.open = false;
                Ok(())
            }
        }
    }
}

impl<DB: Dialect> Adapter for Sqlx<DB> {
    type Tx = SqlxTx<DB>;

    async fn begin(&self) -> DbResult<SqlxTx<DB>> {
        let kind = match &self.tx {
            Some(tx) => {
                DB::TransactionManager::begin(&mut **tx.lock().await, None)
                    .await
                    .map_err(DbError::other)?;
                TxKind::Savepoint(Savepoint {
                    tx: tx.clone(),
                    open: true,
                })
            }
            None => TxKind::Owned(Mutex::new(self.pool.begin().await.map_err(DbError::other)?)),
        };
        Ok(SqlxTx {
            kind,
            sql: self.sql.clone(),
        })
    }

    async fn introspect(&self) -> DbResult<LiveSchema> {
        let names = &self.sql.names;
        let catalog = DB::introspect(&mut *self.conn().await?, names.schema.clone())
            .await
            .map_err(DbError::other)?;
        let mut live = LiveSchema::default();
        for (table, column) in catalog.columns {
            if let Some(logical) = names.logical(&table) {
                live.tables.entry(logical).or_default().insert(column);
            }
        }
        for (table, column, storage) in catalog.id_storage {
            if let Some(logical) = names.logical(&table) {
                live.id_storage.insert((logical, column), storage);
            }
        }
        let indexes: HashSet<(String, String)> = catalog.indexes.into_iter().collect();
        for (table, columns) in &live.tables {
            let physical = names.physical(table);
            for column in columns {
                let name = DB::ident(index_name(&physical, column));
                if indexes.contains(&(physical.clone(), name)) {
                    live.indexes.insert((table.clone(), column.clone()));
                }
            }
        }
        Ok(live)
    }

    async fn apply(&self, plan: &MigrationPlan) -> DbResult<()> {
        let script = self.render_sql(plan)?;
        if script.is_empty() {
            return Ok(());
        }
        let tx = self.begin().await?;
        DB::execute_script(&mut **tx.lock().await, script)
            .await
            .map_err(DbError::other)?;
        tx.commit().await
    }

    fn render_sql(&self, plan: &MigrationPlan) -> DbResult<String> {
        Ok(render::ddl::<DB>(&self.sql.names, plan)
            .iter()
            .map(|statement| format!("{statement};\n"))
            .collect::<Vec<_>>()
            .join("\n"))
    }

    async fn session_with_user(&self, q: SessionWithUser<'_>) -> DbResult<Option<(Row, Row)>> {
        session_with_user::<DB>(&mut *self.conn().await?, &self.sql, q).await
    }
}
