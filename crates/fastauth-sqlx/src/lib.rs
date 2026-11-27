//! The sqlx adapter for [fastauth](https://github.com/lassejlv/fastauth): Postgres, SQLite and
//! MySQL, with migrations. See `docs/concepts/02-database.md`.
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
#[cfg(feature = "mysql")]
mod mysql;
#[cfg(feature = "postgres")]
mod postgres;
mod render;
#[cfg(feature = "sqlite")]
mod sqlite;
mod tx;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use fastauth_core::adapter::{
    Adapter, DbError, DbResult, Delete, Filter, Insert, Op, Queries, Select, SessionWithUser,
    SessionWithUserByToken, Transaction, Update,
};
use fastauth_core::migrate::{
    LiveSchema, MigrationPlan, Step, duplicates_error, index_name, unique_key,
};
use fastauth_core::schema::{ColumnDef, ColumnType, TableDef};
use fastauth_core::value::{DecodeError, Row, Value};
use sqlx::pool::PoolConnection;
use sqlx_core::transaction::TransactionManager;
use tokio::sync::{Mutex, MutexGuard};

pub use sqlx;
pub use sqlx::Pool;
#[cfg(feature = "mysql")]
pub use sqlx::{MySql, MySqlPool};
#[cfg(feature = "postgres")]
pub use sqlx::{PgPool, Postgres};
#[cfg(feature = "sqlite")]
pub use sqlx::{Sqlite, SqlitePool};

use crate::driver::{column_type, from_stored};
use crate::render::{Names, Sql, Statement};
pub use crate::tx::{InTx, SharedTx};

/// A database this crate supports: [`Postgres`], [`Sqlite`] or [`MySql`], each behind the
/// feature of the same name (`postgres`, `sqlite`, `mysql`). Sealed.
pub trait Dialect: driver::Driver {}

impl<DB: driver::Driver> Dialect for DB {}

/// The fastauth adapter over a sqlx pool. `Sqlx::new(pool)` infers the database from the
/// pool: a `PgPool` gives `Sqlx<Postgres>`, a `SqlitePool` gives `Sqlx<Sqlite>`, a
/// `MySqlPool` gives `Sqlx<MySql>`.
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

    /// Fails, naming some of the rows, when a unique constraint the plan adds to an existing
    /// table would fail on the rows already there. Checked before any statement runs, since
    /// MySQL commits each one.
    async fn refuse_duplicates(&self, plan: &MigrationPlan) -> DbResult<()> {
        let new_here: HashSet<(&str, &str)> = plan
            .steps
            .iter()
            .flat_map(|step| match step {
                Step::CreateTable(table) => table
                    .columns
                    .iter()
                    .map(|c| (table.name, c.name))
                    .collect::<Vec<_>>(),
                Step::AddColumn { table, column } => vec![(table.name, column.name)],
                _ => Vec::new(),
            })
            .collect();
        for step in &plan.steps {
            let Step::AddUnique { table, columns } = step else {
                continue;
            };
            if columns.iter().any(|c| new_here.contains(&(table.name, *c))) {
                continue;
            }
            let selected: Vec<(usize, &ColumnDef)> = table
                .primary_key()
                .into_iter()
                .chain(columns.iter().filter_map(|c| table.column(c)))
                .filter_map(|c| Some((table.position(c.name)?, c)))
                .collect();
            let sql = render::duplicates::<DB>(&self.sql.names, table, columns);
            let rows = DB::fetch_all(&mut *self.conn().await?, sql, Vec::new())
                .await
                .map_err(DbError::other)?;
            if rows.is_empty() {
                continue;
            }
            let rows = rows
                .iter()
                .map(|row| {
                    selected
                        .iter()
                        .enumerate()
                        .map(|(i, (position, c))| {
                            DB::decode(row, i, column_type(table, *position))
                                .map(|value| (c.name, from_stored(table, *position, value)))
                                .map_err(|m| DecodeError::new(c.name, m).into())
                        })
                        .collect::<DbResult<Vec<_>>>()
                })
                .collect::<DbResult<Vec<_>>>()?;
            return Err(duplicates_error(table.name, columns, &rows));
        }
        Ok(())
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

#[cfg(feature = "mysql")]
impl Sqlx<MySql> {
    /// The MySQL database for fastauth's tables (MySQL's schemas are databases). Default:
    /// the connection's database. The migrator creates it if it doesn't exist.
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
            DB::decode(row, offset + i, column_type(table, i))
                .map(|value| from_stored(table, i, value))
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
    if !DB::RETURNING {
        return insert_and_read_back::<DB>(conn, sql, q).await;
    }
    let rows = fetch::<DB>(conn, sql, sql.insert::<DB>(q), table).await?;
    let row = rows
        .first()
        .ok_or_else(|| DbError::Schema(format!("insert into `{}` returned no row", table.name)))?;
    decode::<DB>(table, row, 0)
}

/// An insert where the database has no `RETURNING`: the row is read back by primary key, so
/// it comes back as stored (timestamps at the column's precision, JSON normalized).
async fn insert_and_read_back<DB: Dialect>(
    conn: &mut DB::Connection,
    sql: &Sql,
    q: Insert<'_>,
) -> DbResult<Row> {
    let table = q.table;
    let Some(key) = table.columns.iter().position(|column| column.primary_key) else {
        let values = q.values.clone();
        execute::<DB>(conn, sql, sql.insert::<DB>(q), table).await?;
        return Ok(Row::new(table.clone(), values));
    };
    let value = q.values[key].clone();
    execute::<DB>(conn, sql, sql.insert::<DB>(q), table).await?;
    let select = Select {
        table,
        filter: Filter::Cmp {
            column: key,
            op: Op::Eq,
            value,
        },
        order: Vec::new(),
        limit: None,
        offset: None,
    };
    find_one::<DB>(conn, sql, select)
        .await?
        .ok_or_else(|| DbError::Schema(format!("the row inserted into `{}` is gone", table.name)))
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
    session: &Arc<TableDef>,
    user: &Arc<TableDef>,
    (by, value): (&str, Value),
) -> DbResult<Option<(Row, Row)>> {
    for (table, column) in [(session, by), (session, "user_id"), (user, "id")] {
        if table.position(column).is_none() {
            return Err(DbError::Schema(format!(
                "`{}.{column}` missing",
                table.name
            )));
        }
    }
    let statement = sql.session_with_user::<DB>(session, user, by, value);
    let rows = fetch::<DB>(conn, sql, statement, session).await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let found = decode::<DB>(session, row, 0)?;
    let user = decode::<DB>(user, row, session.columns.len())?;
    Ok(Some((found, user)))
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
            None => {
                let tx = match DB::BEGIN {
                    Some(statement) => self.pool.begin_with(statement).await,
                    None => self.pool.begin().await,
                };
                TxKind::Owned(Mutex::new(tx.map_err(DbError::other)?))
            }
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
                let fastauth = DB::ident(index_name(&physical, column));
                let better_auth = DB::ident(format!("{physical}_{column}_idx"));
                if indexes.contains(&(physical.clone(), fastauth))
                    || indexes.contains(&(physical.clone(), better_auth))
                {
                    live.indexes.insert((table.clone(), column.clone()));
                }
            }
        }
        let mut uniques: HashMap<(String, String), Option<Vec<String>>> = HashMap::new();
        for (table, index, column) in catalog.uniques {
            let columns = uniques.entry((table, index)).or_insert(Some(Vec::new()));
            match (columns.as_mut(), column) {
                (Some(columns), Some(column)) => columns.push(column),
                _ => *columns = None,
            }
        }
        live.uniques = Some(
            uniques
                .into_iter()
                .filter_map(|((table, _), columns)| {
                    Some(unique_key(&names.logical(&table)?, &columns?))
                })
                .collect(),
        );
        Ok(live)
    }

    async fn apply(&self, plan: &MigrationPlan) -> DbResult<()> {
        let script = self.render_sql(plan)?;
        if script.is_empty() {
            return Ok(());
        }
        self.refuse_duplicates(plan).await?;
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
        let by = ("token_hash", Value::Bytes(q.token_hash.as_bytes().to_vec()));
        session_with_user::<DB>(&mut *self.conn().await?, &self.sql, q.session, q.user, by).await
    }

    async fn session_with_user_by_token(
        &self,
        q: SessionWithUserByToken<'_>,
    ) -> DbResult<Option<(Row, Row)>> {
        let by = ("token", Value::Text(q.token.to_owned()));
        session_with_user::<DB>(&mut *self.conn().await?, &self.sql, q.session, q.user, by).await
    }

    fn duplicates_query(&self, table: &TableDef, columns: &[&str]) -> Option<String> {
        Some(
            render::duplicates::<DB>(&self.sql.names, table, columns)
                .as_str()
                .to_owned(),
        )
    }
}
