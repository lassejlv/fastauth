//! The database contract. See `docs/concepts/02-database.md`.

use std::future::Future;
use std::sync::Arc;

use crate::crypto::Hash;
use crate::migrate::{LiveSchema, MigrationPlan};
use crate::schema::TableDef;
use crate::value::{Row, Value};

pub type DbResult<T> = Result<T, DbError>;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// A unique constraint failed. Adapters must map their driver's error to this, so
    /// sign-up can answer "user already exists" instead of a 500.
    #[error("unique constraint violated on `{table}`{}", column.as_deref().map(|c| format!(".{c}")).unwrap_or_default())]
    UniqueViolation {
        table: String,
        column: Option<String>,
    },
    #[error("the adapter does not support {0}")]
    Unsupported(&'static str),
    #[error("schema mismatch: {0}")]
    Schema(String),
    #[error("decode: {0}")]
    Decode(#[from] crate::value::DecodeError),
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl DbError {
    pub fn other(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        DbError::Other(Box::new(err))
    }
}

impl From<DbError> for crate::AuthError {
    fn from(err: DbError) -> Self {
        crate::AuthError::internal(err)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Lte,
    Gt,
    Gte,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    Asc,
    Desc,
}

/// A resolved filter: columns are positions in the query's table.
///
/// The text matches (`StartsWith`, `Contains`, `EndsWith`) are case-sensitive and match
/// their string literally: `%`, `_` and other pattern characters are not wildcards. Adapters
/// answer a variant they don't know with [`DbError::Unsupported`].
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Filter {
    All,
    Cmp { column: usize, op: Op, value: Value },
    In { column: usize, values: Vec<Value> },
    Null { column: usize, is_null: bool },
    StartsWith { column: usize, prefix: String },
    Contains { column: usize, substring: String },
    EndsWith { column: usize, suffix: String },
    And(Vec<Filter>),
    Or(Vec<Filter>),
}

#[derive(Clone, Debug)]
pub struct Insert<'a> {
    pub table: &'a Arc<TableDef>,
    /// One value per column, in column order. Defaults are already applied.
    pub values: Vec<Value>,
}

#[derive(Clone, Debug)]
pub struct Select<'a> {
    pub table: &'a Arc<TableDef>,
    pub filter: Filter,
    pub order: Vec<(usize, Order)>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Update<'a> {
    pub table: &'a Arc<TableDef>,
    pub filter: Filter,
    pub set: Vec<(usize, Value)>,
}

#[derive(Clone, Debug)]
pub struct Delete<'a> {
    pub table: &'a Arc<TableDef>,
    pub filter: Filter,
}

/// The fast path for session lookup. SQL adapters answer it with one JOIN.
#[derive(Clone, Debug)]
pub struct SessionWithUser<'a> {
    pub session: &'a Arc<TableDef>,
    pub user: &'a Arc<TableDef>,
    pub token_hash: &'a Hash,
}

/// [`SessionWithUser`] for sessions stored with
/// [`SessionTokens::Raw`](crate::config::SessionTokens::Raw): the session whose `token`
/// column holds `token`.
#[derive(Clone, Debug)]
pub struct SessionWithUserByToken<'a> {
    pub session: &'a Arc<TableDef>,
    pub user: &'a Arc<TableDef>,
    pub token: &'a str,
}

/// The default session lookup: the session row where `column` is `value`, then its user.
async fn session_then_user<A: Adapter + ?Sized>(
    adapter: &A,
    session: &Arc<TableDef>,
    user: &Arc<TableDef>,
    column: &str,
    value: Value,
) -> DbResult<Option<(Row, Row)>> {
    let position = session
        .position(column)
        .ok_or_else(|| DbError::Schema(format!("session.{column} missing")))?;
    let select = Select {
        table: session,
        filter: Filter::Cmp {
            column: position,
            op: Op::Eq,
            value,
        },
        order: Vec::new(),
        limit: Some(1),
        offset: None,
    };
    let Some(found) = adapter.find_one(select).await? else {
        return Ok(None);
    };
    let user_id = found
        .value("user_id")
        .cloned()
        .ok_or_else(|| DbError::Schema("session.user_id missing".into()))?;
    let user_pk = user
        .position("id")
        .ok_or_else(|| DbError::Schema("user.id missing".into()))?;
    let select = Select {
        table: user,
        filter: Filter::Cmp {
            column: user_pk,
            op: Op::Eq,
            value: user_id,
        },
        order: Vec::new(),
        limit: Some(1),
        offset: None,
    };
    Ok(adapter.find_one(select).await?.map(|row| (found, row)))
}

/// CRUD over dynamic rows. Implemented by adapters and by their transactions.
pub trait Queries: Send + Sync {
    fn insert(&self, q: Insert<'_>) -> impl Future<Output = DbResult<Row>> + Send;
    fn find_one(&self, q: Select<'_>) -> impl Future<Output = DbResult<Option<Row>>> + Send;
    fn find_many(&self, q: Select<'_>) -> impl Future<Output = DbResult<Vec<Row>>> + Send;
    fn update(&self, q: Update<'_>) -> impl Future<Output = DbResult<u64>> + Send;
    fn delete(&self, q: Delete<'_>) -> impl Future<Output = DbResult<u64>> + Send;
    fn count(&self, q: Select<'_>) -> impl Future<Output = DbResult<u64>> + Send;
}

pub trait Transaction: Queries + 'static {
    fn commit(self) -> impl Future<Output = DbResult<()>> + Send;
    fn rollback(self) -> impl Future<Output = DbResult<()>> + Send;
}

pub trait Adapter: Queries + 'static {
    type Tx: Transaction;

    fn begin(&self) -> impl Future<Output = DbResult<Self::Tx>> + Send;

    /// Reads the live schema for the migrator. Adapters without DDL return `Unsupported`.
    fn introspect(&self) -> impl Future<Output = DbResult<LiveSchema>> + Send;

    /// Applies a migration plan computed by the migrator.
    fn apply(&self, plan: &MigrationPlan) -> impl Future<Output = DbResult<()>> + Send;

    /// Renders a plan as SQL for `fastauth generate`. Non-SQL adapters return `Unsupported`.
    fn render_sql(&self, plan: &MigrationPlan) -> DbResult<String> {
        let _ = plan;
        Err(DbError::Unsupported("SQL rendering"))
    }

    /// Session plus user in one call. The default does two lookups; SQL adapters override.
    fn session_with_user(
        &self,
        q: SessionWithUser<'_>,
    ) -> impl Future<Output = DbResult<Option<(Row, Row)>>> + Send {
        let value = Value::Bytes(q.token_hash.as_bytes().to_vec());
        session_then_user(self, q.session, q.user, "token_hash", value)
    }

    /// [`session_with_user`](Self::session_with_user) by the token itself, for sessions
    /// stored with [`SessionTokens::Raw`](crate::config::SessionTokens::Raw). The default
    /// does two lookups; SQL adapters override.
    fn session_with_user_by_token(
        &self,
        q: SessionWithUserByToken<'_>,
    ) -> impl Future<Output = DbResult<Option<(Row, Row)>>> + Send {
        let value = Value::Text(q.token.to_owned());
        session_then_user(self, q.session, q.user, "token", value)
    }

    /// A query listing the rows of `table` that share values in `columns`, which a unique
    /// constraint over them would refuse, for the comment above such a migration in
    /// [`Migrator::sql_steps`](crate::migrate::Migrator::sql_steps). `None` (the default)
    /// when the adapter has no query language.
    fn duplicates_query(&self, table: &TableDef, columns: &[&str]) -> Option<String> {
        let _ = (table, columns);
        None
    }
}
