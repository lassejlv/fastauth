//! What each sqlx database implements. Sealed: the trait lives in a private module.

use std::future::Future;

use fastauth_core::schema::{ColumnType, IdStorage, TableDef};
use fastauth_core::value::Value;
use sqlx::error::DatabaseError;
use sqlx::{Database, SqlStr};

/// A bind parameter: a value and the type of the column it is compared with or written to.
#[derive(Debug)]
pub struct Param {
    pub value: Value,
    pub ty: ColumnType,
    /// A filter value that can't be encoded for its column (an id that isn't a UUID on
    /// Postgres) binds as NULL, so the filter matches nothing instead of failing.
    pub lenient: bool,
}

impl Param {
    pub fn write(value: Value, ty: ColumnType) -> Self {
        Self {
            value,
            ty,
            lenient: false,
        }
    }

    pub fn filter(value: Value, ty: ColumnType) -> Self {
        Self {
            value,
            ty,
            lenient: true,
        }
    }
}

/// Which part of a text value a text filter's needle must match.
#[derive(Clone, Copy, Debug)]
pub enum TextMatch {
    StartsWith,
    Contains,
    EndsWith,
}

/// `needle` as a LIKE pattern that matches it literally, with `escape` before every `%`,
/// `_` and `escape`, and a `%` on each side `kind` leaves open.
#[cfg(any(feature = "postgres", feature = "mysql"))]
pub fn like_pattern(kind: TextMatch, needle: &str, escape: char) -> String {
    let mut pattern = String::with_capacity(needle.len() + 2);
    if !matches!(kind, TextMatch::StartsWith) {
        pattern.push('%');
    }
    for ch in needle.chars() {
        if ch == escape || ch == '%' || ch == '_' {
            pattern.push(escape);
        }
        pattern.push(ch);
    }
    if !matches!(kind, TextMatch::EndsWith) {
        pattern.push('%');
    }
    pattern
}

/// Physical table and column names from the database catalog.
#[derive(Debug, Default)]
pub struct Catalog {
    /// `(table, column)`.
    pub columns: Vec<(String, String)>,
    /// `(table, index name)`.
    pub indexes: Vec<(String, String)>,
    /// `(table, column, storage)` for columns whose type an id column can have. Empty where
    /// every strategy stores ids the same way.
    pub id_storage: Vec<(String, String, IdStorage)>,
    /// `(table, index name, column)` for every column of every unique index or constraint
    /// but the primary key. `None` for an expression part, which makes the whole index one
    /// fastauth didn't create.
    pub uniques: Vec<(String, String, Option<String>)>,
}

/// The type `ty` is stored as in `table`: drivers read `ColumnType::Id` as a native UUID,
/// so ids stored as text become `ColumnType::Text`.
pub fn stored_type(table: &TableDef, ty: ColumnType) -> ColumnType {
    match (ty, table.id_storage()) {
        (ColumnType::Id, IdStorage::Text) => ColumnType::Text,
        _ => ty,
    }
}

pub trait Driver: Database {
    /// The character identifiers are quoted with.
    const QUOTE: char;
    /// Whether `INSERT .. RETURNING` works. Without it, an insert reads its row back by
    /// primary key.
    const RETURNING: bool;
    /// Whether PRIMARY KEY, UNIQUE and REFERENCES go in the column definition. MySQL parses
    /// an inline REFERENCES and ignores it, so it gets table constraints instead.
    const INLINE_CONSTRAINTS: bool;
    /// Appended to `CREATE TABLE (..)`.
    const TABLE_OPTIONS: &'static str;
    /// Whether a text value can hold a NUL character. Where it can't (Postgres), a text
    /// filter whose needle holds one binds NULL, so it matches no row instead of failing.
    const TEXT_HOLDS_NUL: bool;
    /// Whether `ALTER TABLE .. ADD COLUMN` accepts an inline UNIQUE constraint.
    const UNIQUE_ON_ADD_COLUMN: bool;
    /// The most bytes one index key may hold, when it's small enough that a unique
    /// constraint over several text columns needs prefix lengths (MySQL's InnoDB: 3072,
    /// with 4 bytes per utf8mb4 character).
    const KEY_BYTES: Option<usize> = None;
    /// The statement an owned transaction begins with, when the default `BEGIN` won't do.
    const BEGIN: Option<&'static str> = None;

    fn param(n: usize, out: &mut String);
    /// Renders a case-sensitive `kind` match of `column` against the needle bound at
    /// `param`, exact for every character, NUL included.
    fn text_match(kind: TextMatch, column: &str, param: &str, out: &mut String);
    /// The value `text_match` binds for `needle`.
    fn text_needle(kind: TextMatch, needle: &str) -> String;
    /// An identifier as the database stores it (Postgres truncates to 63 bytes).
    fn ident(name: String) -> String;
    /// `keyed`: the column is an id, a key or indexed, so its type must be indexable.
    fn sql_type(ty: ColumnType, keyed: bool) -> &'static str;
    fn bool_literal(value: bool) -> &'static str;
    /// The DEFAULT for `DefaultValue::Now`, in `CREATE TABLE` or in `ADD COLUMN`.
    fn now_default(adding: bool) -> String;
    /// A rendered default as it follows `DEFAULT`.
    fn default_expr(value: String) -> String {
        value
    }

    fn fetch_all(
        conn: &mut Self::Connection,
        sql: SqlStr,
        params: Vec<Param>,
    ) -> impl Future<Output = sqlx::Result<Vec<Self::Row>>> + Send;
    fn execute(
        conn: &mut Self::Connection,
        sql: SqlStr,
        params: Vec<Param>,
    ) -> impl Future<Output = sqlx::Result<u64>> + Send;
    fn execute_script(
        conn: &mut Self::Connection,
        script: String,
    ) -> impl Future<Output = sqlx::Result<()>> + Send;
    fn introspect(
        conn: &mut Self::Connection,
        schema: Option<String>,
    ) -> impl Future<Output = sqlx::Result<Catalog>> + Send;

    fn decode(row: &Self::Row, index: usize, ty: ColumnType) -> Result<Value, String>;
    /// The column a unique violation on `table` (stored as `physical`) is about.
    fn violated_column(err: &dyn DatabaseError, physical: &str, table: &TableDef)
    -> Option<String>;
}
