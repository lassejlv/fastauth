use fastauth_core::schema::{ColumnType, TableDef};
use fastauth_core::value::Value;
use sqlx::error::{BoxDynError, DatabaseError};
use sqlx::sqlite::{SqliteArguments, SqliteConnection, SqliteRow};
use sqlx::{Arguments, AssertSqlSafe, Decode, Row, SqlStr, Sqlite, Type};
use time::OffsetDateTime;

use crate::driver::{Catalog, Driver, Param};

const NANOS_PER_MILLI: i128 = 1_000_000;

fn unix_millis(at: OffsetDateTime) -> i64 {
    i64::try_from(at.unix_timestamp_nanos().div_euclid(NANOS_PER_MILLI)).unwrap_or(i64::MAX)
}

fn add(args: &mut SqliteArguments, param: Param) -> Result<(), BoxDynError> {
    match param.value {
        Value::Null => args.add(None::<String>),
        Value::Bool(b) => args.add(b),
        Value::Int(i) => args.add(i),
        Value::Text(text) => args.add(text),
        Value::Bytes(bytes) => args.add(bytes),
        Value::Timestamp(at) => args.add(unix_millis(at)),
        Value::Json(json) => args.add(json.to_string()),
    }
}

fn arguments(params: Vec<Param>) -> sqlx::Result<SqliteArguments> {
    let mut args = SqliteArguments::default();
    for param in params {
        add(&mut args, param).map_err(sqlx::Error::Encode)?;
    }
    Ok(args)
}

fn get<'r, T: Decode<'r, Sqlite> + Type<Sqlite>>(
    row: &'r SqliteRow,
    index: usize,
) -> Result<Option<T>, String> {
    row.try_get(index).map_err(|err| err.to_string())
}

impl Driver for Sqlite {
    const TEXT_MATCH: (&'static str, &'static str) = ("GLOB", "");
    const WILDCARD: char = '*';
    const UNIQUE_ON_ADD_COLUMN: bool = false;
    const QUOTE: char = '"';
    const RETURNING: bool = true;
    const INLINE_CONSTRAINTS: bool = true;
    const TABLE_OPTIONS: &'static str = "";

    fn param(n: usize, out: &mut String) {
        out.push('?');
        out.push_str(&n.to_string());
    }

    fn escape_pattern(text: &str) -> String {
        let mut pattern = String::with_capacity(text.len());
        for ch in text.chars() {
            match ch {
                '*' | '?' | '[' => {
                    pattern.push('[');
                    pattern.push(ch);
                    pattern.push(']');
                }
                ch => pattern.push(ch),
            }
        }
        pattern
    }

    fn ident(name: String) -> String {
        name
    }

    fn sql_type(ty: ColumnType, _keyed: bool) -> &'static str {
        match ty {
            ColumnType::Id | ColumnType::Text | ColumnType::Json => "text",
            ColumnType::Bool | ColumnType::Int | ColumnType::Timestamp => "integer",
            ColumnType::Bytes => "blob",
        }
    }

    fn bool_literal(value: bool) -> &'static str {
        if value { "1" } else { "0" }
    }

    fn now_default(adding: bool) -> String {
        if adding {
            unix_millis(OffsetDateTime::now_utc()).to_string()
        } else {
            "(CAST(unixepoch('subsec') * 1000 AS INTEGER))".to_owned()
        }
    }

    async fn fetch_all(
        conn: &mut SqliteConnection,
        sql: SqlStr,
        params: Vec<Param>,
    ) -> sqlx::Result<Vec<SqliteRow>> {
        sqlx::query_with(sql, arguments(params)?)
            .fetch_all(conn)
            .await
    }

    async fn execute(
        conn: &mut SqliteConnection,
        sql: SqlStr,
        params: Vec<Param>,
    ) -> sqlx::Result<u64> {
        let result = sqlx::query_with(sql, arguments(params)?)
            .execute(conn)
            .await?;
        Ok(result.rows_affected())
    }

    async fn execute_script(conn: &mut SqliteConnection, script: String) -> sqlx::Result<()> {
        sqlx::raw_sql(AssertSqlSafe(script)).execute(conn).await?;
        Ok(())
    }

    async fn introspect(
        conn: &mut SqliteConnection,
        _schema: Option<String>,
    ) -> sqlx::Result<Catalog> {
        let columns = sqlx::query_as(
            "SELECT m.name, p.name FROM sqlite_master AS m \
             JOIN pragma_table_info(m.name) AS p WHERE m.type = 'table' ORDER BY m.name, p.cid",
        )
        .fetch_all(&mut *conn)
        .await?;
        let indexes = sqlx::query_as(
            "SELECT m.name, l.name FROM sqlite_master AS m \
             JOIN pragma_index_list(m.name) AS l WHERE m.type = 'table'",
        )
        .fetch_all(conn)
        .await?;
        Ok(Catalog {
            columns,
            indexes,
            id_storage: Vec::new(),
        })
    }

    fn decode(row: &SqliteRow, index: usize, ty: ColumnType) -> Result<Value, String> {
        let value = match ty {
            ColumnType::Id | ColumnType::Text => get::<String>(row, index)?.map(Value::Text),
            ColumnType::Bool => get::<bool>(row, index)?.map(Value::Bool),
            ColumnType::Int => get::<i64>(row, index)?.map(Value::Int),
            ColumnType::Timestamp => get::<i64>(row, index)?
                .map(|ms| {
                    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * NANOS_PER_MILLI)
                        .map(Value::Timestamp)
                        .map_err(|err| err.to_string())
                })
                .transpose()?,
            ColumnType::Json => get::<String>(row, index)?
                .map(|text| {
                    serde_json::from_str(&text)
                        .map(Value::Json)
                        .map_err(|err| err.to_string())
                })
                .transpose()?,
            ColumnType::Bytes => get::<Vec<u8>>(row, index)?.map(Value::Bytes),
        };
        Ok(value.unwrap_or(Value::Null))
    }

    fn violated_column(
        err: &dyn DatabaseError,
        physical: &str,
        table: &TableDef,
    ) -> Option<String> {
        let failed = err.message().strip_prefix("UNIQUE constraint failed: ")?;
        let first = failed.split(", ").next()?;
        let column = first.strip_prefix(physical)?.strip_prefix('.')?;
        table.column(column).map(|column| column.name.to_owned())
    }
}
