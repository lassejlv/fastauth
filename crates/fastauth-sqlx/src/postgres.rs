use fastauth_core::schema::{ColumnType, IdStorage, TableDef};
use fastauth_core::value::Value;
use sqlx::error::{BoxDynError, DatabaseError};
use sqlx::postgres::{PgArguments, PgConnection, PgRow};
use sqlx::types::{JsonValue, Uuid};
use sqlx::{Arguments, AssertSqlSafe, Decode, Postgres, Row, SqlStr, Type};
use time::OffsetDateTime;

use crate::driver::{Catalog, Driver, Param};
use crate::render::{primary_key_name, unique_name};

const MAX_IDENT: usize = 63;

fn add(args: &mut PgArguments, param: Param) -> Result<(), BoxDynError> {
    match (param.value, param.ty) {
        (Value::Null, ColumnType::Id) => args.add(None::<Uuid>),
        (Value::Null, ColumnType::Text) => args.add(None::<String>),
        (Value::Null, ColumnType::Bool) => args.add(None::<bool>),
        (Value::Null, ColumnType::Int) => args.add(None::<i64>),
        (Value::Null, ColumnType::Timestamp) => args.add(None::<OffsetDateTime>),
        (Value::Null, ColumnType::Json) => args.add(None::<JsonValue>),
        (Value::Null, ColumnType::Bytes) => args.add(None::<Vec<u8>>),
        (Value::Text(text), ColumnType::Id) => match Uuid::parse_str(&text) {
            Ok(id) => args.add(id),
            Err(_) if param.lenient => args.add(None::<Uuid>),
            Err(err) => Err(format!("`{text}` is not a UUID: {err}").into()),
        },
        (Value::Bool(b), _) => args.add(b),
        (Value::Int(i), _) => args.add(i),
        (Value::Text(text), _) => args.add(text),
        (Value::Bytes(bytes), _) => args.add(bytes),
        (Value::Timestamp(at), _) => args.add(at),
        (Value::Json(json), _) => args.add(json),
    }
}

fn arguments(params: Vec<Param>) -> sqlx::Result<PgArguments> {
    let mut args = PgArguments::default();
    for param in params {
        add(&mut args, param).map_err(sqlx::Error::Encode)?;
    }
    Ok(args)
}

fn get<'r, T: Decode<'r, Postgres> + Type<Postgres>>(
    row: &'r PgRow,
    index: usize,
) -> Result<Option<T>, String> {
    row.try_get(index).map_err(|err| err.to_string())
}

impl Driver for Postgres {
    const TEXT_MATCH: (&'static str, &'static str) = ("LIKE", " ESCAPE '\\'");
    const WILDCARD: char = '%';
    const UNIQUE_ON_ADD_COLUMN: bool = true;
    const QUOTE: char = '"';
    const RETURNING: bool = true;
    const INLINE_CONSTRAINTS: bool = true;
    const TABLE_OPTIONS: &'static str = "";

    fn param(n: usize, out: &mut String) {
        out.push('$');
        out.push_str(&n.to_string());
    }

    fn escape_pattern(text: &str) -> String {
        let mut pattern = String::with_capacity(text.len());
        for ch in text.chars() {
            if matches!(ch, '\\' | '%' | '_') {
                pattern.push('\\');
            }
            pattern.push(ch);
        }
        pattern
    }

    fn ident(mut name: String) -> String {
        if name.len() > MAX_IDENT {
            let end = (0..=MAX_IDENT)
                .rev()
                .find(|&i| name.is_char_boundary(i))
                .unwrap_or(0);
            name.truncate(end);
        }
        name
    }

    fn sql_type(ty: ColumnType, _keyed: bool) -> &'static str {
        match ty {
            ColumnType::Id => "uuid",
            ColumnType::Text => "text",
            ColumnType::Bool => "boolean",
            ColumnType::Int => "bigint",
            ColumnType::Timestamp => "timestamptz",
            ColumnType::Json => "jsonb",
            ColumnType::Bytes => "bytea",
        }
    }

    fn bool_literal(value: bool) -> &'static str {
        if value { "true" } else { "false" }
    }

    fn now_default(_adding: bool) -> String {
        "now()".to_owned()
    }

    async fn fetch_all(
        conn: &mut PgConnection,
        sql: SqlStr,
        params: Vec<Param>,
    ) -> sqlx::Result<Vec<PgRow>> {
        sqlx::query_with(sql, arguments(params)?)
            .fetch_all(conn)
            .await
    }

    async fn execute(
        conn: &mut PgConnection,
        sql: SqlStr,
        params: Vec<Param>,
    ) -> sqlx::Result<u64> {
        let result = sqlx::query_with(sql, arguments(params)?)
            .execute(conn)
            .await?;
        Ok(result.rows_affected())
    }

    async fn execute_script(conn: &mut PgConnection, script: String) -> sqlx::Result<()> {
        sqlx::raw_sql(AssertSqlSafe(script)).execute(conn).await?;
        Ok(())
    }

    async fn introspect(conn: &mut PgConnection, schema: Option<String>) -> sqlx::Result<Catalog> {
        let typed: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT table_name::text, column_name::text, data_type::text \
             FROM information_schema.columns \
             WHERE table_schema::text = COALESCE($1::text, current_schema()::text) \
             ORDER BY table_name, ordinal_position",
        )
        .bind(schema.clone())
        .fetch_all(&mut *conn)
        .await?;
        let mut columns = Vec::with_capacity(typed.len());
        let mut id_storage = Vec::new();
        for (table, column, data_type) in typed {
            let storage = match data_type.as_str() {
                "uuid" => Some(IdStorage::Uuid),
                "text" => Some(IdStorage::Text),
                _ => None,
            };
            if let Some(storage) = storage {
                id_storage.push((table.clone(), column.clone(), storage));
            }
            columns.push((table, column));
        }
        let indexes = sqlx::query_as(
            "SELECT tablename::text, indexname::text FROM pg_indexes \
             WHERE schemaname::text = COALESCE($1::text, current_schema()::text)",
        )
        .bind(schema)
        .fetch_all(conn)
        .await?;
        Ok(Catalog {
            columns,
            indexes,
            id_storage,
        })
    }

    fn decode(row: &PgRow, index: usize, ty: ColumnType) -> Result<Value, String> {
        let value = match ty {
            ColumnType::Id => get::<Uuid>(row, index)?.map(|id| Value::Text(id.to_string())),
            ColumnType::Text => get::<String>(row, index)?.map(Value::Text),
            ColumnType::Bool => get::<bool>(row, index)?.map(Value::Bool),
            ColumnType::Int => get::<i64>(row, index)?.map(Value::Int),
            ColumnType::Timestamp => get::<OffsetDateTime>(row, index)?.map(Value::Timestamp),
            ColumnType::Json => get::<JsonValue>(row, index)?.map(Value::Json),
            ColumnType::Bytes => get::<Vec<u8>>(row, index)?.map(Value::Bytes),
        };
        Ok(value.unwrap_or(Value::Null))
    }

    fn violated_column(
        err: &dyn DatabaseError,
        physical: &str,
        table: &TableDef,
    ) -> Option<String> {
        let constraint = err.constraint()?;
        table
            .columns
            .iter()
            .find(|column| {
                let name = if column.primary_key {
                    primary_key_name(physical)
                } else {
                    unique_name(physical, column.name)
                };
                Self::ident(name) == constraint
            })
            .map(|column| column.name.to_owned())
    }
}
