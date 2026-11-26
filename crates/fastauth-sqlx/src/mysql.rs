use fastauth_core::schema::{ColumnType, IdStorage, TableDef};
use fastauth_core::value::Value;
use sqlx::error::{BoxDynError, DatabaseError};
use sqlx::mysql::{MySqlArguments, MySqlConnection, MySqlRow};
use sqlx::types::{JsonValue, Uuid};
use sqlx::{Arguments, AssertSqlSafe, Decode, MySql, Row, SqlStr, Type};
use time::OffsetDateTime;

use crate::driver::{Catalog, Driver, Param};
use crate::render::{primary_key_name, unique_name};

const MAX_IDENT: usize = 64;

fn add(args: &mut MySqlArguments, param: Param) -> Result<(), BoxDynError> {
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

fn arguments(params: Vec<Param>) -> sqlx::Result<MySqlArguments> {
    let mut args = MySqlArguments::default();
    for param in params {
        add(&mut args, param).map_err(sqlx::Error::Encode)?;
    }
    Ok(args)
}

fn get<'r, T: Decode<'r, MySql> + Type<MySql>>(
    row: &'r MySqlRow,
    index: usize,
) -> Result<Option<T>, String> {
    row.try_get(index).map_err(|err| err.to_string())
}

impl Driver for MySql {
    const QUOTE: char = '`';
    const RETURNING: bool = false;
    const INLINE_CONSTRAINTS: bool = false;
    const TABLE_OPTIONS: &'static str =
        " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin";
    const TEXT_MATCH: (&'static str, &'static str) = ("LIKE", " ESCAPE '!'");
    const WILDCARD: char = '%';
    const UNIQUE_ON_ADD_COLUMN: bool = false;

    fn param(_n: usize, out: &mut String) {
        out.push('?');
    }

    fn escape_pattern(text: &str) -> String {
        let mut pattern = String::with_capacity(text.len());
        for ch in text.chars() {
            if matches!(ch, '!' | '%' | '_') {
                pattern.push('!');
            }
            pattern.push(ch);
        }
        pattern
    }

    fn ident(name: String) -> String {
        match name.char_indices().nth(MAX_IDENT) {
            Some((end, _)) => name[..end].to_owned(),
            None => name,
        }
    }

    fn sql_type(ty: ColumnType, keyed: bool) -> &'static str {
        match (ty, keyed) {
            (ColumnType::Id, _) => "binary(16)",
            (ColumnType::Text, true) => "varchar(768)",
            (ColumnType::Text, false) => "longtext",
            (ColumnType::Bool, _) => "boolean",
            (ColumnType::Int, _) => "bigint",
            (ColumnType::Timestamp, _) => "datetime(6)",
            (ColumnType::Json, _) => "json",
            (ColumnType::Bytes, true) => "varbinary(255)",
            (ColumnType::Bytes, false) => "longblob",
        }
    }

    fn bool_literal(value: bool) -> &'static str {
        if value { "true" } else { "false" }
    }

    fn now_default(_adding: bool) -> String {
        "UTC_TIMESTAMP(6)".to_owned()
    }

    fn default_expr(value: String) -> String {
        format!("({value})")
    }

    async fn fetch_all(
        conn: &mut MySqlConnection,
        sql: SqlStr,
        params: Vec<Param>,
    ) -> sqlx::Result<Vec<MySqlRow>> {
        sqlx::query_with(sql, arguments(params)?)
            .fetch_all(conn)
            .await
    }

    async fn execute(
        conn: &mut MySqlConnection,
        sql: SqlStr,
        params: Vec<Param>,
    ) -> sqlx::Result<u64> {
        let result = sqlx::query_with(sql, arguments(params)?)
            .execute(conn)
            .await?;
        Ok(result.rows_affected())
    }

    async fn execute_script(conn: &mut MySqlConnection, script: String) -> sqlx::Result<()> {
        sqlx::raw_sql(AssertSqlSafe(script)).execute(conn).await?;
        Ok(())
    }

    async fn introspect(
        conn: &mut MySqlConnection,
        schema: Option<String>,
    ) -> sqlx::Result<Catalog> {
        let typed: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT CAST(TABLE_NAME AS CHAR), CAST(COLUMN_NAME AS CHAR), CAST(COLUMN_TYPE AS CHAR) \
             FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = COALESCE(?, DATABASE()) \
             ORDER BY TABLE_NAME, ORDINAL_POSITION",
        )
        .bind(schema.clone())
        .fetch_all(&mut *conn)
        .await?;
        let mut columns = Vec::with_capacity(typed.len());
        let mut id_storage = Vec::new();
        for (table, column, column_type) in typed {
            let storage = if column_type == "binary(16)" {
                Some(IdStorage::Uuid)
            } else if column_type.starts_with("varchar")
                || column_type.starts_with("char")
                || column_type.ends_with("text")
            {
                Some(IdStorage::Text)
            } else {
                None
            };
            if let Some(storage) = storage {
                id_storage.push((table.clone(), column.clone(), storage));
            }
            columns.push((table, column));
        }
        let indexes = sqlx::query_as(
            "SELECT DISTINCT CAST(TABLE_NAME AS CHAR), CAST(INDEX_NAME AS CHAR) \
             FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = COALESCE(?, DATABASE())",
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

    fn decode(row: &MySqlRow, index: usize, ty: ColumnType) -> Result<Value, String> {
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

    /// From the message, `Duplicate entry '..' for key 'table.key'` (8.0.19 and later name
    /// the table; earlier versions don't).
    fn violated_column(
        err: &dyn DatabaseError,
        physical: &str,
        table: &TableDef,
    ) -> Option<String> {
        let message = err.message();
        let start = message.rfind(" for key '")? + " for key '".len();
        let key = message[start..].strip_suffix('\'')?;
        let key = key
            .strip_prefix(physical)
            .and_then(|key| key.strip_prefix('.'))
            .unwrap_or(key);
        table
            .columns
            .iter()
            .find(|column| {
                if column.primary_key {
                    key == "PRIMARY" || key == Self::ident(primary_key_name(physical))
                } else {
                    key == Self::ident(unique_name(physical, column.name))
                }
            })
            .map(|column| column.name.to_owned())
    }
}
