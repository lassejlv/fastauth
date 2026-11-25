use std::fmt;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::crypto::Hash;
use crate::schema::{ColumnType, TableDef};

/// A single database value as it crosses the adapter boundary.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", content = "v")]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Text(String),
    Bytes(Vec<u8>),
    Timestamp(#[serde(with = "time::serde::rfc3339")] OffsetDateTime),
    Json(serde_json::Value),
}

impl Value {
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// The JSON a client sees for this value.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Value::Null => serde_json::Value::Null,
            Value::Bool(b) => (*b).into(),
            Value::Int(i) => (*i).into(),
            Value::Text(s) => s.clone().into(),
            Value::Bytes(_) => serde_json::Value::Null,
            Value::Timestamp(t) => t
                .format(&time::format_description::well_known::Rfc3339)
                .map(serde_json::Value::String)
                .unwrap_or(serde_json::Value::Null),
            Value::Json(j) => j.clone(),
        }
    }

    /// Parses client JSON into a value of `ty`, for user-settable columns.
    pub fn from_json(ty: ColumnType, json: &serde_json::Value) -> Option<Value> {
        use serde_json::Value as J;
        Some(match (ty, json) {
            (_, J::Null) => Value::Null,
            (ColumnType::Bool, J::Bool(b)) => Value::Bool(*b),
            (ColumnType::Int, J::Number(n)) => Value::Int(n.as_i64()?),
            (ColumnType::Text | ColumnType::Id, J::String(s)) => Value::Text(s.clone()),
            (ColumnType::Timestamp, J::String(s)) => Value::Timestamp(
                OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?,
            ),
            (ColumnType::Json, j) => Value::Json(j.clone()),
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("column `{column}`: {message}")]
pub struct DecodeError {
    pub column: String,
    pub message: String,
}

impl DecodeError {
    pub fn new(column: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            column: column.into(),
            message: message.into(),
        }
    }
}

/// Rust types that map to one column.
pub trait ColumnValue: Sized + Send + Sync + 'static {
    const TYPE: ColumnType;
    const NULLABLE: bool = false;
    fn into_value(self) -> Value;
    fn from_value(value: Value) -> Result<Self, String>;
}

macro_rules! column_value {
    ($ty:ty, $col:ident, $variant:ident) => {
        impl ColumnValue for $ty {
            const TYPE: ColumnType = ColumnType::$col;
            fn into_value(self) -> Value {
                Value::$variant(self)
            }
            fn from_value(value: Value) -> Result<Self, String> {
                match value {
                    Value::$variant(v) => Ok(v),
                    other => Err(format!("expected {}, got {other:?}", stringify!($variant))),
                }
            }
        }
    };
}

column_value!(bool, Bool, Bool);
column_value!(i64, Int, Int);
column_value!(String, Text, Text);
column_value!(Vec<u8>, Bytes, Bytes);
column_value!(OffsetDateTime, Timestamp, Timestamp);

impl<T: ColumnValue> ColumnValue for Option<T> {
    const TYPE: ColumnType = T::TYPE;
    const NULLABLE: bool = true;
    fn into_value(self) -> Value {
        self.map_or(Value::Null, ColumnValue::into_value)
    }
    fn from_value(value: Value) -> Result<Self, String> {
        match value {
            Value::Null => Ok(None),
            v => T::from_value(v).map(Some),
        }
    }
}

/// A JSON column holding `T`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Json<T>(pub T);

impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> ColumnValue for Json<T> {
    const TYPE: ColumnType = ColumnType::Json;
    fn into_value(self) -> Value {
        Value::Json(serde_json::to_value(self.0).unwrap_or(serde_json::Value::Null))
    }
    fn from_value(value: Value) -> Result<Self, String> {
        match value {
            Value::Json(j) => serde_json::from_value(j)
                .map(Json)
                .map_err(|e| e.to_string()),
            Value::Text(s) => serde_json::from_str(&s)
                .map(Json)
                .map_err(|e| e.to_string()),
            other => Err(format!("expected json, got {other:?}")),
        }
    }
}

/// A primary or foreign key. UUIDv7 text by default.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Id(String);

impl Id {
    pub fn new_v7() -> Self {
        Id(uuid::Uuid::now_v7().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for Id {
    fn from(s: String) -> Self {
        Id(s)
    }
}

impl From<&str> for Id {
    fn from(s: &str) -> Self {
        Id(s.to_owned())
    }
}

impl From<&Id> for Id {
    fn from(id: &Id) -> Self {
        id.clone()
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({})", self.0)
    }
}

impl ColumnValue for Id {
    const TYPE: ColumnType = ColumnType::Id;
    fn into_value(self) -> Value {
        Value::Text(self.0)
    }
    fn from_value(value: Value) -> Result<Self, String> {
        match value {
            Value::Text(s) => Ok(Id(s)),
            other => Err(format!("expected id, got {other:?}")),
        }
    }
}

impl ColumnValue for Hash {
    const TYPE: ColumnType = ColumnType::Bytes;
    fn into_value(self) -> Value {
        Value::Bytes(self.as_bytes().to_vec())
    }
    fn from_value(value: Value) -> Result<Self, String> {
        match value {
            Value::Bytes(b) => Hash::from_slice(&b).ok_or_else(|| "expected 32 bytes".to_owned()),
            other => Err(format!("expected hash bytes, got {other:?}")),
        }
    }
}

/// A row as the adapter returns it: values in the table's column order.
#[derive(Clone, Debug)]
pub struct Row {
    table: Arc<TableDef>,
    values: Vec<Value>,
}

impl Row {
    /// `values` must be in `table`'s column order. Adapters build rows with this.
    pub fn new(table: Arc<TableDef>, values: Vec<Value>) -> Self {
        debug_assert_eq!(
            table.columns.len(),
            values.len(),
            "row width for {}",
            table.name
        );
        Self { table, values }
    }

    pub fn table(&self) -> &Arc<TableDef> {
        &self.table
    }

    pub fn values(&self) -> &[Value] {
        &self.values
    }

    pub fn into_values(self) -> Vec<Value> {
        self.values
    }

    pub fn value(&self, column: &str) -> Option<&Value> {
        self.table.position(column).map(|i| &self.values[i])
    }

    pub fn get<T: ColumnValue>(&self, column: &str) -> Result<T, DecodeError> {
        let value = self.value(column).ok_or_else(|| {
            DecodeError::new(column, format!("no such column on `{}`", self.table.name))
        })?;
        T::from_value(value.clone()).map_err(|m| DecodeError::new(column, m))
    }

    pub(crate) fn set(&mut self, column: &str, value: Value) {
        if let Some(i) = self.table.position(column) {
            self.values[i] = value;
        }
    }

    /// The columns marked `returned`, as a camelCase JSON object: what clients see.
    pub fn to_client_json(&self) -> serde_json::Map<String, serde_json::Value> {
        self.table
            .columns
            .iter()
            .zip(&self.values)
            .filter(|(c, _)| c.returned)
            .map(|(c, v)| (camel_case(c.name), v.to_json()))
            .collect()
    }
}

pub(crate) fn camel_case(snake: &str) -> String {
    let mut out = String::with_capacity(snake.len());
    let mut upper = false;
    for ch in snake.chars() {
        if ch == '_' {
            upper = true;
        } else if upper {
            out.extend(ch.to_uppercase());
            upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}
