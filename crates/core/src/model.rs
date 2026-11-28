use std::marker::PhantomData;

use crate::query::Where;
use crate::schema::ColumnDef;
use crate::value::{ColumnValue, DecodeError, Row, Value};

/// A typed view over some columns of an existing table (`user` or `session`).
/// The app's `.user_fields::<U>()` and each plugin's `UserFields`/`SessionFields` implement it.
/// `#[derive(Fields)]` writes this.
pub trait Fields: Clone + Send + Sync + 'static {
    fn columns() -> &'static [ColumnDef];
    fn decode(row: &Row) -> Result<Self, DecodeError>;
}

impl Fields for () {
    fn columns() -> &'static [ColumnDef] {
        &[]
    }
    fn decode(_: &Row) -> Result<(), DecodeError> {
        Ok(())
    }
}

/// A table owned by core or a plugin. `#[derive(Model)]` writes this.
pub trait Model: Sized + Send + Sync + 'static {
    const TABLE: &'static str;
    fn columns() -> &'static [ColumnDef];
    fn decode(row: &Row) -> Result<Self, DecodeError>;
    /// Column values for an insert. Columns not listed get their default or NULL.
    fn encode(&self) -> Vec<(&'static str, Value)>;
}

/// Which table a typed column lives on. Models point at themselves; `Fields` point at the
/// table they extend, so `TwoFactorUser::TWO_FACTOR_ENABLED` can filter `find::<User>`.
pub trait OnTable {
    type Table: Model;
}

/// A typed column: comparing it with the wrong Rust type, or using it on another table,
/// does not compile.
pub struct Col<O, T> {
    name: &'static str,
    _marker: PhantomData<fn() -> (O, T)>,
}

impl<O, T> Clone for Col<O, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<O, T> Copy for Col<O, T> {}

impl<O, T> std::fmt::Debug for Col<O, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Col({})", self.name)
    }
}

impl<O: OnTable, T: ColumnValue> Col<O, T> {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            _marker: PhantomData,
        }
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The column paired with a value, for raw column lists such as a social profile mapping.
    pub fn value(self, value: impl Into<T>) -> (&'static str, Value) {
        (self.name, value.into().into_value())
    }

    pub fn eq(self, value: impl Into<T>) -> Where<O::Table> {
        Where::cmp(self.name, crate::adapter::Op::Eq, value.into().into_value())
    }

    pub fn ne(self, value: impl Into<T>) -> Where<O::Table> {
        Where::cmp(self.name, crate::adapter::Op::Ne, value.into().into_value())
    }

    pub fn lt(self, value: impl Into<T>) -> Where<O::Table> {
        Where::cmp(self.name, crate::adapter::Op::Lt, value.into().into_value())
    }

    pub fn lte(self, value: impl Into<T>) -> Where<O::Table> {
        Where::cmp(
            self.name,
            crate::adapter::Op::Lte,
            value.into().into_value(),
        )
    }

    pub fn gt(self, value: impl Into<T>) -> Where<O::Table> {
        Where::cmp(self.name, crate::adapter::Op::Gt, value.into().into_value())
    }

    pub fn gte(self, value: impl Into<T>) -> Where<O::Table> {
        Where::cmp(
            self.name,
            crate::adapter::Op::Gte,
            value.into().into_value(),
        )
    }

    pub fn in_(self, values: impl IntoIterator<Item = T>) -> Where<O::Table> {
        Where::in_list(
            self.name,
            values.into_iter().map(ColumnValue::into_value).collect(),
        )
    }

    pub fn is_null(self) -> Where<O::Table> {
        Where::null(self.name, true)
    }

    pub fn is_not_null(self) -> Where<O::Table> {
        Where::null(self.name, false)
    }

    pub fn asc(self) -> (&'static str, crate::adapter::Order) {
        (self.name, crate::adapter::Order::Asc)
    }

    pub fn desc(self) -> (&'static str, crate::adapter::Order) {
        (self.name, crate::adapter::Order::Desc)
    }
}

/// Case-sensitive text matches. The string matches literally: `%`, `_` and `*` are not
/// wildcards.
impl<O: OnTable> Col<O, String> {
    pub fn starts_with(self, prefix: impl Into<String>) -> Where<O::Table> {
        Where::starts_with(self.name, prefix.into())
    }

    pub fn contains(self, substring: impl Into<String>) -> Where<O::Table> {
        Where::contains(self.name, substring.into())
    }

    pub fn ends_with(self, suffix: impl Into<String>) -> Where<O::Table> {
        Where::ends_with(self.name, suffix.into())
    }
}
