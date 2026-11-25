//! The typed query builder plugins use through `ctx.db()`.

use std::marker::PhantomData;
use std::sync::Arc;

use crate::adapter::{
    DbError, DbResult, Delete, Filter, Insert, Op, Order, Queries, Select, Update,
};
use crate::model::{Col, Model, OnTable};
use crate::schema::{DefaultValue, Schema, TableDef};
use crate::value::{ColumnValue, Row, Value};

#[derive(Clone, Debug, PartialEq)]
enum Expr {
    All,
    Cmp(&'static str, Op, Value),
    In(&'static str, Vec<Value>),
    Null(&'static str, bool),
    StartsWith(&'static str, String),
    Contains(&'static str, String),
    EndsWith(&'static str, String),
    And(Vec<Expr>),
    Or(Vec<Expr>),
}

/// A filter on model `M`'s table, built from typed columns.
#[derive(Clone, Debug, PartialEq)]
pub struct Where<M> {
    expr: Expr,
    _model: PhantomData<fn() -> M>,
}

impl<M> Where<M> {
    fn wrap(expr: Expr) -> Self {
        Self {
            expr,
            _model: PhantomData,
        }
    }

    pub fn all() -> Self {
        Self::wrap(Expr::All)
    }

    pub(crate) fn cmp(column: &'static str, op: Op, value: Value) -> Self {
        Self::wrap(Expr::Cmp(column, op, value))
    }

    pub(crate) fn in_list(column: &'static str, values: Vec<Value>) -> Self {
        Self::wrap(Expr::In(column, values))
    }

    pub(crate) fn null(column: &'static str, is_null: bool) -> Self {
        Self::wrap(Expr::Null(column, is_null))
    }

    pub(crate) fn starts_with(column: &'static str, prefix: String) -> Self {
        Self::wrap(Expr::StartsWith(column, prefix))
    }

    pub(crate) fn contains(column: &'static str, substring: String) -> Self {
        Self::wrap(Expr::Contains(column, substring))
    }

    pub(crate) fn ends_with(column: &'static str, suffix: String) -> Self {
        Self::wrap(Expr::EndsWith(column, suffix))
    }

    pub fn and(self, other: Where<M>) -> Self {
        Self::wrap(Expr::And(vec![self.expr, other.expr]))
    }

    pub fn or(self, other: Where<M>) -> Self {
        Self::wrap(Expr::Or(vec![self.expr, other.expr]))
    }

    pub(crate) fn resolve(&self, table: &TableDef) -> DbResult<Filter> {
        resolve(&self.expr, table)
    }
}

fn position(table: &TableDef, column: &str) -> DbResult<usize> {
    table
        .position(column)
        .ok_or_else(|| DbError::Schema(format!("`{}` has no column `{column}`", table.name)))
}

fn resolve(expr: &Expr, table: &TableDef) -> DbResult<Filter> {
    Ok(match expr {
        Expr::All => Filter::All,
        Expr::Cmp(c, op, v) => Filter::Cmp {
            column: position(table, c)?,
            op: *op,
            value: v.clone(),
        },
        Expr::In(c, vs) => Filter::In {
            column: position(table, c)?,
            values: vs.clone(),
        },
        Expr::Null(c, n) => Filter::Null {
            column: position(table, c)?,
            is_null: *n,
        },
        Expr::StartsWith(c, p) => Filter::StartsWith {
            column: position(table, c)?,
            prefix: p.clone(),
        },
        Expr::Contains(c, s) => Filter::Contains {
            column: position(table, c)?,
            substring: s.clone(),
        },
        Expr::EndsWith(c, s) => Filter::EndsWith {
            column: position(table, c)?,
            suffix: s.clone(),
        },
        Expr::And(es) => Filter::And(
            es.iter()
                .map(|e| resolve(e, table))
                .collect::<DbResult<_>>()?,
        ),
        Expr::Or(es) => Filter::Or(
            es.iter()
                .map(|e| resolve(e, table))
                .collect::<DbResult<_>>()?,
        ),
    })
}

/// Builds a full row for `table`: given values, then defaults, then NULL.
pub(crate) fn full_row(table: &TableDef, given: Vec<(&str, Value)>) -> DbResult<Vec<Value>> {
    let mut values: Vec<Option<Value>> = vec![None; table.columns.len()];
    for (name, value) in given {
        values[position(table, name)?] = Some(value);
    }
    let now = time::OffsetDateTime::now_utc();
    table
        .columns
        .iter()
        .zip(values)
        .map(|(column, value)| {
            Ok(match (value, column.default) {
                (Some(v), _) => v,
                (None, Some(DefaultValue::Bool(b))) => Value::Bool(b),
                (None, Some(DefaultValue::Int(i))) => Value::Int(i),
                (None, Some(DefaultValue::Text(s))) => Value::Text(s.to_owned()),
                (None, Some(DefaultValue::Now)) => Value::Timestamp(now),
                (None, None) if column.nullable => Value::Null,
                (None, None) => {
                    return Err(DbError::Schema(format!(
                        "`{}.{}` needs a value",
                        table.name, column.name
                    )));
                }
            })
        })
        .collect()
}

/// Typed access to the database, over the adapter or a transaction.
pub struct Db<'a, Q: ?Sized> {
    queries: &'a Q,
    schema: &'a Schema,
}

impl<Q: ?Sized> Clone for Db<'_, Q> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Q: ?Sized> Copy for Db<'_, Q> {}

impl<'a, Q: Queries + ?Sized> Db<'a, Q> {
    pub fn new(queries: &'a Q, schema: &'a Schema) -> Self {
        Self { queries, schema }
    }

    pub fn schema(&self) -> &'a Schema {
        self.schema
    }

    pub fn raw(&self) -> &'a Q {
        self.queries
    }

    fn table<M: Model>(&self) -> DbResult<&'a Arc<TableDef>> {
        self.schema
            .table(M::TABLE)
            .ok_or_else(|| DbError::Schema(format!("table `{}` is not registered", M::TABLE)))
    }

    pub fn find<M: Model>(&self, filter: Where<M>) -> Find<'a, Q, M> {
        Find {
            db: *self,
            filter,
            order: Vec::new(),
            limit: None,
            offset: None,
        }
    }

    pub async fn insert<M: Model>(&self, model: &M) -> DbResult<M> {
        let table = self.table::<M>()?;
        let values = full_row(table, model.encode())?;
        let row = self.queries.insert(Insert { table, values }).await?;
        Ok(M::decode(&row)?)
    }

    /// Inserts raw column values into `M`'s table, filling defaults. Returns the stored row.
    pub async fn insert_row<M: Model>(&self, values: Vec<(&str, Value)>) -> DbResult<Row> {
        let table = self.table::<M>()?;
        let values = full_row(table, values)?;
        self.queries.insert(Insert { table, values }).await
    }

    pub fn update<M: Model>(&self, filter: Where<M>) -> UpdateBuilder<'a, Q, M> {
        UpdateBuilder {
            db: *self,
            filter,
            set: Vec::new(),
        }
    }

    pub async fn delete<M: Model>(&self, filter: Where<M>) -> DbResult<u64> {
        let table = self.table::<M>()?;
        let filter = filter.resolve(table)?;
        self.queries.delete(Delete { table, filter }).await
    }

    pub async fn count<M: Model>(&self, filter: Where<M>) -> DbResult<u64> {
        let table = self.table::<M>()?;
        let filter = filter.resolve(table)?;
        self.queries
            .count(Select {
                table,
                filter,
                order: Vec::new(),
                limit: None,
                offset: None,
            })
            .await
    }
}

pub struct Find<'a, Q: ?Sized, M> {
    db: Db<'a, Q>,
    filter: Where<M>,
    order: Vec<(&'static str, Order)>,
    limit: Option<u64>,
    offset: Option<u64>,
}

impl<'a, Q: Queries + ?Sized, M: Model> Find<'a, Q, M> {
    pub fn order_by(mut self, (column, order): (&'static str, Order)) -> Self {
        self.order.push((column, order));
        self
    }

    pub fn limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    fn select(&self, limit: Option<u64>) -> DbResult<Select<'a>> {
        let table = self.db.table::<M>()?;
        let order = self
            .order
            .iter()
            .map(|(c, o)| Ok((position(table, c)?, *o)))
            .collect::<DbResult<_>>()?;
        Ok(Select {
            table,
            filter: self.filter.resolve(table)?,
            order,
            limit,
            offset: self.offset,
        })
    }

    pub async fn one(self) -> DbResult<Option<M>> {
        Ok(self.one_row().await?.map(|r| M::decode(&r)).transpose()?)
    }

    pub async fn all(self) -> DbResult<Vec<M>> {
        let rows = self.db.queries.find_many(self.select(self.limit)?).await?;
        Ok(rows.iter().map(M::decode).collect::<Result<_, _>>()?)
    }

    /// The raw row, including columns plugins added (decode them with `Fields::decode`).
    pub async fn one_row(self) -> DbResult<Option<Row>> {
        self.db.queries.find_one(self.select(Some(1))?).await
    }

    pub async fn all_rows(self) -> DbResult<Vec<Row>> {
        self.db.queries.find_many(self.select(self.limit)?).await
    }
}

pub struct UpdateBuilder<'a, Q: ?Sized, M> {
    db: Db<'a, Q>,
    filter: Where<M>,
    set: Vec<(&'static str, Value)>,
}

impl<Q: Queries + ?Sized, M: Model> UpdateBuilder<'_, Q, M> {
    pub fn set<O: OnTable<Table = M>, T: ColumnValue>(
        mut self,
        column: Col<O, T>,
        value: impl Into<T>,
    ) -> Self {
        self.set.push((column.name(), value.into().into_value()));
        self
    }

    /// Sets a column by name, for values whose column isn't known at compile time.
    pub fn set_raw(mut self, column: &'static str, value: Value) -> Self {
        self.set.push((column, value));
        self
    }

    pub async fn exec(self) -> DbResult<u64> {
        let table = self.db.table::<M>()?;
        let mut set = self
            .set
            .iter()
            .map(|(c, v)| Ok((position(table, c)?, v.clone())))
            .collect::<DbResult<Vec<_>>>()?;
        if let Some(updated_at) = table.position("updated_at")
            && !set.iter().any(|(i, _)| *i == updated_at)
        {
            set.push((
                updated_at,
                Value::Timestamp(time::OffsetDateTime::now_utc()),
            ));
        }
        let filter = self.filter.resolve(table)?;
        self.db.queries.update(Update { table, filter, set }).await
    }
}
