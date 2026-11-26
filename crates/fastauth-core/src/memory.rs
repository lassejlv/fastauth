//! An in-memory adapter for tests and examples. Not for production: no durability, and a
//! transaction is a snapshot that overwrites the store on commit.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::adapter::{
    Adapter, DbError, DbResult, Delete, Filter, Insert, Op, Order, Queries, Select, Transaction,
    Update,
};
use crate::migrate::{LiveSchema, MigrationPlan, Step, duplicates_error, unique_key};
use crate::schema::TableDef;
use crate::value::{Row, Value};

type Tables = HashMap<&'static str, Vec<Vec<Value>>>;

#[derive(Clone, Default)]
pub struct MemoryAdapter {
    tables: Arc<Mutex<Tables>>,
    live: Arc<Mutex<LiveSchema>>,
}

impl std::fmt::Debug for MemoryAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryAdapter")
    }
}

impl MemoryAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every row of a table, for assertions in tests.
    pub fn dump(&self, table: &str) -> Vec<Vec<Value>> {
        self.tables
            .lock()
            .unwrap()
            .get(table)
            .cloned()
            .unwrap_or_default()
    }
}

fn compare(a: &Value, b: &Value) -> Option<Ordering> {
    match (a, b) {
        (Value::Bool(a), Value::Bool(b)) => a.partial_cmp(b),
        (Value::Int(a), Value::Int(b)) => a.partial_cmp(b),
        (Value::Text(a), Value::Text(b)) => a.partial_cmp(b),
        (Value::Bytes(a), Value::Bytes(b)) => a.partial_cmp(b),
        (Value::Timestamp(a), Value::Timestamp(b)) => a.partial_cmp(b),
        _ => None,
    }
}

fn matches(filter: &Filter, row: &[Value]) -> bool {
    match filter {
        Filter::All => true,
        Filter::Cmp { column, op, value } => {
            let cell = &row[*column];
            if cell.is_null() || value.is_null() {
                return false;
            }
            let Some(ord) = compare(cell, value) else {
                return *op == Op::Ne && cell != value;
            };
            match op {
                Op::Eq => ord == Ordering::Equal,
                Op::Ne => ord != Ordering::Equal,
                Op::Lt => ord == Ordering::Less,
                Op::Lte => ord != Ordering::Greater,
                Op::Gt => ord == Ordering::Greater,
                Op::Gte => ord != Ordering::Less,
            }
        }
        Filter::In { column, values } => values.contains(&row[*column]),
        Filter::Null { column, is_null } => row[*column].is_null() == *is_null,
        Filter::StartsWith { column, prefix } => {
            matches!(&row[*column], Value::Text(s) if s.starts_with(prefix.as_str()))
        }
        Filter::Contains { column, substring } => {
            matches!(&row[*column], Value::Text(s) if s.contains(substring.as_str()))
        }
        Filter::EndsWith { column, suffix } => {
            matches!(&row[*column], Value::Text(s) if s.ends_with(suffix.as_str()))
        }
        Filter::And(fs) => fs.iter().all(|f| matches(f, row)),
        Filter::Or(fs) => fs.iter().any(|f| matches(f, row)),
    }
}

fn check_unique(
    table: &TableDef,
    rows: &[Vec<Value>],
    candidate: &[Value],
    skip: Option<usize>,
) -> DbResult<()> {
    for (i, column) in table.columns.iter().enumerate() {
        if !(column.unique || column.primary_key) || candidate[i].is_null() {
            continue;
        }
        let clash = rows
            .iter()
            .enumerate()
            .any(|(r, row)| Some(r) != skip && row[i] == candidate[i]);
        if clash {
            return Err(DbError::UniqueViolation {
                table: table.name.to_owned(),
                column: Some(column.name.to_owned()),
            });
        }
    }
    for unique in &table.uniques {
        let positions: Vec<usize> = unique
            .columns
            .iter()
            .filter_map(|c| table.position(c))
            .collect();
        if positions.iter().any(|&i| candidate[i].is_null()) {
            continue;
        }
        let clash = rows
            .iter()
            .enumerate()
            .any(|(r, row)| Some(r) != skip && positions.iter().all(|&i| row[i] == candidate[i]));
        if clash {
            return Err(DbError::UniqueViolation {
                table: table.name.to_owned(),
                column: None,
            });
        }
    }
    Ok(())
}

/// Some rows of `table` that share non-null values in `columns`, for `Step::AddUnique`.
fn duplicates<'t>(
    table: &'t TableDef,
    rows: &[Vec<Value>],
    columns: &[&'t str],
) -> Vec<Vec<(&'t str, Value)>> {
    let positions: Vec<(&str, usize)> = table
        .primary_key()
        .map(|pk| pk.name)
        .into_iter()
        .chain(columns.iter().copied())
        .filter_map(|c| table.position(c).map(|i| (c, i)))
        .collect();
    let key = |row: &Vec<Value>| -> Option<Vec<Value>> {
        let values: Vec<Value> = columns
            .iter()
            .filter_map(|c| table.position(c))
            .map(|i| row[i].clone())
            .collect();
        (!values.iter().any(Value::is_null)).then_some(values)
    };
    rows.iter()
        .filter(|row| {
            key(row).is_some_and(|k| {
                rows.iter()
                    .filter(|other| key(other) == Some(k.clone()))
                    .count()
                    > 1
            })
        })
        .take(10)
        .map(|row| {
            positions
                .iter()
                .map(|&(c, i)| (c, row[i].clone()))
                .collect()
        })
        .collect()
}

fn select(tables: &Tables, q: &Select<'_>) -> Vec<Vec<Value>> {
    let mut rows: Vec<Vec<Value>> = tables
        .get(q.table.name)
        .into_iter()
        .flatten()
        .filter(|r| matches(&q.filter, r))
        .cloned()
        .collect();
    for (column, order) in q.order.iter().rev() {
        rows.sort_by(|a, b| {
            let ord = compare(&a[*column], &b[*column]).unwrap_or(Ordering::Equal);
            if *order == Order::Desc {
                ord.reverse()
            } else {
                ord
            }
        });
    }
    let offset = q.offset.unwrap_or(0) as usize;
    let limit = q.limit.map_or(usize::MAX, |l| l as usize);
    rows.into_iter().skip(offset).take(limit).collect()
}

fn insert(tables: &mut Tables, q: Insert<'_>) -> DbResult<Row> {
    let rows = tables.entry(q.table.name).or_default();
    check_unique(q.table, rows, &q.values, None)?;
    rows.push(q.values.clone());
    Ok(Row::new(q.table.clone(), q.values))
}

fn update(tables: &mut Tables, q: Update<'_>) -> DbResult<u64> {
    let rows = tables.entry(q.table.name).or_default();
    let targets: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| matches(&q.filter, r))
        .map(|(i, _)| i)
        .collect();
    for &i in &targets {
        let mut next = rows[i].clone();
        for (column, value) in &q.set {
            next[*column] = value.clone();
        }
        check_unique(q.table, rows, &next, Some(i))?;
        rows[i] = next;
    }
    Ok(targets.len() as u64)
}

fn delete(tables: &mut Tables, q: Delete<'_>) -> u64 {
    let rows = tables.entry(q.table.name).or_default();
    let before = rows.len();
    rows.retain(|r| !matches(&q.filter, r));
    (before - rows.len()) as u64
}

fn rows_of(table: &Arc<TableDef>, raw: Vec<Vec<Value>>) -> Vec<Row> {
    raw.into_iter()
        .map(|v| Row::new(table.clone(), v))
        .collect()
}

impl Queries for MemoryAdapter {
    async fn insert(&self, q: Insert<'_>) -> DbResult<Row> {
        insert(&mut self.tables.lock().unwrap(), q)
    }

    async fn find_one(&self, mut q: Select<'_>) -> DbResult<Option<Row>> {
        q.limit = Some(1);
        let raw = select(&self.tables.lock().unwrap(), &q);
        Ok(rows_of(q.table, raw).pop())
    }

    async fn find_many(&self, q: Select<'_>) -> DbResult<Vec<Row>> {
        let raw = select(&self.tables.lock().unwrap(), &q);
        Ok(rows_of(q.table, raw))
    }

    async fn update(&self, q: Update<'_>) -> DbResult<u64> {
        update(&mut self.tables.lock().unwrap(), q)
    }

    async fn delete(&self, q: Delete<'_>) -> DbResult<u64> {
        Ok(delete(&mut self.tables.lock().unwrap(), q))
    }

    async fn count(&self, q: Select<'_>) -> DbResult<u64> {
        Ok(select(&self.tables.lock().unwrap(), &q).len() as u64)
    }
}

/// A snapshot of the store. Commit writes it back; drop or rollback discards it.
pub struct MemoryTx {
    target: Arc<Mutex<Tables>>,
    snapshot: Mutex<Tables>,
}

impl Queries for MemoryTx {
    async fn insert(&self, q: Insert<'_>) -> DbResult<Row> {
        insert(&mut self.snapshot.lock().unwrap(), q)
    }

    async fn find_one(&self, mut q: Select<'_>) -> DbResult<Option<Row>> {
        q.limit = Some(1);
        let raw = select(&self.snapshot.lock().unwrap(), &q);
        Ok(rows_of(q.table, raw).pop())
    }

    async fn find_many(&self, q: Select<'_>) -> DbResult<Vec<Row>> {
        let raw = select(&self.snapshot.lock().unwrap(), &q);
        Ok(rows_of(q.table, raw))
    }

    async fn update(&self, q: Update<'_>) -> DbResult<u64> {
        update(&mut self.snapshot.lock().unwrap(), q)
    }

    async fn delete(&self, q: Delete<'_>) -> DbResult<u64> {
        Ok(delete(&mut self.snapshot.lock().unwrap(), q))
    }

    async fn count(&self, q: Select<'_>) -> DbResult<u64> {
        Ok(select(&self.snapshot.lock().unwrap(), &q).len() as u64)
    }
}

impl Transaction for MemoryTx {
    async fn commit(self) -> DbResult<()> {
        *self.target.lock().unwrap() = self.snapshot.into_inner().unwrap();
        Ok(())
    }

    async fn rollback(self) -> DbResult<()> {
        Ok(())
    }
}

impl Adapter for MemoryAdapter {
    type Tx = MemoryTx;

    async fn begin(&self) -> DbResult<MemoryTx> {
        let snapshot = self.tables.lock().unwrap().clone();
        Ok(MemoryTx {
            target: self.tables.clone(),
            snapshot: Mutex::new(snapshot),
        })
    }

    async fn introspect(&self) -> DbResult<LiveSchema> {
        Ok(self.live.lock().unwrap().clone())
    }

    async fn apply(&self, plan: &MigrationPlan) -> DbResult<()> {
        let tables = self.tables.lock().unwrap();
        for step in &plan.steps {
            if let Step::AddUnique { table, columns } = step {
                let rows = tables
                    .get(table.name)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                let clashing = duplicates(table, rows, columns);
                if !clashing.is_empty() {
                    return Err(duplicates_error(table.name, columns, &clashing));
                }
            }
        }
        drop(tables);
        let mut live = self.live.lock().unwrap();
        let mut uniques = live.uniques.take().unwrap_or_default();
        for step in &plan.steps {
            match step {
                Step::CreateTable(t) => {
                    live.tables.insert(
                        t.name.to_owned(),
                        t.columns.iter().map(|c| c.name.to_owned()).collect(),
                    );
                    uniques.extend(
                        t.columns
                            .iter()
                            .filter(|c| c.unique && !c.primary_key)
                            .map(|c| unique_key(t.name, &[c.name])),
                    );
                }
                Step::AddColumn { table, column } => {
                    live.tables
                        .entry(table.name.to_owned())
                        .or_default()
                        .insert(column.name.to_owned());
                    if column.unique {
                        uniques.insert(unique_key(table.name, &[column.name]));
                    }
                }
                Step::AddUnique { table, columns } => {
                    uniques.insert(unique_key(table.name, columns));
                }
                Step::CreateIndex { table, column } => {
                    live.indexes
                        .insert((table.name.to_owned(), column.name.to_owned()));
                }
            }
        }
        live.uniques = Some(uniques);
        Ok(())
    }
}
