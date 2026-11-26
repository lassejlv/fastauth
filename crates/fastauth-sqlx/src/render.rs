//! SQL text. Query text is rendered once per shape and cached; DDL is rendered per plan.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::RwLock;

use fastauth_core::adapter::{
    DbError, DbResult, Delete, Filter, Insert, Op, Order, Select, Update,
};
use fastauth_core::migrate::{MigrationPlan, Step, index_name};
use fastauth_core::schema::{ColumnDef, ColumnType, DefaultValue, OnDelete, Reference, TableDef};
use fastauth_core::value::Value;
use sqlx::{AssertSqlSafe, SqlSafeStr, SqlStr};

use crate::driver::{Driver, Param, stored_type};

/// How logical table names (`user`) map to stored ones (`"auth"."fa_user"`).
#[derive(Clone, Debug, Default)]
pub(crate) struct Names {
    pub(crate) schema: Option<String>,
    pub(crate) prefix: String,
    pub(crate) renames: HashMap<String, String>,
}

impl Names {
    pub(crate) fn physical(&self, table: &str) -> String {
        match self.renames.get(table) {
            Some(renamed) => renamed.clone(),
            None => format!("{}{table}", self.prefix),
        }
    }

    pub(crate) fn logical(&self, physical: &str) -> Option<String> {
        if let Some((logical, _)) = self.renames.iter().find(|(_, p)| *p == physical) {
            return Some(logical.clone());
        }
        physical
            .strip_prefix(self.prefix.as_str())
            .filter(|logical| !self.renames.contains_key(*logical))
            .map(str::to_owned)
    }

    fn qualified<DB: Driver>(&self, table: &str) -> String {
        let table = quote::<DB>(&self.physical(table));
        match &self.schema {
            Some(schema) => format!("{}.{table}", quote::<DB>(schema)),
            None => table,
        }
    }
}

pub(crate) fn quote<DB: Driver>(ident: &str) -> String {
    let q = DB::QUOTE;
    format!("{q}{}{q}", ident.replace(q, &format!("{q}{q}")))
}

pub(crate) fn unique_name(physical: &str, column: &str) -> String {
    format!("{physical}_{column}_key")
}

pub(crate) fn primary_key_name(physical: &str) -> String {
    format!("{physical}_pkey")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Kind {
    Insert,
    Select,
    Count,
    Update,
    Delete,
    SessionWithUser,
}

/// A cache key. `width` is the table's column count, so a schema that adds columns to a
/// table gets fresh SQL; `shape` is everything else the text depends on, never values.
#[derive(Debug, PartialEq, Eq, Hash)]
struct Key {
    kind: Kind,
    table: &'static str,
    width: usize,
    shape: String,
}

impl Key {
    fn new(kind: Kind, table: &TableDef, shape: String) -> Self {
        Self {
            kind,
            table: table.name,
            width: table.columns.len(),
            shape,
        }
    }
}

pub(crate) struct Statement {
    pub(crate) sql: SqlStr,
    pub(crate) params: Vec<Param>,
}

/// Renders and caches query text for one set of naming options.
#[derive(Debug, Default)]
pub(crate) struct Sql {
    pub(crate) names: Names,
    cache: RwLock<HashMap<Key, SqlStr>>,
}

impl Sql {
    pub(crate) fn new(names: Names) -> Self {
        Self {
            names,
            cache: RwLock::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn cached_shapes(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    fn cached(&self, key: Key, render: impl FnOnce() -> String) -> SqlStr {
        if let Some(sql) = self.cache.read().unwrap().get(&key) {
            return sql.clone();
        }
        let sql = AssertSqlSafe(render()).into_sql_str();
        self.cache
            .write()
            .unwrap()
            .entry(key)
            .or_insert(sql)
            .clone()
    }

    pub(crate) fn insert<DB: Driver>(&self, q: Insert<'_>) -> Statement {
        let table = q.table;
        let sql = self.cached(Key::new(Kind::Insert, table, String::new()), || {
            let columns = column_list::<DB>(table, None);
            let mut params = String::new();
            for n in 1..=table.columns.len() {
                if n > 1 {
                    params.push_str(", ");
                }
                DB::param(n, &mut params);
            }
            let mut sql = format!(
                "INSERT INTO {} ({columns}) VALUES ({params})",
                self.names.qualified::<DB>(table.name)
            );
            if DB::RETURNING {
                let _ = write!(sql, " RETURNING {columns}");
            }
            sql
        });
        let params = table
            .columns
            .iter()
            .zip(q.values)
            .map(|(column, value)| Param::write(value, stored_type(table, column.ty)))
            .collect();
        Statement { sql, params }
    }

    pub(crate) fn select<DB: Driver>(&self, q: Select<'_>) -> Statement {
        let table = q.table;
        let paged = q.limit.is_some() || q.offset.is_some();
        let mut shape = filter_shape(&q.filter);
        for (column, order) in &q.order {
            let _ = write!(shape, "|{column}{}", order_sql(*order));
        }
        if paged {
            shape.push_str("|paged");
        }
        let sql = self.cached(Key::new(Kind::Select, table, shape), || {
            let mut sql = format!(
                "SELECT {} FROM {} WHERE ",
                column_list::<DB>(table, None),
                self.names.qualified::<DB>(table.name)
            );
            let mut n = 0;
            render_filter::<DB>(table, &q.filter, &mut n, &mut sql);
            for (i, (column, order)) in q.order.iter().enumerate() {
                sql.push_str(if i == 0 { " ORDER BY " } else { ", " });
                let _ = write!(
                    sql,
                    "{} {}",
                    quote::<DB>(table.columns[*column].name),
                    order_sql(*order)
                );
            }
            if paged {
                sql.push_str(" LIMIT ");
                next_param::<DB>(&mut n, &mut sql);
                sql.push_str(" OFFSET ");
                next_param::<DB>(&mut n, &mut sql);
            }
            sql
        });
        let mut params = Vec::new();
        filter_params::<DB>(table, q.filter, &mut params);
        if paged {
            let int = |n: Option<u64>, default: i64| {
                let n = n.map_or(default, |n| i64::try_from(n).unwrap_or(i64::MAX));
                Param::write(Value::Int(n), ColumnType::Int)
            };
            params.push(int(q.limit, i64::MAX));
            params.push(int(q.offset, 0));
        }
        Statement { sql, params }
    }

    pub(crate) fn count<DB: Driver>(&self, table: &TableDef, filter: Filter) -> Statement {
        let sql = self.cached(Key::new(Kind::Count, table, filter_shape(&filter)), || {
            let mut sql = format!(
                "SELECT COUNT(*) FROM {} WHERE ",
                self.names.qualified::<DB>(table.name)
            );
            render_filter::<DB>(table, &filter, &mut 0, &mut sql);
            sql
        });
        let mut params = Vec::new();
        filter_params::<DB>(table, filter, &mut params);
        Statement { sql, params }
    }

    pub(crate) fn update<DB: Driver>(&self, q: Update<'_>) -> Statement {
        let table = q.table;
        let mut shape = filter_shape(&q.filter);
        for (column, _) in &q.set {
            let _ = write!(shape, "|{column}");
        }
        let sql = self.cached(Key::new(Kind::Update, table, shape), || {
            let mut sql = format!("UPDATE {} SET ", self.names.qualified::<DB>(table.name));
            let mut n = 0;
            for (i, (column, _)) in q.set.iter().enumerate() {
                if i > 0 {
                    sql.push_str(", ");
                }
                let _ = write!(sql, "{} = ", quote::<DB>(table.columns[*column].name));
                next_param::<DB>(&mut n, &mut sql);
            }
            sql.push_str(" WHERE ");
            render_filter::<DB>(table, &q.filter, &mut n, &mut sql);
            sql
        });
        let mut params: Vec<Param> = q
            .set
            .into_iter()
            .map(|(column, value)| {
                Param::write(value, stored_type(table, table.columns[column].ty))
            })
            .collect();
        filter_params::<DB>(table, q.filter, &mut params);
        Statement { sql, params }
    }

    pub(crate) fn delete<DB: Driver>(&self, q: Delete<'_>) -> Statement {
        let table = q.table;
        let sql = self.cached(
            Key::new(Kind::Delete, table, filter_shape(&q.filter)),
            || {
                let mut sql = format!(
                    "DELETE FROM {} WHERE ",
                    self.names.qualified::<DB>(table.name)
                );
                render_filter::<DB>(table, &q.filter, &mut 0, &mut sql);
                sql
            },
        );
        let mut params = Vec::new();
        filter_params::<DB>(table, q.filter, &mut params);
        Statement { sql, params }
    }

    /// One row: the session's columns, then the user's.
    pub(crate) fn session_with_user<DB: Driver>(
        &self,
        session: &TableDef,
        user: &TableDef,
        token_hash: Vec<u8>,
    ) -> Statement {
        let shape = user.columns.len().to_string();
        let sql = self.cached(Key::new(Kind::SessionWithUser, session, shape), || {
            let mut param = String::new();
            DB::param(1, &mut param);
            format!(
                "SELECT {}, {} FROM {} AS s JOIN {} AS u ON u.{} = s.{} WHERE s.{} = {param} LIMIT 1",
                column_list::<DB>(session, Some("s")),
                column_list::<DB>(user, Some("u")),
                self.names.qualified::<DB>(session.name),
                self.names.qualified::<DB>(user.name),
                quote::<DB>("id"),
                quote::<DB>("user_id"),
                quote::<DB>("token_hash"),
            )
        });
        Statement {
            sql,
            params: vec![Param::write(Value::Bytes(token_hash), ColumnType::Bytes)],
        }
    }
}

fn column_list<DB: Driver>(table: &TableDef, alias: Option<&str>) -> String {
    let mut out = String::new();
    for (i, column) in table.columns.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        if let Some(alias) = alias {
            out.push_str(alias);
            out.push('.');
        }
        out.push_str(&quote::<DB>(column.name));
    }
    out
}

fn order_sql(order: Order) -> &'static str {
    match order {
        Order::Asc => "ASC",
        Order::Desc => "DESC",
    }
}

fn next_param<DB: Driver>(n: &mut usize, out: &mut String) {
    *n += 1;
    DB::param(*n, out);
}

fn filter_shape(filter: &Filter) -> String {
    fn walk(filter: &Filter, out: &mut String) {
        let _ = match filter {
            Filter::All => write!(out, "*"),
            Filter::Cmp { column, op, .. } => write!(out, "c{column}{op:?};"),
            Filter::In { column, values } => write!(out, "i{column}:{};", values.len()),
            Filter::Null { column, is_null } => write!(out, "n{column}{is_null};"),
            Filter::StartsWith { column, .. } => write!(out, "s{column};"),
            Filter::Contains { column, .. } => write!(out, "t{column};"),
            Filter::EndsWith { column, .. } => write!(out, "e{column};"),
            Filter::And(filters) | Filter::Or(filters) => {
                out.push_str(if matches!(filter, Filter::And(_)) {
                    "&("
                } else {
                    "|("
                });
                for filter in filters {
                    walk(filter, out);
                }
                write!(out, ")")
            }
            _ => unreachable!("check_filter rejects unknown filters"),
        };
    }
    let mut out = String::new();
    walk(filter, &mut out);
    out
}

fn render_filter<DB: Driver>(table: &TableDef, filter: &Filter, n: &mut usize, out: &mut String) {
    let column = |i: usize| quote::<DB>(table.columns[i].name);
    match filter {
        Filter::All => out.push_str("1 = 1"),
        Filter::Cmp { column: c, op, .. } => {
            out.push_str(&column(*c));
            out.push_str(match op {
                Op::Eq => " = ",
                Op::Ne => " <> ",
                Op::Lt => " < ",
                Op::Lte => " <= ",
                Op::Gt => " > ",
                Op::Gte => " >= ",
            });
            next_param::<DB>(n, out);
        }
        Filter::In { values, .. } if values.is_empty() => out.push_str("1 = 0"),
        Filter::In { column: c, values } => {
            out.push_str(&column(*c));
            out.push_str(" IN (");
            for i in 0..values.len() {
                if i > 0 {
                    out.push_str(", ");
                }
                next_param::<DB>(n, out);
            }
            out.push(')');
        }
        Filter::Null { column: c, is_null } => {
            out.push_str(&column(*c));
            out.push_str(if *is_null { " IS NULL" } else { " IS NOT NULL" });
        }
        Filter::StartsWith { column: c, .. }
        | Filter::Contains { column: c, .. }
        | Filter::EndsWith { column: c, .. } => {
            let (op, suffix) = DB::TEXT_MATCH;
            let _ = write!(out, "{} {op} ", column(*c));
            next_param::<DB>(n, out);
            out.push_str(suffix);
        }
        Filter::And(filters) if filters.is_empty() => out.push_str("1 = 1"),
        Filter::Or(filters) if filters.is_empty() => out.push_str("1 = 0"),
        Filter::And(filters) | Filter::Or(filters) => {
            let joiner = if matches!(filter, Filter::And(_)) {
                " AND "
            } else {
                " OR "
            };
            out.push('(');
            for (i, filter) in filters.iter().enumerate() {
                if i > 0 {
                    out.push_str(joiner);
                }
                render_filter::<DB>(table, filter, n, out);
            }
            out.push(')');
        }
        _ => unreachable!("check_filter rejects unknown filters"),
    }
}

fn filter_params<DB: Driver>(table: &TableDef, filter: Filter, out: &mut Vec<Param>) {
    match filter {
        Filter::All | Filter::Null { .. } => {}
        Filter::Cmp { column, value, .. } => {
            out.push(Param::filter(
                value,
                stored_type(table, table.columns[column].ty),
            ));
        }
        Filter::In { column, values } => {
            let ty = stored_type(table, table.columns[column].ty);
            out.extend(values.into_iter().map(|value| Param::filter(value, ty)));
        }
        Filter::StartsWith { prefix, .. } => {
            out.push(text_pattern::<DB>(DB::escape_pattern(&prefix), false, true));
        }
        Filter::Contains { substring, .. } => {
            out.push(text_pattern::<DB>(
                DB::escape_pattern(&substring),
                true,
                true,
            ));
        }
        Filter::EndsWith { suffix, .. } => {
            out.push(text_pattern::<DB>(DB::escape_pattern(&suffix), true, false));
        }
        Filter::And(filters) | Filter::Or(filters) => {
            for filter in filters {
                filter_params::<DB>(table, filter, out);
            }
        }
        _ => unreachable!("check_filter rejects unknown filters"),
    }
}

/// The `TEXT_MATCH` parameter for an escaped pattern, with wildcards before and after.
fn text_pattern<DB: Driver>(escaped: String, before: bool, after: bool) -> Param {
    let mut pattern = String::with_capacity(escaped.len() + 2);
    if before {
        pattern.push(DB::WILDCARD);
    }
    pattern.push_str(&escaped);
    if after {
        pattern.push(DB::WILDCARD);
    }
    Param::write(Value::Text(pattern), ColumnType::Text)
}

/// Fails on a filter variant this adapter doesn't render, which a newer `fastauth-core` may
/// add, instead of running a query that means something else.
pub(crate) fn check_filter(filter: &Filter) -> DbResult<()> {
    match filter {
        Filter::All
        | Filter::Cmp { .. }
        | Filter::In { .. }
        | Filter::Null { .. }
        | Filter::StartsWith { .. }
        | Filter::Contains { .. }
        | Filter::EndsWith { .. } => Ok(()),
        Filter::And(filters) | Filter::Or(filters) => filters.iter().try_for_each(check_filter),
        _ => Err(DbError::Unsupported("this filter (update fastauth-sqlx)")),
    }
}

/// The statements for a migration plan, in order, without trailing semicolons.
pub(crate) fn ddl<DB: Driver>(names: &Names, plan: &MigrationPlan) -> Vec<String> {
    let mut out = Vec::new();
    if plan.is_empty() {
        return out;
    }
    if let Some(schema) = &names.schema {
        out.push(format!(
            "CREATE SCHEMA IF NOT EXISTS {}",
            quote::<DB>(schema)
        ));
    }
    for step in &plan.steps {
        match step {
            Step::CreateTable(table) => {
                let mut lines: Vec<String> = table
                    .columns
                    .iter()
                    .map(|column| column_def::<DB>(names, table, column, false))
                    .collect();
                if !DB::INLINE_CONSTRAINTS {
                    for column in &table.columns {
                        lines.extend(constraints::<DB>(names, table, column));
                    }
                }
                out.push(format!(
                    "CREATE TABLE {} (\n    {}\n){}",
                    names.qualified::<DB>(table.name),
                    lines.join(",\n    "),
                    DB::TABLE_OPTIONS
                ));
            }
            Step::AddColumn { table, column } => {
                let qualified = names.qualified::<DB>(table.name);
                out.push(format!(
                    "ALTER TABLE {qualified} ADD COLUMN {}",
                    column_def::<DB>(names, table, column, true)
                ));
                if !DB::INLINE_CONSTRAINTS {
                    for constraint in constraints::<DB>(names, table, column) {
                        out.push(format!("ALTER TABLE {qualified} ADD {constraint}"));
                    }
                } else if column.unique && !DB::UNIQUE_ON_ADD_COLUMN {
                    let name = unique_name(&names.physical(table.name), column.name);
                    out.push(format!(
                        "CREATE UNIQUE INDEX {} ON {qualified} ({})",
                        quote::<DB>(&DB::ident(name)),
                        quote::<DB>(column.name)
                    ));
                }
            }
            Step::CreateIndex { table, column } => {
                let name = index_name(&names.physical(table.name), column.name);
                out.push(format!(
                    "CREATE INDEX {} ON {} ({})",
                    quote::<DB>(&DB::ident(name)),
                    names.qualified::<DB>(table.name),
                    quote::<DB>(column.name)
                ));
            }
            Step::AddUnique { table, columns } => {
                let name = unique_name(&names.physical(table.name), &columns.join("_"));
                let parts: Vec<String> = columns
                    .iter()
                    .map(|column| key_part::<DB>(table, columns, column))
                    .collect();
                out.push(format!(
                    "CREATE UNIQUE INDEX {} ON {} ({})",
                    quote::<DB>(&DB::ident(name)),
                    names.qualified::<DB>(table.name),
                    parts.join(", ")
                ));
            }
        }
    }
    out
}

/// One column of a unique index over `columns`. Where keys are small (MySQL), each text
/// column of a multi-column index gets an equal share of the key as a prefix length. Ids
/// and the provider ids fastauth stores are far shorter than their share (at least 384
/// characters for two text columns), so the prefix is the whole value in practice.
fn key_part<DB: Driver>(table: &TableDef, columns: &[&str], column: &str) -> String {
    let quoted = quote::<DB>(column);
    let Some(budget) = DB::KEY_BYTES.filter(|_| columns.len() > 1) else {
        return quoted;
    };
    let ty = |name: &str| table.column(name).map(|c| stored_type(table, c.ty));
    if ty(column) != Some(ColumnType::Text) {
        return quoted;
    }
    let texts = columns
        .iter()
        .filter(|c| ty(c) == Some(ColumnType::Text))
        .count();
    let fixed: usize = columns
        .iter()
        .map(|c| match ty(c) {
            Some(ColumnType::Text) => 0,
            Some(ColumnType::Bytes) => 255,
            _ => 16,
        })
        .sum();
    format!("{quoted}({})", budget.saturating_sub(fixed) / 4 / texts)
}

/// The rows of `table` that share non-null values in `columns` (some of them), primary
/// key first, for refusing a `Step::AddUnique` with a message that names them.
pub(crate) fn duplicates<DB: Driver>(names: &Names, table: &TableDef, columns: &[&str]) -> SqlStr {
    let qualified = names.qualified::<DB>(table.name);
    let list = |cols: &[&str]| {
        cols.iter()
            .map(|c| quote::<DB>(c))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let keys = list(columns);
    let selected: Vec<&str> = table
        .primary_key()
        .map(|pk| pk.name)
        .into_iter()
        .chain(columns.iter().copied())
        .collect();
    let not_null = columns
        .iter()
        .map(|c| format!("{} IS NOT NULL", quote::<DB>(c)))
        .collect::<Vec<_>>()
        .join(" AND ");
    AssertSqlSafe(format!(
        "SELECT {} FROM {qualified} WHERE ({keys}) IN (SELECT {keys} FROM {qualified} \
         WHERE {not_null} GROUP BY {keys} HAVING COUNT(*) > 1) ORDER BY {keys} LIMIT 10",
        list(&selected)
    ))
    .into_sql_str()
}

fn column_def<DB: Driver>(
    names: &Names,
    table: &TableDef,
    column: &ColumnDef,
    adding: bool,
) -> String {
    let physical = names.physical(table.name);
    let keyed = column.primary_key
        || column.unique
        || column.index
        || column.references.is_some()
        || column.ty == ColumnType::Id
        || table
            .uniques
            .iter()
            .any(|u| u.columns.contains(&column.name));
    let mut def = format!(
        "{} {}",
        quote::<DB>(column.name),
        DB::sql_type(stored_type(table, column.ty), keyed)
    );
    if !column.nullable {
        def.push_str(" NOT NULL");
    }
    if let Some(default) = column.default {
        let value = match default {
            DefaultValue::Bool(b) => DB::bool_literal(b).to_owned(),
            DefaultValue::Int(i) => i.to_string(),
            DefaultValue::Text(s) => format!("'{}'", s.replace('\'', "''")),
            DefaultValue::Now => DB::now_default(adding),
        };
        let _ = write!(def, " DEFAULT {}", DB::default_expr(value));
    }
    if !DB::INLINE_CONSTRAINTS {
        return def;
    }
    if column.primary_key {
        let name = DB::ident(primary_key_name(&physical));
        let _ = write!(def, " CONSTRAINT {} PRIMARY KEY", quote::<DB>(&name));
    } else if column.unique && (!adding || DB::UNIQUE_ON_ADD_COLUMN) {
        let name = DB::ident(unique_name(&physical, column.name));
        let _ = write!(def, " CONSTRAINT {} UNIQUE", quote::<DB>(&name));
    }
    if let Some(reference) = column.references {
        let _ = write!(def, " {}", references::<DB>(names, reference));
    }
    def
}

/// `column`'s PRIMARY KEY, UNIQUE and FOREIGN KEY constraints as table constraints, for a
/// database that doesn't take them in the column definition.
fn constraints<DB: Driver>(names: &Names, table: &TableDef, column: &ColumnDef) -> Vec<String> {
    let physical = names.physical(table.name);
    let name = |name: String| quote::<DB>(&DB::ident(name));
    let quoted = quote::<DB>(column.name);
    let mut out = Vec::new();
    if column.primary_key {
        let name = name(primary_key_name(&physical));
        out.push(format!("CONSTRAINT {name} PRIMARY KEY ({quoted})"));
    } else if column.unique {
        let name = name(unique_name(&physical, column.name));
        out.push(format!("CONSTRAINT {name} UNIQUE ({quoted})"));
    }
    if let Some(reference) = column.references {
        let name = name(format!("{physical}_{}_fkey", column.name));
        out.push(format!(
            "CONSTRAINT {name} FOREIGN KEY ({quoted}) {}",
            references::<DB>(names, reference)
        ));
    }
    out
}

fn references<DB: Driver>(names: &Names, reference: Reference) -> String {
    let on_delete = match reference.on_delete {
        OnDelete::Cascade => "CASCADE",
        OnDelete::SetNull => "SET NULL",
        OnDelete::Restrict => "RESTRICT",
    };
    format!(
        "REFERENCES {} ({}) ON DELETE {on_delete}",
        names.qualified::<DB>(reference.table),
        quote::<DB>(reference.column)
    )
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use fastauth_core::adapter::{Filter, Op, Select};
    use fastauth_core::config::IdStrategy;
    use fastauth_core::testing::conformance_schema;
    use fastauth_core::value::Value;
    use sqlx::Sqlite;

    use super::{Names, Sql};

    #[test]
    fn query_text_is_cached_per_shape_not_per_value() {
        let schema = conformance_schema(&IdStrategy::default(), false);
        let user = schema.expect("user");
        let sql = Sql::new(Names::default());
        let select = |filter: Filter| Select {
            table: user,
            filter,
            order: Vec::new(),
            limit: None,
            offset: None,
        };
        let email = |value: &str| Filter::Cmp {
            column: 1,
            op: Op::Eq,
            value: Value::Text(value.to_owned()),
        };
        let ids = |n: usize| Filter::In {
            column: 0,
            values: vec![Value::Text("x".into()); n],
        };

        let first = sql.select::<Sqlite>(select(email("a@acme.dk")));
        let second = sql.select::<Sqlite>(select(email("b@acme.dk")));
        assert_eq!(first.sql, second.sql);
        assert_eq!(sql.cached_shapes(), 1);
        assert!(
            first.sql.as_str().ends_with("WHERE \"email\" = ?1"),
            "{}",
            first.sql.as_str()
        );
        assert!(!first.sql.as_str().contains("a@acme.dk"));

        sql.select::<Sqlite>(select(ids(2)));
        sql.select::<Sqlite>(select(ids(2)));
        sql.select::<Sqlite>(select(ids(3)));
        assert_eq!(sql.cached_shapes(), 3);
    }
}
