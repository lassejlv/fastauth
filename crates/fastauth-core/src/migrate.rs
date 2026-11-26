//! Diffs the configured schema against the live database. Only ever adds.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use crate::adapter::{Adapter, DbError, DbResult};
use crate::schema::{ColumnDef, ColumnType, IdStorage, Schema, TableDef};
use crate::value::Value;

/// What exists in the database, as reported by `Adapter::introspect`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LiveSchema {
    /// Table name to its column names.
    pub tables: HashMap<String, HashSet<String>>,
    /// `(table, column)` pairs with a non-unique index named by `index_name`. Unique
    /// columns are created with an inline constraint and aren't listed here.
    pub indexes: HashSet<(String, String)>,
    /// `(table, column)` pairs whose live type is one an id column can have, and which
    /// one: Postgres reports its `uuid` and `text` columns. Adapters that store ids the
    /// same way under every strategy (SQLite, always `text`) leave it empty.
    pub id_storage: HashMap<(String, String), IdStorage>,
    /// The column sets the database keeps unique, primary keys aside, as [`unique_key`]
    /// builds them. `None` when the adapter doesn't report them: the migrator then adds
    /// unique constraints only with the tables and columns it creates, and can't see one
    /// that is missing from an existing table.
    pub uniques: Option<HashSet<(String, Vec<String>)>>,
}

/// How [`LiveSchema::uniques`] names a unique constraint: the table and its sorted columns.
pub fn unique_key(table: &str, columns: &[impl AsRef<str>]) -> (String, Vec<String>) {
    let mut columns: Vec<String> = columns.iter().map(|c| c.as_ref().to_owned()).collect();
    columns.sort();
    (table.to_owned(), columns)
}

#[derive(Clone, Debug, PartialEq)]
pub enum Step {
    CreateTable(Arc<TableDef>),
    AddColumn {
        table: Arc<TableDef>,
        column: ColumnDef,
    },
    /// A non-unique index (`ColumnDef::index`). Unique columns get an inline constraint.
    CreateIndex {
        table: Arc<TableDef>,
        column: ColumnDef,
    },
    /// A unique constraint on columns that already exist, or will once the steps before it
    /// ran: every [`UniqueDef`](crate::schema::UniqueDef) of a new table, and any unique
    /// set an existing table is missing. Adapters refuse it, naming the rows, when the
    /// table holds duplicates.
    AddUnique {
        table: Arc<TableDef>,
        columns: Vec<&'static str>,
    },
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Step::CreateTable(t) => write!(
                f,
                "create table {} ({} columns, owner {})",
                t.name,
                t.columns.len(),
                t.owner
            ),
            Step::AddColumn { table, column } => {
                write!(
                    f,
                    "add column {}.{} ({:?}, owner {})",
                    table.name, column.name, column.ty, column.owner
                )
            }
            Step::CreateIndex { table, column } => {
                write!(
                    f,
                    "create {}index on {}.{}",
                    if column.unique { "unique " } else { "" },
                    table.name,
                    column.name
                )
            }
            Step::AddUnique { table, columns } => {
                write!(f, "add unique ({}) on {}", columns.join(", "), table.name)
            }
        }
    }
}

/// What an adapter answers for a [`Step::AddUnique`] on a table that already holds rows
/// sharing `columns`: `rows` are some of them, each as `(column, value)` pairs.
pub fn duplicates_error(table: &str, columns: &[&str], rows: &[Vec<(&str, Value)>]) -> DbError {
    let rows: Vec<String> = rows
        .iter()
        .map(|row| {
            let pairs: Vec<String> = row
                .iter()
                .map(|(column, value)| format!("{column}={}", show(value)))
                .collect();
            format!("{{{}}}", pairs.join(", "))
        })
        .collect();
    DbError::Schema(format!(
        "can't add UNIQUE ({}) to `{table}`: these rows share the same values: {}. Delete or \
         merge the duplicates, then run the migrator again (docs/concepts/02-database.md, \
         \"Unique constraints on an existing database\", has a query for each table)",
        columns.join(", "),
        rows.join("; ")
    ))
}

fn show(value: &Value) -> String {
    match value {
        Value::Null => "NULL".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Text(text) => format!("{text:?}"),
        Value::Bytes(bytes) => bytes.iter().map(|b| format!("{b:02x}")).collect(),
        Value::Timestamp(at) => at.to_string(),
        Value::Json(json) => json.to_string(),
    }
}

/// Index name every adapter uses, so introspection can recognise fastauth's indexes.
pub fn index_name(table: &str, column: &str) -> String {
    format!("idx_{table}_{column}")
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MigrationPlan {
    pub steps: Vec<Step>,
    /// Differences the migrator won't fix: extra columns, NOT NULL columns without a
    /// default, id columns stored differently than the configured id strategy stores them.
    pub warnings: Vec<String>,
}

impl MigrationPlan {
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    pub fn diff(schema: &Schema, live: &LiveSchema) -> Self {
        let mut plan = MigrationPlan::default();
        let mut mismatched_ids = Vec::new();
        for table in schema.tables() {
            let Some(live_columns) = live.tables.get(table.name) else {
                plan.steps.push(Step::CreateTable(table.clone()));
                for column in table
                    .columns
                    .iter()
                    .filter(|c| c.index && !c.unique && !c.primary_key)
                {
                    plan.steps.push(Step::CreateIndex {
                        table: table.clone(),
                        column: *column,
                    });
                }
                for unique in &table.uniques {
                    plan.steps.push(Step::AddUnique {
                        table: table.clone(),
                        columns: unique.columns.clone(),
                    });
                }
                continue;
            };
            for column in &table.columns {
                let key = (table.name.to_owned(), column.name.to_owned());
                if column.ty == ColumnType::Id
                    && live
                        .id_storage
                        .get(&key)
                        .is_some_and(|&stored| stored != schema.id_storage())
                {
                    mismatched_ids.push(format!("{}.{}", table.name, column.name));
                }
                if !live_columns.contains(column.name) {
                    if !column.nullable && column.default.is_none() {
                        plan.warnings.push(format!(
                            "{}.{} is NOT NULL without a default; adding it fails if the table has rows",
                            table.name, column.name
                        ));
                    }
                    plan.steps.push(Step::AddColumn {
                        table: table.clone(),
                        column: *column,
                    });
                }
                if column.index
                    && !column.unique
                    && !column.primary_key
                    && !live.indexes.contains(&key)
                {
                    plan.steps.push(Step::CreateIndex {
                        table: table.clone(),
                        column: *column,
                    });
                }
            }
            if let Some(live_uniques) = &live.uniques {
                for columns in table.unique_sets() {
                    let added_with_its_column =
                        columns.len() == 1 && !live_columns.contains(columns[0]);
                    if !added_with_its_column
                        && !live_uniques.contains(&unique_key(table.name, &columns))
                    {
                        plan.steps.push(Step::AddUnique {
                            table: table.clone(),
                            columns,
                        });
                    }
                }
            }
            for extra in live_columns.iter().filter(|c| table.column(c).is_none()) {
                plan.warnings.push(format!(
                    "{}.{extra} exists in the database but not in the config",
                    table.name
                ));
            }
        }
        if !mismatched_ids.is_empty() {
            let (live, configured) = match schema.id_storage() {
                IdStorage::Uuid => ("text", "a UUID id strategy, which stores ids as uuid"),
                IdStorage::Text => (
                    "uuid",
                    "an id strategy that stores ids as text (ULID or custom)",
                ),
            };
            plan.warnings.push(format!(
                "id columns {} are {live} in the database, but the config uses {configured}; \
                 the migrator doesn't change column types. Configure the strategy the database \
                 was created with (`.ids(IdStrategy::UuidV7)` for uuid columns, \
                 `.ids(IdStrategy::Ulid)` for text) or convert the columns yourself",
                mismatched_ids.join(", ")
            ));
        }
        plan
    }
}

/// `auth.migrator()`.
pub struct Migrator<'a, D> {
    adapter: &'a D,
    schema: &'a Schema,
}

impl<'a, D: Adapter> Migrator<'a, D> {
    pub(crate) fn new(adapter: &'a D, schema: &'a Schema) -> Self {
        Self { adapter, schema }
    }

    pub async fn plan(&self) -> DbResult<MigrationPlan> {
        let live = self.adapter.introspect().await?;
        Ok(MigrationPlan::diff(self.schema, &live))
    }

    pub async fn apply(&self, plan: &MigrationPlan) -> DbResult<()> {
        for warning in &plan.warnings {
            tracing::warn!("fastauth migrate: {warning}");
        }
        if plan.is_empty() {
            return Ok(());
        }
        self.adapter.apply(plan).await
    }

    /// Plans and applies. Safe to call on every startup.
    pub async fn run(&self) -> DbResult<MigrationPlan> {
        let plan = self.plan().await?;
        self.apply(&plan).await?;
        Ok(plan)
    }

    /// The plan as SQL, for sqlx migration files.
    pub async fn sql(&self) -> DbResult<String> {
        let plan = self.plan().await?;
        self.adapter.render_sql(&plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IdStrategy;
    use crate::testing::conformance_schema;

    fn live_with_ids(schema: &Schema, stored: IdStorage) -> LiveSchema {
        let mut live = LiveSchema {
            uniques: Some(
                schema
                    .tables()
                    .iter()
                    .flat_map(|t| t.unique_sets().map(|cols| unique_key(t.name, &cols)))
                    .collect(),
            ),
            ..LiveSchema::default()
        };
        for table in schema.tables() {
            for column in &table.columns {
                let key = (table.name.to_owned(), column.name.to_owned());
                live.tables
                    .entry(key.0.clone())
                    .or_default()
                    .insert(key.1.clone());
                if column.index && !column.unique && !column.primary_key {
                    live.indexes.insert(key.clone());
                }
                if column.ty == ColumnType::Id {
                    live.id_storage.insert(key, stored);
                }
            }
        }
        live
    }

    #[test]
    fn matching_id_storage_plans_nothing() {
        for ids in [IdStrategy::Ulid, IdStrategy::UuidV7] {
            let schema = conformance_schema(&ids, false);
            let plan = MigrationPlan::diff(&schema, &live_with_ids(&schema, ids.storage()));
            assert_eq!(plan, MigrationPlan::default(), "{ids:?}");
        }
    }

    fn added_uniques(plan: &MigrationPlan) -> Vec<String> {
        plan.steps
            .iter()
            .filter_map(|step| match step {
                Step::AddUnique { table, columns } => {
                    Some(format!("{}({})", table.name, columns.join(",")))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn new_tables_get_their_multi_column_uniques() {
        let schema = conformance_schema(&IdStrategy::Ulid, false);
        let plan = MigrationPlan::diff(&schema, &LiveSchema::default());
        assert_eq!(added_uniques(&plan), ["account(provider_id,account_id)"]);
    }

    #[test]
    fn a_unique_missing_from_an_existing_table_is_planned() {
        let schema = conformance_schema(&IdStrategy::Ulid, true);
        let mut live = live_with_ids(&schema, IdStorage::Text);
        let uniques = live.uniques.as_mut().unwrap();
        uniques.remove(&unique_key("item", &["nickname"]));
        uniques.remove(&unique_key("account", &["account_id", "provider_id"]));
        let plan = MigrationPlan::diff(&schema, &live);
        assert_eq!(
            added_uniques(&plan),
            ["account(provider_id,account_id)", "item(nickname)"]
        );
    }

    #[test]
    fn a_unique_column_added_now_brings_its_constraint() {
        let v1 = conformance_schema(&IdStrategy::Ulid, false);
        let live = live_with_ids(&v1, IdStorage::Text);
        let plan = MigrationPlan::diff(&conformance_schema(&IdStrategy::Ulid, true), &live);
        assert!(added_uniques(&plan).is_empty(), "{:?}", plan.steps);
    }

    #[test]
    fn without_reported_uniques_existing_tables_get_none() {
        let schema = conformance_schema(&IdStrategy::Ulid, false);
        let mut live = live_with_ids(&schema, IdStorage::Text);
        live.uniques = None;
        assert_eq!(
            MigrationPlan::diff(&schema, &live),
            MigrationPlan::default()
        );
    }

    #[test]
    fn switching_id_strategy_warns_without_altering_columns() {
        let uuid_db = conformance_schema(&IdStrategy::UuidV7, false);
        let live = live_with_ids(&uuid_db, IdStorage::Uuid);
        let plan = MigrationPlan::diff(&conformance_schema(&IdStrategy::Ulid, false), &live);
        assert!(plan.steps.is_empty(), "{:?}", plan.steps);
        let [warning] = plan.warnings.as_slice() else {
            panic!("expected one warning: {:?}", plan.warnings);
        };
        for column in ["user.id", "session.user_id", "item.owner_id"] {
            assert!(warning.contains(column), "{warning}");
        }
        assert!(warning.contains("are uuid in the database"), "{warning}");
        assert!(warning.contains(".ids(IdStrategy::UuidV7)"), "{warning}");

        let text_db = conformance_schema(&IdStrategy::Ulid, false);
        let live = live_with_ids(&text_db, IdStorage::Text);
        let plan = MigrationPlan::diff(&conformance_schema(&IdStrategy::UuidV4, false), &live);
        assert!(plan.steps.is_empty());
        assert_eq!(plan.warnings.len(), 1);
        assert!(plan.warnings[0].contains("are text in the database"));
    }
}
