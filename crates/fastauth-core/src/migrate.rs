//! Diffs the configured schema against the live database. Only ever adds.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use crate::adapter::{Adapter, DbResult};
use crate::schema::{ColumnDef, Schema, TableDef};

/// What exists in the database, as reported by `Adapter::introspect`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LiveSchema {
    /// Table name to its column names.
    pub tables: HashMap<String, HashSet<String>>,
    /// `(table, column)` pairs with a non-unique index named by `index_name`. Unique
    /// columns are created with an inline constraint and aren't listed here.
    pub indexes: HashSet<(String, String)>,
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
        }
    }
}

/// Index name every adapter uses, so introspection can recognise fastauth's indexes.
pub fn index_name(table: &str, column: &str) -> String {
    format!("idx_{table}_{column}")
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MigrationPlan {
    pub steps: Vec<Step>,
    /// Differences the migrator won't fix: extra columns, NOT NULL columns without a default.
    pub warnings: Vec<String>,
}

impl MigrationPlan {
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    pub fn diff(schema: &Schema, live: &LiveSchema) -> Self {
        let mut plan = MigrationPlan::default();
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
                continue;
            };
            for column in &table.columns {
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
                    && !live
                        .indexes
                        .contains(&(table.name.to_owned(), column.name.to_owned()))
                {
                    plan.steps.push(Step::CreateIndex {
                        table: table.clone(),
                        column: *column,
                    });
                }
            }
            for extra in live_columns.iter().filter(|c| table.column(c).is_none()) {
                plan.warnings.push(format!(
                    "{}.{extra} exists in the database but not in the config",
                    table.name
                ));
            }
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
