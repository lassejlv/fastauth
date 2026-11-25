use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ColumnType {
    Id,
    Text,
    Bool,
    Int,
    Timestamp,
    Json,
    Bytes,
}

/// How [`ColumnType::Id`] columns are stored. The configured
/// [`IdStrategy`](crate::config::IdStrategy) decides it, and adapters read it from
/// [`Schema::id_storage`] or [`TableDef::id_storage`] when they create columns and bind ids.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum IdStorage {
    /// The database's native UUID type where it has one (Postgres `uuid`), else text.
    Uuid,
    /// Text on every database.
    #[default]
    Text,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultValue {
    Bool(bool),
    Int(i64),
    Text(&'static str),
    /// The current time at insert.
    Now,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnDelete {
    Cascade,
    SetNull,
    Restrict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reference {
    pub table: &'static str,
    pub column: &'static str,
    pub on_delete: OnDelete,
}

/// One column. Built with const fns so `Fields` and `Model` impls can return `&'static [ColumnDef]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColumnDef {
    pub name: &'static str,
    pub ty: ColumnType,
    pub nullable: bool,
    pub primary_key: bool,
    pub unique: bool,
    pub index: bool,
    pub default: Option<DefaultValue>,
    pub references: Option<Reference>,
    /// Clients may set it through sign-up and update-user bodies.
    pub input: bool,
    /// Serialized to clients.
    pub returned: bool,
    /// The plugin id, `"core"` or `"app"`. Filled in when the column joins the schema.
    pub owner: &'static str,
}

impl ColumnDef {
    pub const fn new(name: &'static str, ty: ColumnType) -> Self {
        Self {
            name,
            ty,
            nullable: false,
            primary_key: false,
            unique: false,
            index: false,
            default: None,
            references: None,
            input: false,
            returned: true,
            owner: "",
        }
    }

    pub const fn primary_key(mut self) -> Self {
        self.primary_key = true;
        self
    }

    pub const fn nullable(mut self) -> Self {
        self.nullable = true;
        self
    }

    pub const fn unique(mut self) -> Self {
        self.unique = true;
        self
    }

    pub const fn index(mut self) -> Self {
        self.index = true;
        self
    }

    pub const fn default(mut self, value: DefaultValue) -> Self {
        self.default = Some(value);
        self
    }

    pub const fn references(
        mut self,
        table: &'static str,
        column: &'static str,
        on_delete: OnDelete,
    ) -> Self {
        self.references = Some(Reference {
            table,
            column,
            on_delete,
        });
        self
    }

    pub const fn input(mut self) -> Self {
        self.input = true;
        self
    }

    pub const fn hidden(mut self) -> Self {
        self.returned = false;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableDef {
    pub name: &'static str,
    pub owner: &'static str,
    pub columns: Vec<ColumnDef>,
    positions: HashMap<&'static str, usize>,
    id_storage: IdStorage,
}

impl TableDef {
    fn new(name: &'static str, owner: &'static str) -> Self {
        Self {
            name,
            owner,
            columns: Vec::new(),
            positions: HashMap::new(),
            id_storage: IdStorage::default(),
        }
    }

    /// How this table's [`ColumnType::Id`] columns are stored; the same for every table
    /// in a schema.
    pub fn id_storage(&self) -> IdStorage {
        self.id_storage
    }

    pub fn position(&self, column: &str) -> Option<usize> {
        self.positions.get(column).copied()
    }

    pub fn column(&self, column: &str) -> Option<&ColumnDef> {
        self.position(column).map(|i| &self.columns[i])
    }

    pub fn primary_key(&self) -> Option<&ColumnDef> {
        self.columns.iter().find(|c| c.primary_key)
    }
}

/// The merged schema for one configuration: core tables, app fields, every plugin's tables
/// and columns. Immutable after `.build()`.
#[derive(Clone, Debug, Default)]
pub struct Schema {
    tables: Vec<Arc<TableDef>>,
    by_name: HashMap<&'static str, usize>,
    id_storage: IdStorage,
}

impl Schema {
    /// How [`ColumnType::Id`] columns are stored, from the configured id strategy.
    pub fn id_storage(&self) -> IdStorage {
        self.id_storage
    }

    pub fn tables(&self) -> &[Arc<TableDef>] {
        &self.tables
    }

    pub fn table(&self, name: &str) -> Option<&Arc<TableDef>> {
        self.by_name.get(name).map(|&i| &self.tables[i])
    }

    /// Panics on a table name the schema doesn't have. Only for core's own tables and
    /// models whose table was registered (checked at build time).
    pub fn expect(&self, name: &str) -> &Arc<TableDef> {
        self.table(name)
            .unwrap_or_else(|| panic!("fastauth: table `{name}` is not in the schema"))
    }
}

/// Collects tables and columns during `.build()` and reports clashes with both owners.
#[derive(Debug, Default)]
pub struct SchemaBuilder {
    tables: Vec<TableDef>,
    pub(crate) owner: &'static str,
    pub(crate) errors: Vec<String>,
}

impl SchemaBuilder {
    pub(crate) fn new() -> Self {
        Self {
            owner: "core",
            ..Self::default()
        }
    }

    /// Adds a new table owned by the current plugin.
    pub fn table(&mut self, name: &'static str, columns: &[ColumnDef]) -> &mut Self {
        if let Some(existing) = self.tables.iter().find(|t| t.name == name) {
            self.errors.push(format!(
                "table `{name}` is defined by both `{}` and `{}`",
                existing.owner, self.owner
            ));
            return self;
        }
        self.tables.push(TableDef::new(name, self.owner));
        self.extend(name, columns)
    }

    /// Adds columns to an existing table (usually `user` or `session`).
    pub fn extend(&mut self, table: &'static str, columns: &[ColumnDef]) -> &mut Self {
        let owner = self.owner;
        let Some(def) = self.tables.iter_mut().find(|t| t.name == table) else {
            self.errors
                .push(format!("`{owner}` adds columns to unknown table `{table}`"));
            return self;
        };
        for column in columns {
            if let Some(clash) = def.column(column.name) {
                self.errors.push(format!(
                    "column `{table}.{}` is defined by both `{}` and `{owner}`",
                    column.name, clash.owner
                ));
                continue;
            }
            let mut column = *column;
            column.owner = owner;
            def.positions.insert(column.name, def.columns.len());
            def.columns.push(column);
        }
        self
    }

    /// Registers a model's table.
    pub fn model<M: crate::model::Model>(&mut self) -> &mut Self {
        self.table(M::TABLE, M::columns())
    }

    pub(crate) fn finish(self, id_storage: IdStorage) -> Result<Schema, Vec<String>> {
        let mut errors = self.errors;
        for table in &self.tables {
            for column in &table.columns {
                if let Some(r) = column.references {
                    let target = self.tables.iter().find(|t| t.name == r.table);
                    if target.and_then(|t| t.column(r.column)).is_none() {
                        errors.push(format!(
                            "column `{}.{}` references missing `{}.{}`",
                            table.name, column.name, r.table, r.column
                        ));
                    }
                }
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        let by_name = self
            .tables
            .iter()
            .enumerate()
            .map(|(i, t)| (t.name, i))
            .collect();
        Ok(Schema {
            tables: self
                .tables
                .into_iter()
                .map(|mut table| {
                    table.id_storage = id_storage;
                    Arc::new(table)
                })
                .collect(),
            by_name,
            id_storage,
        })
    }
}
