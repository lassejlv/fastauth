//! The adapter conformance suite, behind the `testing` feature. An adapter is done when
//! [`run_adapter_conformance`] passes against it:
//!
//! ```ignore
//! #[tokio::test]
//! async fn conformance() {
//!     fastauth_core::testing::run_adapter_conformance(async || MyAdapter::connect(&url()).await).await;
//! }
//! ```
//!
//! Every case gets a fresh adapter from `make`, so each one must start from an empty database.
//! The suite's timestamps have millisecond precision, the coarsest any adapter stores.

use std::sync::Arc;

use serde_json::json;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

use crate::adapter::{
    Adapter, DbError, Delete, Filter, Insert, Op, Order, Queries, Select, SessionWithUser,
    Transaction, Update,
};
use crate::crypto::Hash;
use crate::migrate::{Migrator, Step};
use crate::model::Model;
use crate::models::{Session, User};
use crate::query::full_row;
use crate::schema::{
    ColumnDef, ColumnType as T, DefaultValue, OnDelete, Schema, SchemaBuilder, TableDef,
};
use crate::value::{Id, Row, Value};

const ITEM: &str = "item";

const ITEM_COLUMNS: &[ColumnDef] = &[
    ColumnDef::new("id", T::Id).primary_key(),
    ColumnDef::new("name", T::Text).unique(),
    ColumnDef::new("rank", T::Int).index(),
    ColumnDef::new("active", T::Bool).default(DefaultValue::Bool(true)),
    ColumnDef::new("at", T::Timestamp),
    ColumnDef::new("note", T::Text).nullable(),
    ColumnDef::new("payload", T::Json).nullable(),
    ColumnDef::new("blob", T::Bytes).nullable(),
    ColumnDef::new("owner_id", T::Id)
        .nullable()
        .references("user", "id", OnDelete::SetNull)
        .index(),
];

const ITEM_V2_COLUMNS: &[ColumnDef] = &[
    ColumnDef::new("level", T::Int).default(DefaultValue::Int(0)),
    ColumnDef::new("label", T::Text).default(DefaultValue::Text("it's")),
    ColumnDef::new("touched_at", T::Timestamp).default(DefaultValue::Now),
    ColumnDef::new("nickname", T::Text).nullable().unique(),
    ColumnDef::new("tag", T::Text).nullable().index(),
];

const BASE: OffsetDateTime = datetime!(2026-01-02 03:04:05.678 UTC);

const SEED: [(&str, Option<&str>); 7] = [
    ("alpha", Some("x")),
    ("beta", None),
    ("gamma", Some("y")),
    ("Alpha", None),
    ("al%pha", Some("x")),
    ("a_c", None),
    ("abc", Some("z")),
];

/// The schema the suite runs on: core's tables plus `item`, which has a column of every type.
/// `v2` adds columns to `item`, for the migration round trip.
pub fn conformance_schema(v2: bool) -> Schema {
    let mut builder = SchemaBuilder::new();
    crate::models::register(&mut builder);
    builder.owner = "conformance";
    builder.table(ITEM, ITEM_COLUMNS);
    if v2 {
        builder.extend(ITEM, ITEM_V2_COLUMNS);
    }
    builder.finish().expect("the conformance schema is valid")
}

/// Runs every conformance case, each on a fresh adapter from `make`. Panics on the first
/// failure, naming what differed.
pub async fn run_adapter_conformance<D: Adapter>(make: impl AsyncFn() -> D) {
    migrations(make().await).await;
    Fixture::new(make().await).await.round_trip().await;
    Fixture::new(make().await).await.filters().await;
    Fixture::new(make().await).await.ordering_and_paging().await;
    Fixture::new(make().await).await.update_and_delete().await;
    Fixture::new(make().await).await.unique_violations().await;
    Fixture::new(make().await).await.transactions().await;
    Fixture::new(make().await).await.session_with_user().await;
}

async fn migrations<D: Adapter>(db: D) {
    let v1 = conformance_schema(false);
    let migrator = Migrator::new(&db, &v1);
    let plan = migrator.run().await.expect("first migration");
    let created = plan
        .steps
        .iter()
        .filter(|s| matches!(s, Step::CreateTable(_)))
        .count();
    assert_eq!(created, v1.tables().len(), "first plan creates every table");
    let again = migrator.plan().await.expect("plan after migrating");
    assert!(
        again.is_empty(),
        "plan after migrating is not empty: {again:?}"
    );

    let live = db.introspect().await.expect("introspect");
    for (table, column) in [
        ("session", "user_id"),
        ("account", "user_id"),
        (ITEM, "rank"),
    ] {
        assert!(
            live.indexes
                .contains(&(table.to_owned(), column.to_owned())),
            "introspect misses the index on {table}.{column}: {:?}",
            live.indexes
        );
    }

    let item = v1.expect(ITEM);
    db.insert(Insert {
        table: item,
        values: item_values(item, "existing", 1, None),
    })
    .await
    .expect("insert before adding columns");

    let v2 = conformance_schema(true);
    let migrator = Migrator::new(&db, &v2);
    let plan = migrator.plan().await.expect("plan for v2");
    let added: Vec<&str> = plan
        .steps
        .iter()
        .filter_map(|s| match s {
            Step::AddColumn { column, .. } => Some(column.name),
            _ => None,
        })
        .collect();
    assert_eq!(added, ["level", "label", "touched_at", "nickname", "tag"]);
    let indexed: Vec<&str> = plan
        .steps
        .iter()
        .filter_map(|s| match s {
            Step::CreateIndex { column, .. } => Some(column.name),
            _ => None,
        })
        .collect();
    assert_eq!(indexed, ["tag"]);
    migrator
        .apply(&plan)
        .await
        .expect("adding columns to a table with rows");
    let again = migrator.plan().await.expect("plan after v2");
    assert!(again.is_empty(), "plan after v2 is not empty: {again:?}");
}

fn position(table: &TableDef, column: &str) -> usize {
    table
        .position(column)
        .unwrap_or_else(|| panic!("{}.{column} missing", table.name))
}

fn item_values(table: &TableDef, name: &str, rank: i64, note: Option<&str>) -> Vec<Value> {
    full_row(
        table,
        vec![
            ("id", Value::Text(Id::new_v7().to_string())),
            ("name", Value::Text(name.to_owned())),
            ("rank", Value::Int(rank)),
            ("active", Value::Bool(rank % 2 == 0)),
            ("at", Value::Timestamp(BASE + Duration::hours(rank))),
            (
                "note",
                note.map_or(Value::Null, |n| Value::Text(n.to_owned())),
            ),
        ],
    )
    .expect("item row")
}

fn user_values(table: &TableDef, email: &str) -> Vec<Value> {
    full_row(
        table,
        vec![
            ("id", Value::Text(Id::new_v7().to_string())),
            ("email", Value::Text(email.to_owned())),
            ("name", Value::Text("Conformance".to_owned())),
            ("created_at", Value::Timestamp(BASE)),
            ("updated_at", Value::Timestamp(BASE)),
        ],
    )
    .expect("user row")
}

fn session_values(table: &TableDef, token: &str, user_id: &Value) -> Vec<Value> {
    full_row(
        table,
        vec![
            ("id", Value::Text(Id::new_v7().to_string())),
            (
                "token_hash",
                Value::Bytes(Hash::sha256(token).as_bytes().to_vec()),
            ),
            ("user_id", user_id.clone()),
            ("expires_at", Value::Timestamp(BASE + Duration::days(7))),
            ("user_agent", Value::Text("conformance".to_owned())),
            ("created_at", Value::Timestamp(BASE)),
            ("updated_at", Value::Timestamp(BASE)),
        ],
    )
    .expect("session row")
}

fn assert_unique(result: Result<impl std::fmt::Debug, DbError>, table: &str, column: &str) {
    match result {
        Err(DbError::UniqueViolation {
            table: t,
            column: c,
        }) => {
            assert_eq!((t.as_str(), c.as_deref()), (table, Some(column)));
        }
        other => panic!("expected a unique violation on {table}.{column}, got {other:?}"),
    }
}

struct Fixture<D> {
    db: D,
    schema: Schema,
}

impl<D: Adapter> Fixture<D> {
    async fn new(db: D) -> Self {
        let schema = conformance_schema(false);
        Migrator::new(&db, &schema)
            .run()
            .await
            .expect("migrate the conformance schema");
        Self { db, schema }
    }

    fn table(&self, name: &str) -> &Arc<TableDef> {
        self.schema.expect(name)
    }

    fn cmp(&self, column: &str, op: Op, value: Value) -> Filter {
        Filter::Cmp {
            column: position(self.table(ITEM), column),
            op,
            value,
        }
    }

    fn select(&self, filter: Filter) -> Select<'_> {
        Select {
            table: self.table(ITEM),
            filter,
            order: Vec::new(),
            limit: None,
            offset: None,
        }
    }

    async fn seed(&self) -> Vec<Row> {
        let table = self.table(ITEM);
        let mut rows = Vec::new();
        for (rank, (name, note)) in (1..).zip(SEED) {
            let mut values = item_values(table, name, rank, note);
            if name == "gamma" {
                values[position(table, "blob")] = Value::Bytes(vec![1, 2, 3]);
            }
            let row = self
                .db
                .insert(Insert { table, values })
                .await
                .expect("seed insert");
            rows.push(row);
        }
        rows
    }

    async fn names_in<Q: Queries>(&self, queries: &Q, select: Select<'_>) -> Vec<String> {
        let name = position(self.table(ITEM), "name");
        queries
            .find_many(select)
            .await
            .expect("find_many")
            .iter()
            .map(|row| match &row.values()[name] {
                Value::Text(s) => s.clone(),
                other => panic!("item.name decoded as {other:?}"),
            })
            .collect()
    }

    async fn check(&self, filter: Filter, expected: &[&str]) {
        let mut names = self.names_in(&self.db, self.select(filter.clone())).await;
        names.sort();
        let mut expected: Vec<String> = expected.iter().map(|s| (*s).to_owned()).collect();
        expected.sort();
        assert_eq!(names, expected, "find_many with {filter:?}");
        let count = self
            .db
            .count(self.select(filter.clone()))
            .await
            .expect("count");
        assert_eq!(count, expected.len() as u64, "count with {filter:?}");
    }

    async fn ordered(
        &self,
        order: &[(&str, Order)],
        limit: Option<u64>,
        offset: Option<u64>,
    ) -> Vec<String> {
        let table = self.table(ITEM);
        let select = Select {
            order: order
                .iter()
                .map(|(c, o)| (position(table, c), *o))
                .collect(),
            limit,
            offset,
            ..self.select(Filter::All)
        };
        self.names_in(&self.db, select).await
    }

    async fn round_trip(&self) {
        let users = self.table(User::TABLE);
        let owner = self
            .db
            .insert(Insert {
                table: users,
                values: user_values(users, "owner@acme.dk"),
            })
            .await
            .expect("insert user");
        let table = self.table(ITEM);
        let mut full = item_values(table, "full", 7, Some("a note"));
        full[position(table, "payload")] =
            Value::Json(json!({ "k": [1, "two", null], "n": { "b": true } }));
        full[position(table, "blob")] = Value::Bytes(vec![0, 1, 2, 255]);
        full[position(table, "owner_id")] = owner.values()[0].clone();
        let mut sparse = item_values(table, "sparse", -3, None);
        sparse[position(table, "at")] = Value::Timestamp(datetime!(2026-01-02 05:04:05.001 +02:00));

        for values in [full, sparse] {
            let inserted = self
                .db
                .insert(Insert {
                    table,
                    values: values.clone(),
                })
                .await
                .expect("insert item");
            assert_eq!(
                inserted.values(),
                &values[..],
                "insert returns the stored row"
            );
            let found = self
                .db
                .find_one(self.select(self.cmp("id", Op::Eq, values[0].clone())))
                .await
                .expect("find_one")
                .expect("the inserted item");
            assert_eq!(
                found.values(),
                &values[..],
                "find_one returns what was inserted"
            );
        }
        let missing = self
            .db
            .find_one(self.select(self.cmp("name", Op::Eq, Value::Text("nope".into()))))
            .await
            .expect("find_one");
        assert!(missing.is_none());
    }

    async fn filters(&self) {
        let rows = self.seed().await;
        let all: Vec<&str> = SEED.iter().map(|(n, _)| *n).collect();
        let text = |s: &str| Value::Text(s.to_owned());
        let at = |hours: i64| Value::Timestamp(BASE + Duration::hours(hours));
        let rank = position(self.table(ITEM), "rank");
        let note = position(self.table(ITEM), "note");
        let name = position(self.table(ITEM), "name");

        self.check(Filter::All, &all).await;
        self.check(self.cmp("rank", Op::Eq, Value::Int(3)), &["gamma"])
            .await;
        self.check(
            self.cmp("rank", Op::Ne, Value::Int(3)),
            &["alpha", "beta", "Alpha", "al%pha", "a_c", "abc"],
        )
        .await;
        self.check(self.cmp("rank", Op::Lt, Value::Int(3)), &["alpha", "beta"])
            .await;
        self.check(
            self.cmp("rank", Op::Lte, Value::Int(3)),
            &["alpha", "beta", "gamma"],
        )
        .await;
        self.check(self.cmp("rank", Op::Gt, Value::Int(5)), &["a_c", "abc"])
            .await;
        self.check(
            self.cmp("rank", Op::Gte, Value::Int(5)),
            &["al%pha", "a_c", "abc"],
        )
        .await;
        self.check(self.cmp("name", Op::Eq, text("alpha")), &["alpha"])
            .await;
        self.check(self.cmp("at", Op::Gt, at(5)), &["a_c", "abc"])
            .await;
        self.check(self.cmp("at", Op::Lte, at(1)), &["alpha"]).await;
        self.check(
            self.cmp("active", Op::Eq, Value::Bool(true)),
            &["beta", "Alpha", "a_c"],
        )
        .await;
        self.check(
            self.cmp("blob", Op::Eq, Value::Bytes(vec![1, 2, 3])),
            &["gamma"],
        )
        .await;
        self.check(
            self.cmp("id", Op::Eq, rows[1].values()[0].clone()),
            &["beta"],
        )
        .await;
        self.check(self.cmp("id", Op::Eq, text("not-a-uuid")), &[])
            .await;
        self.check(self.cmp("note", Op::Eq, text("x")), &["alpha", "al%pha"])
            .await;
        self.check(self.cmp("note", Op::Ne, text("x")), &["gamma", "abc"])
            .await;

        let in_ranks = |values: Vec<Value>| Filter::In {
            column: rank,
            values,
        };
        self.check(
            in_ranks(vec![Value::Int(1), Value::Int(3), Value::Int(99)]),
            &["alpha", "gamma"],
        )
        .await;
        self.check(in_ranks(Vec::new()), &[]).await;
        self.check(
            Filter::In {
                column: name,
                values: vec![text("beta"), text("abc")],
            },
            &["beta", "abc"],
        )
        .await;

        let null = |is_null| Filter::Null {
            column: note,
            is_null,
        };
        self.check(null(true), &["beta", "Alpha", "a_c"]).await;
        self.check(null(false), &["alpha", "gamma", "al%pha", "abc"])
            .await;

        let starts = |prefix: &str| Filter::StartsWith {
            column: name,
            prefix: prefix.to_owned(),
        };
        self.check(starts("al"), &["alpha", "al%pha"]).await;
        self.check(starts("al%"), &["al%pha"]).await;
        self.check(starts("a_"), &["a_c"]).await;
        self.check(starts("A"), &["Alpha"]).await;
        self.check(starts(""), &all).await;

        self.check(
            Filter::And(vec![self.cmp("rank", Op::Gt, Value::Int(1)), null(true)]),
            &["beta", "Alpha", "a_c"],
        )
        .await;
        self.check(Filter::And(Vec::new()), &all).await;
        self.check(
            Filter::Or(vec![
                self.cmp("rank", Op::Eq, Value::Int(1)),
                self.cmp("rank", Op::Eq, Value::Int(3)),
            ]),
            &["alpha", "gamma"],
        )
        .await;
        self.check(Filter::Or(Vec::new()), &[]).await;
        self.check(
            Filter::Or(vec![
                Filter::And(vec![self.cmp("rank", Op::Gte, Value::Int(6)), null(true)]),
                self.cmp("name", Op::Eq, text("beta")),
            ]),
            &["a_c", "beta"],
        )
        .await;
    }

    async fn ordering_and_paging(&self) {
        self.seed().await;
        use Order::{Asc, Desc};
        assert_eq!(
            self.ordered(&[("rank", Asc)], None, None).await,
            ["alpha", "beta", "gamma", "Alpha", "al%pha", "a_c", "abc"]
        );
        assert_eq!(
            self.ordered(&[("active", Desc), ("rank", Asc)], None, None)
                .await,
            ["beta", "Alpha", "a_c", "alpha", "gamma", "al%pha", "abc"]
        );
        assert_eq!(
            self.ordered(&[("rank", Desc)], Some(2), None).await,
            ["abc", "a_c"]
        );
        assert_eq!(
            self.ordered(&[("rank", Asc)], Some(2), Some(1)).await,
            ["beta", "gamma"]
        );
        assert_eq!(
            self.ordered(&[("rank", Asc)], None, Some(5)).await,
            ["a_c", "abc"]
        );
        assert_eq!(self.ordered(&[("at", Desc)], Some(1), None).await, ["abc"]);
        assert!(
            self.ordered(&[("rank", Asc)], Some(0), None)
                .await
                .is_empty()
        );

        let table = self.table(ITEM);
        let last = self
            .db
            .find_one(Select {
                order: vec![(position(table, "rank"), Desc)],
                ..self.select(Filter::All)
            })
            .await
            .expect("find_one")
            .expect("a row");
        assert_eq!(
            last.values()[position(table, "name")],
            Value::Text("abc".into())
        );
    }

    async fn update_and_delete(&self) {
        self.seed().await;
        let table = self.table(ITEM);
        let set = |pairs: Vec<(&str, Value)>| -> Vec<(usize, Value)> {
            pairs
                .into_iter()
                .map(|(c, v)| (position(table, c), v))
                .collect()
        };

        let updated = self
            .db
            .update(Update {
                table,
                filter: self.cmp("rank", Op::Gte, Value::Int(6)),
                set: set(vec![
                    ("note", Value::Text("updated".into())),
                    ("active", Value::Bool(false)),
                ]),
            })
            .await
            .expect("update");
        assert_eq!(updated, 2);
        self.check(
            Filter::And(vec![
                self.cmp("note", Op::Eq, Value::Text("updated".into())),
                self.cmp("active", Op::Eq, Value::Bool(false)),
            ]),
            &["a_c", "abc"],
        )
        .await;

        let cleared = self
            .db
            .update(Update {
                table,
                filter: self.cmp("rank", Op::Eq, Value::Int(1)),
                set: set(vec![("note", Value::Null)]),
            })
            .await
            .expect("update to null");
        assert_eq!(cleared, 1);
        self.check(
            Filter::Null {
                column: position(table, "note"),
                is_null: true,
            },
            &["alpha", "beta", "Alpha"],
        )
        .await;

        let none = self
            .db
            .update(Update {
                table,
                filter: self.cmp("rank", Op::Eq, Value::Int(99)),
                set: set(vec![("rank", Value::Int(100))]),
            })
            .await
            .expect("update nothing");
        assert_eq!(none, 0);

        let clash = self
            .db
            .update(Update {
                table,
                filter: self.cmp("name", Op::Eq, Value::Text("beta".into())),
                set: set(vec![("name", Value::Text("alpha".into()))]),
            })
            .await;
        assert_unique(clash, ITEM, "name");

        let deleted = self
            .db
            .delete(Delete {
                table,
                filter: self.cmp("rank", Op::Lt, Value::Int(3)),
            })
            .await
            .expect("delete");
        assert_eq!(deleted, 2);
        let none = self
            .db
            .delete(Delete {
                table,
                filter: self.cmp("rank", Op::Lt, Value::Int(3)),
            })
            .await
            .expect("delete nothing");
        assert_eq!(none, 0);
        self.check(Filter::All, &["gamma", "Alpha", "al%pha", "a_c", "abc"])
            .await;
    }

    async fn unique_violations(&self) {
        let users = self.table(User::TABLE);
        let first = self
            .db
            .insert(Insert {
                table: users,
                values: user_values(users, "taken@acme.dk"),
            })
            .await
            .expect("first user");
        let again = self
            .db
            .insert(Insert {
                table: users,
                values: user_values(users, "taken@acme.dk"),
            })
            .await;
        assert_unique(again, User::TABLE, "email");

        let mut same_id = user_values(users, "other@acme.dk");
        same_id[0] = first.values()[0].clone();
        let again = self
            .db
            .insert(Insert {
                table: users,
                values: same_id,
            })
            .await;
        assert_unique(again, User::TABLE, "id");

        let sessions = self.table(Session::TABLE);
        let user_id = &first.values()[0];
        self.db
            .insert(Insert {
                table: sessions,
                values: session_values(sessions, "token", user_id),
            })
            .await
            .expect("first session");
        let again = self
            .db
            .insert(Insert {
                table: sessions,
                values: session_values(sessions, "token", user_id),
            })
            .await;
        assert_unique(again, Session::TABLE, "token_hash");

        self.db
            .insert(Insert {
                table: users,
                values: user_values(users, "after@acme.dk"),
            })
            .await
            .expect("the adapter still works after a violation");
    }

    async fn transactions(&self) {
        let users = self.table(User::TABLE);
        let email = position(users, "email");
        let all_users = || Select {
            table: users,
            filter: Filter::All,
            order: Vec::new(),
            limit: None,
            offset: None,
        };
        let by_email = |e: &str| Filter::Cmp {
            column: email,
            op: Op::Eq,
            value: Value::Text(e.to_owned()),
        };

        let tx = self.db.begin().await.expect("begin");
        tx.insert(Insert {
            table: users,
            values: user_values(users, "committed@acme.dk"),
        })
        .await
        .expect("insert in tx");
        assert_eq!(
            tx.count(all_users()).await.expect("count in tx"),
            1,
            "a tx sees its own writes"
        );
        let renamed = tx
            .update(Update {
                table: users,
                filter: by_email("committed@acme.dk"),
                set: vec![(position(users, "name"), Value::Text("Renamed".into()))],
            })
            .await
            .expect("update in tx");
        assert_eq!(renamed, 1);
        assert!(
            tx.find_one(Select {
                filter: by_email("committed@acme.dk"),
                ..all_users()
            })
            .await
            .expect("find_one in tx")
            .is_some()
        );
        tx.commit().await.expect("commit");
        assert_eq!(
            self.db.count(all_users()).await.expect("count"),
            1,
            "commit persists"
        );

        let tx = self.db.begin().await.expect("begin");
        tx.insert(Insert {
            table: users,
            values: user_values(users, "rolled-back@acme.dk"),
        })
        .await
        .expect("insert in tx");
        let deleted = tx
            .delete(Delete {
                table: users,
                filter: by_email("committed@acme.dk"),
            })
            .await
            .expect("delete in tx");
        assert_eq!(deleted, 1);
        assert_eq!(
            tx.find_many(all_users())
                .await
                .expect("find_many in tx")
                .len(),
            1
        );
        tx.rollback().await.expect("rollback");
        let names = self.db.find_many(all_users()).await.expect("find_many");
        assert_eq!(
            names.len(),
            1,
            "rollback discards the insert and the delete"
        );
        assert_eq!(
            names[0].values()[email],
            Value::Text("committed@acme.dk".into())
        );

        let tx = self.db.begin().await.expect("begin");
        tx.insert(Insert {
            table: users,
            values: user_values(users, "dropped@acme.dk"),
        })
        .await
        .expect("insert in tx");
        drop(tx);
        assert_eq!(
            self.db.count(all_users()).await.expect("count"),
            1,
            "dropping a tx rolls back"
        );

        let tx = self.db.begin().await.expect("begin");
        let clash = tx
            .insert(Insert {
                table: users,
                values: user_values(users, "committed@acme.dk"),
            })
            .await;
        assert_unique(clash, User::TABLE, "email");
        tx.rollback().await.expect("rollback after a violation");
        assert_eq!(self.db.count(all_users()).await.expect("count"), 1);
    }

    async fn session_with_user(&self) {
        let users = self.table(User::TABLE);
        let sessions = self.table(Session::TABLE);
        let mut pairs = Vec::new();
        for (email, token) in [("one@acme.dk", "token-one"), ("two@acme.dk", "token-two")] {
            let user = self
                .db
                .insert(Insert {
                    table: users,
                    values: user_values(users, email),
                })
                .await
                .expect("insert user");
            let session = self
                .db
                .insert(Insert {
                    table: sessions,
                    values: session_values(sessions, token, &user.values()[0]),
                })
                .await
                .expect("insert session");
            pairs.push((token, session, user));
        }
        for (token, session, user) in &pairs {
            let hash = Hash::sha256(token);
            let (found_session, found_user) = self
                .db
                .session_with_user(SessionWithUser {
                    session: sessions,
                    user: users,
                    token_hash: &hash,
                })
                .await
                .expect("session_with_user")
                .expect("the session exists");
            assert_eq!(found_session.values(), session.values());
            assert_eq!(found_user.values(), user.values());
        }
        let unknown = Hash::sha256("unknown");
        let found = self
            .db
            .session_with_user(SessionWithUser {
                session: sessions,
                user: users,
                token_hash: &unknown,
            })
            .await
            .expect("session_with_user");
        assert!(found.is_none());
    }
}
