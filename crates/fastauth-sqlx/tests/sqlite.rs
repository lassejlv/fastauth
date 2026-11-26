mod common;

use fastauth_core::adapter::{Adapter, Delete, Filter, Insert, Op, Queries, Select};
use fastauth_core::config::IdStrategy;
use fastauth_core::migrate::MigrationPlan;
use fastauth_core::schema::Schema;
use fastauth_core::testing::{conformance_schema, run_adapter_conformance};
use fastauth_core::value::{Id, Value};
use fastauth_sqlx::{Sqlite, SqlitePool, Sqlx};
use time::OffsetDateTime;

async fn adapter() -> Sqlx<Sqlite> {
    let pool = SqlitePool::connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite");
    Sqlx::new(pool)
}

async fn plan(db: &Sqlx<Sqlite>, schema: &Schema) -> MigrationPlan {
    MigrationPlan::diff(schema, &db.introspect().await.unwrap())
}

async fn migrate(db: &Sqlx<Sqlite>, schema: &Schema) {
    db.apply(&plan(db, schema).await).await.unwrap();
}

#[tokio::test]
async fn conformance() {
    run_adapter_conformance(adapter).await;
}

#[tokio::test]
async fn conformance_with_a_table_prefix() {
    run_adapter_conformance(async || adapter().await.table_prefix("fa_")).await;
}

#[tokio::test]
async fn sign_up_sign_in_get_session() {
    common::http_flow(adapter().await, IdStrategy::Ulid).await;
}

#[tokio::test]
async fn sign_up_sign_in_get_session_with_uuid_v7() {
    common::http_flow(adapter().await, IdStrategy::UuidV7).await;
}

#[tokio::test]
async fn sqlite_stores_ids_as_text_under_every_strategy() {
    let db = adapter().await;
    let uuid_schema = conformance_schema(&IdStrategy::UuidV7, false);
    let sql = db.render_sql(&plan(&db, &uuid_schema).await).unwrap();
    assert!(sql.contains("\"id\" text NOT NULL"), "{sql}");
    migrate(&db, &uuid_schema).await;
    let switched = plan(&db, &conformance_schema(&IdStrategy::Ulid, false)).await;
    assert_eq!(switched, MigrationPlan::default());
}

#[tokio::test]
async fn sign_up_sign_in_get_session_with_renamed_tables() {
    common::http_flow(
        adapter()
            .await
            .table_prefix("fa_")
            .rename("user", "accounts"),
        IdStrategy::default(),
    )
    .await;
}

#[tokio::test]
async fn added_columns_get_their_defaults_on_existing_rows() {
    let db = adapter().await;
    let v1 = conformance_schema(&IdStrategy::default(), false);
    migrate(&db, &v1).await;
    let item = v1.expect("item");
    let mut values = vec![Value::Null; item.columns.len()];
    for (column, value) in [
        ("id", Value::Text(Id::new_v7().to_string())),
        ("name", Value::Text("old".into())),
        ("rank", Value::Int(1)),
        ("active", Value::Bool(true)),
        ("at", Value::Timestamp(OffsetDateTime::now_utc())),
    ] {
        values[item.position(column).unwrap()] = value;
    }
    db.insert(Insert {
        table: item,
        values,
    })
    .await
    .unwrap();

    let before = OffsetDateTime::now_utc() - time::Duration::seconds(1);
    let v2 = conformance_schema(&IdStrategy::default(), true);
    migrate(&db, &v2).await;
    let item = v2.expect("item");
    let row = db
        .find_one(Select {
            table: item,
            filter: Filter::All,
            order: Vec::new(),
            limit: None,
            offset: None,
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.value("level"), Some(&Value::Int(0)));
    assert_eq!(row.value("label"), Some(&Value::Text("it's".into())));
    assert_eq!(row.value("nickname"), Some(&Value::Null));
    match row.value("touched_at") {
        Some(Value::Timestamp(at)) => assert!(*at >= before, "{at}"),
        other => panic!("touched_at is {other:?}"),
    }
}

#[tokio::test]
async fn deleting_a_user_cascades_to_sessions() {
    let db = adapter().await;
    let schema = conformance_schema(&IdStrategy::default(), false);
    migrate(&db, &schema).await;
    let (user, session) = (schema.expect("user"), schema.expect("session"));
    let now = Value::Timestamp(OffsetDateTime::now_utc());
    let user_id = Value::Text(Id::new_v7().to_string());
    db.insert(Insert {
        table: user,
        values: vec![
            user_id.clone(),
            Value::Text("a@acme.dk".into()),
            Value::Bool(false),
            Value::Text("A".into()),
            Value::Null,
            Value::Int(0),
            now.clone(),
            now.clone(),
        ],
    })
    .await
    .unwrap();
    db.insert(Insert {
        table: session,
        values: vec![
            Value::Text(Id::new_v7().to_string()),
            Value::Bytes(vec![7; 32]),
            user_id.clone(),
            now.clone(),
            Value::Null,
            Value::Null,
            now.clone(),
            now,
        ],
    })
    .await
    .unwrap();
    let deleted = db
        .delete(Delete {
            table: user,
            filter: Filter::Cmp {
                column: 0,
                op: Op::Eq,
                value: user_id,
            },
        })
        .await
        .unwrap();
    assert_eq!(deleted, 1);
    let all_sessions = Select {
        table: session,
        filter: Filter::All,
        order: Vec::new(),
        limit: None,
        offset: None,
    };
    assert_eq!(db.count(all_sessions).await.unwrap(), 0);
}

#[tokio::test]
async fn render_sql_matches_what_apply_runs() {
    let db = adapter().await.table_prefix("fa_");
    let schema = conformance_schema(&IdStrategy::default(), false);
    let first = plan(&db, &schema).await;
    let sql = db.render_sql(&first).unwrap();
    for expected in [
        "CREATE TABLE \"fa_user\" (\n    \"id\" text NOT NULL CONSTRAINT \"fa_user_pkey\" PRIMARY KEY,\n",
        "\"email\" text NOT NULL CONSTRAINT \"fa_user_email_key\" UNIQUE,",
        "\"email_verified\" integer NOT NULL DEFAULT 0,",
        "\"user_id\" text NOT NULL REFERENCES \"fa_user\" (\"id\") ON DELETE CASCADE,",
        "\"created_at\" integer NOT NULL DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)),",
        "CREATE INDEX \"idx_fa_session_user_id\" ON \"fa_session\" (\"user_id\");",
    ] {
        assert!(sql.contains(expected), "missing {expected:?} in:\n{sql}");
    }
    db.apply(&first).await.unwrap();
    let after = plan(&db, &schema).await;
    assert!(after.is_empty(), "{after:?}");
    assert_eq!(db.render_sql(&after).unwrap(), "");
}
