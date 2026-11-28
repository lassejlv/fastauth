mod common;

use std::sync::Mutex;

use fastauth_core::adapter::Adapter;
use fastauth_core::config::IdStrategy;
use fastauth_core::migrate::MigrationPlan;
use fastauth_core::testing::{
    conformance_schema, run_adapter_conformance, run_adapter_conformance_renamed,
};
use fastauth_core::value::Id;
use fastauth_sqlx::sqlx::postgres::PgPoolOptions;
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{PgPool, Sqlx};

/// A pool for `DATABASE_URL`, or `None` (and the test is skipped) when it isn't set.
async fn database() -> Option<PgPool> {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL is not set; skipping the Postgres test");
        return None;
    };
    Some(
        PgPool::connect(&url)
            .await
            .expect("connect to DATABASE_URL"),
    )
}

fn fresh_schema() -> String {
    format!("fastauth_test_{}", Id::new_v7().as_str().replace('-', ""))
}

async fn drop_schemas(pool: &PgPool, schemas: Vec<String>) {
    for schema in schemas {
        pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
            .await
            .expect("drop test schema");
    }
}

fn render_for(ids: &IdStrategy) -> String {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://localhost/unused")
        .unwrap();
    let db = Sqlx::new(pool).schema("auth").table_prefix("fa_");
    let plan = MigrationPlan::diff(&conformance_schema(ids, false), &Default::default());
    db.render_sql(&plan).unwrap()
}

#[tokio::test]
async fn render_sql_with_text_ids() {
    let sql = render_for(&IdStrategy::Ulid);
    for expected in [
        "CREATE TABLE \"auth\".\"fa_user\" (\n    \"id\" text NOT NULL CONSTRAINT \"fa_user_pkey\" PRIMARY KEY,\n",
        "\"user_id\" text NOT NULL REFERENCES \"auth\".\"fa_user\" (\"id\") ON DELETE CASCADE,",
        "\"owner_id\" text REFERENCES \"auth\".\"fa_user\" (\"id\") ON DELETE SET NULL\n)",
    ] {
        assert!(sql.contains(expected), "missing {expected:?} in:\n{sql}");
    }
    assert!(!sql.contains("uuid"), "{sql}");
}

#[tokio::test]
async fn render_sql() {
    let sql = render_for(&IdStrategy::UuidV7);
    for expected in [
        "CREATE SCHEMA IF NOT EXISTS \"auth\";\n",
        "CREATE TABLE \"auth\".\"fa_user\" (\n    \"id\" uuid NOT NULL CONSTRAINT \"fa_user_pkey\" PRIMARY KEY,\n",
        "\"email\" text NOT NULL CONSTRAINT \"fa_user_email_key\" UNIQUE,",
        "\"email_verified\" boolean NOT NULL DEFAULT false,",
        "\"token_hash\" bytea NOT NULL CONSTRAINT \"fa_session_token_hash_key\" UNIQUE,",
        "\"user_id\" uuid NOT NULL REFERENCES \"auth\".\"fa_user\" (\"id\") ON DELETE CASCADE,",
        "\"created_at\" timestamptz NOT NULL DEFAULT now(),",
        "\"payload\" jsonb,",
        "\"owner_id\" uuid REFERENCES \"auth\".\"fa_user\" (\"id\") ON DELETE SET NULL\n)",
        "CREATE INDEX \"idx_fa_session_user_id\" ON \"auth\".\"fa_session\" (\"user_id\");",
    ] {
        assert!(sql.contains(expected), "missing {expected:?} in:\n{sql}");
    }
}

#[tokio::test]
async fn conformance() {
    let Some(pool) = database().await else {
        return;
    };
    let schemas = Mutex::new(Vec::new());
    run_adapter_conformance(async || {
        let schema = fresh_schema();
        schemas.lock().unwrap().push(schema.clone());
        Sqlx::new(pool.clone()).schema(schema).table_prefix("fa_")
    })
    .await;
    drop_schemas(&pool, schemas.into_inner().unwrap()).await;
}

#[tokio::test]
async fn conformance_with_camel_case_columns() {
    let Some(pool) = database().await else {
        return;
    };
    let schemas = Mutex::new(Vec::new());
    run_adapter_conformance_renamed(async || {
        let schema = fresh_schema();
        schemas.lock().unwrap().push(schema.clone());
        Sqlx::new(pool.clone()).schema(schema)
    })
    .await;
    drop_schemas(&pool, schemas.into_inner().unwrap()).await;
}

#[tokio::test]
async fn sign_up_sign_in_get_session_on_the_search_path() {
    flow_on_the_search_path(IdStrategy::Ulid).await;
}

#[tokio::test]
async fn sign_up_sign_in_get_session_with_uuid_v7() {
    flow_on_the_search_path(IdStrategy::UuidV7).await;
}

async fn flow_on_the_search_path(ids: IdStrategy) {
    let Some(admin) = database().await else {
        return;
    };
    let storage = ids.storage();
    let schema = fresh_schema();
    admin
        .execute(AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .await
        .unwrap();
    let search_path = format!("SET search_path TO \"{schema}\"");
    let pool = PgPoolOptions::new()
        .after_connect(move |conn, _| {
            let search_path = search_path.clone();
            Box::pin(async move {
                conn.execute(AssertSqlSafe(search_path)).await?;
                Ok(())
            })
        })
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    common::http_flow(Sqlx::new(pool.clone()), ids).await;

    let live = Sqlx::new(pool).introspect().await.unwrap();
    assert!(live.tables["user"].contains("email"), "{live:?}");
    for column in [
        ("user", "id"),
        ("session", "user_id"),
        ("account", "user_id"),
    ] {
        let key = (column.0.to_owned(), column.1.to_owned());
        assert_eq!(live.id_storage.get(&key), Some(&storage), "{column:?}");
    }
    assert!(
        live.indexes
            .contains(&("session".to_owned(), "user_id".to_owned()))
    );
    drop_schemas(&admin, vec![schema]).await;
}

#[tokio::test]
async fn switching_id_storage_warns_and_alters_nothing() {
    let Some(pool) = database().await else {
        return;
    };
    let mut schemas = Vec::new();
    for (created_with, switched_to, live_type) in [
        (IdStrategy::UuidV7, IdStrategy::Ulid, "uuid"),
        (IdStrategy::Ulid, IdStrategy::UuidV4, "text"),
    ] {
        let schema = fresh_schema();
        schemas.push(schema.clone());
        let db = Sqlx::new(pool.clone()).schema(schema).table_prefix("fa_");
        let created = conformance_schema(&created_with, false);
        let plan = MigrationPlan::diff(&created, &db.introspect().await.unwrap());
        db.apply(&plan).await.unwrap();
        let live = db.introspect().await.unwrap();
        assert_eq!(
            MigrationPlan::diff(&created, &live),
            MigrationPlan::default()
        );

        let switched = MigrationPlan::diff(&conformance_schema(&switched_to, false), &live);
        assert!(switched.steps.is_empty(), "{:?}", switched.steps);
        let [warning] = switched.warnings.as_slice() else {
            panic!("expected one warning: {:?}", switched.warnings);
        };
        assert!(
            warning.contains(&format!("are {live_type} in the database")),
            "{warning}"
        );
        for column in [
            "user.id",
            "session.user_id",
            "account.user_id",
            "item.owner_id",
        ] {
            assert!(warning.contains(column), "{warning}");
        }
        db.apply(&switched).await.unwrap();
        assert_eq!(
            db.introspect().await.unwrap(),
            live,
            "applying altered nothing"
        );
    }
    drop_schemas(&pool, schemas).await;
}
