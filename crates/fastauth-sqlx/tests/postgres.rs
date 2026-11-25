mod common;

use std::sync::Mutex;

use fastauth_core::adapter::Adapter;
use fastauth_core::migrate::MigrationPlan;
use fastauth_core::testing::{conformance_schema, run_adapter_conformance};
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

#[tokio::test]
async fn render_sql() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://localhost/unused")
        .unwrap();
    let db = Sqlx::new(pool).schema("auth").table_prefix("fa_");
    let plan = MigrationPlan::diff(&conformance_schema(false), &Default::default());
    let sql = db.render_sql(&plan).unwrap();
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
async fn sign_up_sign_in_get_session_on_the_search_path() {
    let Some(admin) = database().await else {
        return;
    };
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
    common::http_flow(Sqlx::new(pool.clone())).await;

    let live = Sqlx::new(pool).introspect().await.unwrap();
    assert!(live.tables["user"].contains("email"), "{live:?}");
    assert!(
        live.indexes
            .contains(&("session".to_owned(), "user_id".to_owned()))
    );
    drop_schemas(&admin, vec![schema]).await;
}
