mod common;

use std::str::FromStr;
use std::sync::Mutex;

use fastauth_core::adapter::Adapter;
use fastauth_core::config::IdStrategy;
use fastauth_core::migrate::MigrationPlan;
use fastauth_core::testing::{conformance_schema, run_adapter_conformance};
use fastauth_core::value::Id;
use fastauth_sqlx::sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use fastauth_sqlx::sqlx::{AssertSqlSafe, Executor};
use fastauth_sqlx::{MySqlPool, Sqlx};

/// A pool for `MYSQL_DATABASE_URL`, or `None` (and the test is skipped) when it isn't set.
async fn server() -> Option<MySqlPool> {
    let Ok(url) = std::env::var("MYSQL_DATABASE_URL") else {
        eprintln!("MYSQL_DATABASE_URL is not set; skipping the MySQL test");
        return None;
    };
    Some(
        MySqlPool::connect(&url)
            .await
            .expect("connect to MYSQL_DATABASE_URL"),
    )
}

fn fresh_name() -> String {
    format!("fastauth_test_{}", Id::new_v7().as_str().replace('-', ""))
}

/// A new, empty database on the server and a pool connected to it.
async fn fresh_database(server: &MySqlPool) -> (String, MySqlPool) {
    let name = fresh_name();
    server
        .execute(AssertSqlSafe(format!("CREATE DATABASE `{name}`")))
        .await
        .expect("create test database");
    let url = std::env::var("MYSQL_DATABASE_URL").unwrap();
    let options = MySqlConnectOptions::from_str(&url).unwrap().database(&name);
    let pool = MySqlPoolOptions::new().connect_with(options).await.unwrap();
    (name, pool)
}

async fn drop_databases(server: &MySqlPool, names: Vec<String>) {
    for name in names {
        server
            .execute(AssertSqlSafe(format!("DROP DATABASE `{name}`")))
            .await
            .expect("drop test database");
    }
}

fn render_for(ids: &IdStrategy) -> String {
    let pool = MySqlPoolOptions::new()
        .connect_lazy("mysql://localhost/unused")
        .unwrap();
    let db = Sqlx::new(pool).schema("auth").table_prefix("fa_");
    let plan = MigrationPlan::diff(&conformance_schema(ids, false), &Default::default());
    db.render_sql(&plan).unwrap()
}

#[tokio::test]
async fn render_sql_with_text_ids() {
    let sql = render_for(&IdStrategy::Ulid);
    for expected in [
        "CREATE TABLE `auth`.`fa_user` (\n    `id` varchar(768) NOT NULL,\n",
        "`user_id` varchar(768) NOT NULL,",
        "CONSTRAINT `fa_user_pkey` PRIMARY KEY (`id`),",
        "CONSTRAINT `fa_session_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `auth`.`fa_user` (`id`) ON DELETE CASCADE",
        "CONSTRAINT `fa_item_owner_id_fkey` FOREIGN KEY (`owner_id`) REFERENCES `auth`.`fa_user` (`id`) ON DELETE SET NULL\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;",
    ] {
        assert!(sql.contains(expected), "missing {expected:?} in:\n{sql}");
    }
    assert!(!sql.contains("binary(16)"), "{sql}");
}

#[tokio::test]
async fn render_sql() {
    let sql = render_for(&IdStrategy::UuidV7);
    for expected in [
        "CREATE SCHEMA IF NOT EXISTS `auth`;\n",
        "CREATE TABLE `auth`.`fa_user` (\n    `id` binary(16) NOT NULL,\n",
        "`email` varchar(768) NOT NULL,",
        "CONSTRAINT `fa_user_email_key` UNIQUE (`email`)",
        "`email_verified` boolean NOT NULL DEFAULT (false),",
        "`token_hash` varbinary(255) NOT NULL,",
        "CONSTRAINT `fa_session_token_hash_key` UNIQUE (`token_hash`)",
        "`user_id` binary(16) NOT NULL,",
        "`created_at` datetime(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),",
        "`payload` json,",
        "CREATE INDEX `idx_fa_session_user_id` ON `auth`.`fa_session` (`user_id`);",
    ] {
        assert!(sql.contains(expected), "missing {expected:?} in:\n{sql}");
    }
}

#[tokio::test]
async fn conformance() {
    let Some(server) = server().await else {
        return;
    };
    let databases = Mutex::new(Vec::new());
    run_adapter_conformance(async || {
        let name = fresh_name();
        databases.lock().unwrap().push(name.clone());
        Sqlx::new(server.clone()).schema(name).table_prefix("fa_")
    })
    .await;
    drop_databases(&server, databases.into_inner().unwrap()).await;
}

#[tokio::test]
async fn sign_up_sign_in_get_session_with_ulid() {
    flow(IdStrategy::Ulid).await;
}

#[tokio::test]
async fn sign_up_sign_in_get_session_with_uuid_v7() {
    flow(IdStrategy::UuidV7).await;
}

async fn flow(ids: IdStrategy) {
    let Some(server) = server().await else {
        return;
    };
    let storage = ids.storage();
    let (name, pool) = fresh_database(&server).await;
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
    drop_databases(&server, vec![name]).await;
}

#[tokio::test]
async fn switching_id_storage_warns_and_alters_nothing() {
    let Some(server) = server().await else {
        return;
    };
    let mut databases = Vec::new();
    for (created_with, switched_to, live_type) in [
        (IdStrategy::UuidV7, IdStrategy::Ulid, "uuid"),
        (IdStrategy::Ulid, IdStrategy::UuidV4, "text"),
    ] {
        let (name, pool) = fresh_database(&server).await;
        databases.push(name);
        let db = Sqlx::new(pool).table_prefix("fa_");
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
    drop_databases(&server, databases).await;
}
