//! fastauth on MySQL with every first-party plugin: the app binary's commands, and a schema
//! with every plugin's tables and columns that migrates, takes a user and then has nothing
//! pending. Skipped without `MYSQL_DATABASE_URL`.

use clap::Parser;
use fastauth::cli::Cli;
use fastauth::plugins::admin::Admin;
use fastauth::plugins::anonymous::Anonymous;
use fastauth::plugins::api_key::ApiKeys;
use fastauth::plugins::bearer::Bearer;
use fastauth::plugins::email_otp::EmailOtp;
use fastauth::plugins::jwt::Jwt;
use fastauth::plugins::magic_link::MagicLink;
use fastauth::plugins::multi_session::MultiSession;
use fastauth::plugins::organization::Organization;
use fastauth::plugins::passkey::Passkey;
use fastauth::plugins::two_factor::TwoFactor;
use fastauth::plugins::username::Username;
use fastauth::prelude::*;
use fastauth::routes::CreateUserInput;
use fastauth::sqlx::sqlx::{AssertSqlSafe, Executor};

type Everything = plugins![
    TwoFactor,
    Organization,
    Admin,
    ApiKeys,
    MagicLink,
    EmailOtp,
    Bearer,
    Jwt,
    Passkey,
    Username,
    Anonymous,
    MultiSession,
];

fn build(pool: MySqlPool) -> Result<Auth<Sqlx<MySql>, (), Everything>, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_base64(&Secret::generate()))
        .base_url("http://localhost:3000")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .mailer(LogMailer)
        .plugin(TwoFactor::new())
        .plugin(Organization::default())
        .plugin(Admin::new())
        .plugin(ApiKeys::new())
        .plugin(MagicLink::new())
        .plugin(EmailOtp::new())
        .plugin(Bearer::new())
        .plugin(Jwt::new())
        .plugin(Passkey::new())
        .plugin(Username::new())
        .plugin(Anonymous::new())
        .plugin(MultiSession::new())
        .build()
}

/// A fresh database on the `MYSQL_DATABASE_URL` server and its URL, or `None`.
async fn fresh_database() -> Option<(MySqlPool, String, String)> {
    let Ok(url) = std::env::var("MYSQL_DATABASE_URL") else {
        eprintln!("MYSQL_DATABASE_URL is not set; skipping the MySQL test");
        return None;
    };
    let server = MySqlPool::connect(&url)
        .await
        .expect("connect to MYSQL_DATABASE_URL");
    let name = format!("fastauth_facade_{}", Id::new_v7().as_str().replace('-', ""));
    server
        .execute(AssertSqlSafe(format!("CREATE DATABASE `{name}`")))
        .await
        .unwrap();
    let (base, query) = url.split_once('?').unwrap_or((&url, ""));
    let (server_url, _) = base.rsplit_once('/').unwrap();
    let mut database_url = format!("{server_url}/{name}");
    if !query.is_empty() {
        database_url = format!("{database_url}?{query}");
    }
    Some((server, name, database_url))
}

async fn fastauth(url: &str, args: &[&str]) -> anyhow::Result<()> {
    let argv = ["fastauth", "--database-url", url]
        .into_iter()
        .chain(args.iter().copied());
    Cli::parse_from(argv).run(build).await
}

#[tokio::test]
async fn cli_generates_and_migrates_every_plugin() {
    let Some((server, name, url)) = fresh_database().await else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("migrations");
    assert!(fastauth(&url, &["status"]).await.is_err(), "steps pending");
    fastauth(&url, &["generate", "--out", out.to_str().unwrap()])
        .await
        .unwrap();
    let file = std::fs::read_dir(&out).unwrap().next().unwrap().unwrap();
    let sql = std::fs::read_to_string(file.path()).unwrap();
    for expected in [
        "CREATE TABLE `user` (\n    `id` varchar(768) NOT NULL,",
        "`token_hash` varbinary(255) NOT NULL,",
        "CONSTRAINT `user_email_key` UNIQUE (`email`)",
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;",
        "CREATE TABLE `passkey`",
        "CREATE TABLE `organization`",
        "CREATE TABLE `apikey`",
        "CREATE TABLE `two_factor`",
        "CREATE TABLE `jwks`",
    ] {
        assert!(sql.contains(expected), "missing {expected:?} in:\n{sql}");
    }

    fastauth(&url, &["migrate"]).await.unwrap();
    fastauth(&url, &["status"]).await.unwrap();

    let pool = MySqlPool::connect(&url).await.unwrap();
    let auth = build(pool).unwrap();
    assert!(auth.migrator().plan().await.unwrap().is_empty());
    let user = auth
        .api()
        .create_user(CreateUserInput {
            email: "ada@acme.dk".into(),
            name: "Ada".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(user.email, "ada@acme.dk");

    server
        .execute(AssertSqlSafe(format!("DROP DATABASE `{name}`")))
        .await
        .unwrap();
}
