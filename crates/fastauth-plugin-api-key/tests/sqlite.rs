//! The same counters on a real database: SQLite through the sqlx adapter, several
//! connections to one file.

use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::prelude::*;
use fastauth_plugin_api_key::{ApiKeys, ApiKeysExt, CreateApiKeyInput};
use fastauth_sqlx::{Sqlite, SqlitePool, Sqlx};

type AppAuth = Auth<Sqlx<Sqlite>, (), plugins![ApiKeys]>;

async fn auth() -> (AppAuth, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("fastauth-api-key-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let pool = SqlitePool::connect(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .expect("SQLite file");
    let auth: AppAuth = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url("http://localhost:3000")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .plugin(ApiKeys::new())
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrations");
    (auth, path)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_verifies_on_sqlite() {
    let (auth, path) = auth().await;
    let user = auth
        .api()
        .create_user(fastauth_core::routes::CreateUserInput {
            email: "ada@acme.dk".into(),
            name: "Ada".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let created = auth
        .api_keys()
        .create(CreateApiKeyInput {
            user_id: Some(user.id.clone()),
            remaining: Some(5),
            rate_limit_max: Some(100),
            rate_limit_time_window: Some(60_000),
            permissions: Some([("files".to_owned(), vec!["read".to_owned()])].into()),
            ..Default::default()
        })
        .await
        .unwrap();

    let tasks: Vec<_> = (0..32)
        .map(|_| {
            let auth = auth.clone();
            let key = created.key.clone();
            tokio::spawn(async move { auth.api_keys().verify(&key, None).await.unwrap() })
        })
        .collect();
    let mut valid = 0;
    for task in tasks {
        valid += usize::from(task.await.unwrap().valid);
    }
    assert_eq!(valid, 5);

    let code = auth
        .api_keys()
        .verify(&created.key, None)
        .await
        .unwrap()
        .error
        .unwrap()
        .code;
    assert!(
        code == "USAGE_EXCEEDED" || code == "INVALID_API_KEY",
        "{code}"
    );
    let list = auth
        .api_keys()
        .list(fastauth_plugin_api_key::ListApiKeysInput {
            user_id: Some(user.id.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(list.api_keys.is_empty(), "the used-up key is deleted");

    let refilling = auth
        .api_keys()
        .create(CreateApiKeyInput {
            user_id: Some(user.id.clone()),
            refill_amount: Some(3),
            refill_interval: Some(60_000),
            rate_limit_max: Some(2),
            rate_limit_time_window: Some(60_000),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut valid = 0;
    for _ in 0..4 {
        valid += usize::from(
            auth.api_keys()
                .verify(&refilling.key, None)
                .await
                .unwrap()
                .valid,
        );
    }
    assert_eq!(valid, 2, "the rate limit stops the third");
    let key = auth
        .api_keys()
        .get(fastauth_plugin_api_key::GetApiKeyInput {
            id: refilling.api_key.id.clone(),
            user_id: Some(user.id.clone()),
        })
        .await
        .unwrap();
    assert_eq!(key.remaining, Some(1));
    assert_eq!(key.request_count, 2);
    let _ = std::fs::remove_file(path);
}
