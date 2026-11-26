use std::net::SocketAddr;

use anyhow::{Context, bail};
use fastauth::models::User;
use fastauth::plugins::admin::{AdminExt, CreateUserInput, Roles};
use fastauth::prelude::*;
use fastauth::query::Db;
use fastauth_example_fullstack::auth::{self, AppAuth};
use fastauth_example_fullstack::config::Config;
use fastauth_example_fullstack::routes::{self, AppState, Features};
use serde_json::{Map, json};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=warn".into()),
        )
        .init();

    let config = Config::from_env()?;
    let pool = PgPool::connect(&config.database_url)
        .await
        .context("connecting to DATABASE_URL")?;
    sqlx::migrate!()
        .run(&pool)
        .await
        .context("applying migrations/")?;

    let auth = auth::build(&config, pool.clone())?;
    let pending = auth.migrator().plan().await?;
    if !pending.is_empty() {
        bail!(
            "the auth config needs {} schema changes that migrations/ doesn't have; run \
             `cargo run --bin fastauth -- generate` and restart",
            pending.steps.len()
        );
    }
    seed_admin(&auth, &config).await?;

    let state = AppState {
        auth: auth.clone(),
        pool,
        features: Features::from_config(&config),
    };
    let mut app = routes::router()
        .merge(auth.router())
        .layer(auth.session_layer())
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    if let Some(dist) = &config.web_dist {
        let index = ServeFile::new(dist.join("index.html"));
        app = app.fallback_service(ServeDir::new(dist).fallback(index));
    }

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port)).await?;
    tracing::info!("listening on port {}; open {}", config.port, config.app_url);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}

/// Creates the first admin from `ADMIN_EMAIL` and `ADMIN_PASSWORD` when no user has that
/// email. Later admins get the role from an existing admin in the app.
async fn seed_admin(auth: &AppAuth, config: &Config) -> anyhow::Result<()> {
    let Some(seed) = &config.admin else {
        return Ok(());
    };
    let existing = Db::new(auth.adapter(), auth.schema())
        .find::<User>(User::EMAIL.eq(seed.email.to_lowercase()))
        .one()
        .await?;
    if existing.is_some() {
        return Ok(());
    }
    let mut data = Map::new();
    data.insert("emailVerified".into(), json!(true));
    auth.admin()
        .create_user(CreateUserInput {
            email: seed.email.clone(),
            password: Some(seed.password.clone()),
            name: "Admin".into(),
            role: Some(Roles::One("admin".into())),
            data,
        })
        .await?;
    tracing::info!(email = %seed.email, "created the first admin");
    Ok(())
}
