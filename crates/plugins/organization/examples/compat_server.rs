//! The server `tests/compat/better-auth/run-organization.sh` points Better Auth's
//! `organizationClient` at: email and password plus the organization plugin, on
//! localhost:$PORT (3000 by default). In memory, or on MySQL when `DATABASE_URL` is set (an
//! empty database; tables are created on start).
//!
//! ```bash
//! cargo run -p fastauth-plugin-organization --example compat_server --features axum
//! ```

use std::error::Error;
use std::net::SocketAddr;

use axum::Router;
use fastauth_axum::AuthRouter;
use fastauth_core::adapter::Adapter;
use fastauth_core::prelude::*;
use fastauth_plugin_organization::Organization;
use fastauth_sqlx::{MySqlPool, Sqlx};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_owned());
    match std::env::var("DATABASE_URL") {
        Ok(url) => serve(Sqlx::new(MySqlPool::connect(&url).await?), &port).await,
        Err(_) => serve(MemoryAdapter::new(), &port).await,
    }
}

async fn serve<D: Adapter>(db: D, port: &str) -> Result<(), Box<dyn Error>> {
    let auth: Auth<D, (), plugins![Organization]> = FastAuth::builder()
        .app_name("Acme")
        .secret(Secret::from_base64(&Secret::generate()))
        .base_url(format!("http://localhost:{port}"))
        .database(db)
        .email_password(EmailPassword::default())
        .rate_limit(RateLimit::disabled())
        // Better Auth skips the verified-email check for its own random invitation ids, and
        // organization.ts accepts with an unverified account; fastauth requires it by default.
        .plugin(Organization::default().require_email_verification_on_invitation(false))
        .build()?;
    auth.migrator().run().await?;
    let app = Router::new()
        .merge(auth.router())
        .layer(auth.session_layer())
        .with_state(auth);
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    println!("listening on http://localhost:{port}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
