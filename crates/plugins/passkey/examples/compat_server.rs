//! The server `compat/better-auth/run-passkey.sh` points Better Auth's `passkeyClient` at: email
//! and password plus the passkey plugin, on localhost:$PORT (3000 unless set). In memory, or on
//! MySQL when `DATABASE_URL` is set (an empty database; tables are created on start).
//! Passkey-first sign-up is on, taking the new user's email from `addPasskey`'s `context`.
//!
//! ```bash
//! cargo run -p fastauth-plugin-passkey --example compat_server
//! ```

use std::error::Error;
use std::net::SocketAddr;

use axum::Router;
use fastauth_axum::AuthRouter;
use fastauth_core::adapter::Adapter;
use fastauth_core::prelude::*;
use fastauth_plugin_passkey::{Passkey, PasskeyUser};
use fastauth_sqlx::{MySqlPool, Sqlx};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
    match std::env::var("DATABASE_URL") {
        Ok(url) => serve(Sqlx::new(MySqlPool::connect(&url).await?), &port).await,
        Err(_) => serve(MemoryAdapter::new(), &port).await,
    }
}

async fn serve<D: Adapter>(db: D, port: &str) -> Result<(), Box<dyn Error>> {
    let auth: Auth<D, (), plugins![Passkey]> = FastAuth::builder()
        .app_name("Acme")
        .secret(Secret::from_base64(&Secret::generate()))
        .base_url(format!("http://localhost:{port}"))
        .database(db)
        .email_password(EmailPassword::default())
        .rate_limit(RateLimit::disabled())
        .plugin(Passkey::new().sign_up(|request| async move {
            let email = request.context.ok_or_else(|| {
                AuthError::bad_request("EMAIL_REQUIRED", "pass the new user's email as context")
            })?;
            Ok(PasskeyUser {
                name: request.name.unwrap_or_default(),
                email,
                email_verified: false,
            })
        }))
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
