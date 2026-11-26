//! The server `compat/better-auth/run-passkey.sh` points Better Auth's `passkeyClient` at: email
//! and password plus the passkey plugin, in memory, on localhost:$PORT (3000 unless set).
//! Passkey-first sign-up is on, taking the new user's email from `addPasskey`'s `context`.
//!
//! ```bash
//! cargo run -p fastauth-plugin-passkey --example compat_server
//! ```

use std::net::SocketAddr;

use axum::Router;
use fastauth_axum::AuthRouter;
use fastauth_core::prelude::*;
use fastauth_plugin_passkey::{Passkey, PasskeyUser};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
    let auth: Auth<MemoryAdapter, (), plugins![Passkey]> = FastAuth::builder()
        .app_name("Acme")
        .secret(Secret::from_base64(&Secret::generate()))
        .base_url(format!("http://localhost:{port}"))
        .database(MemoryAdapter::new())
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
