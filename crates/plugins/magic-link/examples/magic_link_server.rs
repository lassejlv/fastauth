//! The server `tests/compat/better-auth/run-magic-link.sh` points Better Auth's client at: email and
//! password plus the magic link plugin, in memory, on localhost:$PORT (3000 by default).
//!
//! Emails go to the JSON-lines file in `FASTAUTH_OUTBOX` (default `outbox.jsonl`), so the
//! compat script can read the links a real mailer would deliver. Only for that test.
//!
//! ```bash
//! cargo run -p fastauth-plugin-magic-link --example magic_link_server
//! ```

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;

use axum::Router;
use fastauth_axum::AuthRouter;
use fastauth_core::mail::MailError;
use fastauth_core::prelude::*;
use fastauth_plugin_magic_link::MagicLink;

/// Appends each plugin email to a file as one JSON line.
struct Outbox(PathBuf);

impl Mailer for Outbox {
    async fn send(&self, email: AuthEmail) -> Result<(), MailError> {
        let AuthEmail::Plugin(email) = email else {
            return Ok(());
        };
        let line = serde_json::json!({
            "to": email.to,
            "kind": email.kind,
            "url": email.url,
            "code": email.code,
        });
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.0)
            .map_err(|e| MailError(e.to_string()))?;
        writeln!(file, "{line}").map_err(|e| MailError(e.to_string()))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port: u16 = std::env::var("PORT").map_or(Ok(3000), |p| p.parse())?;
    let outbox = std::env::var("FASTAUTH_OUTBOX").unwrap_or_else(|_| "outbox.jsonl".into());
    let auth: Auth<MemoryAdapter, (), plugins![MagicLink]> = FastAuth::builder()
        .app_name("Acme")
        .secret(Secret::from_base64(&Secret::generate()))
        .base_url(format!("http://localhost:{port}"))
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default())
        .email_verification(EmailVerification::default().send_on_sign_up(false))
        .rate_limit(RateLimit::disabled())
        .mailer(Outbox(outbox.into()))
        .plugin(MagicLink::new())
        .build()?;
    let app = Router::new()
        .merge(auth.router())
        .layer(auth.session_layer())
        .with_state(auth);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    println!("listening on http://localhost:{port}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
