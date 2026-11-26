use std::path::PathBuf;

use fastauth::mail::MailError;
use fastauth::prelude::*;
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::AsyncWriteExt;

/// A development mailer: appends each email to a JSON Lines file and logs it. Swap it for
/// one that talks to your email provider; nothing else changes.
#[derive(Clone, Debug)]
pub struct OutboxMailer {
    path: PathBuf,
}

impl OutboxMailer {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl Mailer for OutboxMailer {
    async fn send(&self, email: AuthEmail) -> Result<(), MailError> {
        let (subject, text) = email.default_text("Acme");
        let (kind, url) = match &email {
            AuthEmail::VerifyEmail(e) => ("verify-email", Some(e.url.clone())),
            AuthEmail::ResetPassword(e) => ("reset-password", Some(e.url.clone())),
            AuthEmail::Plugin(e) => (e.kind, e.url.clone()),
            _ => ("other", None),
        };
        let line = json!({
            "at": OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default(),
            "kind": kind,
            "to": email.to(),
            "subject": subject,
            "url": url,
            "text": text,
        });
        tracing::info!(
            to = email.to(),
            kind,
            url = url.as_deref(),
            "email written to the outbox"
        );

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .map_err(|e| MailError(e.to_string()))?;
        file.write_all(format!("{line}\n").as_bytes())
            .await
            .map_err(|e| MailError(e.to_string()))?;
        Ok(())
    }
}
