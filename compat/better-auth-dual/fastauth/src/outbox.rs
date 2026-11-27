use std::path::PathBuf;

use fastauth::mail::MailError;
use fastauth::prelude::*;
use serde_json::json;
use tokio::io::AsyncWriteExt;

/// Appends each email to a JSON Lines file the suite reads links and codes from.
#[derive(Clone, Debug)]
pub struct Outbox {
    path: PathBuf,
}

impl Outbox {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl Mailer for Outbox {
    async fn send(&self, email: AuthEmail) -> Result<(), MailError> {
        let (kind, url, code) = match &email {
            AuthEmail::VerifyEmail(e) => ("verify-email", Some(e.url.clone()), None),
            AuthEmail::ResetPassword(e) => ("reset-password", Some(e.url.clone()), None),
            AuthEmail::Plugin(e) => (e.kind, e.url.clone(), e.code.clone()),
            _ => ("other", None, None),
        };
        let line =
            json!({ "app": "fastauth", "kind": kind, "to": email.to(), "url": url, "code": code });
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .map_err(|e| MailError(e.to_string()))?;
        file.write_all(format!("{line}\n").as_bytes())
            .await
            .map_err(|e| MailError(e.to_string()))
    }
}
