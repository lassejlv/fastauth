//! Auth emails. A `Mailer` turns each typed email into a message.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyEmail {
    pub to: String,
    pub name: String,
    pub url: String,
    pub token: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResetPassword {
    pub to: String,
    pub name: String,
    pub url: String,
    pub token: String,
}

/// An email from a plugin (OTP codes, magic links, invitations).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginEmail {
    pub kind: &'static str,
    pub to: String,
    pub subject: String,
    pub text: String,
    pub url: Option<String>,
    pub code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthEmail {
    VerifyEmail(VerifyEmail),
    ResetPassword(ResetPassword),
    Plugin(PluginEmail),
}

impl AuthEmail {
    pub fn to(&self) -> &str {
        match self {
            AuthEmail::VerifyEmail(e) => &e.to,
            AuthEmail::ResetPassword(e) => &e.to,
            AuthEmail::Plugin(e) => &e.to,
        }
    }

    /// A plain-text subject and body, for mailers without templates.
    pub fn default_text(&self, app_name: &str) -> (String, String) {
        match self {
            AuthEmail::VerifyEmail(e) => (
                format!("Verify your email for {app_name}"),
                format!("Hi {},\n\nConfirm your email address: {}\n", e.name, e.url),
            ),
            AuthEmail::ResetPassword(e) => (
                format!("Reset your {app_name} password"),
                format!(
                    "Hi {},\n\nReset your password: {}\n\nIgnore this email if you didn't ask.\n",
                    e.name, e.url
                ),
            ),
            AuthEmail::Plugin(e) => (e.subject.clone(), e.text.clone()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("sending email failed: {0}")]
pub struct MailError(pub String);

pub trait Mailer: Send + Sync + 'static {
    fn send(&self, email: AuthEmail) -> impl Future<Output = Result<(), MailError>> + Send;
}

pub(crate) trait DynMailer: Send + Sync {
    fn send(
        &self,
        email: AuthEmail,
    ) -> Pin<Box<dyn Future<Output = Result<(), MailError>> + Send + '_>>;
}

impl<M: Mailer> DynMailer for M {
    fn send(
        &self,
        email: AuthEmail,
    ) -> Pin<Box<dyn Future<Output = Result<(), MailError>> + Send + '_>> {
        Box::pin(Mailer::send(self, email))
    }
}

/// Logs emails instead of sending them. For development.
#[derive(Clone, Debug, Default)]
pub struct LogMailer;

impl Mailer for LogMailer {
    async fn send(&self, email: AuthEmail) -> Result<(), MailError> {
        let (subject, body) = email.default_text("fastauth");
        tracing::info!(to = email.to(), %subject, %body, "fastauth email (LogMailer, not sent)");
        Ok(())
    }
}

/// Keeps every email in memory. For tests.
#[derive(Clone, Default)]
pub struct MemoryMailer {
    sent: Arc<Mutex<Vec<AuthEmail>>>,
}

impl fmt::Debug for MemoryMailer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemoryMailer({} sent)", self.sent.lock().unwrap().len())
    }
}

impl MemoryMailer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sent(&self) -> Vec<AuthEmail> {
        self.sent.lock().unwrap().clone()
    }

    pub fn last(&self) -> Option<AuthEmail> {
        self.sent.lock().unwrap().last().cloned()
    }
}

impl Mailer for MemoryMailer {
    async fn send(&self, email: AuthEmail) -> Result<(), MailError> {
        self.sent.lock().unwrap().push(email);
        Ok(())
    }
}
