//! Auth emails. A `Mailer` turns each typed email into a message.

use std::any::TypeId;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Semaphore;

/// What `Debug` prints instead of a link, token or code.
const REDACTED: &str = "[redacted]";

/// Debug output never shows the link or the token.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyEmail {
    pub to: String,
    pub name: String,
    pub url: String,
    pub token: String,
}

impl fmt::Debug for VerifyEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyEmail")
            .field("to", &self.to)
            .field("name", &self.name)
            .field("url", &REDACTED)
            .field("token", &REDACTED)
            .finish()
    }
}

/// Debug output never shows the link or the token.
#[derive(Clone, PartialEq, Eq)]
pub struct ResetPassword {
    pub to: String,
    pub name: String,
    pub url: String,
    pub token: String,
}

impl fmt::Debug for ResetPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResetPassword")
            .field("to", &self.to)
            .field("name", &self.name)
            .field("url", &REDACTED)
            .field("token", &REDACTED)
            .finish()
    }
}

/// An email from a plugin (OTP codes, magic links, invitations). Debug output never shows
/// the body, the link or the code.
#[derive(Clone, PartialEq, Eq)]
pub struct PluginEmail {
    pub kind: &'static str,
    pub to: String,
    pub subject: String,
    pub text: String,
    pub url: Option<String>,
    pub code: Option<String>,
}

impl fmt::Debug for PluginEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginEmail")
            .field("kind", &self.kind)
            .field("to", &self.to)
            .field("subject", &self.subject)
            .field("text", &REDACTED)
            .field("url", &self.url.as_ref().map(|_| REDACTED))
            .field("code", &self.code.as_ref().map(|_| REDACTED))
            .finish()
    }
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

    /// Whether this is one of the built-in mailers that do no I/O (`MemoryMailer`,
    /// `LogMailer`), so sending inline costs nothing and reveals nothing.
    fn in_process(&self) -> bool;
}

impl<M: Mailer> DynMailer for M {
    fn send(
        &self,
        email: AuthEmail,
    ) -> Pin<Box<dyn Future<Output = Result<(), MailError>> + Send + '_>> {
        Box::pin(Mailer::send(self, email))
    }

    fn in_process(&self) -> bool {
        let id = TypeId::of::<M>();
        id == TypeId::of::<MemoryMailer>() || id == TypeId::of::<LogMailer>()
    }
}

/// Background sends that run at once. Each holds a thread of tokio's blocking pool while the
/// mailer works, so a slow mailer can't take the threads password hashing needs.
const MAX_CONCURRENT_SENDS: usize = 8;
/// Background sends allowed to wait for a slot; beyond that an email is dropped and logged.
const MAX_QUEUED_SENDS: usize = 10_000;
/// How long one send may take before it is abandoned and logged.
const SEND_TIMEOUT: Duration = Duration::from_secs(60);

static SENDING: Semaphore = Semaphore::const_new(MAX_CONCURRENT_SENDS);
static QUEUED: AtomicUsize = AtomicUsize::new(0);

/// Sends `email` without making the request wait for the mailer, so a route answers in the
/// same time whether or not it sent anything. A failed, dropped or timed-out send is logged,
/// since there's no request left to answer.
///
/// Sends run on tokio's blocking pool, which keeps a mailer that blocks off the async workers,
/// at most `MAX_CONCURRENT_SENDS` at a time per process, each cut off after `SEND_TIMEOUT`
/// when its future yields. Up to `MAX_QUEUED_SENDS` more wait in line; past that, emails
/// are dropped rather than queued without bound.
///
/// `MemoryMailer` and `LogMailer` send inline: they take no time, and tests can read
/// `MemoryMailer` as soon as the response arrives.
pub(crate) async fn send_in_background(mailer: Arc<dyn DynMailer>, email: AuthEmail) {
    let kind = match &email {
        AuthEmail::VerifyEmail(_) => "verify-email",
        AuthEmail::ResetPassword(_) => "reset-password",
        AuthEmail::Plugin(e) => e.kind,
    };
    if mailer.in_process() {
        if let Err(err) = mailer.send(email).await {
            tracing::error!(kind, error = %err, "fastauth could not send an email");
        }
        return;
    }
    if QUEUED.fetch_add(1, Ordering::SeqCst) >= MAX_QUEUED_SENDS {
        QUEUED.fetch_sub(1, Ordering::SeqCst);
        tracing::error!(
            kind,
            "fastauth dropped an email: {MAX_QUEUED_SENDS} are already waiting for the mailer"
        );
        return;
    }
    let runtime = tokio::runtime::Handle::current();
    tokio::spawn(async move {
        let permit = SENDING.acquire().await.expect("never closed");
        let sent = tokio::task::spawn_blocking(move || {
            runtime.block_on(tokio::time::timeout(SEND_TIMEOUT, mailer.send(email)))
        })
        .await;
        drop(permit);
        QUEUED.fetch_sub(1, Ordering::SeqCst);
        match sent {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(err))) => {
                tracing::error!(kind, error = %err, "fastauth could not send an email");
            }
            Ok(Err(_)) => tracing::error!(
                kind,
                "fastauth gave up on an email: the mailer took longer than {SEND_TIMEOUT:?}"
            ),
            Err(err) => tracing::error!(kind, error = %err, "the mailer panicked"),
        }
    });
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
