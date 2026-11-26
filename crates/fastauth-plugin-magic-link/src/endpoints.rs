//! `POST /sign-in/magic-link` and `GET /magic-link/verify`.

use fastauth_core::mail::{AuthEmail, PluginEmail};
use fastauth_core::plugin_prelude::*;
use fastauth_core::routes::{Status, normalize_email};
use serde_json::{Map, Value as Json};
use url::Url;

use crate::{MagicLink, MagicLinkError};

/// What the `verification` row of a pending link is for. The row stores the token's hash.
const IDENTIFIER: &str = "magic-link";

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    email: String,
    #[serde(default)]
    name: Option<String>,
}

fn invalid_callback_url() -> AuthError {
    AuthError::new(
        StatusCode::FORBIDDEN,
        codes::INVALID_CALLBACK_URL,
        "Invalid callbackURL",
    )
}

/// Better Auth's origin check: each URL is a relative path or on a trusted origin.
fn check_urls<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    callback: Option<&str>,
    error_callback: Option<&str>,
    new_user_callback: Option<&str>,
) -> Result<(), AuthError> {
    let unsafe_url = |url: Option<&str>| url.is_some_and(|u| !ctx.config().is_safe_redirect(u));
    if unsafe_url(callback) {
        return Err(invalid_callback_url());
    }
    if unsafe_url(error_callback) {
        return Err(MagicLinkError::InvalidErrorCallbackUrl.into());
    }
    if unsafe_url(new_user_callback) {
        return Err(MagicLinkError::InvalidNewUserCallbackUrl.into());
    }
    Ok(())
}

/// `POST /sign-in/magic-link`: emails a single-use sign-in link. Answers `{"status": true}`
/// whether or not the email belongs to a user.
pub struct SignInMagicLink(pub(crate) Arc<MagicLink>);

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInMagicLinkInput {
    pub email: String,
    /// The new user's name, when the link signs them up.
    #[serde(default)]
    pub name: Option<String>,
    /// Where the link lands after signing in (default `/`).
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
    /// Where the link lands when it created the user (default: `callbackURL`).
    #[serde(default, rename = "newUserCallbackURL")]
    pub new_user_callback_url: Option<String>,
    /// Where the link lands with `?error=..` when it fails (default: `callbackURL`).
    #[serde(default, rename = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
    /// Better Auth passes this to `sendMagicLink`. fastauth's mailer doesn't see it; read it
    /// in a `hook::<SignInMagicLink>().before(..)` instead.
    #[serde(default)]
    pub metadata: Option<Map<String, Json>>,
}

impl<D: Adapter> Endpoint<D> for SignInMagicLink {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/sign-in/magic-link";
    type Access = Public;
    type Input = SignInMagicLinkInput;
    type Output = Status;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: SignInMagicLinkInput,
    ) -> Result<Status, AuthError> {
        let email = normalize_email(&input.email)?;
        check_urls(
            &ctx,
            input.callback_url.as_deref(),
            input.error_callback_url.as_deref(),
            input.new_user_callback_url.as_deref(),
        )?;
        let internal = ctx.internal();
        let record = serde_json::to_string(&Record {
            email: email.clone(),
            name: input.name,
        })
        .map_err(AuthError::internal)?;
        let token = internal
            .create_verification(IDENTIFIER, self.0.expires_in, Some(record))
            .await?;

        let mut url = Url::parse(&format!("{}/magic-link/verify", ctx.config().auth_url()))
            .map_err(AuthError::internal)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("token", &token);
            query.append_pair("callbackURL", input.callback_url.as_deref().unwrap_or("/"));
            if let Some(new_user) = &input.new_user_callback_url {
                query.append_pair("newUserCallbackURL", new_user);
            }
            if let Some(error) = &input.error_callback_url {
                query.append_pair("errorCallbackURL", error);
            }
        }
        let app_name = &ctx.config().app_name;
        let minutes = self.0.expires_in.whole_minutes().max(1);
        internal
            .send_email(AuthEmail::Plugin(PluginEmail {
                kind: "magic-link",
                to: email,
                subject: format!("Sign in to {app_name}"),
                text: format!(
                    "Sign in to {app_name} with this link: {url}\n\nIt works once and expires \
                     in {minutes} minutes. Ignore this email if you didn't ask for it.\n"
                ),
                url: Some(url.into()),
                code: None,
            }))
            .await?;
        Ok(Status { status: true })
    }
}

/// `GET /magic-link/verify`: the link in the email. Consumes the token and signs the user in,
/// creating them first when the email is new (unless sign-up is disabled).
///
/// With `callbackURL` it redirects there (or to `newUserCallbackURL` for a new user); without
/// one it answers `{ token, user, session }`. Failures redirect to `errorCallbackURL` (or
/// `callbackURL`) with `?error=INVALID_TOKEN`, `new_user_signup_disabled`, or the code (and
/// `error_description`) of a failed sign-up or a sign-in gate that denied. When another plugin's sign-in gate challenges (two-factor), the answer is
/// its JSON, or with `callbackURL` a redirect carrying its fields as query parameters.
pub struct VerifyMagicLink(pub(crate) Arc<MagicLink>);

#[derive(Debug, Default, Deserialize)]
pub struct VerifyMagicLinkInput {
    pub token: String,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(default, rename = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
    #[serde(default, rename = "newUserCallbackURL")]
    pub new_user_callback_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum VerifyMagicLinkOutput {
    /// Signed in, no `callbackURL`: Better Auth's `{ token, user, session }`.
    SignedIn {
        token: String,
        user: Map<String, Json>,
        session: Map<String, Json>,
    },
    /// A sign-in gate's answer, e.g. `{"twoFactorRedirect": true}`.
    Challenge(Json),
    /// Answered with a 302 to `url` over HTTP.
    Redirect { redirect: bool, url: String },
}

fn redirect<D: Adapter, A>(ctx: &Ctx<D, A>, url: Url) -> VerifyMagicLinkOutput {
    let url = String::from(url);
    ctx.redirect(url.clone());
    VerifyMagicLinkOutput::Redirect {
        redirect: true,
        url,
    }
}

/// A gate's challenge fields as query parameters: strings as is, arrays comma-joined.
fn with_challenge(mut url: Url, body: &Json) -> Url {
    if let Some(fields) = body.as_object() {
        let mut query = url.query_pairs_mut();
        for (key, value) in fields {
            let value = match value {
                Json::String(s) => s.clone(),
                Json::Array(items) => items
                    .iter()
                    .map(|i| i.as_str().map_or_else(|| i.to_string(), str::to_owned))
                    .collect::<Vec<_>>()
                    .join(","),
                other => other.to_string(),
            };
            query.append_pair(key, &value);
        }
    }
    url
}

impl<D: Adapter> Endpoint<D> for VerifyMagicLink {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/magic-link/verify";
    type Access = Public;
    type Input = VerifyMagicLinkInput;
    type Output = VerifyMagicLinkOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: VerifyMagicLinkInput,
    ) -> Result<VerifyMagicLinkOutput, AuthError> {
        check_urls(
            &ctx,
            input.callback_url.as_deref(),
            input.error_callback_url.as_deref(),
            input.new_user_callback_url.as_deref(),
        )?;
        let base = &ctx.config().base_url;
        let resolve = |url: &str| base.join(url).map_err(|_| invalid_callback_url());
        let callback = resolve(input.callback_url.as_deref().unwrap_or("/"))?;
        let error_callback = match &input.error_callback_url {
            Some(url) => resolve(url)?,
            None => callback.clone(),
        };
        let new_user_callback = match &input.new_user_callback_url {
            Some(url) => resolve(url)?,
            None => callback.clone(),
        };
        let fail = |error: &str, description: Option<&str>| {
            let mut url = error_callback.clone();
            url.query_pairs_mut().append_pair("error", error);
            if let Some(description) = description {
                url.query_pairs_mut()
                    .append_pair("error_description", description);
            }
            Ok(redirect(&ctx, url))
        };

        let internal = ctx.internal();
        let record = internal
            .find_verification(&input.token)
            .await?
            .filter(|v| v.identifier == IDENTIFIER)
            .and_then(|v| serde_json::from_str::<Record>(v.data.as_deref()?).ok());
        let Some(record) = record else {
            return fail(codes::INVALID_TOKEN, None);
        };
        if internal.consume_verification(&input.token).await?.is_none() {
            return fail(codes::INVALID_TOKEN, None);
        }

        let (user, is_new) = match internal.find_user_by_email(&record.email).await? {
            Some(user) => (internal.claim_unverified_user(user).await?, false),
            None if self.0.disable_sign_up => return fail("new_user_signup_disabled", None),
            None => {
                let new_user = NewUser {
                    email: record.email,
                    name: record.name.unwrap_or_default(),
                    email_verified: true,
                    ..NewUser::default()
                };
                match internal.create_user(new_user, None).await {
                    Ok(user) => (user, true),
                    Err(err) if !err.status().is_server_error() => {
                        return fail(err.code(), Some(err.message()));
                    }
                    Err(err) => return Err(err),
                }
            }
        };

        let target = if is_new { new_user_callback } else { callback };
        let redirects = input.callback_url.is_some();
        let signed_in = match internal.sign_in(user, MagicLink::ID, true).await {
            Ok(result) => result,
            Err(err) if !err.status().is_server_error() => {
                return fail(err.code(), Some(err.message()));
            }
            Err(err) => return Err(err),
        };
        Ok(match signed_in {
            SignInResult::SignedIn(_) if redirects => redirect(&ctx, target),
            SignInResult::SignedIn(session) => VerifyMagicLinkOutput::SignedIn {
                token: session.token.clone().unwrap_or_default(),
                user: session.user.to_json(),
                session: session.to_json(),
            },
            SignInResult::Challenge(body) if redirects => {
                redirect(&ctx, with_challenge(target, &body))
            }
            SignInResult::Challenge(body) => VerifyMagicLinkOutput::Challenge(body),
        })
    }
}
