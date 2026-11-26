mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::plugin_prelude::*;
use fastauth_core::prelude::{EmailPassword, FastAuth, MemoryAdapter, RateLimit};
use fastauth_core::routes::{
    CreateUser, CreateUserInput, GetSession, SignUpEmail, SignUpEmailInput,
};
use fastauth_core::{Auth, plugins};
use serde_json::json;

// ---------------------------------------------------------------- a plugin with user fields

#[derive(Default)]
struct Beta {
    challenge_members: bool,
}

#[derive(Clone, Debug, PartialEq)]
struct BetaUser {
    beta: bool,
}

impl Fields for BetaUser {
    fn columns() -> &'static [ColumnDef] {
        const COLUMNS: &[ColumnDef] =
            &[ColumnDef::new("beta", ColumnType::Bool).default(DefaultValue::Bool(false))];
        COLUMNS
    }
    fn decode(row: &Row) -> Result<Self, DecodeError> {
        Ok(Self {
            beta: row.get("beta")?,
        })
    }
}

impl OnTable for BetaUser {
    type Table = User;
}

impl BetaUser {
    const BETA: Col<BetaUser, bool> = Col::new("beta");
}

struct JoinBeta;

#[derive(Serialize)]
struct Joined {
    beta: bool,
}

impl<D: Adapter> Endpoint<D> for JoinBeta {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/beta/join";
    type Access = Authenticated;
    type Input = Empty;
    type Output = Joined;

    async fn call(&self, ctx: Ctx<D, Authenticated>, _: Empty) -> Result<Joined, AuthError> {
        let id = ctx.session().user.id.clone();
        ctx.db()
            .update::<User>(User::ID.eq(&id))
            .set(BetaUser::BETA, true)
            .exec()
            .await?;
        Ok(Joined { beta: true })
    }
}

struct HeaderResolver;

impl<D: Adapter> SessionResolver<D> for HeaderResolver {
    async fn resolve(
        &self,
        ctx: &Ctx<D>,
        headers: &HeaderMap,
    ) -> Result<Option<Resolved>, AuthError> {
        let Some(email) = headers.get("x-test-user").and_then(|v| v.to_str().ok()) else {
            return Ok(None);
        };
        Ok(ctx
            .internal()
            .find_user_by_email(email)
            .await?
            .map(|u| Resolved::User(u.id.clone())))
    }
}

impl Plugin for Beta {
    const ID: &'static str = "beta";
    type Requires = ();
    type UserFields = BetaUser;
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(JoinBeta);
        app.session_resolver(HeaderResolver);
        app.hook::<SignUpEmail>()
            .before(|_ctx, mut input: SignUpEmailInput| async move {
                if input.email.ends_with("@spam.dk") {
                    return Err(AuthError::bad_request("SPAM", "no spam"));
                }
                input.name = input.name.to_uppercase();
                Ok(Before::Continue(input))
            });
        app.hook::<GetSession>()
            .after(|_ctx, output: Option<serde_json::Value>| async move {
                Ok(After::Continue(output.map(|mut o| {
                    o["hookedBy"] = json!("beta");
                    o
                })))
            });
        let challenge = self.challenge_members;
        app.sign_in_gate(move |_ctx, attempt| async move {
            let fields: BetaUser = attempt.user.fields().map_err(AuthError::internal)?;
            Ok(if challenge && fields.beta {
                Gate::Challenge(json!({ "betaRedirect": true }))
            } else {
                Gate::Allow
            })
        });
    }
}

/// Server-side API, only on auth instances with `Beta`.
trait BetaExt: AuthInstance + Sized {
    async fn join_beta<I>(&self, token: &str) -> Result<Joined, AuthError>
    where
        Self: HasPlugin<Beta, I>,
    {
        Ok(self
            .api()
            .session_token(token)
            .call(&JoinBeta, Empty {})
            .await?
            .data)
    }
}

impl<A: AuthInstance> BetaExt for A {}

// ---------------------------------------------------------------- a plugin that requires Beta

struct BetaBilling {
    calls: Arc<AtomicUsize>,
}

impl Plugin for BetaBilling {
    const ID: &'static str = "beta-billing";
    type Requires = (Beta,);
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        let calls = self.calls.clone();
        app.on(
            move |_event: fastauth_core::events::UserCreated, ctx: Ctx<D>| {
                let calls = calls.clone();
                async move {
                    let _beta: &Beta = ctx.plugin::<Beta>();
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        );
    }
}

type AppAuth = Auth<MemoryAdapter, (), plugins![Beta, BetaBilling]>;

fn app(challenge_members: bool) -> (AppAuth, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let auth = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Beta { challenge_members })
        .plugin(BetaBilling {
            calls: calls.clone(),
        })
        .build()
        .expect("valid config");
    (auth, calls)
}

#[tokio::test]
async fn plugin_fields_are_typed_on_the_session() {
    let (auth, calls) = app(false);
    let mut client = Client::new(auth.clone());
    let res = client.sign_up("p@acme.dk", "correct horse").await;
    assert_eq!(res.json["user"]["beta"], false);
    assert_eq!(
        res.json["user"]["name"], "TEST USER",
        "before hook changed the input"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "event handler ran once");

    let token = res.json["token"].as_str().unwrap().to_owned();
    let before = auth.get_session_by_token(&token).await.unwrap().unwrap();
    assert!(!before.user.plugin::<Beta, _>().beta);

    assert!(
        client.post("/beta/join", json!({})).await.json["beta"]
            .as_bool()
            .unwrap()
    );
    let after = auth.get_session_by_token(&token).await.unwrap().unwrap();
    assert!(after.user.plugin::<Beta, _>().beta);
    assert_eq!(client.get("/get-session").await.json["hookedBy"], "beta");
}

#[tokio::test]
async fn extension_trait_calls_the_plugin_endpoint() {
    let (auth, _) = app(false);
    let mut client = Client::new(auth.clone());
    let token = client.sign_up("e@acme.dk", "correct horse").await.json["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(auth.join_beta(&token).await.unwrap().beta);
    assert!(auth.join_beta("bogus").await.is_err());
}

#[tokio::test]
async fn hooks_can_reject() {
    let (auth, calls) = app(false);
    let res = Client::new(auth)
        .sign_up("x@spam.dk", "correct horse")
        .await;
    assert_eq!(res.json["code"], "SPAM");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no event when the endpoint failed"
    );
}

#[tokio::test]
async fn gates_challenge_without_creating_a_session() {
    let (auth, _) = app(true);
    let mut client = Client::new(auth.clone());
    client.sign_up("g@acme.dk", "correct horse").await;
    client.post("/beta/join", json!({})).await;
    client.jar.clear();
    let res = client
        .post(
            "/sign-in/email",
            json!({ "email": "g@acme.dk", "password": "correct horse" }),
        )
        .await;
    assert_eq!(res.json, json!({ "betaRedirect": true }));
    assert!(client.jar.is_empty(), "no session cookie");
}

#[tokio::test]
async fn resolvers_turn_headers_into_sessions() {
    let (auth, _) = app(false);
    Client::new(auth.clone())
        .sign_up("r@acme.dk", "correct horse")
        .await;
    let mut headers = HeaderMap::new();
    headers.insert("x-test-user", "r@acme.dk".parse().unwrap());
    let session = auth.get_session(&headers).await.unwrap().unwrap();
    assert_eq!(session.user.email, "r@acme.dk");
    assert!(session.view().ephemeral);
}

#[test]
fn hooking_an_unregistered_endpoint_fails_the_build() {
    let err = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .plugin(Beta::default())
        .build()
        .unwrap_err();
    assert!(
        err.problems.iter().any(|p| p.contains("SignUpEmail")),
        "{err}"
    );
}

#[test]
fn schema_shows_owners() {
    let (auth, _) = app(false);
    let user = auth.schema().table("user").unwrap();
    assert_eq!(user.column("beta").unwrap().owner, "beta");
    assert_eq!(user.column("email").unwrap().owner, "core");
    assert!(!auth.plugin::<Beta, _>().challenge_members);
}

#[tokio::test]
async fn hooks_can_target_server_only_endpoints() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let auth: Auth<MemoryAdapter> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .configure(move |app| {
            app.hook::<CreateUser>()
                .before(move |_ctx, input: CreateUserInput| {
                    seen.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if input.email.ends_with("@spam.dk") {
                            return Err(AuthError::bad_request("SPAM", "no spam"));
                        }
                        Ok(Before::Continue(input))
                    }
                });
        })
        .build()
        .expect("CreateUser is a server endpoint, so it can be hooked");
    let input = |email: &str| CreateUserInput {
        email: email.into(),
        name: "Server".into(),
        ..CreateUserInput::default()
    };
    let err = auth
        .api()
        .create_user(input("bot@spam.dk"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "SPAM");
    auth.api().create_user(input("ok@acme.dk")).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let status = Client::new(auth.clone())
        .post("/create-user", json!({ "email": "x@acme.dk", "name": "X" }))
        .await
        .status;
    assert_eq!(status, http::StatusCode::NOT_FOUND, "still no HTTP route");
}

/// (new session's email, the email of the session the request came with).
type SeenSessions = Arc<std::sync::Mutex<Vec<(String, Option<String>)>>>;

#[tokio::test]
async fn session_hooks_run_in_the_request_and_see_the_previous_session() {
    let seen: SeenSessions = Arc::default();
    let record = seen.clone();
    let auth: Auth<MemoryAdapter> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .configure(move |app| {
            let record = record.clone();
            app.on_session_created(move |ctx, session| {
                let record = record.clone();
                async move {
                    let previous = match ctx.signed_cookie("session_token") {
                        Some(token) => ctx
                            .internal()
                            .find_session_by_token(&token)
                            .await?
                            .map(|s| s.user.email.clone()),
                        None => None,
                    };
                    record
                        .lock()
                        .unwrap()
                        .push((session.user.email.clone(), previous));
                    ctx.set_signed_cookie("last_sign_in", &session.user.email, None);
                    if session.user.email.starts_with("refused") {
                        return Err(AuthError::bad_request("REFUSED", "refused"));
                    }
                    Ok(())
                }
            });
        })
        .build()
        .expect("valid config");
    let mut client = Client::new(auth.clone());
    client.sign_up("a@acme.dk", "correct horse").await;
    Client::new(auth.clone())
        .sign_up("b@acme.dk", "correct horse")
        .await;
    let res = client
        .post(
            "/sign-in/email",
            json!({ "email": "b@acme.dk", "password": "correct horse" }),
        )
        .await;
    assert!(
        res.set_cookies()
            .iter()
            .any(|c| c.starts_with("fastauth.last_sign_in=")),
        "a hook can set cookies"
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            ("a@acme.dk".to_owned(), None),
            ("b@acme.dk".to_owned(), None),
            ("b@acme.dk".to_owned(), Some("a@acme.dk".to_owned())),
        ]
    );
    let refused = Client::new(auth.clone())
        .sign_up("refused@acme.dk", "correct horse")
        .await;
    assert_eq!(refused.json["code"], "REFUSED");
}
