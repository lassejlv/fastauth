//! Passkey-first sign-up (`Passkey::sign_up`): a signed-out visitor registers a passkey and
//! that creates their user.

mod common;

use std::collections::HashSet;
use std::sync::Mutex;

use common::authenticator::Authenticator;
use common::{Client, ORIGIN, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::plugin_prelude::*;
use fastauth_core::prelude::{EmailPassword, FastAuth, MemoryAdapter, RateLimit};
use fastauth_core::{Auth, PluginSet, plugins};
use fastauth_plugin_passkey::{Passkey, PasskeyUser};
use serde_json::{Value, json};

type SignUpAuth = Auth<MemoryAdapter, (), plugins![Ban, Claim, ApiKeyish, Passkey]>;

/// Passkey-first sign-up where the client passes the email as `context`, plus three test
/// plugins: a sign-in gate, an endpoint that claims a user by email the way magic links and
/// email codes do, and a resolver that turns a `test-user` cookie into an ephemeral session,
/// like an API key.
fn auth(ban: &Ban) -> SignUpAuth {
    FastAuth::builder()
        .secret(secret())
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(ban.clone())
        .plugin(Claim)
        .plugin(ApiKeyish)
        .plugin(Passkey::new().sign_up(|request| async move {
            let email = request.context.ok_or_else(|| {
                AuthError::bad_request("EMAIL_REQUIRED", "pass the email as context")
            })?;
            Ok(PasskeyUser {
                name: request.name.unwrap_or_default(),
                email,
                email_verified: false,
            })
        }))
        .build()
        .expect("valid config")
}

async fn users(auth: &SignUpAuth) -> usize {
    auth.api().call(&CountUsers, Empty {}).await.unwrap().data
}

/// A passkey-first registration from options to `verify-registration`.
async fn sign_up<P: PluginSet>(
    client: &mut Client<MemoryAdapter, (), P>,
    key: &mut Authenticator,
    query: &str,
    mut body: Value,
) -> common::Res {
    let options = client
        .get(&format!("/passkey/generate-register-options?{query}"))
        .await;
    assert_eq!(options.status, StatusCode::OK, "{}", options.json);
    body["response"] = key.create(&options.json, ORIGIN).unwrap();
    client.post("/passkey/verify-registration", body).await
}

#[tokio::test]
async fn registering_signed_out_creates_the_user() {
    let auth = auth(&Ban::default());
    let mut ada = Client::new(auth.clone());
    let options = ada
        .get("/passkey/generate-register-options?context=Ada%40Acme.dk&name=Ada")
        .await;
    assert_eq!(options.status, StatusCode::OK, "{}", options.json);
    assert_eq!(options.json["user"]["name"], "Ada");
    assert_eq!(options.json["user"]["displayName"], "ada@acme.dk");
    assert_eq!(options.json["excludeCredentials"], json!([]));
    assert_eq!(
        users(&auth).await,
        0,
        "no user before the attestation verifies"
    );

    let mut key = Authenticator::new();
    let res = ada
        .post(
            "/passkey/verify-registration",
            json!({
                "response": key.create(&options.json, ORIGIN).unwrap(),
                "name": "Laptop",
                "createSession": true,
            }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["name"], "Laptop");
    assert_eq!(res.json["credentialID"], key.credential_id());
    assert_eq!(res.json["user"]["email"], "ada@acme.dk");
    assert_eq!(res.json["user"]["name"], "Ada");
    assert_eq!(res.json["user"]["emailVerified"], false);
    assert_eq!(res.json["userId"], res.json["user"]["id"]);
    assert!(res.json["session"]["token"].is_string());
    let session = ada.get("/get-session").await.json;
    assert_eq!(session["user"]["email"], "ada@acme.dk");
    assert_eq!(
        ada.get("/passkey/list-user-passkeys").await.json[0]["id"],
        res.json["id"]
    );

    let mut phone = Client::new(auth.clone());
    let signed_in = phone.sign_in_with_passkey(&mut key).await;
    assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.json);
    assert_eq!(signed_in.json["user"]["email"], "ada@acme.dk");
}

#[tokio::test]
async fn without_create_session_the_user_signs_in_afterwards() {
    let auth = auth(&Ban::default());
    let mut ada = Client::new(auth.clone());
    let mut key = Authenticator::new();
    let res = sign_up(&mut ada, &mut key, "context=ada%40acme.dk", json!({})).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert!(res.json.get("session").is_none());
    assert!(res.json.get("user").is_none());
    assert_eq!(ada.get("/get-session").await.json, json!(null));

    let res = ada.sign_in_with_passkey(&mut key).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["email"], "ada@acme.dk");
}

#[tokio::test]
async fn off_by_default() {
    let auth: Auth<MemoryAdapter, (), plugins![Passkey]> = FastAuth::builder()
        .secret(secret())
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .rate_limit(RateLimit::disabled())
        .plugin(Passkey::new())
        .build()
        .unwrap();
    let mut visitor = Client::new(auth);
    let res = visitor
        .get("/passkey/generate-register-options?context=ada%40acme.dk")
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.json);
    let res = visitor
        .post("/passkey/verify-registration", json!({ "response": {} }))
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.json);
}

#[tokio::test]
async fn the_resolver_decides() {
    let auth = auth(&Ban::default());
    let mut visitor = Client::new(auth.clone());
    let res = visitor.get("/passkey/generate-register-options").await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json["code"], "EMAIL_REQUIRED");
    let res = visitor
        .get("/passkey/generate-register-options?context=not-an-email")
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json["code"], "INVALID_EMAIL");
}

#[tokio::test]
async fn never_adds_a_passkey_to_an_existing_user() {
    let auth = auth(&Ban::default());
    let mut bob = Client::new(auth.clone());
    assert_eq!(bob.sign_up("bob@acme.dk").await.status, StatusCode::OK);

    let mut mallory = Client::new(auth.clone());
    let mut key = Authenticator::new();
    let res = sign_up(
        &mut mallory,
        &mut key,
        "context=bob%40acme.dk",
        json!({ "createSession": true }),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", res.json);
    assert_eq!(res.json["code"], "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL");
    assert_eq!(mallory.get("/get-session").await.json, json!(null));
    assert_eq!(bob.get("/passkey/list-user-passkeys").await.json, json!([]));
    let res = mallory.sign_in_with_passkey(&mut key).await;
    assert_eq!(res.json["code"], "PASSKEY_NOT_FOUND");
}

#[tokio::test]
async fn signed_in_users_register_for_themselves() {
    let auth = auth(&Ban::default());
    let mut ada = Client::new(auth.clone());
    let user = ada.sign_up("ada@acme.dk").await.json["user"].clone();
    let mut key = Authenticator::new();
    let res = sign_up(&mut ada, &mut key, "context=eve%40acme.dk", json!({})).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["userId"], user["id"], "the context is ignored");
    assert_eq!(users(&auth).await, 1);
}

#[tokio::test]
async fn challenges_stay_with_their_kind_of_registration() {
    let auth = auth(&Ban::default());

    let mut ada = Client::new(auth.clone());
    let options = ada
        .get("/passkey/generate-register-options?context=ada%40acme.dk")
        .await
        .json;
    assert_eq!(ada.sign_up("ada@acme.dk").await.status, StatusCode::OK);
    let res = ada
        .post(
            "/passkey/verify-registration",
            json!({ "response": Authenticator::new().create(&options, ORIGIN).unwrap() }),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.json);
    assert_eq!(
        res.json["code"],
        "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"
    );

    let options = ada.get("/passkey/generate-register-options").await.json;
    assert_eq!(
        ada.post("/sign-out", json!({})).await.status,
        StatusCode::OK
    );
    let res = ada
        .post(
            "/passkey/verify-registration",
            json!({ "response": Authenticator::new().create(&options, ORIGIN).unwrap() }),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.json);
    assert_eq!(res.json["code"], "UNAUTHORIZED");
    assert_eq!(users(&auth).await, 1);
}

#[tokio::test]
async fn ephemeral_sessions_dont_fall_back_to_sign_up() {
    let auth = auth(&Ban::default());
    let mut ada = Client::new(auth.clone());
    let user = ada.sign_up("ada@acme.dk").await.json["user"].clone();
    let mut key_holder = Client::new(auth.clone());
    key_holder
        .jar
        .insert("test-user".into(), user["id"].as_str().unwrap().to_owned());
    assert_eq!(
        key_holder.get("/get-session").await.json["user"]["id"],
        user["id"]
    );
    let res = key_holder
        .get("/passkey/generate-register-options?context=eve%40acme.dk")
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.json);
    assert_eq!(res.json["code"], "SESSION_NOT_FRESH");
    let res = key_holder
        .post("/passkey/verify-registration", json!({ "response": {} }))
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.json);
}

#[tokio::test]
async fn create_session_runs_the_sign_in_gates() {
    let ban = Ban::default();
    ban.banned.lock().unwrap().insert("eve@acme.dk".into());
    let auth = auth(&ban);
    let mut eve = Client::new(auth.clone());
    let mut key = Authenticator::new();
    let res = sign_up(
        &mut eve,
        &mut key,
        "context=eve%40acme.dk",
        json!({ "createSession": true }),
    )
    .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.json);
    assert_eq!(res.json["code"], "BANNED_USER");
    assert_eq!(eve.get("/get-session").await.json, json!(null));
    assert_eq!(
        ban.methods.lock().unwrap().as_slice(),
        ["passkey"],
        "the gate saw a passkey sign-in"
    );
}

#[tokio::test]
async fn proving_the_email_deletes_passkeys_from_before() {
    let auth = auth(&Ban::default());
    let mut mallory = Client::new(auth.clone());
    let mut key = Authenticator::new();
    let res = sign_up(
        &mut mallory,
        &mut key,
        "context=ada%40acme.dk",
        json!({ "createSession": true }),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["emailVerified"], false);

    let mut ada = Client::new(auth.clone());
    let claimed = ada
        .post("/test/claim", json!({ "email": "ada@acme.dk" }))
        .await;
    assert_eq!(claimed.status, StatusCode::OK, "{}", claimed.json);
    assert_eq!(ada.get("/passkey/list-user-passkeys").await.json, json!([]));
    assert_eq!(mallory.get("/get-session").await.json, json!(null));
    let res = mallory.sign_in_with_passkey(&mut key).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.json);
    assert_eq!(res.json["code"], "PASSKEY_NOT_FOUND");
}

/// Denies banned emails and records the method of every sign-in it judges.
#[derive(Clone, Default)]
struct Ban {
    banned: Arc<Mutex<HashSet<String>>>,
    methods: Arc<Mutex<Vec<String>>>,
}

impl Plugin for Ban {
    const ID: &'static str = "ban";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        let ban = self.clone();
        app.sign_in_gate(move |_ctx, attempt| {
            ban.methods.lock().unwrap().push(attempt.method.to_string());
            let banned = ban.banned.lock().unwrap().contains(&attempt.user.email);
            async move {
                Ok(if banned {
                    Gate::Deny(AuthError::new(
                        StatusCode::FORBIDDEN,
                        "BANNED_USER",
                        "you have been banned",
                    ))
                } else {
                    Gate::Allow
                })
            }
        });
    }
}

/// `POST /test/claim { email }` does to an unverified user what a magic link or an email
/// code does, then signs in as them; `GET /test/users` counts users.
struct Claim;

#[derive(Deserialize)]
struct ClaimInput {
    email: String,
}

impl Plugin for Claim {
    const ID: &'static str = "claim";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(ClaimUser).endpoint(CountUsers);
    }
}

struct ClaimUser;

impl<D: Adapter> Endpoint<D> for ClaimUser {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/test/claim";
    type Access = Public;
    type Input = ClaimInput;
    type Output = Value;

    async fn call(&self, ctx: Ctx<D, Public>, input: ClaimInput) -> Result<Value, AuthError> {
        let internal = ctx.internal();
        let user = internal
            .find_user_by_email(&input.email)
            .await?
            .ok_or_else(|| AuthError::internal("no such user"))?;
        let user = internal.claim_unverified_user(user).await?;
        internal.create_session(&user.id, true).await?;
        Ok(json!({ "status": true }))
    }
}

struct CountUsers;

impl<D: Adapter> Endpoint<D> for CountUsers {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/test/users";
    type Access = Public;
    type Input = Empty;
    type Output = usize;

    async fn call(&self, ctx: Ctx<D, Public>, _: Empty) -> Result<usize, AuthError> {
        Ok(ctx.db().find::<User>(Where::all()).all().await?.len())
    }
}

/// Turns a `test-user` cookie into an ephemeral session for that user id, like an API key.
struct ApiKeyish;

impl Plugin for ApiKeyish {
    const ID: &'static str = "api-keyish";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.session_resolver(CookieUser);
    }
}

struct CookieUser;

impl<D: Adapter> SessionResolver<D> for CookieUser {
    async fn resolve(
        &self,
        _ctx: &Ctx<D>,
        headers: &HeaderMap,
    ) -> Result<Option<Resolved>, AuthError> {
        Ok(headers
            .get(http::header::COOKIE)
            .and_then(|c| c.to_str().ok())
            .and_then(|c| c.split("; ").find_map(|p| p.strip_prefix("test-user=")))
            .map(|id| Resolved::User(Id::from(id.to_owned()))))
    }
}
