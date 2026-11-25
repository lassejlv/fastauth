//! Sign-in gates after a challenge: `complete_sign_in` runs every gate but the challenger's.

mod common;

use std::collections::HashSet;
use std::sync::Mutex;

use common::{Client, Res, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::plugin_prelude::*;
use fastauth_core::prelude::{EmailPassword, FastAuth, MemoryAdapter, RateLimit};
use fastauth_core::routes::{CreateUserInput, SignInOutput};
use fastauth_core::{PluginSet, plugins};
use serde_json::json;

const PASSWORD: &str = "correct horse";

// ------------------------------------------------- a challenger, like two-factor

/// Challenges users whose email starts with `pin`; `/pin/verify` with `1234` finishes.
struct Pin;

#[derive(Deserialize)]
struct PinInput {
    pin: String,
    /// The challenger id to finish as; one test passes a wrong one.
    #[serde(default)]
    challenger: Option<String>,
}

struct VerifyPin;

impl<D: Adapter> Endpoint<D> for VerifyPin {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/pin/verify";
    type Access = Public;
    type Input = PinInput;
    type Output = SignInOutput;

    async fn call(&self, ctx: Ctx<D, Public>, input: PinInput) -> Result<SignInOutput, AuthError> {
        let pending = ctx
            .signed_cookie("pin")
            .ok_or_else(|| AuthError::bad_request("NO_PENDING_SIGN_IN", "no pending sign-in"))?;
        let (user_id, method) = pending.split_once('|').expect("user|method");
        if input.pin != "1234" {
            return Err(AuthError::bad_request("INVALID_PIN", "invalid pin"));
        }
        let user = ctx
            .internal()
            .find_user_by_id(&Id::from(user_id))
            .await?
            .expect("pending user exists");
        ctx.delete_cookie("pin");
        let challenger = input.challenger.as_deref().unwrap_or(Pin::ID);
        let result = ctx
            .internal()
            .complete_sign_in(challenger, user, method.to_owned(), true)
            .await?;
        Ok(SignInOutput::from_result(&ctx, result, None))
    }
}

impl Plugin for Pin {
    const ID: &'static str = "pin";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(VerifyPin);
        app.sign_in_gate(|ctx, attempt| async move {
            if !attempt.user.email.starts_with("pin") {
                return Ok(Gate::Allow);
            }
            let pending = format!("{}|{}", attempt.user.id, attempt.method);
            ctx.set_signed_cookie("pin", &pending, None);
            Ok(Gate::Challenge(json!({ "pinRedirect": true })))
        });
    }
}

// ------------------------------------------------- a ban, like admin

/// Denies banned emails, and records the method of every attempt it judges.
#[derive(Clone, Default)]
struct Ban {
    banned: Arc<Mutex<HashSet<String>>>,
    methods: Arc<Mutex<Vec<String>>>,
}

impl Ban {
    fn ban(&self, email: &str) {
        self.banned.lock().unwrap().insert(email.to_owned());
    }
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
                if banned {
                    return Ok(Gate::Deny(AuthError::new(
                        StatusCode::FORBIDDEN,
                        "BANNED_USER",
                        "you have been banned",
                    )));
                }
                Ok(Gate::Allow)
            }
        });
    }
}

// ------------------------------------------------- a second challenger

/// Challenges users whose email contains `terms`, e.g. to accept new terms.
struct Terms;

impl Plugin for Terms {
    const ID: &'static str = "terms";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.sign_in_gate(|_ctx, attempt| async move {
            Ok(if attempt.user.email.contains("terms") {
                Gate::Challenge(json!({ "termsRedirect": true }))
            } else {
                Gate::Allow
            })
        });
    }
}

macro_rules! auth {
    ($($plugin:expr),+) => {
        FastAuth::builder()
            .secret(secret())
            .base_url("http://localhost:3000")
            .database(MemoryAdapter::new())
            .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
            .rate_limit(RateLimit::disabled())
            $(.plugin($plugin))+
            .build()
            .expect("valid config")
    };
}

type PinThenBan = Client<MemoryAdapter, (), plugins![Pin, Ban, Terms]>;
type BanThenPin = Client<MemoryAdapter, (), plugins![Ban, Pin]>;

fn pin_then_ban() -> (PinThenBan, Ban) {
    let ban = Ban::default();
    (Client::new(auth!(Pin, ban.clone(), Terms)), ban)
}

fn ban_then_pin() -> (BanThenPin, Ban) {
    let ban = Ban::default();
    (Client::new(auth!(ban.clone(), Pin)), ban)
}

trait GateClient {
    async fn create(&mut self, email: &str);
    async fn sign_in(&mut self, email: &str) -> Res;
    async fn verify(&mut self, body: serde_json::Value) -> Res;
    fn has_session(&self) -> bool;
}

impl<P: PluginSet> GateClient for Client<MemoryAdapter, (), P> {
    async fn create(&mut self, email: &str) {
        self.auth
            .api()
            .create_user(CreateUserInput {
                email: email.into(),
                name: "Test User".into(),
                password: Some(PASSWORD.into()),
                fields: Default::default(),
            })
            .await
            .expect("create user");
    }

    async fn sign_in(&mut self, email: &str) -> Res {
        self.post(
            "/sign-in/email",
            json!({ "email": email, "password": PASSWORD }),
        )
        .await
    }

    async fn verify(&mut self, body: serde_json::Value) -> Res {
        self.post("/pin/verify", body).await
    }

    fn has_session(&self) -> bool {
        self.jar.contains_key("fastauth.session_token")
    }
}

/// Creates the user and signs in up to the pin challenge.
async fn challenged(client: &mut impl GateClient, email: &str) {
    client.create(email).await;
    let res = client.sign_in(email).await;
    assert_eq!(res.json, json!({ "pinRedirect": true }), "challenged first");
    assert!(!client.has_session());
}

#[tokio::test]
async fn completing_a_challenge_runs_the_other_gates_once_with_the_original_method() {
    let (mut client, ban) = pin_then_ban();
    challenged(&mut client, "pin@acme.dk").await;
    assert!(ban.methods.lock().unwrap().is_empty(), "ban runs after pin");
    let res = client.verify(json!({ "pin": "1234" })).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["email"], "pin@acme.dk");
    assert!(
        client.has_session(),
        "pin's own gate didn't challenge again"
    );
    assert_eq!(*ban.methods.lock().unwrap(), ["email"]);
}

#[tokio::test]
async fn a_gate_registered_after_the_challenger_denies_on_completion() {
    let (mut client, ban) = pin_then_ban();
    ban.ban("pin@acme.dk");
    challenged(&mut client, "pin@acme.dk").await;
    let res = client.verify(json!({ "pin": "1234" })).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.json);
    assert_eq!(res.json["code"], "BANNED_USER");
    assert!(!client.has_session());
    assert!(
        !client.jar.contains_key("fastauth.pin"),
        "pending sign-in gone"
    );
}

#[tokio::test]
async fn a_gate_registered_before_the_challenger_runs_again_on_completion() {
    let (mut client, ban) = ban_then_pin();
    challenged(&mut client, "pin@acme.dk").await;
    assert_eq!(*ban.methods.lock().unwrap(), ["email"]);
    ban.ban("pin@acme.dk");
    let res = client.verify(json!({ "pin": "1234" })).await;
    assert_eq!(res.json["code"], "BANNED_USER", "{}", res.json);
    assert!(!client.has_session());
    assert_eq!(*ban.methods.lock().unwrap(), ["email", "email"]);

    let (mut client, _) = ban_then_pin();
    challenged(&mut client, "pin@acme.dk").await;
    let res = client.verify(json!({ "pin": "1234" })).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert!(client.has_session());
}

#[tokio::test]
async fn a_remaining_gate_can_challenge_in_turn() {
    let (mut client, _) = pin_then_ban();
    challenged(&mut client, "pin-terms@acme.dk").await;
    let res = client.verify(json!({ "pin": "1234" })).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json, json!({ "termsRedirect": true }));
    assert!(!client.has_session());
}

#[tokio::test]
async fn completing_for_a_plugin_without_gates_is_an_internal_error() {
    let (mut client, _) = pin_then_ban();
    challenged(&mut client, "pin@acme.dk").await;
    let res = client
        .verify(json!({ "pin": "1234", "challenger": "nobody" }))
        .await;
    assert_eq!(
        res.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        res.json
    );
    assert!(!client.has_session());
}

fn find_pin<A: AuthInstance>(auth: &A) -> Option<&Pin> {
    auth.try_plugin::<Pin>()
}

#[test]
fn generic_code_finds_registered_plugins() {
    let (client, _) = ban_then_pin();
    assert!(find_pin(&client.auth).is_some());
    assert!(client.auth.try_plugin::<Terms>().is_none());
}
