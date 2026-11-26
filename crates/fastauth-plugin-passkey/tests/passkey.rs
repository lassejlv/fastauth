//! Passkey ceremonies against the memory adapter, driven by a software authenticator.

mod common;

use std::collections::HashSet;
use std::sync::Mutex;

use common::authenticator::{AAGUID, Authenticator};
use common::{Client, ORIGIN, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::models::Verification;
use fastauth_core::plugin_prelude::*;
use fastauth_core::prelude::{EmailPassword, FastAuth, MemoryAdapter, RateLimit};
use fastauth_core::{Auth, PluginSet, plugins};
use fastauth_plugin_passkey::webauthn_rs::prelude::Uuid;
use fastauth_plugin_passkey::{DeletePasskeyInput, Passkey, PasskeyExt, UpdatePasskeyInput};
use fastauth_plugin_two_factor::{TwoFactor, totp};
use serde_json::{Value, json};

type PasskeyAuth = Auth<MemoryAdapter, (), plugins![Passkey]>;
type GatedAuth = Auth<MemoryAdapter, (), plugins![TwoFactor, Ban, Passkey]>;

fn auth() -> PasskeyAuth {
    FastAuth::builder()
        .secret(secret())
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Passkey::new().rp_name("Acme"))
        .build()
        .expect("valid config")
}

/// A signed-up user with one passkey on `key`.
async fn user_with_passkey<P: PluginSet>(
    auth: &Auth<MemoryAdapter, (), P>,
    email: &str,
    key: &mut Authenticator,
) -> (Client<MemoryAdapter, (), P>, Value) {
    let mut client = Client::new(auth.clone());
    assert_eq!(client.sign_up(email).await.status, StatusCode::OK);
    let added = client.add_passkey(key, Some("Laptop")).await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.json);
    (client, added.json)
}

fn has_challenge_cookie<D, U, P>(client: &Client<D, U, P>) -> bool {
    client.jar.contains_key("fastauth.passkey")
}

#[tokio::test]
async fn registers_and_signs_in() {
    let auth = auth();
    let mut ada = Client::new(auth.clone());
    let user = ada.sign_up("ada@acme.dk").await.json["user"].clone();

    let options = ada
        .get("/passkey/generate-register-options?name=Ada%27s%20laptop&authenticatorAttachment=platform")
        .await;
    assert_eq!(options.status, StatusCode::OK, "{}", options.json);
    let options = options.json;
    assert_eq!(options["rp"], json!({ "name": "Acme", "id": "localhost" }));
    assert_eq!(options["user"]["name"], "Ada's laptop");
    assert_eq!(options["user"]["displayName"], "ada@acme.dk");
    assert_eq!(options["attestation"], "none");
    assert_eq!(options["excludeCredentials"], json!([]));
    assert_eq!(
        options["authenticatorSelection"]["residentKey"],
        "preferred"
    );
    assert_eq!(
        options["authenticatorSelection"]["authenticatorAttachment"],
        "platform"
    );
    assert_eq!(
        options["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert!(options["challenge"].as_str().is_some_and(|c| c.len() >= 43));
    assert!(has_challenge_cookie(&ada));

    let mut key = Authenticator::new();
    let response = key.create(&options, ORIGIN).unwrap();
    let added = ada
        .post(
            "/passkey/verify-registration",
            json!({ "response": response, "name": "  Laptop " }),
        )
        .await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.json);
    let passkey = added.json;
    assert_eq!(passkey["name"], "Laptop");
    assert_eq!(passkey["userId"], user["id"]);
    assert_eq!(passkey["credentialID"], key.credential_id());
    assert_eq!(passkey["counter"], 1);
    assert_eq!(passkey["deviceType"], "singleDevice");
    assert_eq!(passkey["backedUp"], false);
    assert_eq!(passkey["transports"], "internal,hybrid");
    assert_eq!(passkey["aaguid"], Uuid::from_bytes(AAGUID).to_string());
    assert!(passkey["publicKey"].as_str().is_some_and(|k| k.len() > 40));
    assert!(passkey["createdAt"].is_string());
    assert!(passkey.get("session").is_none());
    assert!(
        !has_challenge_cookie(&ada),
        "the challenge cookie is cleared"
    );

    let listed = ada.get("/passkey/list-user-passkeys").await;
    assert_eq!(listed.json, json!([passkey]));

    let mut phone = Client::new(auth.clone());
    let options = phone
        .get("/passkey/generate-authenticate-options")
        .await
        .json;
    assert_eq!(options["rpId"], "localhost");
    assert_eq!(options["userVerification"], "required");
    assert_eq!(
        options
            .get("allowCredentials")
            .cloned()
            .unwrap_or(json!([])),
        json!([])
    );
    let response = key.get(&options, ORIGIN).unwrap();
    let signed_in = phone
        .post(
            "/passkey/verify-authentication",
            json!({ "response": response }),
        )
        .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.json);
    assert_eq!(signed_in.json["user"]["email"], "ada@acme.dk");
    assert!(signed_in.json["session"]["token"].is_string());
    assert_eq!(signed_in.json["session"]["userId"], user["id"]);
    let session = phone.get("/get-session").await.json;
    assert_eq!(session["user"]["id"], user["id"]);

    let listed = ada.get("/passkey/list-user-passkeys").await.json;
    assert_eq!(listed[0]["counter"], 2, "the counter advanced");
}

#[tokio::test]
async fn signed_in_options_list_the_users_passkeys() {
    let auth = auth();
    let mut key = Authenticator::new();
    let (mut ada, passkey) = user_with_passkey(&auth, "ada@acme.dk", &mut key).await;

    let options = ada.get("/passkey/generate-authenticate-options").await.json;
    assert_eq!(
        options["allowCredentials"],
        json!([{
            "type": "public-key",
            "id": passkey["credentialID"],
            "transports": ["internal", "hybrid"],
        }])
    );

    let options = ada.get("/passkey/generate-register-options").await.json;
    assert_eq!(
        options["excludeCredentials"][0]["id"],
        passkey["credentialID"]
    );
    assert!(
        key.create(&options, ORIGIN).is_none(),
        "the authenticator refuses to register twice"
    );
}

#[tokio::test]
async fn challenges_work_once_and_expire() {
    let auth = auth();
    let mut key = Authenticator::new();
    user_with_passkey(&auth, "ada@acme.dk", &mut key).await;

    let mut phone = Client::new(auth.clone());
    let options = phone
        .get("/passkey/generate-authenticate-options")
        .await
        .json;
    let body = json!({ "response": key.get(&options, ORIGIN).unwrap() });
    let jar = phone.jar.clone();
    assert_eq!(
        phone
            .post("/passkey/verify-authentication", body.clone())
            .await
            .status,
        StatusCode::OK
    );
    phone.jar = jar;
    let replayed = phone.post("/passkey/verify-authentication", body).await;
    assert_eq!(replayed.status, StatusCode::BAD_REQUEST);
    assert_eq!(replayed.json["code"], "CHALLENGE_NOT_FOUND");

    let mut late = Client::new(auth.clone());
    let options = late
        .get("/passkey/generate-authenticate-options")
        .await
        .json;
    auth.api()
        .db()
        .update::<Verification>(Verification::IDENTIFIER.eq("passkey"))
        .set(
            Verification::EXPIRES_AT,
            OffsetDateTime::now_utc() - Duration::seconds(1),
        )
        .exec()
        .await
        .unwrap();
    let res = late
        .post(
            "/passkey/verify-authentication",
            json!({ "response": key.get(&options, ORIGIN).unwrap() }),
        )
        .await;
    assert_eq!(
        res.json["code"], "CHALLENGE_NOT_FOUND",
        "an expired challenge"
    );

    let mut cookieless = Client::new(auth.clone());
    let res = cookieless
        .post("/passkey/verify-authentication", json!({ "response": {} }))
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json["code"], "CHALLENGE_NOT_FOUND");
}

#[tokio::test]
async fn ceremonies_dont_share_challenges() {
    let auth = auth();
    let mut ada = Client::new(auth.clone());
    ada.sign_up("ada@acme.dk").await;
    ada.get("/passkey/generate-register-options").await;
    let res = ada
        .post("/passkey/verify-authentication", json!({ "response": {} }))
        .await;
    assert_eq!(res.json["code"], "CHALLENGE_NOT_FOUND");

    ada.get("/passkey/generate-authenticate-options").await;
    let res = ada
        .post("/passkey/verify-registration", json!({ "response": {} }))
        .await;
    assert_eq!(res.json["code"], "CHALLENGE_NOT_FOUND");
}

#[tokio::test]
async fn rejects_bad_assertions() {
    let auth = auth();
    let mut key = Authenticator::new();
    user_with_passkey(&auth, "ada@acme.dk", &mut key).await;
    let mut phone = Client::new(auth.clone());

    let options = phone
        .get("/passkey/generate-authenticate-options")
        .await
        .json;
    let response = key.get(&options, "https://evil.example").unwrap();
    let res = phone
        .post(
            "/passkey/verify-authentication",
            json!({ "response": response }),
        )
        .await;
    assert_eq!(
        res.status,
        StatusCode::BAD_REQUEST,
        "wrong origin: {}",
        res.json
    );
    assert_eq!(res.json["code"], "AUTHENTICATION_FAILED");

    let options = phone
        .get("/passkey/generate-authenticate-options")
        .await
        .json;
    let mut response = key.get(&options, ORIGIN).unwrap();
    let other = key.get(&options, ORIGIN).unwrap();
    response["response"]["signature"] = other["response"]["signature"].clone();
    let res = phone
        .post(
            "/passkey/verify-authentication",
            json!({ "response": response }),
        )
        .await;
    assert_eq!(
        res.status,
        StatusCode::UNAUTHORIZED,
        "a forged signature: {}",
        res.json
    );
    assert_eq!(res.json["code"], "AUTHENTICATION_FAILED");

    let mut unregistered = Authenticator::new();
    unregistered.create(
        &json!({ "rp": { "id": "localhost" }, "user": { "id": "eA" }, "challenge": "eA" }),
        ORIGIN,
    );
    let options = phone
        .get("/passkey/generate-authenticate-options")
        .await
        .json;
    let res = phone
        .post(
            "/passkey/verify-authentication",
            json!({ "response": unregistered.get(&options, ORIGIN).unwrap() }),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json["code"], "PASSKEY_NOT_FOUND");

    key.verifies_user = false;
    let options = phone
        .get("/passkey/generate-authenticate-options")
        .await
        .json;
    let res = phone
        .post(
            "/passkey/verify-authentication",
            json!({ "response": key.get(&options, ORIGIN).unwrap() }),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "no user verification");
    assert_eq!(res.json["code"], "AUTHENTICATION_FAILED");
    assert_eq!(phone.get("/get-session").await.json, json!(null));
}

#[tokio::test]
async fn checks_and_updates_the_signature_counter() {
    let auth = auth();
    let mut key = Authenticator::new();
    let (mut ada, _) = user_with_passkey(&auth, "ada@acme.dk", &mut key).await;
    let mut clone = key.clone();

    let mut phone = Client::new(auth.clone());
    assert_eq!(
        phone.sign_in_with_passkey(&mut key).await.status,
        StatusCode::OK
    );
    assert_eq!(
        phone.sign_in_with_passkey(&mut key).await.status,
        StatusCode::OK
    );
    assert_eq!(
        ada.get("/passkey/list-user-passkeys").await.json[0]["counter"],
        3
    );

    let mut thief = Client::new(auth.clone());
    let res = thief.sign_in_with_passkey(&mut clone).await;
    assert_eq!(
        res.status,
        StatusCode::BAD_REQUEST,
        "a counter that went back: {}",
        res.json
    );
    assert_eq!(res.json["code"], "AUTHENTICATION_FAILED");
    assert_eq!(thief.get("/get-session").await.json, json!(null));
    assert_eq!(
        ada.get("/passkey/list-user-passkeys").await.json[0]["counter"],
        3
    );

    let mut synced = Authenticator::new();
    synced.counts = false;
    synced.synced = true;
    let (mut bob, passkey) = user_with_passkey(&auth, "bob@acme.dk", &mut synced).await;
    assert_eq!(passkey["counter"], 0);
    assert_eq!(passkey["deviceType"], "multiDevice");
    assert_eq!(passkey["backedUp"], true);
    let mut laptop = Client::new(auth.clone());
    for _ in 0..2 {
        let res = laptop.sign_in_with_passkey(&mut synced).await;
        assert_eq!(
            res.status,
            StatusCode::OK,
            "a passkey that doesn't count: {}",
            res.json
        );
    }
    assert_eq!(
        bob.get("/passkey/list-user-passkeys").await.json[0]["counter"],
        0
    );
}

#[tokio::test]
async fn registration_checks() {
    let auth = auth();
    let mut anonymous = Client::new(auth.clone());
    let res = anonymous.get("/passkey/generate-register-options").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);

    let mut ada = Client::new(auth.clone());
    ada.sign_up("ada@acme.dk").await;
    let mut bob = Client::new(auth.clone());
    bob.sign_up("bob@acme.dk").await;

    let options = bob.get("/passkey/generate-register-options").await.json;
    let cookie = bob.jar["fastauth.passkey"].clone();
    ada.jar.insert("fastauth.passkey".into(), cookie);
    let mut key = Authenticator::new();
    let res = ada
        .post(
            "/passkey/verify-registration",
            json!({ "response": key.create(&options, ORIGIN).unwrap() }),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.json);
    assert_eq!(
        res.json["code"],
        "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"
    );

    let options = ada.get("/passkey/generate-register-options").await.json;
    let res = ada
        .post(
            "/passkey/verify-registration",
            json!({ "response": key.create(&options, "https://evil.example").unwrap() }),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json["code"], "FAILED_TO_VERIFY_REGISTRATION");

    let options = ada.get("/passkey/generate-register-options").await.json;
    let mut unverified = Authenticator::new();
    unverified.verifies_user = false;
    let res = ada
        .post(
            "/passkey/verify-registration",
            json!({ "response": unverified.create(&options, ORIGIN).unwrap() }),
        )
        .await;
    assert_eq!(
        res.json["code"], "FAILED_TO_VERIFY_REGISTRATION",
        "user verification is required"
    );
    assert_eq!(ada.get("/passkey/list-user-passkeys").await.json, json!([]));
}

#[tokio::test]
async fn verify_registration_can_create_a_session() {
    let auth = auth();
    let mut ada = Client::new(auth.clone());
    let first = ada.sign_up("ada@acme.dk").await.json["token"].clone();
    let options = ada.get("/passkey/generate-register-options").await.json;
    let mut key = Authenticator::new();
    let res = ada
        .post(
            "/passkey/verify-registration",
            json!({ "response": key.create(&options, ORIGIN).unwrap(), "createSession": true }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["credentialID"], key.credential_id());
    assert_eq!(res.json["user"]["email"], "ada@acme.dk");
    let token = res.json["session"]["token"].as_str().unwrap();
    assert_ne!(json!(token), first, "a new session");
    let sessions = ada.get("/list-sessions").await.json;
    assert_eq!(sessions.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn manages_passkeys() {
    let auth = auth();
    let mut key = Authenticator::new();
    let (mut ada, passkey) = user_with_passkey(&auth, "ada@acme.dk", &mut key).await;
    let id = passkey["id"].as_str().unwrap();
    let (mut bob, _) = user_with_passkey(&auth, "bob@acme.dk", &mut Authenticator::new()).await;

    let res = ada
        .post(
            "/passkey/update-passkey",
            json!({ "id": id, "name": "   " }),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    let res = bob
        .post(
            "/passkey/update-passkey",
            json!({ "id": id, "name": "Mine" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        res.json["code"],
        "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"
    );
    let res = ada
        .post(
            "/passkey/update-passkey",
            json!({ "id": "nope", "name": "Mine" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(res.json["code"], "PASSKEY_NOT_FOUND");
    let res = ada
        .post(
            "/passkey/update-passkey",
            json!({ "id": id, "name": " Work laptop " }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["passkey"]["name"], "Work laptop");
    assert_eq!(res.json["passkey"]["id"], passkey["id"]);

    let listed = auth.passkey().list(&ada.headers()).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name.as_deref(), Some("Work laptop"));
    let renamed = auth
        .passkey()
        .update(
            &ada.headers(),
            UpdatePasskeyInput {
                id: id.into(),
                name: "Laptop".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(renamed.data.passkey.name.as_deref(), Some("Laptop"));

    let res = bob
        .post("/passkey/delete-passkey", json!({ "id": id }))
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json["code"], "UNAUTHORIZED");
    let res = ada
        .post("/passkey/delete-passkey", json!({ "id": id }))
        .await;
    assert_eq!(res.json, json!({ "status": true }));
    assert_eq!(ada.get("/passkey/list-user-passkeys").await.json, json!([]));
    let err = auth
        .passkey()
        .delete(&ada.headers(), DeletePasskeyInput { id: id.into() })
        .await
        .unwrap_err();
    assert_eq!(err.code(), "PASSKEY_NOT_FOUND");

    let res = Client::new(auth.clone())
        .sign_in_with_passkey(&mut key)
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json["code"], "PASSKEY_NOT_FOUND");
}

/// Denies banned emails and records the method of every sign-in it judges, like admin's ban.
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

fn base32_decode(s: &str) -> Vec<u8> {
    let mut bits = 0u64;
    let mut count = 0;
    let mut out = Vec::new();
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => continue,
        };
        bits = (bits << 5) | u64::from(v);
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    out
}

#[tokio::test]
async fn sign_in_runs_the_gates() {
    let ban = Ban::default();
    let auth: GatedAuth = FastAuth::builder()
        .secret(secret())
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(TwoFactor::new().skip_verification_on_enable(true))
        .plugin(ban.clone())
        .plugin(Passkey::new())
        .build()
        .unwrap();

    let mut key = Authenticator::new();
    let (mut ada, _) = user_with_passkey(&auth, "ada@acme.dk", &mut key).await;
    let enabled = ada
        .post(
            "/two-factor/enable",
            json!({ "password": "correct horse battery" }),
        )
        .await;
    assert_eq!(enabled.status, StatusCode::OK, "{}", enabled.json);
    let uri = enabled.json["totpURI"].as_str().unwrap().to_owned();
    let secret = base32_decode(
        uri.split("secret=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap(),
    );

    let mut phone = Client::new(auth.clone());
    let res = phone.sign_in_with_passkey(&mut key).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["twoFactorRedirect"], true);
    assert!(res.json.get("session").is_none());
    assert_eq!(phone.get("/get-session").await.json, json!(null));
    let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
    let res = phone
        .post(
            "/two-factor/verify-totp",
            json!({ "code": totp::totp(&secret, now, 30, 6) }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(
        phone.get("/get-session").await.json["user"]["email"],
        "ada@acme.dk"
    );
    assert_eq!(
        ban.methods.lock().unwrap().last().map(String::as_str),
        Some("passkey"),
        "the method survives the challenge"
    );

    let mut carol_key = Authenticator::new();
    user_with_passkey(&auth, "carol@acme.dk", &mut carol_key).await;
    ban.banned.lock().unwrap().insert("carol@acme.dk".into());
    let mut thief = Client::new(auth.clone());
    let res = thief.sign_in_with_passkey(&mut carol_key).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(res.json["code"], "BANNED_USER");
    assert_eq!(thief.get("/get-session").await.json, json!(null));
    assert_eq!(
        ban.methods.lock().unwrap().last().map(String::as_str),
        Some("passkey")
    );
}
