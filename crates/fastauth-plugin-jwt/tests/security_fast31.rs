//! FAST-31 security review (area: tokens / JWT). Each `sec_*` test asserts the secure
//! behaviour and fails on fastauth 0.3.0; `guard_*` tests pin behaviour that is already right.

mod common;

use common::{secret, send};
use fastauth_core::adapter::Adapter;
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_plugin_jwt::jsonwebtoken::{self, EncodingKey, Header};
use fastauth_plugin_jwt::{JwksVerifier, Jwt, JwtExt, VerifyError};
use http::Method;
use serde_json::{Map, Value, json};

const BASE: &str = "http://localhost:3000";

type JwtAuth<D> = Auth<D, (), plugins![Jwt]>;

fn build<D: Adapter>(db: D, jwt: Jwt) -> JwtAuth<D> {
    FastAuth::builder()
        .secret(secret())
        .base_url(BASE)
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(jwt)
        .build()
        .expect("valid config")
}

fn claims(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn verifier(auth: &JwtAuth<MemoryAdapter>) -> JwksVerifier {
    let jwks = serde_json::to_string(&auth.jwt().jwks().await.unwrap()).unwrap();
    JwksVerifier::from_json(&jwks, BASE, BASE).unwrap()
}

/// TOKENS-3: `JwksVerifier` (and the server `verify`, which uses it) never checks `nbf`:
/// jsonwebtoken's `Validation::new` leaves `validate_nbf = false`. A token that says it is not
/// valid for another hour verifies now. The verifier's doc promises `exp, nbf, iss and aud`.
#[tokio::test]
async fn sec_jwks_verifier_rejects_a_token_before_its_nbf() {
    let auth = build(MemoryAdapter::new(), Jwt::new());
    let token = auth
        .jwt()
        .sign(claims(json!({ "sub": "user_1", "nbf": now() + 3600 })))
        .await
        .unwrap();
    let local = verifier(&auth).await.verify::<Map<String, Value>>(&token);
    let server = auth.jwt().verify(&token).await.unwrap();
    println!(
        "JwksVerifier: {:?}",
        local.as_ref().map(|c| c["nbf"].clone())
    );
    println!(
        "auth.jwt().verify: {:?}",
        server.as_ref().map(|c| c["nbf"].clone())
    );
    assert!(
        local.is_err(),
        "JwksVerifier accepted a token whose nbf is an hour away"
    );
    assert!(
        server.is_none(),
        "auth.jwt().verify accepted a token whose nbf is an hour away"
    );
}

/// TOKENS-4: rotation promises "tokens signed by the retired keys verify until the grace period
/// ends", but `VerifyJwt` checks against every stored key (`keys::all`), never removes a key, and
/// ignores the grace period. A token from a key retired (e.g. because it leaked) keeps verifying
/// on the server forever, while `/jwks` has already dropped it.
#[tokio::test]
async fn sec_server_verify_rejects_keys_past_their_grace_period() {
    let auth = build(
        MemoryAdapter::new(),
        Jwt::new().grace_period(Duration::seconds(1)),
    );
    let token = auth
        .jwt()
        .sign(claims(json!({ "sub": "user_1", "exp": now() + 86_400 })))
        .await
        .unwrap();
    let old_kid = jsonwebtoken::decode_header(&token).unwrap().kid.unwrap();
    auth.jwt().rotate().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;

    let published: Vec<String> = auth
        .jwt()
        .jwks()
        .await
        .unwrap()
        .keys
        .iter()
        .map(|k| k["kid"].as_str().unwrap().to_owned())
        .collect();
    println!("retired kid {old_kid}; /jwks now lists {published:?}");
    assert!(
        !published.contains(&old_kid),
        "/jwks drops the key after its grace period"
    );
    let verified = auth.jwt().verify(&token).await.unwrap();
    println!("auth.jwt().verify after the grace period: {verified:?}");
    assert!(
        verified.is_none(),
        "a token from key {old_kid}, retired past its grace period, still verifies on the server"
    );
}

/// Algorithm confusion: the verifier takes the algorithm from the JWK, never from the token, and
/// HMAC or `none` tokens never verify, even when they name a real kid.
#[tokio::test]
async fn guard_alg_none_and_hs256_with_the_public_key_are_rejected() {
    let auth = build(MemoryAdapter::new(), Jwt::new());
    let real = auth
        .jwt()
        .sign(claims(json!({ "sub": "user_1" })))
        .await
        .unwrap();
    let kid = jsonwebtoken::decode_header(&real).unwrap().kid.unwrap();
    let jwks = auth.jwt().jwks().await.unwrap();
    let public_x = jwks.keys[0]["x"].as_str().unwrap().to_owned();
    let verifier = verifier(&auth).await;
    let body = json!({ "sub": "admin", "iss": BASE, "aud": BASE, "exp": now() + 600 });

    let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some(kid.clone());
    let jwk_json = Value::Object(jwks.keys[0].clone()).to_string();
    for key in [public_x.as_bytes(), jwk_json.as_bytes()] {
        let key = EncodingKey::from_secret(key).unwrap();
        let forged = jsonwebtoken::encode(&header, &body, &key).unwrap();
        assert!(
            verifier.verify::<Value>(&forged).is_err(),
            "HS256 with the public key"
        );
        assert!(auth.jwt().verify(&forged).await.unwrap().is_none());
    }

    let b64 = |v: &Value| fastauth_core::crypto::base64url(v.to_string().as_bytes());
    for alg in ["none", "None", "NONE"] {
        let unsigned = format!(
            "{}.{}.",
            b64(&json!({ "alg": alg, "kid": kid })),
            b64(&body)
        );
        assert!(verifier.verify::<Value>(&unsigned).is_err(), "alg={alg}");
        assert!(
            auth.jwt().verify(&unsigned).await.unwrap().is_none(),
            "alg={alg}"
        );
    }

    let mut es = Header::new(jsonwebtoken::Algorithm::ES256);
    es.kid = Some(kid);
    let mismatched = format!(
        "{}.{}.{}",
        b64(&serde_json::to_value(&es).unwrap()),
        b64(&body),
        real.rsplit('.').next().unwrap()
    );
    assert!(
        verifier.verify::<Value>(&mismatched).is_err(),
        "header alg ≠ key alg"
    );
}

/// Repro for the JWKS-refetch guidance (TOKENS-6, info): `VerifyError::UnknownKey` is decided
/// from the unauthenticated header alone, so anyone can produce it at will with any garbage
/// token. The module docs tell resource servers to refetch the JWKS on every `UnknownKey`.
#[tokio::test]
async fn sec_repro_unknown_key_is_attacker_controlled() {
    let auth = build(MemoryAdapter::new(), Jwt::new());
    auth.jwt().sign(Map::new()).await.unwrap();
    let verifier = verifier(&auth).await;
    let b64 = |v: &Value| fastauth_core::crypto::base64url(v.to_string().as_bytes());
    let mut unknown = 0;
    for i in 0..1000 {
        let forged = format!(
            "{}.e30.AA",
            b64(&json!({ "alg": "EdDSA", "kid": format!("k{i}") }))
        );
        if matches!(
            verifier.verify::<Value>(&forged),
            Err(VerifyError::UnknownKey(_))
        ) {
            unknown += 1;
        }
    }
    let no_kid = format!("{}.e30.AA", b64(&json!({ "alg": "EdDSA" })));
    println!(
        "{unknown}/1000 unsigned tokens with random kids produced UnknownKey; no kid: {:?}",
        verifier.verify::<Value>(&no_kid).err()
    );
    assert_eq!(unknown, 1000);
}

/// The server-only endpoints are not routed over HTTP.
#[tokio::test]
async fn guard_server_only_jwt_endpoints_are_not_routed() {
    let auth = build(MemoryAdapter::new(), Jwt::new());
    for path in ["/sign-jwt", "/verify-jwt", "/jwks/rotate"] {
        let res = send(
            &auth,
            Method::POST,
            path,
            &[],
            Some(json!({ "payload": { "sub": "x" } })),
        )
        .await;
        assert_eq!(res.status, 404, "{path}: {}", res.json);
    }
}

/// TOKENS-6 hardening: a token without a `kid` is `Invalid`, so it never asks a resource
/// server to refetch the JWKS.
#[tokio::test]
async fn sec_a_token_without_a_kid_is_invalid_not_an_unknown_key() {
    let auth = build(MemoryAdapter::new(), Jwt::new());
    auth.jwt().sign(Map::new()).await.unwrap();
    let verifier = verifier(&auth).await;
    let b64 = |v: &Value| fastauth_core::crypto::base64url(v.to_string().as_bytes());
    let no_kid = format!("{}.e30.AA", b64(&json!({ "alg": "EdDSA" })));
    assert!(
        matches!(
            verifier.verify::<Value>(&no_kid),
            Err(VerifyError::Invalid(_))
        ),
        "{:?}",
        verifier.verify::<Value>(&no_kid).err()
    );
}

/// TOKENS-4 hardening: rotating deletes the keys whose grace period has ended.
#[tokio::test]
async fn sec_rotate_deletes_keys_past_their_grace_period() {
    let auth = build(
        MemoryAdapter::new(),
        Jwt::new().grace_period(Duration::seconds(1)),
    );
    auth.jwt().sign(Map::new()).await.unwrap();
    auth.jwt().rotate().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    auth.jwt().rotate().await.unwrap();
    let stored = fastauth_core::query::Db::new(auth.adapter(), auth.schema())
        .find::<fastauth_plugin_jwt::JsonWebKey>(fastauth_core::query::Where::all())
        .all()
        .await
        .unwrap();
    assert_eq!(
        stored.len(),
        2,
        "the first key's grace period ended, so only the second (retired) and third remain"
    );
}
