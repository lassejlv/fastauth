mod common;

use common::{Res, bearer, cookie, postgres, secret, send, sqlite};
use fastauth_core::PluginSet;
use fastauth_core::adapter::Adapter;
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_plugin_bearer::{Bearer, SET_AUTH_TOKEN};
use fastauth_plugin_jwt::jsonwebtoken;
use fastauth_plugin_jwt::{
    JsonWebKey, JwksVerifier, Jwt, JwtAlgorithm, JwtExt, SET_AUTH_JWT, VerifyError,
};
use http::{Method, StatusCode};
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

/// Signs up and returns the user id and the session cookie value.
async fn sign_up<D: Adapter, P: PluginSet>(auth: &Auth<D, (), P>, email: &str) -> (String, String) {
    let res = send(
        auth,
        Method::POST,
        "/sign-up/email",
        &[],
        Some(json!({ "email": email, "password": "correct horse", "name": "Ada" })),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let id = res.json["user"]["id"].as_str().unwrap().to_owned();
    (id, res.session_cookie().unwrap())
}

async fn get<D: Adapter, P: PluginSet>(
    auth: &Auth<D, (), P>,
    path: &str,
    session: Option<&str>,
) -> Res {
    let cookie = session.map(cookie);
    let headers: Vec<(&str, &str)> = cookie.iter().map(|c| ("cookie", c.as_str())).collect();
    send(auth, Method::GET, path, &headers, None).await
}

async fn token<D: Adapter, P: PluginSet>(auth: &Auth<D, (), P>, session: &str) -> String {
    let res = get(auth, "/token", Some(session)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    res.json["token"].as_str().unwrap().to_owned()
}

async fn verifier<D: Adapter, P: PluginSet>(auth: &Auth<D, (), P>) -> JwksVerifier {
    let jwks = get(auth, "/jwks", None).await;
    assert_eq!(jwks.status, StatusCode::OK, "{}", jwks.json);
    JwksVerifier::from_json(&jwks.json.to_string(), BASE, BASE).expect("a JWKS")
}

fn header(token: &str) -> jsonwebtoken::Header {
    jsonwebtoken::decode_header(token).unwrap()
}

/// The whole flow, run on every adapter.
async fn jwt_flow<D: Adapter>(db: D) {
    let auth = build(db, Jwt::new());
    auth.migrator().run().await.expect("migrations");

    let anonymous = get(&auth, "/token", None).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert_eq!(anonymous.json["code"], "UNAUTHORIZED");

    let (user_id, session) = sign_up(&auth, "ada@acme.dk").await;

    let jwks = get(&auth, "/jwks", None).await;
    let keys = jwks.json["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1, "{}", jwks.json);
    let key = keys[0].as_object().unwrap();
    assert_eq!(key["alg"], "EdDSA");
    assert_eq!(key["crv"], "Ed25519");
    assert_eq!(key["kty"], "OKP");
    assert!(key["x"].as_str().is_some_and(|x| x.len() == 43));
    assert!(!key.contains_key("d"), "no private key material: {key:?}");
    let kid = key["kid"].as_str().unwrap().to_owned();

    let stored = auth
        .api()
        .db()
        .find::<JsonWebKey>(JsonWebKey::ID.eq(Id::from(kid.as_str())))
        .one()
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.private_key.contains("PRIVATE"));
    assert_eq!(stored.alg.as_deref(), Some("EdDSA"));
    assert_eq!(stored.crv.as_deref(), Some("Ed25519"));
    assert_eq!(stored.expires_at, None);

    let jwt = token(&auth, &session).await;
    let head = header(&jwt);
    assert_eq!(head.alg, jsonwebtoken::Algorithm::EdDSA);
    assert_eq!(head.kid.as_deref(), Some(kid.as_str()));
    assert_eq!(head.typ, None, "like Better Auth, no typ");
    let claims: Map<String, Value> = verifier(&auth).await.verify(&jwt).expect("valid");
    assert_eq!(claims["sub"], user_id.as_str());
    assert_eq!(claims["id"], user_id.as_str());
    assert_eq!(claims["email"], "ada@acme.dk");
    assert_eq!(claims["name"], "Ada");
    assert_eq!(claims["emailVerified"], false);
    assert_eq!(claims["iss"], BASE);
    assert_eq!(claims["aud"], BASE);
    let iat = claims["iat"].as_i64().unwrap();
    assert_eq!(claims["exp"].as_i64().unwrap() - iat, 15 * 60);

    let with_session = get(&auth, "/get-session", Some(&session)).await;
    assert_eq!(with_session.json["user"]["email"], "ada@acme.dk");
    let header_jwt = with_session.header(SET_AUTH_JWT).expect("set-auth-jwt");
    let claims: Map<String, Value> = verifier(&auth).await.verify(header_jwt).unwrap();
    assert_eq!(claims["sub"], user_id.as_str());
    assert_eq!(
        with_session.header("access-control-expose-headers"),
        Some(SET_AUTH_JWT)
    );
    let signed_out = get(&auth, "/get-session", None).await;
    assert_eq!(signed_out.json, Value::Null);
    assert_eq!(signed_out.header(SET_AUTH_JWT), None);

    assert_eq!(
        auth.jwt().verify(&jwt).await.unwrap().unwrap()["sub"],
        user_id.as_str()
    );
    let tampered = format!("{}x", &jwt[..jwt.len() - 1]);
    assert!(auth.jwt().verify(&tampered).await.unwrap().is_none());
    assert!(matches!(
        JwksVerifier::from_json(
            &get(&auth, "/jwks", None).await.json.to_string(),
            BASE,
            "https://elsewhere"
        )
        .unwrap()
        .verify::<Value>(&jwt),
        Err(VerifyError::Invalid(_))
    ));

    let rotated = auth.jwt().rotate().await.unwrap();
    assert_ne!(rotated.as_str(), kid);
    let jwks = get(&auth, "/jwks", None).await;
    assert_eq!(
        jwks.json["keys"].as_array().unwrap().len(),
        2,
        "the retired key is still listed"
    );
    let fresh = token(&auth, &session).await;
    assert_eq!(header(&fresh).kid.as_deref(), Some(rotated.as_str()));
    let verifier = verifier(&auth).await;
    verifier
        .verify::<Value>(&jwt)
        .expect("old tokens verify in the grace period");
    verifier.verify::<Value>(&fresh).expect("new tokens verify");
    assert!(auth.jwt().verify(&jwt).await.unwrap().is_some());
}

#[tokio::test]
async fn jwt_flow_on_memory() {
    jwt_flow(MemoryAdapter::new()).await;
}

#[tokio::test]
async fn jwt_flow_on_sqlite() {
    jwt_flow(sqlite().await).await;
}

#[tokio::test]
async fn jwt_flow_on_postgres() {
    let Some((db, cleanup)) = postgres().await else {
        return;
    };
    jwt_flow(db).await;
    cleanup.drop_schema().await;
}

#[tokio::test]
async fn es256_and_rs256_keys() {
    for (alg, jose, kty) in [
        (JwtAlgorithm::ES256, jsonwebtoken::Algorithm::ES256, "EC"),
        (JwtAlgorithm::RS256, jsonwebtoken::Algorithm::RS256, "RSA"),
    ] {
        let auth = build(MemoryAdapter::new(), Jwt::new().algorithm(alg));
        let (user_id, session) = sign_up(&auth, "ada@acme.dk").await;
        let jwt = token(&auth, &session).await;
        assert_eq!(header(&jwt).alg, jose);
        let jwks = get(&auth, "/jwks", None).await.json;
        let key = &jwks["keys"][0];
        assert_eq!(key["alg"], alg.name());
        assert_eq!(key["kty"], kty);
        match alg {
            JwtAlgorithm::ES256 => {
                assert_eq!(key["crv"], "P-256");
                assert!(key["x"].is_string() && key["y"].is_string());
            }
            _ => {
                assert!(key.get("crv").is_none(), "{key}");
                assert_eq!(key["e"], "AQAB");
                assert!(key["n"].as_str().unwrap().len() > 300);
            }
        }
        let claims: Map<String, Value> = verifier(&auth).await.verify(&jwt).unwrap();
        assert_eq!(claims["sub"], user_id.as_str());
    }
}

#[tokio::test]
async fn switching_algorithms_keeps_old_tokens_verifying() {
    let db = MemoryAdapter::new();
    let ed = build(db.clone(), Jwt::new());
    let (_, session) = sign_up(&ed, "ada@acme.dk").await;
    let old = token(&ed, &session).await;
    let es = build(db, Jwt::new().algorithm(JwtAlgorithm::ES256));
    let new = token(&es, &session).await;
    assert_eq!(header(&new).alg, jsonwebtoken::Algorithm::ES256);
    let verifier = verifier(&es).await;
    assert_eq!(verifier.jwks().keys.len(), 2);
    verifier.verify::<Value>(&old).unwrap();
    verifier.verify::<Value>(&new).unwrap();
}

#[tokio::test]
async fn issuer_audience_expiration_and_payload() {
    let auth = build(
        MemoryAdapter::new(),
        Jwt::new()
            .issuer("https://auth.acme.dk")
            .audience("https://api.acme.dk")
            .expiration_time(Duration::hours(1))
            .define_payload(|session| async move {
                let mut claims = Map::new();
                claims.insert("email".into(), session.user.email.clone().into());
                claims.insert("role".into(), "member".into());
                claims.insert("sub".into(), "overridden".into());
                Ok(claims)
            }),
    );
    let (user_id, session) = sign_up(&auth, "ada@acme.dk").await;
    let jwt = token(&auth, &session).await;
    let jwks = get(&auth, "/jwks", None).await.json.to_string();
    let claims: Map<String, Value> =
        JwksVerifier::from_json(&jwks, "https://auth.acme.dk", "https://api.acme.dk")
            .unwrap()
            .verify(&jwt)
            .unwrap();
    assert_eq!(claims["sub"], user_id.as_str(), "sub is always the user id");
    assert_eq!(claims["role"], "member");
    assert_eq!(claims["email"], "ada@acme.dk");
    assert!(
        claims.get("name").is_none(),
        "the payload replaces the user"
    );
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        3600
    );
    assert!(
        JwksVerifier::from_json(&jwks, BASE, BASE)
            .unwrap()
            .verify::<Value>(&jwt)
            .is_err()
    );
    assert!(auth.jwt().verify(&jwt).await.unwrap().is_some());
}

#[tokio::test]
async fn sign_keeps_given_claims() {
    let auth = build(MemoryAdapter::new(), Jwt::new());
    let mut claims = Map::new();
    claims.insert("sub".into(), "service-a".into());
    claims.insert("iat".into(), 1_000.into());
    claims.insert("scope".into(), "read".into());
    let jwt = auth.jwt().sign(claims).await.unwrap();
    let decoded = jsonwebtoken::dangerous::insecure_decode::<Map<String, Value>>(&jwt)
        .unwrap()
        .claims;
    assert_eq!(decoded["exp"], 1_000 + 900, "exp follows the given iat");
    assert_eq!(decoded["scope"], "read");
    assert_eq!(decoded["iss"], BASE);
    assert!(
        auth.jwt().verify(&jwt).await.unwrap().is_none(),
        "expired long ago"
    );
}

#[tokio::test]
async fn keys_rotate_on_their_interval() {
    let auth = build(
        MemoryAdapter::new(),
        Jwt::new()
            .rotation_interval(Duration::seconds(1))
            .grace_period(Duration::seconds(1)),
    );
    let (_, session) = sign_up(&auth, "ada@acme.dk").await;
    let first = token(&auth, &session).await;
    let first_kid = header(&first).kid.unwrap();
    let stored = auth
        .api()
        .db()
        .find::<JsonWebKey>(fastauth_core::query::Where::all())
        .all()
        .await
        .unwrap();
    assert!(stored[0].expires_at.is_some());
    assert_eq!(token(&auth, &session).await.len(), first.len());

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let second = token(&auth, &session).await;
    let second_kid = header(&second).kid.unwrap();
    assert_ne!(first_kid, second_kid, "the expired key no longer signs");
    let listed: Vec<String> = auth
        .jwt()
        .jwks()
        .await
        .unwrap()
        .keys
        .iter()
        .map(|k| k["kid"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        listed.len(),
        2,
        "the expired key is listed in its grace period"
    );

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let listed = auth.jwt().jwks().await.unwrap().keys;
    assert!(
        listed.iter().all(|k| k["kid"] != first_kid.as_str()),
        "past the grace period the key is gone: {listed:?}"
    );
}

#[tokio::test]
async fn private_keys_need_the_secret() {
    let db = MemoryAdapter::new();
    let auth = build(db.clone(), Jwt::new());
    let (_, session) = sign_up(&auth, "ada@acme.dk").await;
    token(&auth, &session).await;

    let other_secret = || Secret::from_bytes(vec![9u8; 32]);
    let rotated: JwtAuth<MemoryAdapter> = FastAuth::builder()
        .secret(other_secret())
        .base_url(BASE)
        .database(db.clone())
        .plugin(Jwt::new())
        .build()
        .unwrap();
    let err = rotated.jwt().sign(Map::new()).await.unwrap_err();
    assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let both: JwtAuth<MemoryAdapter> = FastAuth::builder()
        .secrets([other_secret(), secret()])
        .base_url(BASE)
        .database(db)
        .plugin(Jwt::new())
        .build()
        .unwrap();
    both.jwt()
        .sign(Map::new())
        .await
        .expect("the old secret still decrypts");
}

#[tokio::test]
async fn the_header_can_be_turned_off() {
    let auth = build(MemoryAdapter::new(), Jwt::new().disable_jwt_header());
    let (_, session) = sign_up(&auth, "ada@acme.dk").await;
    let res = get(&auth, "/get-session", Some(&session)).await;
    assert_eq!(res.json["user"]["email"], "ada@acme.dk");
    assert_eq!(res.header(SET_AUTH_JWT), None);
    token(&auth, &session).await;
}

#[tokio::test]
async fn unknown_keys_are_reported() {
    let auth = build(MemoryAdapter::new(), Jwt::new());
    let jwt = auth.jwt().sign(Map::new()).await.unwrap();
    let empty = JwksVerifier::from_json(r#"{"keys":[]}"#, BASE, BASE).unwrap();
    assert!(matches!(
        empty.verify::<Value>(&jwt),
        Err(VerifyError::UnknownKey(Some(_)))
    ));
    assert!(matches!(
        empty.verify::<Value>("not a jwt"),
        Err(VerifyError::Invalid(_))
    ));
}

#[tokio::test]
async fn server_api_token_and_bearer_sessions() {
    let auth: Auth<MemoryAdapter, (), plugins![Bearer, Jwt]> = FastAuth::builder()
        .secret(secret())
        .base_url(BASE)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .session(SessionConfig::default().update_age(Duration::ZERO))
        .plugin(Bearer::new())
        .plugin(Jwt::new())
        .build()
        .unwrap();
    let res = send(
        &auth,
        Method::POST,
        "/sign-up/email",
        &[],
        Some(json!({ "email": "ada@acme.dk", "password": "correct horse", "name": "Ada" })),
    )
    .await;
    let signed = res.header(SET_AUTH_TOKEN).unwrap().to_owned();
    let user_id = res.json["user"]["id"].as_str().unwrap().to_owned();

    let res = send(
        &auth,
        Method::GET,
        "/get-session",
        &[("authorization", &bearer(&signed))],
        None,
    )
    .await;
    assert!(res.header(SET_AUTH_JWT).is_some());
    assert!(res.header(SET_AUTH_TOKEN).is_some());
    assert_eq!(
        res.header("access-control-expose-headers"),
        Some("set-auth-jwt, set-auth-token")
    );

    let res = send(
        &auth,
        Method::GET,
        "/token",
        &[("authorization", &bearer(&signed))],
        None,
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);

    let headers = [(
        http::header::AUTHORIZATION,
        bearer(&signed).parse().unwrap(),
    )]
    .into_iter()
    .collect();
    let jwt = auth.jwt().headers(&headers).token().await.unwrap();
    assert_eq!(
        auth.jwt().verify(&jwt).await.unwrap().unwrap()["sub"],
        user_id.as_str()
    );
    assert_eq!(auth.jwt().token().await.unwrap_err().code(), "UNAUTHORIZED");
}
