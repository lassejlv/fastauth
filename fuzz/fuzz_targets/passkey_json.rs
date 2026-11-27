//! Passkey registration and authentication JSON. Raw bodies, and WebAuthn responses whose
//! client data, attestation object, authenticator data, credential id and signature are
//! fuzzed one part at a time around a real P-256 credential. Assertions are signed with the
//! real key when the fuzzer asks for it, so the checks behind the signature are reached: a
//! sign-in only succeeds with the real key over the issued challenge, the app's origin,
//! `webauthn.get`, the RP id hash and user presence; a registration only with the issued
//! challenge, the app's origin and `webauthn.create`. Nothing answers 500.

#![no_main]

use arbitrary::Arbitrary;
use fastauth_core::crypto::{Argon2id, Secret, base64url};
use fastauth_core::prelude::*;
use fastauth_fuzz::authenticator::{UP, client_data, create, rp_id_hash};
use fastauth_fuzz::client::Client;
use fastauth_fuzz::json::ArbJson;
use fastauth_fuzz::{BASE_URL, SECRET};
use fastauth_plugin_passkey::Passkey;
use http::{Method, StatusCode};
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value, json};

type PasskeyAuth = Auth<MemoryAdapter, (), plugins![Passkey]>;

#[derive(Arbitrary, Debug)]
enum Field {
    Real,
    Text(String),
    Any(ArbJson),
}

impl Field {
    fn value(&self, real: &str) -> Value {
        match self {
            Field::Real => json!(real),
            Field::Text(text) => json!(text),
            Field::Any(any) => any.to_json(),
        }
    }

    fn is_real(&self, real: &str) -> bool {
        self.value(real) == json!(real)
    }
}

#[derive(Arbitrary, Debug)]
struct ClientData {
    kind: Field,
    challenge: Field,
    origin: Field,
    extra: Vec<(String, ArbJson)>,
}

impl ClientData {
    fn encode(&self, kind: &str, challenge: &str) -> Vec<u8> {
        let mut map = Map::new();
        for (k, v) in self.extra.iter().take(4) {
            map.insert(k.clone(), v.to_json());
        }
        map.insert("type".into(), self.kind.value(kind));
        map.insert("challenge".into(), self.challenge.value(challenge));
        map.insert("origin".into(), self.origin.value(BASE_URL));
        Value::Object(map).to_string().into_bytes()
    }

    fn is_real(&self, kind: &str, challenge: &str) -> bool {
        self.kind.is_real(kind)
            && self.challenge.is_real(challenge)
            && self.origin.is_real(BASE_URL)
    }
}

#[derive(Arbitrary, Debug)]
enum Bytes {
    Real,
    Raw(Vec<u8>),
    Flip(u16, u8),
}

impl Bytes {
    fn apply(&self, real: &[u8]) -> Vec<u8> {
        match self {
            Bytes::Real => real.to_vec(),
            Bytes::Raw(raw) => raw.clone(),
            Bytes::Flip(pos, xor) => {
                let mut out = real.to_vec();
                if !out.is_empty() {
                    let i = usize::from(*pos) % out.len();
                    out[i] ^= xor;
                }
                out
            }
        }
    }

    fn is_real(&self, real: &[u8]) -> bool {
        self.apply(real) == real
    }
}

#[derive(Arbitrary, Debug)]
enum Input {
    RegisterRaw(Vec<u8>),
    Register {
        client_data: ClientData,
        attestation: Bytes,
        id: Option<Vec<u8>>,
    },
    AuthenticateRaw(Vec<u8>),
    Authenticate {
        client_data: ClientData,
        rp_id_hash: Option<[u8; 32]>,
        flags: u8,
        counter: u32,
        extensions: Vec<u8>,
        signature: Bytes,
        sign_real_data: bool,
        credential: Option<Vec<u8>>,
        user_handle: Option<String>,
    },
}

fn build() -> PasskeyAuth {
    FastAuth::builder()
        .secret(Secret::from_bytes(SECRET.to_vec()))
        .base_url(BASE_URL)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(256, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Passkey::new())
        .build()
        .expect("valid config")
}

fn post_raw<
    D: fastauth_core::adapter::Adapter,
    U: fastauth_core::model::Fields,
    P: fastauth_core::PluginSet,
>(
    client: &mut Client<'_, D, U, P>,
    path: &str,
    body: Vec<u8>,
) -> fastauth_fuzz::client::Reply {
    let mut request = http::Request::builder()
        .method(Method::POST)
        .uri(format!("/api/auth{path}"))
        .header(http::header::ORIGIN, BASE_URL)
        .header(http::header::CONTENT_TYPE, "application/json");
    if let Some(cookies) = client.cookie_header() {
        request = request.header(http::header::COOKIE, cookies);
    }
    client.send_raw(request.body(bytes::Bytes::from(body)).unwrap())
}

fuzz_target!(|input: Input| {
    let auth = build();
    let mut owner = Client::new(&auth);
    owner.sign_up("pk@acme.dk");
    let options = owner.get("/passkey/generate-register-options");
    assert_eq!(options.status, StatusCode::OK, "{}", options.json);
    let (response, key, _) = create(&options.json, BASE_URL, [1; 16]);
    let registered = owner.post(
        "/passkey/verify-registration",
        &json!({ "response": response }),
    );
    assert_eq!(registered.status, StatusCode::OK, "{}", registered.json);

    match input {
        Input::RegisterRaw(body) => {
            let options = owner.get("/passkey/generate-register-options");
            assert_eq!(options.status, StatusCode::OK);
            let reply = post_raw(&mut owner, "/passkey/verify-registration", body);
            assert_ne!(
                reply.status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{}",
                reply.json
            );
        }
        Input::Register {
            client_data: cd,
            attestation,
            id,
        } => {
            let options = owner.get("/passkey/generate-register-options");
            assert_eq!(options.status, StatusCode::OK);
            let challenge = options.json["challenge"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let (mut response, _, real_attestation) = create(&options.json, BASE_URL, [2; 16]);
            response["response"]["clientDataJSON"] =
                json!(base64url(&cd.encode("webauthn.create", &challenge)));
            response["response"]["attestationObject"] =
                json!(base64url(&attestation.apply(&real_attestation)));
            if let Some(id) = &id {
                response["id"] = json!(base64url(id));
                response["rawId"] = json!(base64url(id));
            }
            let reply = owner.post(
                "/passkey/verify-registration",
                &json!({ "response": response }),
            );
            assert_ne!(
                reply.status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{}",
                reply.json
            );
            if reply.status == StatusCode::OK {
                assert!(
                    cd.is_real("webauthn.create", &challenge),
                    "registered with client data {cd:?}"
                );
            }
        }
        Input::AuthenticateRaw(body) => {
            let mut stranger = Client::new(&auth);
            let options = stranger.get("/passkey/generate-authenticate-options");
            assert_eq!(options.status, StatusCode::OK);
            let reply = post_raw(&mut stranger, "/passkey/verify-authentication", body);
            assert_ne!(
                reply.status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{}",
                reply.json
            );
            assert!(!reply.signs_in(), "signed in with a raw body");
        }
        Input::Authenticate {
            client_data: cd,
            rp_id_hash: hash,
            flags,
            counter,
            extensions,
            signature,
            sign_real_data,
            credential,
            user_handle,
        } => {
            let mut stranger = Client::new(&auth);
            let options = stranger.get("/passkey/generate-authenticate-options");
            assert_eq!(options.status, StatusCode::OK);
            let challenge = options.json["challenge"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let real_hash = rp_id_hash();
            let mut auth_data = hash.map_or_else(|| real_hash.clone(), |h| h.to_vec());
            auth_data.push(flags);
            auth_data.extend(counter.to_be_bytes());
            auth_data.extend(extensions.iter().take(64));
            let client_json = cd.encode("webauthn.get", &challenge);
            let real_signature = if sign_real_data {
                key.sign(&auth_data, &client_json)
            } else {
                key.sign(
                    &auth_data,
                    &client_data("webauthn.get", &challenge, BASE_URL),
                )
            };
            let id = credential.clone().unwrap_or_else(|| key.id.clone());
            let response = json!({
                "id": base64url(&id),
                "rawId": base64url(&id),
                "type": "public-key",
                "authenticatorAttachment": "platform",
                "response": {
                    "clientDataJSON": base64url(&client_json),
                    "authenticatorData": base64url(&auth_data),
                    "signature": base64url(&signature.apply(&real_signature)),
                    "userHandle": user_handle.clone().unwrap_or_else(|| key.user_handle.clone()),
                },
            });
            let reply = stranger.post(
                "/passkey/verify-authentication",
                &json!({ "response": response }),
            );
            assert_ne!(
                reply.status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{}",
                reply.json
            );
            if reply.signs_in() || reply.status == StatusCode::OK {
                assert!(
                    signature.is_real(&real_signature),
                    "signed in with a changed signature"
                );
                assert!(
                    sign_real_data || cd.is_real("webauthn.get", &challenge),
                    "signed in with a signature over other client data"
                );
                assert!(
                    cd.is_real("webauthn.get", &challenge),
                    "signed in with client data {cd:?}"
                );
                assert_eq!(
                    auth_data[..32],
                    real_hash[..],
                    "signed in with another RP id hash"
                );
                assert!(
                    flags & UP != 0,
                    "signed in without user presence (flags {flags:#x})"
                );
                assert_eq!(id, key.id, "signed in with credential id {id:?}");
            }
        }
    }
});
