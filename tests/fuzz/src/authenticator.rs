//! A software passkey: one P-256 credential with `none` attestation, and assertions built from
//! caller-chosen authenticator data and client data, signed with the real key or not at all.

use std::collections::BTreeMap;

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use fastauth_core::crypto::base64url;
use serde_cbor_2::Value as Cbor;
use serde_json::{Value, json};

pub const UP: u8 = 0x01;
pub const UV: u8 = 0x04;
pub const AT: u8 = 0x40;
pub const RP_ID: &str = "localhost";

pub struct SoftKey {
    pub id: Vec<u8>,
    pub user_handle: String,
    key: EcdsaKeyPair,
}

fn int(i: i64) -> Cbor {
    Cbor::Integer(i.into())
}

pub fn rp_id_hash() -> Vec<u8> {
    digest(&SHA256, RP_ID.as_bytes()).as_ref().to_vec()
}

pub fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
    json!({ "type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false })
        .to_string()
        .into_bytes()
}

/// The `AuthenticatorAttestationResponse` JSON for registration `options`, and the key.
pub fn create(options: &Value, origin: &str, id: [u8; 16]) -> (Value, SoftKey, Vec<u8>) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
    let point = key.public_key().as_ref().to_vec();
    let cose_key = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
        (int(1), int(2)),
        (int(3), int(-7)),
        (int(-1), int(1)),
        (int(-2), Cbor::Bytes(point[1..33].to_vec())),
        (int(-3), Cbor::Bytes(point[33..65].to_vec())),
    ])))
    .unwrap();
    let mut auth_data = rp_id_hash();
    auth_data.push(UP | UV | AT);
    auth_data.extend(1u32.to_be_bytes());
    auth_data.extend(*b"fastauth-fuzzkey");
    auth_data.extend((id.len() as u16).to_be_bytes());
    auth_data.extend(id);
    auth_data.extend(&cose_key);
    let attestation_object = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
        (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
    ])))
    .unwrap();
    let challenge = options["challenge"].as_str().unwrap_or_default();
    let response = json!({
        "id": base64url(&id),
        "rawId": base64url(&id),
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": base64url(&client_data("webauthn.create", challenge, origin)),
            "attestationObject": base64url(&attestation_object),
            "transports": ["internal"],
        },
    });
    let user_handle = options["user"]["id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    (
        response,
        SoftKey {
            id: id.to_vec(),
            user_handle,
            key,
        },
        attestation_object,
    )
}

impl SoftKey {
    /// An ECDSA signature over `auth_data || SHA-256(client_data)`, as an authenticator signs.
    pub fn sign(&self, auth_data: &[u8], client_data: &[u8]) -> Vec<u8> {
        let mut signed = auth_data.to_vec();
        signed.extend(digest(&SHA256, client_data).as_ref());
        self.key
            .sign(&SystemRandom::new(), &signed)
            .unwrap()
            .as_ref()
            .to_vec()
    }
}
