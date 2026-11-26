//! A software passkey authenticator: P-256 credentials, `none` attestation, and the JSON a
//! browser hands to Better Auth's client (`RegistrationResponseJSON` and
//! `AuthenticationResponseJSON`), so tests drive real WebAuthn ceremonies.

use std::collections::BTreeMap;

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use fastauth_core::crypto::{base64url, base64url_decode, random_bytes};
use serde_cbor_2::Value as Cbor;
use serde_json::{Value, json};

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;

/// This authenticator's AAGUID.
pub const AAGUID: [u8; 16] = *b"fastauth-testkey";

struct SoftCredential {
    id: Vec<u8>,
    rp_id: String,
    user_handle: String,
    pkcs8: Vec<u8>,
}

/// A platform authenticator holding discoverable credentials. Clone it to model a cloned
/// key: both copies sign, but the counters diverge.
pub struct Authenticator {
    credentials: Vec<SoftCredential>,
    counter: u32,
    /// Whether the signature counter advances (synced passkeys usually keep it at 0).
    pub counts: bool,
    /// Whether the user verifies (PIN or biometric).
    pub verifies_user: bool,
    /// Backup eligible and backed up, like a synced passkey.
    pub synced: bool,
}

impl Clone for Authenticator {
    fn clone(&self) -> Self {
        Self {
            credentials: self
                .credentials
                .iter()
                .map(|c| SoftCredential {
                    id: c.id.clone(),
                    rp_id: c.rp_id.clone(),
                    user_handle: c.user_handle.clone(),
                    pkcs8: c.pkcs8.clone(),
                })
                .collect(),
            counter: self.counter,
            counts: self.counts,
            verifies_user: self.verifies_user,
            synced: self.synced,
        }
    }
}

impl Default for Authenticator {
    fn default() -> Self {
        Self {
            credentials: Vec::new(),
            counter: 0,
            counts: true,
            verifies_user: true,
            synced: false,
        }
    }
}

fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
    json!({ "type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false })
        .to_string()
        .into_bytes()
}

fn int(i: i64) -> Cbor {
    Cbor::Integer(i.into())
}

impl Authenticator {
    pub fn new() -> Self {
        Self::default()
    }

    fn flags(&self) -> u8 {
        let mut flags = UP;
        if self.verifies_user {
            flags |= UV;
        }
        if self.synced {
            flags |= BE | BS;
        }
        flags
    }

    fn next_counter(&mut self) -> u32 {
        if self.counts {
            self.counter += 1;
        }
        self.counter
    }

    /// The id of the newest credential, base64url.
    pub fn credential_id(&self) -> String {
        base64url(&self.credentials.last().expect("a credential").id)
    }

    /// `navigator.credentials.create()`. `None` when a credential of this authenticator is in
    /// `excludeCredentials` (the browser's `InvalidStateError`).
    pub fn create(&mut self, options: &Value, origin: &str) -> Option<Value> {
        let rp_id = options["rp"]["id"].as_str().expect("rp.id").to_owned();
        let excluded: Vec<Vec<u8>> = options["excludeCredentials"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| base64url_decode(c["id"].as_str()?))
            .collect();
        if self.credentials.iter().any(|c| excluded.contains(&c.id)) {
            return None;
        }
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .unwrap()
            .as_ref()
            .to_vec();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8).unwrap();
        let point = key.public_key().as_ref();
        let cose_key = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
            (int(1), int(2)),
            (int(3), int(-7)),
            (int(-1), int(1)),
            (int(-2), Cbor::Bytes(point[1..33].to_vec())),
            (int(-3), Cbor::Bytes(point[33..65].to_vec())),
        ])))
        .unwrap();
        let id = random_bytes::<16>().to_vec();
        let mut auth_data = digest(&SHA256, rp_id.as_bytes()).as_ref().to_vec();
        auth_data.push(self.flags() | AT);
        let counter = self.next_counter();
        auth_data.extend(counter.to_be_bytes());
        auth_data.extend(AAGUID);
        auth_data.extend((id.len() as u16).to_be_bytes());
        auth_data.extend(&id);
        auth_data.extend(&cose_key);
        let attestation_object = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
        ])))
        .unwrap();
        let challenge = options["challenge"].as_str().expect("challenge");
        let response = json!({
            "id": base64url(&id),
            "rawId": base64url(&id),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "clientDataJSON": base64url(&client_data("webauthn.create", challenge, origin)),
                "attestationObject": base64url(&attestation_object),
                "transports": ["internal", "hybrid"],
            },
        });
        self.credentials.push(SoftCredential {
            id,
            rp_id,
            user_handle: options["user"]["id"].as_str().expect("user.id").to_owned(),
            pkcs8,
        });
        Some(response)
    }

    /// `navigator.credentials.get()`: answers with the newest credential for the RP that
    /// `allowCredentials` permits (any, when it's empty).
    pub fn get(&mut self, options: &Value, origin: &str) -> Option<Value> {
        let rp_id = options["rpId"].as_str().expect("rpId");
        let allowed: Vec<Vec<u8>> = options["allowCredentials"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| base64url_decode(c["id"].as_str()?))
            .collect();
        let index = self
            .credentials
            .iter()
            .rposition(|c| c.rp_id == rp_id && (allowed.is_empty() || allowed.contains(&c.id)))?;
        let mut auth_data = digest(&SHA256, rp_id.as_bytes()).as_ref().to_vec();
        auth_data.push(self.flags());
        let counter = self.next_counter();
        auth_data.extend(counter.to_be_bytes());
        let challenge = options["challenge"].as_str().expect("challenge");
        let client_data = client_data("webauthn.get", challenge, origin);
        let credential = &self.credentials[index];
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &credential.pkcs8).unwrap();
        let mut signed = auth_data.clone();
        signed.extend(digest(&SHA256, &client_data).as_ref());
        let signature = key.sign(&SystemRandom::new(), &signed).unwrap();
        Some(json!({
            "id": base64url(&credential.id),
            "rawId": base64url(&credential.id),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "clientDataJSON": base64url(&client_data),
                "authenticatorData": base64url(&auth_data),
                "signature": base64url(signature.as_ref()),
                "userHandle": credential.user_handle,
            },
        }))
    }
}
