//! The glue between webauthn-rs and the `passkey` table: the relying party, Better Auth's
//! column encodings, and the challenge stored between the two steps of a ceremony.

use base64::Engine;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::{DecodePaddingMode, general_purpose::STANDARD};
use fastauth_core::config::CoreConfig;
use fastauth_core::crypto::base64url_decode;
use fastauth_core::plugin_prelude::*;
use webauthn_rs::prelude::{
    AttestationFormat, AttestationMetadata, COSEKey, Credential, DiscoverableAuthentication,
    ParsedAttestation, ParsedAttestationData, PasskeyRegistration, Url, Uuid, Webauthn,
    WebauthnBuilder,
};
use webauthn_rs_proto::{AuthenticatorTransport, UserVerificationPolicy};

use crate::PasskeyError;
use crate::model::PasskeyRow;

/// Better Auth's `base64.encode` pads; decoding accepts either.
const BASE64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// How long a challenge (and its cookie) lives: Better Auth's five minutes.
pub(crate) const CHALLENGE_TTL: Duration = Duration::minutes(5);
/// The signed cookie naming the pending challenge: `{prefix}.passkey`.
pub(crate) const CHALLENGE_COOKIE: &str = "passkey";
/// The `verification` rows holding challenges.
pub(crate) const IDENTIFIER: &str = "passkey";

/// `deviceType` for a credential that may be synced.
pub(crate) const MULTI_DEVICE: &str = "multiDevice";
pub(crate) const SINGLE_DEVICE: &str = "singleDevice";

/// What a `verification` row remembers between `generate-*` and `verify-*`.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub(crate) enum Challenge {
    Registration {
        #[serde(rename = "userId")]
        user_id: String,
        state: PasskeyRegistration,
    },
    Authentication {
        state: DiscoverableAuthentication,
    },
}

pub(crate) fn relying_party(
    rp_id: Option<&str>,
    rp_name: Option<&str>,
    origins: &[String],
    config: &CoreConfig,
) -> Result<Webauthn, AuthError> {
    let rp_id = rp_id
        .or(config.base_url.host_str())
        .ok_or(PasskeyError::OriginNotConfigured)?;
    let origins: Vec<Url> = if origins.is_empty() {
        let base = config.base_url.origin().ascii_serialization();
        std::iter::once(base.as_str())
            .chain(
                config
                    .trusted_origins
                    .iter()
                    .map(String::as_str)
                    .filter(|o| !o.contains(['*', '?'])),
            )
            .filter_map(|o| Url::parse(o).ok())
            .collect()
    } else {
        origins
            .iter()
            .map(|o| Url::parse(o).map_err(|_| PasskeyError::OriginNotConfigured))
            .collect::<Result<_, _>>()?
    };
    let (first, rest) = origins
        .split_first()
        .ok_or(PasskeyError::OriginNotConfigured)?;
    let rp_name = rp_name.unwrap_or(&config.app_name);
    rest.iter()
        .fold(
            WebauthnBuilder::new(rp_id, first).map_err(|_| PasskeyError::OriginNotConfigured)?,
            |builder, origin| builder.append_allowed_origin(origin),
        )
        .rp_name(rp_name)
        .build()
        .map_err(|_| PasskeyError::OriginNotConfigured.into())
}

/// What registration stores that webauthn-rs's `Credential` doesn't keep in Better Auth's
/// shape: the COSE public key exactly as the authenticator sent it, and its AAGUID.
pub(crate) struct Attested {
    pub public_key: String,
    pub aaguid: String,
}

/// Reads the attested credential data out of an attestation object that webauthn-rs already
/// verified: `authData` is rpIdHash (32), flags (1), signCount (4), AAGUID (16), credential id
/// length (2), credential id, then the COSE key.
pub(crate) fn attested(attestation_object: &[u8]) -> Option<Attested> {
    let object: serde_cbor_2::Value = serde_cbor_2::from_slice(attestation_object).ok()?;
    let serde_cbor_2::Value::Map(object) = object else {
        return None;
    };
    let serde_cbor_2::Value::Bytes(auth_data) =
        object.get(&serde_cbor_2::Value::Text("authData".into()))?
    else {
        return None;
    };
    let aaguid: [u8; 16] = auth_data.get(37..53)?.try_into().ok()?;
    let id_len = u16::from_be_bytes(auth_data.get(53..55)?.try_into().ok()?) as usize;
    let key = auth_data.get(55 + id_len..)?;
    let mut de = serde_cbor_2::Deserializer::from_slice(key);
    serde_cbor_2::Value::deserialize(&mut de).ok()?;
    Some(Attested {
        public_key: STANDARD.encode(&key[..de.byte_offset()]),
        aaguid: Uuid::from_bytes(aaguid).to_string(),
    })
}

pub(crate) fn transports(row_transports: Option<&str>) -> Option<Vec<AuthenticatorTransport>> {
    let transports: Vec<_> = row_transports?
        .split(',')
        .filter_map(|t| t.trim().parse().ok())
        .collect();
    (!transports.is_empty()).then_some(transports)
}

pub(crate) fn credential_id(row: &PasskeyRow) -> Result<Vec<u8>, AuthError> {
    base64url_decode(&row.credential_id)
        .ok_or_else(|| AuthError::internal("a passkey's credential id isn't base64url"))
}

/// Rebuilds the webauthn-rs credential a row stores, to verify an assertion against.
pub(crate) fn credential(row: &PasskeyRow) -> Result<Credential, AuthError> {
    let broken = |what: &str| AuthError::internal(format!("passkey {}: {what}", row.id));
    let key = BASE64
        .decode(&row.public_key)
        .map_err(|_| broken("public key isn't base64"))?;
    let key: serde_cbor_2::Value =
        serde_cbor_2::from_slice(&key).map_err(|_| broken("public key isn't CBOR"))?;
    let cred = COSEKey::try_from(&key).map_err(|_| broken("public key isn't a COSE key"))?;
    Ok(Credential {
        cred_id: credential_id(row)?,
        cred,
        counter: u32::try_from(row.counter).map_err(|_| broken("counter out of range"))?,
        transports: transports(row.transports.as_deref()),
        user_verified: true,
        backup_eligible: row.device_type == MULTI_DEVICE,
        backup_state: row.backed_up,
        registration_policy: UserVerificationPolicy::Required,
        extensions: Default::default(),
        attestation: ParsedAttestation {
            data: ParsedAttestationData::None,
            metadata: AttestationMetadata::None,
        },
        attestation_format: AttestationFormat::None,
    })
}
