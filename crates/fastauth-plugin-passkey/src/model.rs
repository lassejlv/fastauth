//! The `passkey` table.

use fastauth_core::plugin_prelude::*;

/// A row of `passkey`: one registered WebAuthn credential. The columns are Better Auth's, in
/// snake case, so a Better Auth passkey table carries over.
#[derive(Model, Clone, Debug, PartialEq, Eq)]
#[model(table = "passkey")]
pub struct PasskeyRow {
    #[model(id)]
    pub id: Id,
    /// The name the user gave it, if any.
    pub name: Option<String>,
    /// The credential's COSE public key, base64 (Better Auth's encoding).
    pub public_key: String,
    #[model(references = User, on_delete = Cascade, index)]
    pub user_id: Id,
    /// The credential id, base64url without padding: what browsers send as `id`.
    #[model(unique)]
    pub credential_id: String,
    /// The authenticator's signature counter as of the last sign-in. Zero for authenticators
    /// that don't count (most synced passkeys).
    pub counter: i64,
    /// `singleDevice`, or `multiDevice` when the credential may be synced (backup eligible).
    pub device_type: String,
    /// Whether the credential is backed up (synced) right now.
    pub backed_up: bool,
    /// The browser's transport hints, comma-separated (`internal,hybrid`).
    pub transports: Option<String>,
    #[model(default = now)]
    pub created_at: OffsetDateTime,
    /// The authenticator model's AAGUID, all zeros when the authenticator hides it.
    pub aaguid: Option<String>,
}
