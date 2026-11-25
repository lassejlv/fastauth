//! The column two-factor adds to `user`, and its `two_factor` table.

use fastauth_core::plugin_prelude::*;

/// The column two-factor adds to `user`. Apps read it with
/// `session.user.plugin::<TwoFactor, _>()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoFactorUser {
    /// On after the first verified TOTP code, or right after enabling with
    /// `skip_verification_on_enable`.
    pub two_factor_enabled: bool,
}

impl TwoFactorUser {
    pub const TWO_FACTOR_ENABLED: Col<TwoFactorUser, bool> = Col::new("two_factor_enabled");
}

impl OnTable for TwoFactorUser {
    type Table = User;
}

impl Fields for TwoFactorUser {
    fn columns() -> &'static [ColumnDef] {
        const COLUMNS: &[ColumnDef] = &[ColumnDef::new("two_factor_enabled", ColumnType::Bool)
            .default(DefaultValue::Bool(false))];
        COLUMNS
    }

    fn decode(row: &Row) -> Result<Self, DecodeError> {
        Ok(Self {
            two_factor_enabled: row.get("two_factor_enabled")?,
        })
    }
}

/// A row of `two_factor`: one user's TOTP secret and backup codes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoFactorRow {
    pub id: Id,
    pub user_id: Id,
    /// The TOTP secret, encrypted with the auth secret.
    pub secret: Vec<u8>,
    /// SHA-256 hashes of the unused backup codes as a JSON array, encrypted.
    pub backup_codes: Vec<u8>,
    /// The last TOTP time step a code was accepted for, so each code works once.
    pub last_used_step: Option<i64>,
}

impl TwoFactorRow {
    pub const ID: Col<TwoFactorRow, Id> = Col::new("id");
    pub const USER_ID: Col<TwoFactorRow, Id> = Col::new("user_id");
    pub const BACKUP_CODES: Col<TwoFactorRow, Vec<u8>> = Col::new("backup_codes");
    pub const LAST_USED_STEP: Col<TwoFactorRow, Option<i64>> = Col::new("last_used_step");
}

impl OnTable for TwoFactorRow {
    type Table = TwoFactorRow;
}

impl Model for TwoFactorRow {
    const TABLE: &'static str = "two_factor";

    fn columns() -> &'static [ColumnDef] {
        const COLUMNS: &[ColumnDef] = &[
            ColumnDef::new("id", ColumnType::Id).primary_key(),
            ColumnDef::new("user_id", ColumnType::Id)
                .references(User::TABLE, "id", OnDelete::Cascade)
                .index(),
            ColumnDef::new("secret", ColumnType::Bytes).hidden(),
            ColumnDef::new("backup_codes", ColumnType::Bytes).hidden(),
            ColumnDef::new("last_used_step", ColumnType::Int)
                .nullable()
                .hidden(),
        ];
        COLUMNS
    }

    fn decode(row: &Row) -> Result<Self, DecodeError> {
        Ok(Self {
            id: row.get("id")?,
            user_id: row.get("user_id")?,
            secret: row.get("secret")?,
            backup_codes: row.get("backup_codes")?,
            last_used_step: row.get("last_used_step")?,
        })
    }

    fn encode(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("id", self.id.clone().into_value()),
            ("user_id", self.user_id.clone().into_value()),
            ("secret", self.secret.clone().into_value()),
            ("backup_codes", self.backup_codes.clone().into_value()),
            ("last_used_step", self.last_used_step.into_value()),
        ]
    }
}
