//! The column the anonymous plugin adds to `user`.

use fastauth_core::plugin_prelude::*;

/// The column anonymous adds to `user`. Clients can't set it. Apps read it with
/// `session.user.plugin::<Anonymous, _>()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousUser {
    /// True for users created by `/sign-in/anonymous`.
    pub is_anonymous: bool,
}

impl AnonymousUser {
    pub const IS_ANONYMOUS: Col<AnonymousUser, bool> = Col::new("is_anonymous");
}

impl OnTable for AnonymousUser {
    type Table = User;
}

impl Fields for AnonymousUser {
    fn columns() -> &'static [ColumnDef] {
        const COLUMNS: &[ColumnDef] =
            &[ColumnDef::new("is_anonymous", ColumnType::Bool).default(DefaultValue::Bool(false))];
        COLUMNS
    }

    fn decode(row: &Row) -> Result<Self, DecodeError> {
        Ok(Self {
            is_anonymous: row.get("is_anonymous")?,
        })
    }
}

/// Whether `user` was created by `/sign-in/anonymous` and is still a guest. A user whose
/// email is verified (moved to a real address, for example with an email code) is a real
/// account, whatever the column says, so linking never deletes it.
pub fn is_anonymous(user: &UserView) -> bool {
    !user.email_verified
        && user
            .fields::<AnonymousUser>()
            .is_ok_and(|fields| fields.is_anonymous)
}
