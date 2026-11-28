//! The columns the username plugin adds to `user`.

use fastauth_core::plugin_prelude::*;

/// The columns username adds to `user`, both settable on sign-up and update-user. Apps read
/// them with `session.user.plugin::<Username, _>()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsernameUser {
    /// The normalized username (lowercase by default), unique across users. Sign-in looks it
    /// up after normalizing what the user typed.
    pub username: Option<String>,
    /// The username as the user wrote it, for display. Defaults to the username on sign-up.
    pub display_username: Option<String>,
}

impl UsernameUser {
    pub const USERNAME: Col<UsernameUser, Option<String>> = Col::new("username");
    pub const DISPLAY_USERNAME: Col<UsernameUser, Option<String>> = Col::new("display_username");
}

impl OnTable for UsernameUser {
    type Table = User;
}

impl Fields for UsernameUser {
    fn columns() -> &'static [ColumnDef] {
        const COLUMNS: &[ColumnDef] = &[
            ColumnDef::new("username", ColumnType::Text)
                .nullable()
                .unique()
                .input(),
            ColumnDef::new("display_username", ColumnType::Text)
                .nullable()
                .input(),
        ];
        COLUMNS
    }

    fn decode(row: &Row) -> Result<Self, DecodeError> {
        Ok(Self {
            username: row.get("username")?,
            display_username: row.get("display_username")?,
        })
    }
}
