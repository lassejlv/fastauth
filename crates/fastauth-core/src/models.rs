//! Core tables: `user`, `session`, `account`, `verification`.

use time::OffsetDateTime;

use crate::crypto::Hash;
use crate::model::{Col, Model, OnTable};
use crate::schema::{ColumnDef, ColumnType as T, DefaultValue, OnDelete, SchemaBuilder};
use crate::value::{ColumnValue, DecodeError, Id, Row, Value};

const fn timestamps() -> [ColumnDef; 2] {
    [
        ColumnDef::new("created_at", T::Timestamp).default(DefaultValue::Now),
        ColumnDef::new("updated_at", T::Timestamp).default(DefaultValue::Now),
    ]
}

macro_rules! columns {
    ($($col:expr),* $(,)?) => {{
        const STAMPS: [ColumnDef; 2] = timestamps();
        const COLUMNS: &[ColumnDef] = &[$($col,)* STAMPS[0], STAMPS[1]];
        COLUMNS
    }};
}

pub(crate) fn register(schema: &mut SchemaBuilder) {
    schema
        .model::<User>()
        .model::<Session>()
        .model::<Account>()
        .unique(Account::TABLE, &["provider_id", "account_id"])
        .model::<Verification>();
}

fn get<T: ColumnValue>(row: &Row, column: &str) -> Result<T, DecodeError> {
    row.get(column)
}

/// The core columns of `user`. Plugin and app columns live on the same row; read them from
/// `AuthUser` (typed) or `UserView::fields` (inside plugins).
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: Id,
    pub email: String,
    pub email_verified: bool,
    pub name: String,
    pub image: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl User {
    pub const ID: Col<User, Id> = Col::new("id");
    pub const EMAIL: Col<User, String> = Col::new("email");
    pub const EMAIL_VERIFIED: Col<User, bool> = Col::new("email_verified");
    pub const NAME: Col<User, String> = Col::new("name");
    pub const IMAGE: Col<User, Option<String>> = Col::new("image");
    /// A random value that changes whenever proof of the email claims the user. A sign-in or
    /// account link that started before a claim can't finish after it. Never sent to clients.
    pub const SECURITY_STAMP: Col<User, i64> = Col::new("security_stamp");
    pub const CREATED_AT: Col<User, OffsetDateTime> = Col::new("created_at");
    pub const UPDATED_AT: Col<User, OffsetDateTime> = Col::new("updated_at");
}

impl OnTable for User {
    type Table = User;
}

impl Model for User {
    const TABLE: &'static str = "user";

    fn columns() -> &'static [ColumnDef] {
        columns![
            ColumnDef::new("id", T::Id).primary_key(),
            ColumnDef::new("email", T::Text).unique(),
            ColumnDef::new("email_verified", T::Bool).default(DefaultValue::Bool(false)),
            ColumnDef::new("name", T::Text).input(),
            ColumnDef::new("image", T::Text).nullable().input(),
            ColumnDef::new("security_stamp", T::Int)
                .default(DefaultValue::Int(0))
                .hidden(),
        ]
    }

    fn decode(row: &Row) -> Result<Self, DecodeError> {
        Ok(Self {
            id: get(row, "id")?,
            email: get(row, "email")?,
            email_verified: get(row, "email_verified")?,
            name: get(row, "name")?,
            image: get(row, "image")?,
            created_at: get(row, "created_at")?,
            updated_at: get(row, "updated_at")?,
        })
    }

    fn encode(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("id", self.id.clone().into_value()),
            ("email", self.email.clone().into_value()),
            ("email_verified", self.email_verified.into_value()),
            ("name", self.name.clone().into_value()),
            ("image", self.image.clone().into_value()),
            ("created_at", self.created_at.into_value()),
            ("updated_at", self.updated_at.into_value()),
        ]
    }
}

/// A row of `session`. The token itself is never stored, only its SHA-256.
#[derive(Clone, Debug, PartialEq)]
pub struct Session {
    pub id: Id,
    pub token_hash: Hash,
    pub user_id: Id,
    pub expires_at: OffsetDateTime,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Session {
    pub const ID: Col<Session, Id> = Col::new("id");
    pub const TOKEN_HASH: Col<Session, Hash> = Col::new("token_hash");
    pub const USER_ID: Col<Session, Id> = Col::new("user_id");
    pub const EXPIRES_AT: Col<Session, OffsetDateTime> = Col::new("expires_at");
    pub const CREATED_AT: Col<Session, OffsetDateTime> = Col::new("created_at");
    pub const UPDATED_AT: Col<Session, OffsetDateTime> = Col::new("updated_at");
}

impl OnTable for Session {
    type Table = Session;
}

impl Model for Session {
    const TABLE: &'static str = "session";

    fn columns() -> &'static [ColumnDef] {
        columns![
            ColumnDef::new("id", T::Id).primary_key(),
            ColumnDef::new("token_hash", T::Bytes).unique().hidden(),
            ColumnDef::new("user_id", T::Id)
                .references("user", "id", OnDelete::Cascade)
                .index(),
            ColumnDef::new("expires_at", T::Timestamp),
            ColumnDef::new("ip_address", T::Text).nullable(),
            ColumnDef::new("user_agent", T::Text).nullable(),
        ]
    }

    fn decode(row: &Row) -> Result<Self, DecodeError> {
        Ok(Self {
            id: get(row, "id")?,
            token_hash: get(row, "token_hash")?,
            user_id: get(row, "user_id")?,
            expires_at: get(row, "expires_at")?,
            ip_address: get(row, "ip_address")?,
            user_agent: get(row, "user_agent")?,
            created_at: get(row, "created_at")?,
            updated_at: get(row, "updated_at")?,
        })
    }

    fn encode(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("id", self.id.clone().into_value()),
            ("token_hash", self.token_hash.into_value()),
            ("user_id", self.user_id.clone().into_value()),
            ("expires_at", self.expires_at.into_value()),
            ("ip_address", self.ip_address.clone().into_value()),
            ("user_agent", self.user_agent.clone().into_value()),
            ("created_at", self.created_at.into_value()),
            ("updated_at", self.updated_at.into_value()),
        ]
    }
}

/// A way to sign in: `provider_id = "credential"` holds the password hash; OAuth providers
/// hold encrypted tokens.
#[derive(Clone, Debug, PartialEq)]
pub struct Account {
    pub id: Id,
    pub user_id: Id,
    pub provider_id: String,
    pub account_id: String,
    pub password_hash: Option<String>,
    /// `Keys::encrypt`ed.
    pub access_token: Option<Vec<u8>>,
    /// `Keys::encrypt`ed.
    pub refresh_token: Option<Vec<u8>>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<OffsetDateTime>,
    pub refresh_token_expires_at: Option<OffsetDateTime>,
    pub scope: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Account {
    pub const CREDENTIAL: &'static str = "credential";

    pub const ID: Col<Account, Id> = Col::new("id");
    pub const USER_ID: Col<Account, Id> = Col::new("user_id");
    pub const PROVIDER_ID: Col<Account, String> = Col::new("provider_id");
    pub const ACCOUNT_ID: Col<Account, String> = Col::new("account_id");
    pub const PASSWORD_HASH: Col<Account, Option<String>> = Col::new("password_hash");
    pub const ACCESS_TOKEN: Col<Account, Option<Vec<u8>>> = Col::new("access_token");
    pub const REFRESH_TOKEN: Col<Account, Option<Vec<u8>>> = Col::new("refresh_token");
    pub const ID_TOKEN: Col<Account, Option<String>> = Col::new("id_token");
    pub const ACCESS_TOKEN_EXPIRES_AT: Col<Account, Option<OffsetDateTime>> =
        Col::new("access_token_expires_at");
    pub const REFRESH_TOKEN_EXPIRES_AT: Col<Account, Option<OffsetDateTime>> =
        Col::new("refresh_token_expires_at");
    pub const SCOPE: Col<Account, Option<String>> = Col::new("scope");
}

impl OnTable for Account {
    type Table = Account;
}

impl Model for Account {
    const TABLE: &'static str = "account";

    fn columns() -> &'static [ColumnDef] {
        columns![
            ColumnDef::new("id", T::Id).primary_key(),
            ColumnDef::new("user_id", T::Id)
                .references("user", "id", OnDelete::Cascade)
                .index(),
            ColumnDef::new("provider_id", T::Text),
            ColumnDef::new("account_id", T::Text).index(),
            ColumnDef::new("password_hash", T::Text).nullable().hidden(),
            ColumnDef::new("access_token", T::Bytes).nullable().hidden(),
            ColumnDef::new("refresh_token", T::Bytes)
                .nullable()
                .hidden(),
            ColumnDef::new("id_token", T::Text).nullable().hidden(),
            ColumnDef::new("access_token_expires_at", T::Timestamp).nullable(),
            ColumnDef::new("refresh_token_expires_at", T::Timestamp).nullable(),
            ColumnDef::new("scope", T::Text).nullable(),
        ]
    }

    fn decode(row: &Row) -> Result<Self, DecodeError> {
        Ok(Self {
            id: get(row, "id")?,
            user_id: get(row, "user_id")?,
            provider_id: get(row, "provider_id")?,
            account_id: get(row, "account_id")?,
            password_hash: get(row, "password_hash")?,
            access_token: get(row, "access_token")?,
            refresh_token: get(row, "refresh_token")?,
            id_token: get(row, "id_token")?,
            access_token_expires_at: get(row, "access_token_expires_at")?,
            refresh_token_expires_at: get(row, "refresh_token_expires_at")?,
            scope: get(row, "scope")?,
            created_at: get(row, "created_at")?,
            updated_at: get(row, "updated_at")?,
        })
    }

    fn encode(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("id", self.id.clone().into_value()),
            ("user_id", self.user_id.clone().into_value()),
            ("provider_id", self.provider_id.clone().into_value()),
            ("account_id", self.account_id.clone().into_value()),
            ("password_hash", self.password_hash.clone().into_value()),
            ("access_token", self.access_token.clone().into_value()),
            ("refresh_token", self.refresh_token.clone().into_value()),
            ("id_token", self.id_token.clone().into_value()),
            (
                "access_token_expires_at",
                self.access_token_expires_at.into_value(),
            ),
            (
                "refresh_token_expires_at",
                self.refresh_token_expires_at.into_value(),
            ),
            ("scope", self.scope.clone().into_value()),
            ("created_at", self.created_at.into_value()),
            ("updated_at", self.updated_at.into_value()),
        ]
    }
}

/// Single-use values: email verification, password reset, OAuth state, OTPs.
/// `identifier` says what the value is for; only the hash of the value is stored.
#[derive(Clone, Debug, PartialEq)]
pub struct Verification {
    pub id: Id,
    pub identifier: String,
    pub value_hash: Hash,
    /// Extra data, e.g. an OAuth PKCE verifier or a callback URL.
    pub data: Option<String>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Verification {
    pub const ID: Col<Verification, Id> = Col::new("id");
    pub const IDENTIFIER: Col<Verification, String> = Col::new("identifier");
    pub const VALUE_HASH: Col<Verification, Hash> = Col::new("value_hash");
    pub const EXPIRES_AT: Col<Verification, OffsetDateTime> = Col::new("expires_at");
}

impl OnTable for Verification {
    type Table = Verification;
}

impl Model for Verification {
    const TABLE: &'static str = "verification";

    fn columns() -> &'static [ColumnDef] {
        columns![
            ColumnDef::new("id", T::Id).primary_key(),
            ColumnDef::new("identifier", T::Text).index(),
            ColumnDef::new("value_hash", T::Bytes).unique().hidden(),
            ColumnDef::new("data", T::Text).nullable().hidden(),
            ColumnDef::new("expires_at", T::Timestamp),
        ]
    }

    fn decode(row: &Row) -> Result<Self, DecodeError> {
        Ok(Self {
            id: get(row, "id")?,
            identifier: get(row, "identifier")?,
            value_hash: get(row, "value_hash")?,
            data: get(row, "data")?,
            expires_at: get(row, "expires_at")?,
            created_at: get(row, "created_at")?,
            updated_at: get(row, "updated_at")?,
        })
    }

    fn encode(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("id", self.id.clone().into_value()),
            ("identifier", self.identifier.clone().into_value()),
            ("value_hash", self.value_hash.into_value()),
            ("data", self.data.clone().into_value()),
            ("expires_at", self.expires_at.into_value()),
            ("created_at", self.created_at.into_value()),
            ("updated_at", self.updated_at.into_value()),
        ]
    }
}
