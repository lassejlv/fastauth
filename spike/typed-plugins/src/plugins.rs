//! Three toy plugins: `TwoFactor` adds a user column, a table, an endpoint and an
//! extension trait; `Organization` adds a table and an endpoint; `OrgBilling` exists to
//! require `Organization`.

use std::marker::PhantomData;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{
    Adapter, AuthError, AuthHandle, Column, ColumnType, Ctx, DefaultValue, Endpoint, Fields,
    HasPlugin, Method, Plugin, Record, Registry, Schema, Value, boolean,
};

// --------------------------------------------------------------------------- two factor

pub struct TwoFactor {
    pub issuer: String,
}

impl Default for TwoFactor {
    fn default() -> Self {
        Self {
            issuer: "fastauth".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TwoFactorUser {
    pub two_factor_enabled: bool,
}

impl Fields for TwoFactorUser {
    fn columns() -> &'static [Column] {
        &[Column {
            name: "two_factor_enabled",
            ty: ColumnType::Bool,
            default: Some(DefaultValue::Bool(false)),
        }]
    }
    fn decode(record: &Record) -> Result<Self, AuthError> {
        Ok(Self {
            two_factor_enabled: boolean(record, "two_factor_enabled")?,
        })
    }
}

impl Plugin for TwoFactor {
    const ID: &'static str = "two-factor";
    type Requires = ();
    type UserFields = TwoFactorUser;

    fn schema(&self, schema: &mut Schema) {
        schema.table(
            "two_factor",
            Self::ID,
            &[
                Column {
                    name: "user_id",
                    ty: ColumnType::Text,
                    default: None,
                },
                Column {
                    name: "secret",
                    ty: ColumnType::Text,
                    default: None,
                },
            ],
        );
    }

    fn endpoints<D: Adapter>(self: &Arc<Self>, routes: &mut Registry<D>) {
        routes.endpoint(Enable(self.clone()));
    }
}

pub struct Enable(Arc<TwoFactor>);

#[derive(Deserialize)]
pub struct EnableInput {}

#[derive(Debug, Serialize)]
pub struct EnableOutput {
    pub totp_uri: String,
}

impl<D: Adapter> Endpoint<D> for Enable {
    const METHOD: Method = Method::Post;
    const PATH: &'static str = "/two-factor/enable";
    type Input = EnableInput;
    type Output = EnableOutput;

    async fn call(&self, ctx: Ctx<D>, _input: EnableInput) -> Result<EnableOutput, AuthError> {
        let session = ctx.require_session().await?;
        let id = Value::Text(session.user_id.clone());
        let set = Record::from([("two_factor_enabled".to_owned(), Value::Bool(true))]);
        ctx.db.update("user", "id", id, set).await?;
        let secret = "JBSWY3DPEHPK3PXP".to_owned();
        ctx.db
            .insert(
                "two_factor",
                Record::from([
                    ("user_id".to_owned(), Value::Text(session.user_id.clone())),
                    ("secret".to_owned(), Value::Text(secret.clone())),
                ]),
            )
            .await?;
        Ok(EnableOutput {
            totp_uri: format!(
                "otpauth://totp/{}:{}?secret={secret}",
                self.0.issuer, session.user_id
            ),
        })
    }
}

/// Typed server-side API, only callable when `TwoFactor` is registered.
pub trait TwoFactorExt: AuthHandle + Sized {
    fn two_factor<I>(&self) -> TwoFactorApi<'_, Self, I>
    where
        Self: HasPlugin<TwoFactor, I>,
    {
        TwoFactorApi {
            auth: self,
            _index: PhantomData,
        }
    }
}

impl<D: Adapter, U, P> TwoFactorExt for crate::Auth<D, U, P> {}

pub struct TwoFactorApi<'a, A, I> {
    auth: &'a A,
    _index: PhantomData<I>,
}

impl<A: HasPlugin<TwoFactor, I>, I> TwoFactorApi<'_, A, I> {
    pub async fn enable(&self, session_token: &str) -> Result<EnableOutput, AuthError> {
        let endpoint = Enable(self.auth.plugin_arc().clone());
        endpoint
            .call(
                self.auth.ctx(Some(session_token.to_owned())),
                EnableInput {},
            )
            .await
    }
}

// --------------------------------------------------------------------------- organization

#[derive(Default)]
pub struct Organization {
    pub allow_user_to_create: bool,
}

impl Plugin for Organization {
    const ID: &'static str = "organization";
    type Requires = ();
    type UserFields = ();

    fn schema(&self, schema: &mut Schema) {
        schema.table(
            "organization",
            Self::ID,
            &[
                Column {
                    name: "id",
                    ty: ColumnType::Text,
                    default: None,
                },
                Column {
                    name: "name",
                    ty: ColumnType::Text,
                    default: None,
                },
            ],
        );
    }

    fn endpoints<D: Adapter>(self: &Arc<Self>, routes: &mut Registry<D>) {
        routes.endpoint(CreateOrganization);
    }
}

pub struct CreateOrganization;

#[derive(Deserialize)]
pub struct CreateOrganizationInput {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct CreateOrganizationOutput {
    pub id: String,
}

impl<D: Adapter> Endpoint<D> for CreateOrganization {
    const METHOD: Method = Method::Post;
    const PATH: &'static str = "/organization/create";
    type Input = CreateOrganizationInput;
    type Output = CreateOrganizationOutput;

    async fn call(
        &self,
        ctx: Ctx<D>,
        input: CreateOrganizationInput,
    ) -> Result<Self::Output, AuthError> {
        ctx.require_session().await?;
        let id = format!("org_{}", input.name.to_lowercase());
        ctx.db
            .insert(
                "organization",
                Record::from([
                    ("id".to_owned(), Value::Text(id.clone())),
                    ("name".to_owned(), Value::Text(input.name)),
                ]),
            )
            .await?;
        Ok(CreateOrganizationOutput { id })
    }
}

// --------------------------------------------------------------------------- org billing

/// Exists to prove `Requires`: it reads `Organization` config at runtime without a
/// fallible lookup, because registration already proved the plugin is there.
pub struct OrgBilling;

impl Plugin for OrgBilling {
    const ID: &'static str = "org-billing";
    type Requires = (Organization,);
    type UserFields = ();

    fn endpoints<D: Adapter>(self: &Arc<Self>, routes: &mut Registry<D>) {
        routes.endpoint(BillingStatus);
    }
}

pub struct BillingStatus;

#[derive(Debug, Serialize)]
pub struct BillingStatusOutput {
    pub orgs_self_serve: bool,
}

impl<D: Adapter> Endpoint<D> for BillingStatus {
    const METHOD: Method = Method::Get;
    const PATH: &'static str = "/org-billing/status";
    type Input = ();
    type Output = BillingStatusOutput;

    async fn call(&self, ctx: Ctx<D>, _: ()) -> Result<BillingStatusOutput, AuthError> {
        Ok(BillingStatusOutput {
            orgs_self_serve: ctx.plugin::<Organization>().allow_user_to_create,
        })
    }
}
