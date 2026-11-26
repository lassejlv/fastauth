//! The `/admin/*` endpoints, the ban check, and the helpers they share.

use fastauth_core::events::{PasswordChanged, UserDeleted, UserUpdated};
use fastauth_core::plugin_prelude::*;
use fastauth_core::routes::Status;
use fastauth_core::schema::ColumnDef;
use serde_json::{Map, Value as Json};
use time::format_description::well_known::Rfc3339;

use crate::{Admin, AdminError, AdminSession, AdminUser, Permissions};

const ADMIN_SESSION_COOKIE: &str = "admin_session";
const SESSION_TOKEN_COOKIE: &str = "session_token";
const DONT_REMEMBER_COOKIE: &str = "dont_remember";
const SESSION_CACHE_COOKIE: &str = "session_data";
const BAN_COLUMNS: [&str; 3] = ["banned", "banReason", "banExpires"];

/// Who an admin endpoint runs for: an HTTP request, whose session needs the right
/// permissions, or the server API, which is trusted.
#[derive(Clone, Debug)]
pub struct Caller {
    plugin: Arc<Admin>,
    server: bool,
}

impl Caller {
    pub(crate) fn http(plugin: Arc<Admin>) -> Self {
        Self {
            plugin,
            server: false,
        }
    }

    pub(crate) fn server(plugin: Arc<Admin>) -> Self {
        Self {
            plugin,
            server: true,
        }
    }

    /// The caller's session, after checking it may do `action` on `resource`. `None` for
    /// server calls; 401 without a session; `denied` without the permission.
    fn check<'c, D: Adapter>(
        &self,
        ctx: &'c Ctx<D, MaybeAuthenticated>,
        resource: &str,
        action: &str,
        denied: AdminError,
    ) -> Result<Option<&'c SessionView>, AuthError> {
        if self.server {
            return Ok(None);
        }
        let session = ctx.session().ok_or_else(AuthError::unauthorized)?;
        if !may(&self.plugin, Some(session), resource, action)? {
            return Err(denied.into());
        }
        Ok(Some(session))
    }

    /// Like `check` for a second permission the request needs (e.g. `set-role` on create).
    fn also(
        &self,
        session: Option<&SessionView>,
        resource: &str,
        action: &str,
        denied: AdminError,
    ) -> Result<(), AuthError> {
        if may(&self.plugin, session, resource, action)? {
            Ok(())
        } else {
            Err(denied.into())
        }
    }
}

/// Whether the session may do `action` on `resource`; server calls (`None`) may do anything.
fn may(
    plugin: &Admin,
    session: Option<&SessionView>,
    resource: &str,
    action: &str,
) -> Result<bool, AuthError> {
    let Some(session) = session else {
        return Ok(true);
    };
    let fields = admin_fields(&session.user)?;
    Ok(plugin.has_permission(
        &session.user.id,
        fields.role.as_deref(),
        &Permissions::new().allow(resource, [action]),
    ))
}

/// Refuses acting on another admin's account without `user:impersonate-admins`, the line
/// impersonation draws, so an admin can't take another admin over by setting their
/// password or email. Server calls (`None`) and acting on yourself pass.
fn check_target(
    plugin: &Admin,
    session: Option<&SessionView>,
    target: &UserView,
) -> Result<(), AuthError> {
    let Some(session) = session.filter(|s| s.user.id != target.id) else {
        return Ok(());
    };
    if plugin.is_admin(&target.id, admin_fields(target)?.role.as_deref())
        && !may(plugin, Some(session), "user", "impersonate-admins")?
    {
        return Err(AdminError::YouCannotManageAdmins.into());
    }
    Ok(())
}

fn admin_fields(user: &UserView) -> Result<AdminUser, AuthError> {
    user.fields().map_err(AuthError::internal)
}

/// The error a banned user's sign-in gets, or `None`. Lifts the ban when it has expired.
pub(crate) async fn ban_error<D: Adapter, A>(
    plugin: &Admin,
    ctx: &Ctx<D, A>,
    user: &UserView,
) -> Result<Option<AuthError>, AuthError> {
    let fields = admin_fields(user)?;
    if !fields.banned {
        return Ok(None);
    }
    if fields.ban_expires.is_some_and(|t| t <= ctx.now()) {
        lift_ban(ctx, &user.id).await?;
        return Ok(None);
    }
    Ok(Some(plugin.banned_error(fields.ban_reason.as_deref())))
}

async fn lift_ban<D: Adapter, A>(ctx: &Ctx<D, A>, user_id: &Id) -> Result<(), AuthError> {
    ctx.db()
        .update::<User>(User::ID.eq(user_id))
        .set(AdminUser::BANNED, false)
        .set(AdminUser::BAN_REASON, None::<String>)
        .set(AdminUser::BAN_EXPIRES, None::<OffsetDateTime>)
        .exec()
        .await?;
    Ok(())
}

async fn find_user<D: Adapter, A>(ctx: &Ctx<D, A>, id: &Id) -> Result<UserView, AuthError> {
    ctx.internal()
        .find_user_by_id(id)
        .await?
        .ok_or_else(user_not_found)
}

fn user_not_found() -> AuthError {
    AuthError::new(
        StatusCode::NOT_FOUND,
        codes::USER_NOT_FOUND,
        "User not found",
    )
}

fn invalid_field(message: String) -> AuthError {
    AuthError::bad_request(codes::INVALID_FIELD, message)
}

fn camel_case(snake: &str) -> String {
    let mut out = String::with_capacity(snake.len());
    let mut upper = false;
    for ch in snake.chars() {
        if ch == '_' {
            upper = true;
        } else if upper {
            out.extend(ch.to_uppercase());
            upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// The `user` column a client names in camelCase. Hidden columns don't exist for clients.
fn user_column<D: Adapter, A>(ctx: &Ctx<D, A>, key: &str) -> Result<ColumnDef, AuthError> {
    ctx.schema()
        .expect(User::TABLE)
        .columns
        .iter()
        .find(|c| c.returned && camel_case(c.name) == key)
        .copied()
        .ok_or_else(|| invalid_field(format!("unknown field `{key}`")))
}

fn column_value(column: &ColumnDef, key: &str, json: &Json) -> Result<Value, AuthError> {
    Value::from_json(column.ty, json)
        .filter(|v| !v.is_null() || column.nullable)
        .ok_or_else(|| invalid_field(format!("field `{key}` has the wrong type")))
}

fn normalize_email(email: &str) -> Result<String, AuthError> {
    let email = email.trim().to_lowercase();
    let valid = email.len() <= 254
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
        });
    if !valid {
        return Err(AuthError::bad_request(
            codes::INVALID_EMAIL,
            "Invalid email",
        ));
    }
    Ok(email)
}

fn email_taken() -> AuthError {
    AuthError::bad_request(
        codes::USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL,
        "User already exists. Use another email.",
    )
}

/// One role or several: `"admin"` or `["admin", "support"]`. Stored comma-separated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Roles {
    One(String),
    Many(Vec<String>),
}

impl Roles {
    fn names(&self) -> Vec<&str> {
        let parts: Vec<&str> = match self {
            Roles::One(role) => vec![role.as_str()],
            Roles::Many(roles) => roles.iter().map(String::as_str).collect(),
        };
        parts
            .into_iter()
            .flat_map(|r| r.split(','))
            .map(str::trim)
            .filter(|r| !r.is_empty())
            .collect()
    }

    /// The `user.role` value, after checking every role is defined.
    fn stored(&self, plugin: &Admin) -> Result<String, AuthError> {
        let names = self.names();
        if names.is_empty() {
            return Err(AdminError::InvalidRoleType.into());
        }
        if names.iter().any(|r| !plugin.has_role_defined(r)) {
            return Err(AdminError::YouAreNotAllowedToSetNonExistentValue.into());
        }
        Ok(names.join(","))
    }

    fn from_json(json: &Json) -> Result<Self, AuthError> {
        serde_json::from_value(json.clone()).map_err(|_| AdminError::InvalidRoleType.into())
    }
}

impl From<&str> for Roles {
    fn from(role: &str) -> Self {
        Roles::One(role.to_owned())
    }
}

impl From<String> for Roles {
    fn from(role: String) -> Self {
        Roles::One(role)
    }
}

impl<const N: usize> From<[&str; N]> for Roles {
    fn from(roles: [&str; N]) -> Self {
        Roles::Many(roles.iter().map(|r| (*r).to_owned()).collect())
    }
}

/// `{ "user": {..} }`.
#[derive(Debug, Serialize)]
pub struct UserOutput {
    pub user: UserView,
}

/// `{ "success": true }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Success {
    pub success: bool,
}

/// Body of the endpoints that name one user.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserIdInput {
    pub user_id: Id,
}

// ---------------------------------------------------------------------------- create-user

/// Body of `/admin/create-user`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserInput {
    pub email: String,
    /// Creates a credential account. Without it the user signs in some other way.
    #[serde(default)]
    pub password: Option<String>,
    pub name: String,
    /// The user's roles; the default role when absent.
    #[serde(default)]
    pub role: Option<Roles>,
    /// Any other user columns by camelCase name, including app and plugin columns.
    #[serde(default)]
    pub data: Map<String, Json>,
}

/// `POST /admin/create-user`: needs `user:create`, plus `user:set-role` to pick a role
/// and `user:ban` to set ban columns.
pub struct CreateUser(pub(crate) Caller);

impl<D: Adapter> Endpoint<D> for CreateUser {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/admin/create-user";
    type Access = MaybeAuthenticated;
    type Input = CreateUserInput;
    type Output = UserOutput;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        mut input: CreateUserInput,
    ) -> Result<UserOutput, AuthError> {
        let caller = &self.0;
        let plugin = &caller.plugin;
        let session = caller.check(
            &ctx,
            "user",
            "create",
            AdminError::YouAreNotAllowedToCreateUsers,
        )?;
        let data_role = input.data.remove("role");
        let role = match (input.role, data_role) {
            (Some(role), _) => Some(role),
            (None, Some(json)) => Some(Roles::from_json(&json)?),
            (None, None) => None,
        };
        let role = match role {
            Some(role) => {
                caller.also(
                    session,
                    "user",
                    "set-role",
                    AdminError::YouAreNotAllowedToChangeUsersRole,
                )?;
                role.stored(plugin)?
            }
            None => plugin.default_role.clone(),
        };
        if BAN_COLUMNS.iter().any(|k| input.data.contains_key(*k)) {
            caller.also(
                session,
                "user",
                "ban",
                AdminError::YouAreNotAllowedToBanUsers,
            )?;
        }
        let email = normalize_email(&input.email)?;
        let internal = ctx.internal();
        if let Some(password) = &input.password {
            internal.validate_new_password(password)?;
        }
        if internal.find_user_by_email(&email).await?.is_some() {
            return Err(email_taken());
        }
        let mut extra = vec![("role", Value::Text(role))];
        for (key, json) in &input.data {
            let column = user_column(&ctx, key)?;
            if matches!(
                column.name,
                "id" | "email" | "name" | "created_at" | "updated_at"
            ) {
                return Err(invalid_field(format!("field `{key}` can't be set")));
            }
            extra.push((column.name, column_value(&column, key, json)?));
        }
        let missing = ctx.schema().expect(User::TABLE).columns.iter().find(|c| {
            c.owner != "core"
                && !c.nullable
                && c.default.is_none()
                && !extra.iter().any(|(name, _)| *name == c.name)
        });
        if let Some(column) = missing {
            return Err(invalid_field(format!(
                "field `{}` is required",
                camel_case(column.name)
            )));
        }
        let account = match &input.password {
            Some(password) => Some(NewAccount::credential(
                ctx.passwords()
                    .hash(password)
                    .await
                    .map_err(AuthError::internal)?,
            )),
            None => None,
        };
        let user = NewUser {
            email,
            name: input.name,
            extra,
            ..NewUser::default()
        };
        let user = internal.create_user(user, account).await?;
        Ok(UserOutput { user })
    }
}

// ---------------------------------------------------------------------------- list-users

/// Which column `searchValue` matches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SearchField {
    #[default]
    Email,
    Name,
}

/// How `searchValue` matches. Case-sensitive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchOperator {
    #[default]
    Contains,
    StartsWith,
    EndsWith,
}

/// `asc` or `desc`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    #[default]
    Asc,
    Desc,
}

/// How `filterValue` compares with `filterField`. `in` and `not_in` take a
/// comma-separated list; the text operators are case-sensitive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WhereOperator {
    #[default]
    Eq,
    Ne,
    Lt,
    Lte,
    Gt,
    Gte,
    In,
    NotIn,
    Contains,
    StartsWith,
    EndsWith,
}

/// Query of `/admin/list-users`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUsersQuery {
    pub search_value: Option<String>,
    pub search_field: Option<SearchField>,
    pub search_operator: Option<SearchOperator>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    /// A user column in camelCase.
    pub sort_by: Option<String>,
    pub sort_direction: Option<SortDirection>,
    /// A user column in camelCase; `email` by default.
    pub filter_field: Option<String>,
    /// Parsed as the column's type: `true`, `42`, an RFC 3339 timestamp, or text.
    pub filter_value: Option<String>,
    pub filter_operator: Option<WhereOperator>,
}

/// `{ "users": [..], "total": 42, "limit": 10, "offset": 0 }`. `total` counts every match.
#[derive(Debug, Serialize)]
pub struct UserList {
    pub users: Vec<UserView>,
    pub total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

/// `GET /admin/list-users`: needs `user:list`. Search, filters, sorting and paging all
/// run in the database; `total` counts every match.
pub struct ListUsers(pub(crate) Caller);

/// A case-sensitive text match on a text column.
fn text_match(
    column: &ColumnDef,
    operator: WhereOperator,
    value: &str,
) -> Result<Where<User>, AuthError> {
    use fastauth_core::schema::ColumnType;
    if !matches!(column.ty, ColumnType::Text | ColumnType::Id) {
        return Err(invalid_field(format!(
            "`{}` isn't text",
            camel_case(column.name)
        )));
    }
    let col = Col::<User, String>::new(column.name);
    Ok(match operator {
        WhereOperator::StartsWith => col.starts_with(value),
        WhereOperator::EndsWith => col.ends_with(value),
        _ => col.contains(value),
    })
}

fn parse_filter<T: ColumnValue>(
    column: &'static str,
    operator: WhereOperator,
    raw: &str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Where<User>, AuthError> {
    let col = Col::<User, T>::new(column);
    let one = || {
        parse(raw.trim())
            .ok_or_else(|| invalid_field(format!("can't compare `{column}` with `{raw}`")))
    };
    let many = || {
        raw.split(',')
            .map(|v| {
                parse(v.trim())
                    .ok_or_else(|| invalid_field(format!("can't compare `{column}` with `{v}`")))
            })
            .collect::<Result<Vec<T>, AuthError>>()
    };
    Ok(match operator {
        WhereOperator::Ne => col.ne(one()?),
        WhereOperator::Lt => col.lt(one()?),
        WhereOperator::Lte => col.lte(one()?),
        WhereOperator::Gt => col.gt(one()?),
        WhereOperator::Gte => col.gte(one()?),
        WhereOperator::In => col.in_(many()?),
        WhereOperator::NotIn => {
            let mut values = many()?.into_iter();
            let first = values
                .next()
                .ok_or_else(|| invalid_field("`not_in` needs a value".to_owned()))?;
            values.fold(col.ne(first), |filter, v| filter.and(col.ne(v)))
        }
        _ => col.eq(one()?),
    })
}

fn comparison(
    column: &ColumnDef,
    operator: WhereOperator,
    raw: &str,
) -> Result<Where<User>, AuthError> {
    use fastauth_core::schema::ColumnType;
    let name = column.name;
    match column.ty {
        ColumnType::Text | ColumnType::Id => {
            parse_filter::<String>(name, operator, raw, |v| Some(v.to_owned()))
        }
        ColumnType::Bool => parse_filter::<bool>(name, operator, raw, |v| v.parse().ok()),
        ColumnType::Int => parse_filter::<i64>(name, operator, raw, |v| v.parse().ok()),
        ColumnType::Timestamp => parse_filter::<OffsetDateTime>(name, operator, raw, |v| {
            OffsetDateTime::parse(v, &Rfc3339).ok()
        }),
        _ => Err(invalid_field(format!(
            "`{}` can't be filtered",
            camel_case(name)
        ))),
    }
}

impl<D: Adapter> Endpoint<D> for ListUsers {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/admin/list-users";
    type Access = MaybeAuthenticated;
    type Input = ListUsersQuery;
    type Output = UserList;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        query: ListUsersQuery,
    ) -> Result<UserList, AuthError> {
        self.0.check(
            &ctx,
            "user",
            "list",
            AdminError::YouAreNotAllowedToListUsers,
        )?;
        let mut conditions = Vec::new();
        if let Some(value) = query.search_value.as_deref().filter(|v| !v.is_empty()) {
            let field = match query.search_field.unwrap_or_default() {
                SearchField::Email => "email",
                SearchField::Name => "name",
            };
            let operator = match query.search_operator.unwrap_or_default() {
                SearchOperator::Contains => WhereOperator::Contains,
                SearchOperator::StartsWith => WhereOperator::StartsWith,
                SearchOperator::EndsWith => WhereOperator::EndsWith,
            };
            conditions.push(text_match(&user_column(&ctx, field)?, operator, value)?);
        }
        if let Some(value) = &query.filter_value {
            let column = user_column(&ctx, query.filter_field.as_deref().unwrap_or("email"))?;
            let operator = query.filter_operator.unwrap_or_default();
            conditions.push(match operator {
                WhereOperator::Contains | WhereOperator::StartsWith | WhereOperator::EndsWith => {
                    text_match(&column, operator, value)?
                }
                _ => comparison(&column, operator, value)?,
            });
        }
        let filter = conditions
            .into_iter()
            .reduce(Where::and)
            .unwrap_or_else(Where::all);
        let mut find = ctx.db().find::<User>(filter.clone());
        if let Some(sort_by) = &query.sort_by {
            let column = user_column(&ctx, sort_by)?;
            let col = Col::<User, String>::new(column.name);
            find = find.order_by(match query.sort_direction.unwrap_or_default() {
                SortDirection::Asc => col.asc(),
                SortDirection::Desc => col.desc(),
            });
        }
        let total = ctx.db().count::<User>(filter).await?;
        if let Some(offset) = query.offset {
            find = find.offset(offset);
        }
        if let Some(limit) = query.limit {
            find = find.limit(limit);
        }
        let users = find
            .all_rows()
            .await?
            .into_iter()
            .map(UserView::from_row)
            .collect::<Result<_, _>>()
            .map_err(AuthError::internal)?;
        Ok(UserList {
            users,
            total,
            limit: query.limit,
            offset: query.offset,
        })
    }
}

// ---------------------------------------------------------------------------- get-user

/// Query of `/admin/get-user`.
#[derive(Clone, Debug, Deserialize)]
pub struct GetUserQuery {
    pub id: Id,
}

/// `GET /admin/get-user?id=..`: needs `user:get`. Answers the user itself, unwrapped.
pub struct GetUser(pub(crate) Caller);

impl<D: Adapter> Endpoint<D> for GetUser {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/admin/get-user";
    type Access = MaybeAuthenticated;
    type Input = GetUserQuery;
    type Output = UserView;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        query: GetUserQuery,
    ) -> Result<UserView, AuthError> {
        self.0
            .check(&ctx, "user", "get", AdminError::YouAreNotAllowedToGetUser)?;
        find_user(&ctx, &query.id).await
    }
}

// ---------------------------------------------------------------------------- set-role

/// Body of `/admin/set-role`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRoleInput {
    pub user_id: Id,
    pub role: Roles,
}

/// `POST /admin/set-role`: needs `user:set-role`. Every role must be defined.
pub struct SetRole(pub(crate) Caller);

impl<D: Adapter> Endpoint<D> for SetRole {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/admin/set-role";
    type Access = MaybeAuthenticated;
    type Input = SetRoleInput;
    type Output = UserOutput;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: SetRoleInput,
    ) -> Result<UserOutput, AuthError> {
        let session = self.0.check(
            &ctx,
            "user",
            "set-role",
            AdminError::YouAreNotAllowedToChangeUsersRole,
        )?;
        let role = input.role.stored(&self.0.plugin)?;
        let target = find_user(&ctx, &input.user_id).await?;
        check_target(&self.0.plugin, session, &target)?;
        ctx.db()
            .update::<User>(User::ID.eq(&input.user_id))
            .set(AdminUser::ROLE, Some(role))
            .exec()
            .await?;
        updated(&ctx, &input.user_id).await
    }
}

/// Emits `UserUpdated` and answers the user as it is now.
async fn updated<D: Adapter, A>(ctx: &Ctx<D, A>, user_id: &Id) -> Result<UserOutput, AuthError> {
    ctx.emit(UserUpdated {
        user_id: user_id.clone(),
    });
    Ok(UserOutput {
        user: find_user(ctx, user_id).await?,
    })
}

// ---------------------------------------------------------------------------- ban-user

/// Body of `/admin/ban-user`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BanUserInput {
    pub user_id: Id,
    /// Defaults to the configured reason, or `"No reason"`.
    #[serde(default)]
    pub ban_reason: Option<String>,
    /// Seconds until the ban lifts. Defaults to the configured expiry, or never.
    #[serde(default)]
    pub ban_expires_in: Option<i64>,
}

impl BanUserInput {
    /// A ban with the configured reason and expiry.
    pub fn new(user_id: impl Into<Id>) -> Self {
        Self {
            user_id: user_id.into(),
            ban_reason: None,
            ban_expires_in: None,
        }
    }

    /// Why the user is banned.
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.ban_reason = Some(reason.into());
        self
    }

    /// When the ban lifts, from now.
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.ban_expires_in = Some(duration.whole_seconds());
        self
    }
}

/// `POST /admin/ban-user`: needs `user:ban`. Revokes every session of the user.
pub struct BanUser(pub(crate) Caller);

impl<D: Adapter> Endpoint<D> for BanUser {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/admin/ban-user";
    type Access = MaybeAuthenticated;
    type Input = BanUserInput;
    type Output = UserOutput;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: BanUserInput,
    ) -> Result<UserOutput, AuthError> {
        let plugin = &self.0.plugin;
        let session = self
            .0
            .check(&ctx, "user", "ban", AdminError::YouAreNotAllowedToBanUsers)?;
        let target = find_user(&ctx, &input.user_id).await?;
        if session.is_some_and(|s| s.user.id == input.user_id) {
            return Err(AdminError::YouCannotBanYourself.into());
        }
        check_target(plugin, session, &target)?;
        let reason = input
            .ban_reason
            .filter(|r| !r.is_empty())
            .or_else(|| plugin.default_ban_reason.clone())
            .unwrap_or_else(|| "No reason".to_owned());
        let expires = input
            .ban_expires_in
            .filter(|s| *s != 0)
            .map(Duration::seconds)
            .or(plugin.default_ban_expires_in)
            .map(|d| ctx.now() + d);
        ctx.db()
            .update::<User>(User::ID.eq(&input.user_id))
            .set(AdminUser::BANNED, true)
            .set(AdminUser::BAN_REASON, Some(reason))
            .set(AdminUser::BAN_EXPIRES, expires)
            .exec()
            .await?;
        ctx.internal()
            .revoke_user_sessions(&input.user_id, None)
            .await?;
        updated(&ctx, &input.user_id).await
    }
}

// ---------------------------------------------------------------------------- unban-user

/// `POST /admin/unban-user`: needs `user:ban`.
pub struct UnbanUser(pub(crate) Caller);

impl<D: Adapter> Endpoint<D> for UnbanUser {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/admin/unban-user";
    type Access = MaybeAuthenticated;
    type Input = UserIdInput;
    type Output = UserOutput;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: UserIdInput,
    ) -> Result<UserOutput, AuthError> {
        self.0
            .check(&ctx, "user", "ban", AdminError::YouAreNotAllowedToBanUsers)?;
        find_user(&ctx, &input.user_id).await?;
        lift_ban(&ctx, &input.user_id).await?;
        updated(&ctx, &input.user_id).await
    }
}

// ---------------------------------------------------------------------------- update-user

/// Body of `/admin/update-user`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserInput {
    pub user_id: Id,
    /// User columns by camelCase name.
    pub data: Map<String, Json>,
}

/// `POST /admin/update-user`: needs `user:update`, plus `user:set-role` for `role`,
/// `user:ban` for the ban columns and `user:set-email` for `email` and `emailVerified`.
/// Answers the user itself, unwrapped. Setting `banned: true` revokes the user's sessions.
pub struct UpdateUser(pub(crate) Caller);

impl<D: Adapter> Endpoint<D> for UpdateUser {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/admin/update-user";
    type Access = MaybeAuthenticated;
    type Input = UpdateUserInput;
    type Output = UserView;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: UpdateUserInput,
    ) -> Result<UserView, AuthError> {
        let caller = &self.0;
        let session = caller.check(
            &ctx,
            "user",
            "update",
            AdminError::YouAreNotAllowedToUpdateUsers,
        )?;
        let data = input.data;
        if data.is_empty() {
            return Err(AdminError::NoDataToUpdate.into());
        }
        if data.contains_key("password") {
            return Err(AdminError::PasswordCannotBeUpdatedViaUpdateUser.into());
        }
        if data.contains_key("id") {
            return Err(AdminError::UserIdCannotBeUpdated.into());
        }
        let mut set = Vec::new();
        if let Some(role) = data.get("role") {
            caller.also(
                session,
                "user",
                "set-role",
                AdminError::YouAreNotAllowedToChangeUsersRole,
            )?;
            let role = Roles::from_json(role)?.stored(&caller.plugin)?;
            set.push(("role", Value::Text(role)));
        }
        let banning = data.get("banned") == Some(&Json::Bool(true));
        if BAN_COLUMNS.iter().any(|k| data.contains_key(*k)) {
            caller.also(
                session,
                "user",
                "ban",
                AdminError::YouAreNotAllowedToBanUsers,
            )?;
            if banning && session.is_some_and(|s| s.user.id == input.user_id) {
                return Err(AdminError::YouCannotBanYourself.into());
            }
        }
        if data.contains_key("email") || data.contains_key("emailVerified") {
            caller.also(
                session,
                "user",
                "set-email",
                AdminError::YouAreNotAllowedToSetUsersEmail,
            )?;
        }
        let target = find_user(&ctx, &input.user_id).await?;
        check_target(&caller.plugin, session, &target)?;
        if let Some(email) = data.get("email") {
            let email = normalize_email(email.as_str().unwrap_or_default())?;
            let existing = ctx.internal().find_user_by_email(&email).await?;
            if existing.is_some_and(|u| u.id != input.user_id) {
                return Err(email_taken());
            }
            set.push(("email", Value::Text(email)));
        }
        for (key, json) in &data {
            if matches!(key.as_str(), "role" | "email") {
                continue;
            }
            let column = user_column(&ctx, key)?;
            if matches!(column.name, "created_at" | "updated_at") {
                return Err(invalid_field(format!("field `{key}` can't be set")));
            }
            set.push((column.name, column_value(&column, key, json)?));
        }
        let mut update = ctx.db().update::<User>(User::ID.eq(&input.user_id));
        for (column, value) in set {
            update = update.set_raw(column, value);
        }
        update.exec().await?;
        if banning {
            ctx.internal()
                .revoke_user_sessions(&input.user_id, None)
                .await?;
        }
        Ok(updated(&ctx, &input.user_id).await?.user)
    }
}

// ---------------------------------------------------------------------------- set-user-password

/// Body of `/admin/set-user-password`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetUserPasswordInput {
    pub new_password: String,
    pub user_id: Id,
}

/// `POST /admin/set-user-password`: needs `user:set-password`. Checks the password policy,
/// creates the credential account when the user has none, and emits `PasswordChanged`.
pub struct SetUserPassword(pub(crate) Caller);

impl<D: Adapter> Endpoint<D> for SetUserPassword {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/admin/set-user-password";
    type Access = MaybeAuthenticated;
    type Input = SetUserPasswordInput;
    type Output = Status;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: SetUserPasswordInput,
    ) -> Result<Status, AuthError> {
        let session = self.0.check(
            &ctx,
            "user",
            "set-password",
            AdminError::YouAreNotAllowedToSetUsersPassword,
        )?;
        let internal = ctx.internal();
        internal.validate_new_password(&input.new_password)?;
        let target = find_user(&ctx, &input.user_id).await?;
        check_target(&self.0.plugin, session, &target)?;
        internal
            .set_password(&input.user_id, &input.new_password)
            .await?;
        ctx.emit(PasswordChanged {
            user_id: input.user_id,
        });
        Ok(Status { status: true })
    }
}

// ---------------------------------------------------------------------------- remove-user

/// `POST /admin/remove-user`: needs `user:delete`. Deletes the user's sessions and
/// accounts, then the user, and emits `SessionRevoked` (when they had sessions) and
/// `UserDeleted`.
pub struct RemoveUser(pub(crate) Caller);

impl<D: Adapter> Endpoint<D> for RemoveUser {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/admin/remove-user";
    type Access = MaybeAuthenticated;
    type Input = UserIdInput;
    type Output = Success;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: UserIdInput,
    ) -> Result<Success, AuthError> {
        let session = self.0.check(
            &ctx,
            "user",
            "delete",
            AdminError::YouAreNotAllowedToDeleteUsers,
        )?;
        if session.is_some_and(|s| s.user.id == input.user_id) {
            return Err(AdminError::YouCannotRemoveYourself.into());
        }
        let user = find_user(&ctx, &input.user_id).await?;
        check_target(&self.0.plugin, session, &user)?;
        ctx.internal()
            .revoke_user_sessions(&input.user_id, None)
            .await?;
        ctx.db()
            .delete::<Account>(Account::USER_ID.eq(&input.user_id))
            .await?;
        ctx.db().delete::<User>(User::ID.eq(&input.user_id)).await?;
        ctx.emit(UserDeleted {
            user_id: input.user_id,
            email: user.email.clone(),
        });
        Ok(Success { success: true })
    }
}

// ---------------------------------------------------------------------------- sessions

/// `{ "sessions": [..] }`.
#[derive(Debug, Serialize)]
pub struct SessionList {
    pub sessions: Vec<Map<String, Json>>,
}

/// `POST /admin/list-user-sessions`: needs `session:list`. The user's unexpired sessions.
pub struct ListUserSessions(pub(crate) Caller);

impl<D: Adapter> Endpoint<D> for ListUserSessions {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/admin/list-user-sessions";
    type Access = MaybeAuthenticated;
    type Input = UserIdInput;
    type Output = SessionList;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: UserIdInput,
    ) -> Result<SessionList, AuthError> {
        self.0.check(
            &ctx,
            "session",
            "list",
            AdminError::YouAreNotAllowedToListUsersSessions,
        )?;
        let rows = ctx
            .db()
            .find::<Session>(
                Session::USER_ID
                    .eq(&input.user_id)
                    .and(Session::EXPIRES_AT.gt(ctx.now())),
            )
            .order_by(Session::CREATED_AT.desc())
            .all_rows()
            .await?;
        Ok(SessionList {
            sessions: rows.iter().map(Row::to_client_json).collect(),
        })
    }
}

/// Body of `/admin/revoke-user-session`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeUserSessionInput {
    pub session_token: String,
}

/// `POST /admin/revoke-user-session`: needs `session:revoke`. Succeeds when no session
/// with that token is left, even if there never was one.
pub struct RevokeUserSession(pub(crate) Caller);

impl<D: Adapter> Endpoint<D> for RevokeUserSession {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/admin/revoke-user-session";
    type Access = MaybeAuthenticated;
    type Input = RevokeUserSessionInput;
    type Output = Success;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: RevokeUserSessionInput,
    ) -> Result<Success, AuthError> {
        let caller = self.0.check(
            &ctx,
            "session",
            "revoke",
            AdminError::YouAreNotAllowedToRevokeUsersSessions,
        )?;
        let found = ctx
            .db()
            .find::<Session>(Session::TOKEN_HASH.eq(Hash::sha256(&input.session_token)))
            .one()
            .await?;
        if let Some(session) = found {
            if let Some(owner) = ctx.internal().find_user_by_id(&session.user_id).await? {
                check_target(&self.0.plugin, caller, &owner)?;
            }
            ctx.internal()
                .revoke_session(&session.user_id, &session.id)
                .await?;
        }
        Ok(Success { success: true })
    }
}

/// `POST /admin/revoke-user-sessions`: needs `session:revoke`.
pub struct RevokeUserSessions(pub(crate) Caller);

impl<D: Adapter> Endpoint<D> for RevokeUserSessions {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/admin/revoke-user-sessions";
    type Access = MaybeAuthenticated;
    type Input = UserIdInput;
    type Output = Success;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: UserIdInput,
    ) -> Result<Success, AuthError> {
        let session = self.0.check(
            &ctx,
            "session",
            "revoke",
            AdminError::YouAreNotAllowedToRevokeUsersSessions,
        )?;
        if let Some(target) = ctx.internal().find_user_by_id(&input.user_id).await? {
            check_target(&self.0.plugin, session, &target)?;
        }
        ctx.internal()
            .revoke_user_sessions(&input.user_id, None)
            .await?;
        Ok(Success { success: true })
    }
}

// ---------------------------------------------------------------------------- impersonation

/// `{ "session": {..}, "user": {..} }`.
#[derive(Debug, Serialize)]
pub struct SessionOutput {
    pub session: Map<String, Json>,
    pub user: UserView,
}

/// `POST /admin/impersonate-user`: needs `user:impersonate`, plus
/// `user:impersonate-admins` when the target is an admin. Signs the browser in as the
/// user with a short session marked `impersonatedBy`, and keeps the admin's session token
/// in a signed `{prefix}.admin_session` cookie for `stop-impersonating`. Impersonation
/// sessions can't impersonate, and banned users can't be impersonated.
pub struct ImpersonateUser(pub(crate) Arc<Admin>);

impl<D: Adapter> Endpoint<D> for ImpersonateUser {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/admin/impersonate-user";
    type Access = Authenticated;
    type Input = UserIdInput;
    type Output = SessionOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: UserIdInput,
    ) -> Result<SessionOutput, AuthError> {
        let plugin = &self.0;
        let admin = ctx.session();
        let denied = || AuthError::from(AdminError::YouAreNotAllowedToImpersonateUsers);
        if !may(plugin, Some(admin), "user", "impersonate")? {
            return Err(denied());
        }
        let impersonating = admin
            .fields::<AdminSession>()
            .map_err(AuthError::internal)?
            .impersonated_by
            .is_some();
        let Some(admin_token) = admin.token.as_deref().filter(|_| !impersonating) else {
            return Err(denied());
        };
        let target = find_user(&ctx, &input.user_id).await?;
        let target_role = admin_fields(&target)?.role;
        if plugin.is_admin(&target.id, target_role.as_deref())
            && !may(plugin, Some(admin), "user", "impersonate-admins")?
        {
            return Err(AdminError::YouCannotImpersonateAdmins.into());
        }
        if let Some(err) = ban_error(plugin, &ctx, &target).await? {
            return Err(err);
        }

        let now = ctx.now();
        let dont_remember = ctx.signed_cookie(DONT_REMEMBER_COOKIE).is_some();
        let remaining = admin.session.expires_at - now;
        ctx.set_signed_cookie(
            ADMIN_SESSION_COOKIE,
            &format!("{admin_token}:{}", if dont_remember { "1" } else { "" }),
            (!dont_remember).then_some(remaining),
        );
        let session = ctx.internal().create_session(&target.id, false).await?;
        let expires_at = now + plugin.impersonation_session_duration;
        ctx.db()
            .update::<Session>(Session::ID.eq(&session.session.id))
            .set(AdminSession::IMPERSONATED_BY, Some(admin.user.id.clone()))
            .set(Session::EXPIRES_AT, expires_at)
            .exec()
            .await?;
        let mut json = session.to_json();
        json.insert(
            "impersonatedBy".into(),
            Json::String(admin.user.id.to_string()),
        );
        json.insert("expiresAt".into(), Value::Timestamp(expires_at).to_json());
        Ok(SessionOutput {
            session: json,
            user: target,
        })
    }
}

/// `POST /admin/stop-impersonating`: ends the impersonation session and signs the browser
/// back in as the admin from the `admin_session` cookie.
pub struct StopImpersonating;

impl<D: Adapter> Endpoint<D> for StopImpersonating {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/admin/stop-impersonating";
    type Access = Authenticated;
    type Input = Empty;
    type Output = SessionOutput;

    async fn call(&self, ctx: Ctx<D, Authenticated>, _: Empty) -> Result<SessionOutput, AuthError> {
        let current = ctx.session();
        let admin_id = current
            .fields::<AdminSession>()
            .map_err(AuthError::internal)?
            .impersonated_by
            .ok_or(AdminError::NotImpersonating)?;
        let missing = || AuthError::internal("failed to find the admin session");
        let cookie = ctx
            .signed_cookie(ADMIN_SESSION_COOKIE)
            .ok_or_else(missing)?;
        let (token, dont_remember) = cookie.split_once(':').ok_or_else(missing)?;
        let row = ctx
            .db()
            .find::<Session>(Session::TOKEN_HASH.eq(Hash::sha256(token)))
            .one_row()
            .await?
            .ok_or_else(missing)?;
        let admin_session = Session::decode(&row).map_err(AuthError::internal)?;
        let now = ctx.now();
        if admin_session.user_id != admin_id || admin_session.expires_at <= now {
            return Err(missing());
        }
        let admin = find_user(&ctx, &admin_id).await?;
        ctx.internal()
            .revoke_session(&current.user.id, &current.session.id)
            .await?;

        let dont_remember = !dont_remember.is_empty();
        ctx.set_signed_cookie(
            SESSION_TOKEN_COOKIE,
            token,
            (!dont_remember).then_some(admin_session.expires_at - now),
        );
        if dont_remember {
            ctx.set_signed_cookie(DONT_REMEMBER_COOKIE, "true", None);
        } else {
            ctx.delete_cookie(DONT_REMEMBER_COOKIE);
        }
        ctx.delete_cookie(SESSION_CACHE_COOKIE);
        ctx.delete_cookie(ADMIN_SESSION_COOKIE);
        let mut session = row.to_client_json();
        session.insert("token".into(), Json::String(token.to_owned()));
        Ok(SessionOutput {
            session,
            user: admin,
        })
    }
}

// ---------------------------------------------------------------------------- has-permission

/// Body of `/admin/has-permission`. Over HTTP the caller's session decides; server calls
/// name a user or a role.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HasPermissionInput {
    #[serde(default)]
    pub user_id: Option<Id>,
    #[serde(default)]
    pub role: Option<String>,
    /// Better Auth's older spelling of `permissions`.
    #[serde(default)]
    pub permission: Option<Permissions>,
    #[serde(default)]
    pub permissions: Option<Permissions>,
}

/// `{ "error": null, "success": true }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PermissionOutput {
    pub error: Option<String>,
    pub success: bool,
}

/// `POST /admin/has-permission`: whether the signed-in user (any user, not only admins)
/// may do everything in `permissions`.
pub struct HasPermission(pub(crate) Caller);

impl<D: Adapter> Endpoint<D> for HasPermission {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/admin/has-permission";
    type Access = MaybeAuthenticated;
    type Input = HasPermissionInput;
    type Output = PermissionOutput;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: HasPermissionInput,
    ) -> Result<PermissionOutput, AuthError> {
        let Some(permissions) = input.permissions.or(input.permission) else {
            return Err(AuthError::bad_request(
                codes::INVALID_BODY,
                "invalid permission check. no permission(s) were passed.",
            ));
        };
        let session = match ctx.session() {
            Some(session) => Some(session),
            None if self.0.server => None,
            None => return Err(AuthError::unauthorized()),
        };
        let (user_id, role) = match (session, input.role, input.user_id) {
            (Some(session), _, _) => (session.user.id.clone(), admin_fields(&session.user)?.role),
            (None, Some(role), user_id) => (user_id.unwrap_or_else(|| Id::from("")), Some(role)),
            (None, None, Some(user_id)) => {
                let user = ctx
                    .internal()
                    .find_user_by_id(&user_id)
                    .await?
                    .ok_or_else(|| {
                        AuthError::bad_request(codes::USER_NOT_FOUND, "user not found")
                    })?;
                (user_id, admin_fields(&user)?.role)
            }
            (None, None, None) => {
                return Err(AuthError::bad_request(
                    codes::INVALID_BODY,
                    "user id or role is required",
                ));
            }
        };
        Ok(PermissionOutput {
            error: None,
            success: self
                .0
                .plugin
                .has_permission(&user_id, role.as_deref(), &permissions),
        })
    }
}
