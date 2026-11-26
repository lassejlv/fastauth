//! The app's own routes, next to fastauth's under `/api/auth`.

use axum::extract::{FromRef, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use fastauth::plugins::admin::{Admin, AdminUser, RequireRole, role};
use fastauth::plugins::organization::extract::{FromPath, OrgMember, RequirePermission};
use fastauth::plugins::organization::path_param;
use fastauth::plugins::two_factor::TwoFactor;
use fastauth::prelude::*;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::auth::{AppAuth, ProjectCreate};
use crate::config::Config;

#[derive(Clone, FromRef)]
pub struct AppState {
    pub auth: AppAuth,
    pub pool: PgPool,
    pub features: Features,
}

/// What the React app needs to know before anyone signs in.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Features {
    pub github: bool,
}

impl Features {
    pub fn from_config(config: &Config) -> Self {
        Self {
            github: config.github.is_some(),
        }
    }
}

path_param!(pub OrgId = "org_id");

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/features", get(features))
        .route("/api/me", get(me))
        .route(
            "/api/orgs/{org_id}/projects",
            get(list_projects).post(create_project),
        )
        .route("/api/admin/overview", get(admin_overview))
}

async fn features(State(features): State<Features>) -> Json<Features> {
    Json(features)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Me {
    id: String,
    email: String,
    name: String,
    role: Option<String>,
    two_factor_enabled: bool,
    /// True when the request was signed in by an `x-api-key` header, not a cookie.
    via_api_key: bool,
}

async fn me(session: Session<AppAuth>) -> Json<Me> {
    let admin: &AdminUser = session.user.plugin::<Admin, _>();
    Json(Me {
        id: session.user.id.to_string(),
        email: session.user.email.clone(),
        name: session.user.name.clone(),
        role: admin.role.clone(),
        two_factor_enabled: session.user.plugin::<TwoFactor, _>().two_factor_enabled,
        via_api_key: session.view().ephemeral,
    })
}

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct Project {
    id: String,
    name: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    created_by_name: String,
    created_by_email: String,
}

/// Any member of the organization in the path may list its projects. Anyone else gets
/// 403 `YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION` before this runs.
async fn list_projects(
    member: OrgMember<AppAuth, FromPath<OrgId>>,
    State(pool): State<PgPool>,
) -> Result<Json<Vec<Project>>, AuthError> {
    let projects = sqlx::query_as::<_, Project>(
        "SELECT p.id, p.name, p.created_at, u.name AS created_by_name, \
         u.email AS created_by_email \
         FROM project p JOIN \"user\" u ON u.id = p.created_by \
         WHERE p.organization_id = $1 ORDER BY p.created_at DESC",
    )
    .bind(member.organization_id.to_string())
    .fetch_all(&pool)
    .await
    .map_err(AuthError::internal)?;
    Ok(Json(projects))
}

#[derive(Deserialize)]
struct NewProject {
    name: String,
}

/// Owners and admins may create projects; members get 403 `PERMISSION_DENIED`.
async fn create_project(
    member: RequirePermission<AppAuth, ProjectCreate, FromPath<OrgId>>,
    State(pool): State<PgPool>,
    Json(input): Json<NewProject>,
) -> Result<(StatusCode, Json<Project>), AuthError> {
    let name = input.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(AuthError::bad_request(
            "INVALID_PROJECT_NAME",
            "a project name is 1 to 100 characters",
        ));
    }
    let project = sqlx::query_as::<_, Project>(
        "WITH p AS (INSERT INTO project (organization_id, name, created_by) \
         VALUES ($1, $2, $3) RETURNING *) \
         SELECT p.id, p.name, p.created_at, u.name AS created_by_name, \
         u.email AS created_by_email \
         FROM p JOIN \"user\" u ON u.id = p.created_by",
    )
    .bind(member.organization_id.to_string())
    .bind(name)
    .bind(member.user_id.to_string())
    .fetch_one(&pool)
    .await
    .map_err(AuthError::internal)?;
    Ok((StatusCode::CREATED, Json(project)))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminOverview {
    users: i64,
    banned: i64,
    organizations: i64,
}

/// Only users with an admin role get here; others get 403 `FORBIDDEN`.
async fn admin_overview(
    _admin: RequireRole<AppAuth, role::Admin>,
    State(pool): State<PgPool>,
) -> Result<Json<AdminOverview>, AuthError> {
    let (users, banned, organizations) = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT (SELECT count(*) FROM \"user\"), \
         (SELECT count(*) FROM \"user\" WHERE banned), \
         (SELECT count(*) FROM organization)",
    )
    .fetch_one(&pool)
    .await
    .map_err(AuthError::internal)?;
    Ok(Json(AdminOverview {
        users,
        banned,
        organizations,
    }))
}
