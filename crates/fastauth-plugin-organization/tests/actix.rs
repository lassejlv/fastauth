//! The organization extractors in actix-web: the same cases as `extract.rs`, through
//! `fastauth_actix`.
#![cfg(feature = "actix")]

mod common;

use actix_web::test::{self, TestRequest};
use actix_web::web;
use common::{Client, secret};
use fastauth_actix::AuthScope;
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_plugin_organization::access::MemberDelete;
use fastauth_plugin_organization::extract::{ActiveMember, FromPath, OrgMember, RequirePermission};
use fastauth_plugin_organization::{Organization, OrganizationExt, Permission, Roles, path_param};
use http::StatusCode;
use serde_json::{Value, json};

type AppAuth = Auth<MemoryAdapter, (), plugins![Organization]>;
type App = Client<MemoryAdapter, (), plugins![Organization]>;

path_param!(OrgId = "org_id");

struct InvoicePay;

impl Permission for InvoicePay {
    const RESOURCE: &'static str = "invoice";
    const ACTIONS: &'static [&'static str] = &["pay"];
}

async fn dashboard(member: ActiveMember<AppAuth>) -> String {
    member.role.clone()
}

async fn org_page(member: OrgMember<AppAuth, FromPath<OrgId>>) -> String {
    format!("{} {}", member.organization_id, member.role)
}

async fn remove_member(
    member: RequirePermission<AppAuth, MemberDelete, FromPath<OrgId>>,
) -> String {
    member.into_inner().role
}

async fn pay_invoice(member: RequirePermission<AppAuth, InvoicePay>) -> String {
    member.role.clone()
}

fn auth() -> AppAuth {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .session(SessionConfig::default().cookie_cache(Duration::minutes(5)))
        .rate_limit(RateLimit::disabled())
        .plugin(
            Organization::default()
                .roles(Roles::new().role("billing", [("invoice", &["read", "pay"])])),
        )
        .build()
        .expect("valid config")
}

async fn call(
    auth: &AppAuth,
    client: Option<&App>,
    method: &str,
    uri: &str,
) -> (StatusCode, String) {
    let app = test::init_service(
        actix_web::App::new()
            .app_data(web::Data::new(auth.clone()))
            .service(auth.scope())
            .route("/dashboard", web::get().to(dashboard))
            .route("/orgs/{org_id}", web::get().to(org_page))
            .route("/orgs/{org_id}/members", web::delete().to(remove_member))
            .route("/invoices/pay", web::get().to(pay_invoice))
            .route("/broken", web::get().to(org_page)),
    )
    .await;
    let mut request = TestRequest::default()
        .method(method.parse().unwrap())
        .uri(uri);
    if let Some(cookies) = client.and_then(Client::cookie_header) {
        request = request.insert_header(("cookie", cookies));
    }
    let response = test::call_service(&app, request.to_request()).await;
    let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
    let body = test::read_body(response).await;
    (status, String::from_utf8(body.to_vec()).unwrap())
}

fn code(body: &str) -> String {
    serde_json::from_str::<Value>(body).unwrap()["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

async fn user(auth: &AppAuth, email: &str) -> (App, Id) {
    let mut client = Client::new(auth.clone());
    let res = client.sign_up(email, "correct horse").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let id = Id::from(res.json["user"]["id"].as_str().unwrap());
    (client, id)
}

#[actix_web::test]
async fn set_active_drives_active_member() {
    let auth = auth();
    let (status, body) = call(&auth, None, "GET", "/dashboard").await;
    assert_eq!(
        (status, code(&body).as_str()),
        (StatusCode::UNAUTHORIZED, "UNAUTHORIZED")
    );

    let (mut owner, _) = user(&auth, "owner@acme.dk").await;
    let org = owner
        .post(
            "/organization/create",
            json!({ "name": "Acme", "slug": "acme", "keepCurrentActiveOrganization": true }),
        )
        .await
        .json["id"]
        .as_str()
        .unwrap()
        .to_owned();
    owner.get("/get-session").await;
    assert!(
        owner.jar.keys().any(|k| k.ends_with("session_data")),
        "cookie cache is on"
    );
    let (status, body) = call(&auth, Some(&owner), "GET", "/dashboard").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "NO_ACTIVE_ORGANIZATION");

    let res = owner
        .post("/organization/set-active", json!({ "organizationId": org }))
        .await;
    assert_eq!(res.status, StatusCode::OK);
    let (status, body) = call(&auth, Some(&owner), "GET", "/dashboard").await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "owner"));

    owner
        .post(
            "/organization/set-active",
            json!({ "organizationId": null }),
        )
        .await;
    let (status, _) = call(&auth, Some(&owner), "GET", "/dashboard").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn org_member_reads_the_path_and_require_permission_checks_roles() {
    let auth = auth();
    let (mut owner, _) = user(&auth, "owner@acme.dk").await;
    let org = owner
        .post(
            "/organization/create",
            json!({ "name": "Acme", "slug": "acme" }),
        )
        .await
        .json["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let org_id = Id::from(org.as_str());
    let (member, member_id) = user(&auth, "member@acme.dk").await;
    let (billing, billing_id) = user(&auth, "billing@acme.dk").await;
    let (stranger, _) = user(&auth, "stranger@acme.dk").await;
    let api = auth.organization();
    api.add_member(&org_id, &member_id, "member").await.unwrap();
    api.add_member(&org_id, &billing_id, "billing")
        .await
        .unwrap();

    let page = format!("/orgs/{org}");
    let (status, body) = call(&auth, Some(&member), "GET", &page).await;
    assert_eq!((status, body), (StatusCode::OK, format!("{org} member")));
    let (status, body) = call(&auth, Some(&stranger), "GET", &page).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&body), "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION");

    let members = format!("/orgs/{org}/members");
    let (status, body) = call(&auth, Some(&member), "DELETE", &members).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "PERMISSION_DENIED");
    let (status, body) = call(&auth, Some(&owner), "DELETE", &members).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "owner"));

    let mut billing = billing;
    billing
        .post("/organization/set-active", json!({ "organizationId": org }))
        .await;
    let mut member = member;
    member
        .post("/organization/set-active", json!({ "organizationId": org }))
        .await;
    let (status, body) = call(&auth, Some(&billing), "GET", "/invoices/pay").await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "billing"));
    let (status, body) = call(&auth, Some(&member), "GET", "/invoices/pay").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&body), "PERMISSION_DENIED");
    let (status, _) = call(&auth, Some(&owner), "GET", "/invoices/pay").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "owners only get custom permissions granted to them"
    );

    let (status, _) = call(&auth, Some(&owner), "GET", "/broken").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
