#![allow(dead_code)]

use std::collections::HashMap;

use bytes::Bytes;
use fastauth_core::{Auth, PluginSet, adapter::Adapter, model::Fields};
use http::{HeaderMap, Method, Request, StatusCode, header};
use serde_json::Value;

pub const ORIGIN: &str = "http://localhost:3000";

pub fn secret() -> fastauth_core::crypto::Secret {
    fastauth_core::crypto::Secret::from_bytes(vec![42u8; 32])
}

/// Speaks HTTP to `Auth::handle` and keeps a cookie jar, like a browser.
pub struct Client<D, U, P> {
    pub auth: Auth<D, U, P>,
    pub jar: HashMap<String, String>,
}

pub struct Res {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub json: Value,
}

impl Res {
    pub fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }

    pub fn location(&self) -> Option<&str> {
        self.headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
    }
}

impl<D: Adapter, U: Fields, P: PluginSet> Client<D, U, P> {
    pub fn new(auth: Auth<D, U, P>) -> Self {
        Self {
            auth,
            jar: HashMap::new(),
        }
    }

    pub fn cookie_header(&self) -> Option<String> {
        (!self.jar.is_empty()).then(|| {
            self.jar
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ")
        })
    }

    pub async fn send(&mut self, method: Method, path: &str, body: Option<Value>) -> Res {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("/api/auth{path}"))
            .header(header::ORIGIN, ORIGIN);
        if let Some(cookies) = self.cookie_header() {
            builder = builder.header(header::COOKIE, cookies);
        }
        let body = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
        let response = self.auth.handle(builder.body(body).unwrap()).await;
        for cookie in response.headers().get_all(header::SET_COOKIE) {
            let cookie = cookie.to_str().unwrap();
            let (pair, attrs) = cookie.split_once(';').unwrap_or((cookie, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if attrs.contains("Max-Age=0") {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.to_owned(), value.to_owned());
            }
        }
        let status = response.status();
        let headers = response.headers().clone();
        let json = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
        Res {
            status,
            headers,
            json,
        }
    }

    pub async fn post(&mut self, path: &str, body: Value) -> Res {
        self.send(Method::POST, path, Some(body)).await
    }

    pub async fn get(&mut self, path: &str) -> Res {
        self.send(Method::GET, path, None).await
    }

    pub async fn sign_up(&mut self, email: &str, password: &str) -> Res {
        self.post(
            "/sign-up/email",
            serde_json::json!({ "email": email, "password": password, "name": "Test User" }),
        )
        .await
    }
}
