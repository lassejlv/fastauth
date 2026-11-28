//! A cookie-keeping HTTP client over `Auth::handle`, generic over the auth type, for targets
//! that drive multi-step flows on their own auth instance.

use std::collections::BTreeMap;

use bytes::Bytes;
use fastauth_core::adapter::Adapter;
use fastauth_core::model::Fields;
use fastauth_core::{Auth, PluginSet};
use http::{HeaderMap, Method, Request, StatusCode, header};
use serde_json::Value;

use crate::{BASE_URL, RUNTIME};

pub struct Client<'a, D, U, P> {
    pub auth: &'a Auth<D, U, P>,
    /// name -> value, as the browser would send them back.
    pub jar: BTreeMap<String, String>,
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub json: Value,
}

impl Reply {
    /// The `name=value` pairs of every `Set-Cookie`, with their attributes.
    pub fn set_cookies(&self) -> Vec<&str> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect()
    }

    /// Whether the reply sets a non-empty session cookie.
    pub fn signs_in(&self) -> bool {
        self.set_cookies().iter().any(|c| {
            let pair = c.split(';').next().unwrap_or_default();
            pair.split_once('=').is_some_and(|(name, value)| {
                name == "fastauth.session_token" && !value.is_empty() && !c.contains("Max-Age=0")
            })
        })
    }

    pub fn location(&self) -> Option<&str> {
        self.headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
    }
}

impl<'a, D: Adapter, U: Fields, P: PluginSet> Client<'a, D, U, P> {
    pub fn new(auth: &'a Auth<D, U, P>) -> Self {
        Self {
            auth,
            jar: BTreeMap::new(),
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

    /// Sends `request` as is (the jar is not added) and keeps the cookies it sets.
    pub fn send_raw(&mut self, request: Request<Bytes>) -> Reply {
        let response = RUNTIME.block_on(self.auth.handle(request));
        let reply = Reply {
            status: response.status(),
            headers: response.headers().clone(),
            json: serde_json::from_slice(response.body()).unwrap_or(Value::Null),
        };
        for cookie in reply.set_cookies() {
            let pair = cookie.split(';').next().unwrap_or_default();
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if value.is_empty() || cookie.contains("Max-Age=0") {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.to_owned(), value.to_owned());
            }
        }
        reply
    }

    /// `path` relative to `/api/auth`, with the jar's cookies and the app's Origin.
    pub fn send(&mut self, method: Method, path: &str, body: Option<&Value>) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("/api/auth{path}"))
            .header(header::ORIGIN, BASE_URL);
        if let Some(cookies) = self.cookie_header() {
            request = request.header(header::COOKIE, cookies);
        }
        let body = body.map_or_else(Bytes::new, |b| Bytes::from(b.to_string()));
        if !body.is_empty() {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        self.send_raw(request.body(body).expect("a valid request"))
    }

    pub fn get(&mut self, path: &str) -> Reply {
        self.send(Method::GET, path, None)
    }

    pub fn post(&mut self, path: &str, body: &Value) -> Reply {
        self.send(Method::POST, path, Some(body))
    }

    /// Signs up `email` with password `PASSWORD` and returns the raw session token.
    pub fn sign_up(&mut self, email: &str) -> String {
        let reply = self.post(
            "/sign-up/email",
            &serde_json::json!({ "email": email, "password": PASSWORD, "name": "Fuzz" }),
        );
        assert_eq!(reply.status, StatusCode::OK, "sign-up: {}", reply.json);
        reply.json["token"]
            .as_str()
            .expect("sign-up returns a token")
            .to_owned()
    }
}

pub const PASSWORD: &str = "correct horse";
