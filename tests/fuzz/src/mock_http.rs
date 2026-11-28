//! A fake OAuth provider backend: canned token and userinfo answers for Google.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use fastauth_oauth::{HttpClient, HttpClientError};
use http::{Request, Response};

pub const GOOGLE_TOKEN: &str = "https://oauth2.googleapis.com/token";
pub const GOOGLE_USERINFO: &str = "https://openidconnect.googleapis.com/v1/userinfo";

#[derive(Clone, Default)]
pub struct MockHttp {
    routes: Arc<Mutex<HashMap<String, (u16, Bytes)>>>,
}

impl MockHttp {
    pub fn respond(&self, url: &str, status: u16, body: impl Into<Bytes>) {
        self.routes
            .lock()
            .unwrap()
            .insert(url.to_owned(), (status, body.into()));
    }

    /// A verified Google account for `email`.
    pub fn google_user(&self, email: &str) {
        self.respond(
            GOOGLE_TOKEN,
            200,
            serde_json::json!({
                "access_token": "ya29.google-access",
                "expires_in": 3599,
                "scope": "openid email profile",
                "token_type": "Bearer",
                "id_token": "header.payload.signature"
            })
            .to_string(),
        );
        self.respond(
            GOOGLE_USERINFO,
            200,
            serde_json::json!({
                "sub": format!("google-{email}"),
                "email": email,
                "email_verified": true,
                "name": "Ada Lovelace"
            })
            .to_string(),
        );
    }
}

impl HttpClient for MockHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpClientError> {
        let url = request.uri().to_string();
        let (status, body) = self
            .routes
            .lock()
            .unwrap()
            .get(&url)
            .cloned()
            .unwrap_or((404, Bytes::from_static(br#"{"message":"Not Found"}"#)));
        let mut response = Response::new(body);
        *response.status_mut() = http::StatusCode::from_u16(status).unwrap_or_default();
        Ok(response)
    }
}
