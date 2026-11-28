//! The outgoing HTTP client OAuth uses, and the limits every call runs under.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use fastauth_core::endpoint::BoxFuture;
use http::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use http::{HeaderValue, Request, Response};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::provider::OAuthError;

/// How long one outgoing call may take, connect to last byte.
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// The largest response body accepted from a provider.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HttpClientError {
    #[error("request timed out after {}s", TIMEOUT.as_secs())]
    Timeout,
    #[error("response is larger than {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,
    #[error(transparent)]
    Transport(Box<dyn std::error::Error + Send + Sync>),
}

impl HttpClientError {
    pub fn transport(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        HttpClientError::Transport(Box::new(err))
    }
}

/// Sends one request. Implement it to reuse the client your app already has; the timeout
/// and size cap are enforced on top of any implementation.
pub trait HttpClient: Send + Sync + 'static {
    fn send(
        &self,
        request: Request<Bytes>,
    ) -> impl Future<Output = Result<Response<Bytes>, HttpClientError>> + Send;
}

pub(crate) trait DynHttpClient: Send + Sync {
    fn send(
        &self,
        request: Request<Bytes>,
    ) -> BoxFuture<'_, Result<Response<Bytes>, HttpClientError>>;
}

impl<C: HttpClient> DynHttpClient for C {
    fn send(
        &self,
        request: Request<Bytes>,
    ) -> BoxFuture<'_, Result<Response<Bytes>, HttpClientError>> {
        Box::pin(HttpClient::send(self, request))
    }
}

/// The client handed to providers: any `HttpClient`, with the timeout, the size cap and a
/// `User-Agent` (GitHub rejects requests without one).
#[derive(Clone, Copy)]
pub struct Http<'a> {
    client: &'a dyn DynHttpClient,
}

impl fmt::Debug for Http<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Http(..)")
    }
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
    error_description: Option<String>,
}

impl<'a> Http<'a> {
    pub fn new<C: HttpClient>(client: &'a C) -> Self {
        Self { client }
    }

    pub(crate) fn from_dyn(client: &'a dyn DynHttpClient) -> Self {
        Self { client }
    }

    pub async fn send(
        &self,
        mut request: Request<Bytes>,
    ) -> Result<Response<Bytes>, HttpClientError> {
        request
            .headers_mut()
            .entry(USER_AGENT)
            .or_insert(HeaderValue::from_static("fastauth"));
        let response = tokio::time::timeout(TIMEOUT, self.client.send(request))
            .await
            .map_err(|_| HttpClientError::Timeout)??;
        if response.body().len() > MAX_RESPONSE_BYTES {
            return Err(HttpClientError::TooLarge);
        }
        Ok(response)
    }

    /// Sends `request` and decodes a JSON answer. A non-2xx answer becomes
    /// `OAuthError::Provider` when it carries an OAuth `error`, `OAuthError::Status` otherwise.
    pub async fn json<T: DeserializeOwned>(
        &self,
        request: Request<Bytes>,
    ) -> Result<T, OAuthError> {
        let response = self.send(request).await?;
        let status = response.status();
        let body = response.body();
        if !status.is_success() {
            return Err(match serde_json::from_slice::<ErrorBody>(body) {
                Ok(e) => OAuthError::Provider {
                    error: e.error,
                    description: e.error_description,
                },
                Err(_) => OAuthError::Status {
                    status,
                    body: String::from_utf8_lossy(&body[..body.len().min(200)]).into_owned(),
                },
            });
        }
        serde_json::from_slice(body).map_err(|e| OAuthError::Decode(e.to_string()))
    }

    /// `GET url` with a bearer token, JSON answer.
    pub async fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        access_token: &str,
    ) -> Result<T, OAuthError> {
        let request = Request::get(url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .body(Bytes::new())
            .map_err(|e| OAuthError::Decode(e.to_string()))?;
        self.json(request).await
    }
}

/// The default `HttpClient`, on reqwest with rustls.
#[cfg(feature = "reqwest")]
#[derive(Clone, Debug)]
pub struct ReqwestClient {
    client: reqwest::Client,
}

#[cfg(feature = "reqwest")]
impl ReqwestClient {
    /// A client with the 10 s timeout and nothing else configured.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .expect("the TLS backend initialises");
        Self::from_client(client)
    }

    /// Wraps a client you already have. OAuth calls still get the timeout and size cap.
    pub fn from_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[cfg(feature = "reqwest")]
impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "reqwest")]
impl HttpClient for ReqwestClient {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpClientError> {
        let request = reqwest::Request::try_from(request).map_err(HttpClientError::transport)?;
        let mut response = self
            .client
            .execute(request)
            .await
            .map_err(HttpClientError::transport)?;
        if response
            .content_length()
            .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
        {
            return Err(HttpClientError::TooLarge);
        }
        let status = response.status();
        let headers = std::mem::take(response.headers_mut());
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(HttpClientError::transport)? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(HttpClientError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        let mut out = Response::new(Bytes::from(body));
        *out.status_mut() = status;
        *out.headers_mut() = headers;
        Ok(out)
    }
}
