//! Cookie parsing and Set-Cookie building.

use http::HeaderMap;
use http::header::COOKIE;
use time::Duration;

use crate::config::{CoreConfig, SameSite};

/// Finds a cookie by name in the `Cookie` headers.
pub fn read<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim_matches('"'))
}

pub fn has_any(headers: &HeaderMap) -> bool {
    headers.contains_key(COOKIE)
}

/// A cookie to set or clear on the response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetCookie {
    pub name: String,
    pub value: String,
    /// `None`: a browser-session cookie. `Some(0)`: delete.
    pub max_age: Option<Duration>,
    pub http_only: bool,
}

impl SetCookie {
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
        max_age: Option<Duration>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            max_age,
            http_only: true,
        }
    }

    pub fn delete(name: impl Into<String>) -> Self {
        Self::new(name, "", Some(Duration::ZERO))
    }

    pub fn to_header(&self, config: &CoreConfig) -> String {
        let mut out = format!("{}={}; Path=/", self.name, self.value);
        if let Some(max_age) = self.max_age {
            out.push_str(&format!("; Max-Age={}", max_age.whole_seconds().max(0)));
        }
        if let Some(domain) = &config.cookies.domain {
            out.push_str(&format!("; Domain={domain}"));
        }
        if self.http_only {
            out.push_str("; HttpOnly");
        }
        if config.secure_cookies {
            out.push_str("; Secure");
        }
        out.push_str(match config.cookies.same_site {
            SameSite::Strict => "; SameSite=Strict",
            SameSite::Lax => "; SameSite=Lax",
            SameSite::None => "; SameSite=None",
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn reads_cookie_among_others() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_static("a=1; fastauth.session_token=tok.sig; b=2"),
        );
        assert_eq!(read(&headers, "fastauth.session_token"), Some("tok.sig"));
        assert_eq!(read(&headers, "missing"), None);
    }
}
