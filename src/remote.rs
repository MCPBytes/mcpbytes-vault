use crate::{
    config,
    protocol::{WireEnvelope, WireRequest},
};
use std::{future::Future, pin::Pin, time::Duration};
use zeroize::Zeroizing;

pub const DEADLINE: Duration = Duration::from_secs(90);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Timeout,
    Unavailable,
    Authentication,
    InvalidResponse,
    Transport,
    Configuration,
}
impl Error {
    pub fn allows_fallback(self) -> bool {
        matches!(self, Self::Timeout | Self::Unavailable)
    }
    pub fn code(self) -> &'static str {
        match self {
            Self::Timeout => "remote_timeout",
            Self::Unavailable => "remote_unavailable",
            Self::Authentication => "remote_authentication_failed",
            Self::InvalidResponse => "invalid_remote_response",
            Self::Transport => "remote_transport_failed",
            Self::Configuration => "remote_configuration_error",
        }
    }
}
pub trait Client: Send + Sync {
    fn fetch<'a>(
        &'a self,
        request: &'a WireRequest,
    ) -> Pin<Box<dyn Future<Output = Result<WireEnvelope, Error>> + Send + 'a>>;
}
pub struct HttpsClient {
    client: reqwest::Client,
    url: String,
    key_env: String,
}
impl HttpsClient {
    pub fn new(remote: &config::Remote) -> Result<Self, Error> {
        config::validate_remote_url(&remote.url).map_err(|_| Error::Configuration)?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(15))
            .user_agent(concat!("mcpbytes-vault/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            client,
            url: remote.url.clone(),
            key_env: remote.api_key_env.clone(),
        })
    }
    async fn attempt(&self, request: &WireRequest) -> Result<WireEnvelope, Error> {
        let key = Zeroizing::new(std::env::var(&self.key_env).map_err(|_| Error::Configuration)?);
        if key.len() != 48
            || !key.starts_with("mcpb_")
            || !key[5..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(Error::Configuration);
        }
        let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", key.as_str()))
            .map_err(|_| Error::Configuration)?;
        value.set_sensitive(true);
        let mut response = self
            .client
            .post(&self.url)
            .header(reqwest::header::AUTHORIZATION, value)
            .header(reqwest::header::CACHE_CONTROL, "no-store")
            .json(request)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    Error::Timeout
                } else {
                    Error::Transport
                }
            })?;
        match response.status().as_u16() {
            200 => (),
            408 | 429 | 502 | 503 | 504 => return Err(Error::Unavailable),
            401 | 403 => return Err(Error::Authentication),
            _ => return Err(Error::InvalidResponse),
        }
        if response.content_length().is_some_and(|n| n > 4096)
            || !response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| s.split(';').next() == Some("application/json"))
        {
            return Err(Error::InvalidResponse);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| {
            if e.is_timeout() {
                Error::Timeout
            } else {
                Error::Transport
            }
        })? {
            if body.len() + chunk.len() > 4096 {
                return Err(Error::InvalidResponse);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| Error::InvalidResponse)
    }
}
impl Client for HttpsClient {
    fn fetch<'a>(
        &'a self,
        request: &'a WireRequest,
    ) -> Pin<Box<dyn Future<Output = Result<WireEnvelope, Error>> + Send + 'a>> {
        Box::pin(async move {
            // The same recipient and request identity are retained for every attempt.
            // The outer helper deadline covers all attempts together, including their bodies.
            for attempt in 0..3 {
                match self.attempt(request).await {
                    Err(error) if error.allows_fallback() && attempt < 2 => {
                        tokio::time::sleep(Duration::from_millis(200)).await
                    }
                    result => return result,
                }
            }
            Err(Error::Timeout)
        })
    }
}
