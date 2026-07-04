use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::{header, HeaderMap, HeaderName, Method, Response, StatusCode, Uri};
use futures_util::TryStreamExt;
use reqwest::Client;
use tracing::info;

use crate::auth::authenticate;
use crate::config::{Config, UpstreamConfig};
use crate::error::{response_from_builder, BridgeError};
use crate::ntlm;

#[derive(Clone)]
pub struct ProxyClient {
    config: UpstreamConfig,
}

impl ProxyClient {
    pub fn new(config: UpstreamConfig) -> Self {
        Self { config }
    }

    pub async fn forward(
        &self,
        cfg: &Config,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<Response<Body>, BridgeError> {
        let creds = authenticate(&headers, &method, &uri, &cfg.auth, &cfg.upstream.domain)?;
        let url = target_url(&self.config.base_url, &uri)?;
        if cfg.log.log_requests {
            info!(%method, %url, "proxy request");
        }

        let client = self.client()?;
        let negotiate = ntlm::negotiate_header(&self.config.workstation, &creds.domain)?;
        let challenge = self
            .send_negotiate(&client, &method, &url, &headers, negotiate)
            .await?;
        let auth = ntlm::authenticate_header(&challenge, &creds, &self.config.workstation)?;
        let resp = self
            .send_authenticated(&client, method, &url, headers, body, auth)
            .await?;

        if cfg.log.log_requests {
            info!(status = %resp.status(), %url, "proxy response");
        }

        response_from_reqwest(resp)
    }

    fn client(&self) -> Result<Client, BridgeError> {
        Client::builder()
            .http1_only()
            .pool_max_idle_per_host(1)
            .connect_timeout(Duration::from_secs(self.config.connect_timeout_secs))
            .danger_accept_invalid_certs(self.config.accept_invalid_certs)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| BridgeError::Internal(format!("building HTTP client: {e}")))
    }

    async fn send_negotiate(
        &self,
        client: &Client,
        method: &Method,
        url: &str,
        headers: &HeaderMap,
        negotiate: String,
    ) -> Result<String, BridgeError> {
        let req_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
            .map_err(|e| BridgeError::Internal(format!("converting method: {e}")))?;
        let mut req = client
            .request(req_method, url)
            .header(header::AUTHORIZATION, negotiate);
        copy_request_headers(&mut req, headers, true);

        let resp = req
            .send()
            .await
            .map_err(|e| BridgeError::Upstream(e.to_string()))?;

        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Err(BridgeError::Upstream(format!(
                "expected NTLM challenge, got {}",
                resp.status()
            )));
        }

        let challenge = find_www_authenticate(resp.headers())
            .ok_or(BridgeError::MissingNtlmChallenge)?
            .to_string();

        // Drain the response so reqwest can return the TCP connection to this
        // request-local pool. NTLM requires the next request to reuse it.
        resp.bytes()
            .await
            .map_err(|e| BridgeError::Upstream(e.to_string()))?;

        Ok(challenge)
    }

    async fn send_authenticated(
        &self,
        client: &Client,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Bytes,
        auth: String,
    ) -> Result<reqwest::Response, BridgeError> {
        let req_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
            .map_err(|e| BridgeError::Internal(format!("converting method: {e}")))?;
        let mut req = client
            .request(req_method, url)
            .header(header::AUTHORIZATION, auth)
            .body(body);
        copy_request_headers(&mut req, &headers, false);

        let resp = req
            .send()
            .await
            .map_err(|e| BridgeError::Upstream(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(BridgeError::UpstreamAuthFailed);
        }
        Ok(resp)
    }
}

fn target_url(base_url: &str, uri: &Uri) -> Result<String, BridgeError> {
    let base = base_url.trim_end_matches('/');
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    let url = format!("{base}{path}");
    reqwest::Url::parse(&url).map_err(|e| BridgeError::BadUpstreamUrl(format!("{url}: {e}")))?;
    Ok(url)
}

fn copy_request_headers(req: &mut reqwest::RequestBuilder, headers: &HeaderMap, negotiating: bool) {
    let mut builder = std::mem::replace(req, reqwest::Client::new().get("http://127.0.0.1/"));
    for (name, value) in headers {
        if should_skip_request_header(name, negotiating) {
            continue;
        }
        builder = builder.header(name, value);
    }
    *req = builder;
}

fn should_skip_request_header(name: &HeaderName, negotiating: bool) -> bool {
    if name == header::AUTHORIZATION || name == header::HOST || name == header::CONTENT_LENGTH {
        return true;
    }
    if negotiating && (name == header::CONTENT_TYPE || name == header::EXPECT) {
        return true;
    }
    is_hop_by_hop(name)
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn find_www_authenticate(headers: &reqwest::header::HeaderMap) -> Option<&str> {
    headers
        .get_all(reqwest::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| ntlm::extract_ntlm_payload(value).is_some())
}

fn response_from_reqwest(resp: reqwest::Response) -> Result<Response<Body>, BridgeError> {
    let status = StatusCode::from_u16(resp.status().as_u16())
        .map_err(|e| BridgeError::Internal(format!("converting status: {e}")))?;
    let mut builder = Response::builder().status(status);
    for (name, value) in resp.headers() {
        if is_hop_by_hop(name) {
            continue;
        }
        builder = builder.header(name, value);
    }

    let stream = resp.bytes_stream().map_err(std::io::Error::other);
    Ok(response_from_builder(builder, Body::from_stream(stream)))
}

#[cfg(test)]
mod tests {
    use axum::http::Uri;

    use super::target_url;

    #[test]
    fn appends_path_and_query_to_base_url() {
        let uri = Uri::from_static("/one/two?q=1");
        assert_eq!(
            target_url("http://example.test/root", &uri).unwrap(),
            "http://example.test/root/one/two?q=1"
        );
    }
}
