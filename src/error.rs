use axum::body::Body;
use axum::http::{header, response, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("{message}")]
    Unauthorized {
        message: String,
        challenges: Vec<String>,
    },

    #[error("invalid upstream URL: {0}")]
    BadUpstreamUrl(String),

    #[error("upstream authentication failed")]
    UpstreamAuthFailed,

    #[error("upstream returned no NTLM challenge")]
    MissingNtlmChallenge,

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error("NTLM error: {0}")]
    Ntlm(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for BridgeError {
    fn into_response(self) -> Response {
        let (status, kind) = match &self {
            BridgeError::Unauthorized { .. } | BridgeError::UpstreamAuthFailed => {
                (StatusCode::UNAUTHORIZED, "unauthorized")
            }
            BridgeError::BadUpstreamUrl(_) => (StatusCode::BAD_GATEWAY, "bad_gateway"),
            BridgeError::MissingNtlmChallenge => (StatusCode::BAD_GATEWAY, "bad_gateway"),
            BridgeError::Upstream(_) => (StatusCode::BAD_GATEWAY, "bad_gateway"),
            BridgeError::Ntlm(_) => (StatusCode::BAD_GATEWAY, "bad_gateway"),
            BridgeError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };

        let challenges = match &self {
            BridgeError::Unauthorized { challenges, .. } => Some(challenges.clone()),
            BridgeError::UpstreamAuthFailed => {
                Some(vec!["Basic realm=\"ntlm-bridge\"".to_string()])
            }
            _ => None,
        };

        let body = Json(json!({
            "error": kind,
            "message": self.to_string(),
        }));

        let mut resp = (status, body).into_response();
        if let Some(values) = challenges {
            for value in values {
                if let Ok(value) = HeaderValue::from_str(&value) {
                    resp.headers_mut().append(header::WWW_AUTHENTICATE, value);
                }
            }
        }
        resp
    }
}

pub fn response_from_builder(builder: response::Builder, body: Body) -> Response {
    builder.body(body).unwrap_or_else(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "internal",
                "message": format!("building response: {e}"),
            })),
        )
            .into_response()
    })
}
