use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{header, HeaderMap, Method, Uri};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::{AuthConfig, UserConfig};
use crate::error::BridgeError;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmCredentials {
    pub username: String,
    pub password: String,
    pub domain: String,
}

pub fn authenticate(
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    auth: &AuthConfig,
    default_domain: &str,
) -> Result<NtlmCredentials, BridgeError> {
    let challenges = challenge_headers(auth);
    let Some(header) = headers.get(header::AUTHORIZATION) else {
        return Err(BridgeError::Unauthorized {
            message: "missing Authorization header".into(),
            challenges,
        });
    };
    let header = header.to_str().map_err(|_| BridgeError::Unauthorized {
        message: "invalid Authorization header: non-ascii header".into(),
        challenges: challenge_headers(auth),
    })?;

    if let Some(value) = strip_ascii_prefix(header, "Basic ") {
        return authenticate_basic(value, default_domain).map_err(|message| {
            BridgeError::Unauthorized {
                message,
                challenges: challenge_headers(auth),
            }
        });
    }

    if let Some(value) = strip_ascii_prefix(header, "Digest ") {
        return authenticate_digest(value, method, uri, auth, default_domain).map_err(|message| {
            BridgeError::Unauthorized {
                message,
                challenges: challenge_headers(auth),
            }
        });
    }

    Err(BridgeError::Unauthorized {
        message: "invalid Authorization header: expected Basic or Digest scheme".into(),
        challenges,
    })
}

pub fn challenge_headers(auth: &AuthConfig) -> Vec<String> {
    let escaped_realm = auth.realm.replace('\\', "\\\\").replace('"', "\\\"");
    let mut values = vec![format!("Basic realm=\"{escaped_realm}\"")];
    if !auth.users.is_empty() {
        values.push(format!(
            "Digest realm=\"{escaped_realm}\", nonce=\"{}\", algorithm=MD5, qop=\"auth\"",
            make_nonce(auth)
        ));
    }
    values
}

fn authenticate_basic(value: &str, default_domain: &str) -> Result<NtlmCredentials, String> {
    let raw = STANDARD
        .decode(value.trim())
        .map_err(|_| "invalid Authorization header: invalid base64".to_string())?;
    let decoded = String::from_utf8(raw)
        .map_err(|_| "invalid Authorization header: invalid utf-8".to_string())?;
    let (user, password) = decoded
        .split_once(':')
        .ok_or_else(|| "invalid Authorization header: missing colon".to_string())?;
    if user.is_empty() {
        return Err("invalid Authorization header: empty user".into());
    }
    let (domain, username) = split_ntlm_user(user, default_domain);
    Ok(NtlmCredentials {
        username,
        password: password.to_string(),
        domain,
    })
}

fn authenticate_digest(
    value: &str,
    method: &Method,
    uri: &Uri,
    auth: &AuthConfig,
    default_domain: &str,
) -> Result<NtlmCredentials, String> {
    if auth.users.is_empty() {
        return Err("Digest authentication is not configured".into());
    }

    let fields = parse_digest_fields(value)?;
    let username = required_field(&fields, "username")?;
    let realm = required_field(&fields, "realm")?;
    let nonce = required_field(&fields, "nonce")?;
    let digest_uri = required_field(&fields, "uri")?;
    let response = required_field(&fields, "response")?;
    let qop = fields.get("qop").map(String::as_str).unwrap_or("");
    let nc = fields.get("nc").map(String::as_str).unwrap_or("");
    let cnonce = fields.get("cnonce").map(String::as_str).unwrap_or("");

    if realm != auth.realm {
        return Err("invalid Digest realm".into());
    }
    verify_nonce(&nonce, auth)?;

    let expected_uri = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    if digest_uri != expected_uri {
        return Err("Digest uri does not match request target".into());
    }

    let user = auth
        .users
        .iter()
        .find(|u| u.username == username)
        .ok_or_else(|| "unknown Digest user".to_string())?;

    if qop != "auth" && !qop.is_empty() {
        return Err("unsupported Digest qop".into());
    }

    let ha1 = md5_hex(format!(
        "{}:{}:{}",
        user.username, auth.realm, user.password
    ));
    let ha2 = md5_hex(format!("{}:{}", method.as_str(), digest_uri));
    let expected = if qop == "auth" {
        if nc.is_empty() || cnonce.is_empty() {
            return Err("Digest qop requires nc and cnonce".into());
        }
        md5_hex(format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}"))
    } else {
        md5_hex(format!("{ha1}:{nonce}:{ha2}"))
    };

    if expected.as_bytes().ct_eq(response.as_bytes()).unwrap_u8() != 1 {
        return Err("invalid Digest response".into());
    }

    Ok(credentials_from_user(user, default_domain))
}

fn credentials_from_user(user: &UserConfig, default_domain: &str) -> NtlmCredentials {
    let ntlm_user = user.ntlm_username.as_deref().unwrap_or(&user.username);
    let (domain, username) = match &user.domain {
        Some(domain) => (domain.clone(), ntlm_user.to_string()),
        None => split_ntlm_user(ntlm_user, default_domain),
    };
    NtlmCredentials {
        username,
        password: user.password.clone(),
        domain,
    }
}

fn split_ntlm_user(user: &str, default_domain: &str) -> (String, String) {
    if let Some((domain, username)) = user.split_once('\\') {
        return (domain.to_string(), username.to_string());
    }
    (default_domain.to_string(), user.to_string())
}

fn strip_ascii_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|s| s.eq_ignore_ascii_case(prefix))
        .map(|_| &value[prefix.len()..])
}

fn required_field(fields: &HashMap<String, String>, name: &str) -> Result<String, String> {
    fields
        .get(name)
        .cloned()
        .ok_or_else(|| format!("Digest field missing: {name}"))
}

fn parse_digest_fields(input: &str) -> Result<HashMap<String, String>, String> {
    let mut fields = HashMap::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] == b',' || bytes[i].is_ascii_whitespace()) {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' {
            i += 1;
        }
        if i >= bytes.len() {
            return Err("invalid Digest field".into());
        }
        let key = input[key_start..i].trim().to_ascii_lowercase();
        i += 1;

        let value = if i < bytes.len() && bytes[i] == b'"' {
            i += 1;
            let mut value = String::new();
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' if i + 1 < bytes.len() => {
                        value.push(bytes[i + 1] as char);
                        i += 2;
                    }
                    b'"' => {
                        i += 1;
                        break;
                    }
                    b => {
                        value.push(b as char);
                        i += 1;
                    }
                }
            }
            value
        } else {
            let start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            input[start..i].trim().to_string()
        };

        fields.insert(key, value);
    }

    Ok(fields)
}

fn make_nonce(auth: &AuthConfig) -> String {
    let now = unix_time_secs();
    let mut mac = HmacSha256::new_from_slice(auth.digest_nonce_secret.as_bytes())
        .expect("HMAC accepts keys of any size");
    mac.update(&now.to_be_bytes());
    mac.update(auth.realm.as_bytes());
    let digest = mac.finalize().into_bytes();

    let mut raw = Vec::with_capacity(24);
    raw.extend_from_slice(&now.to_be_bytes());
    raw.extend_from_slice(&digest[..16]);
    URL_SAFE_NO_PAD.encode(raw)
}

fn verify_nonce(nonce: &str, auth: &AuthConfig) -> Result<(), String> {
    let raw = URL_SAFE_NO_PAD
        .decode(nonce)
        .map_err(|_| "invalid Digest nonce".to_string())?;
    if raw.len() != 24 {
        return Err("invalid Digest nonce".into());
    }

    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&raw[..8]);
    let ts = u64::from_be_bytes(ts_bytes);
    let now = unix_time_secs();
    if ts > now || now.saturating_sub(ts) > auth.digest_nonce_ttl_secs {
        return Err("stale Digest nonce".into());
    }

    let mut mac = HmacSha256::new_from_slice(auth.digest_nonce_secret.as_bytes())
        .expect("HMAC accepts keys of any size");
    mac.update(&ts.to_be_bytes());
    mac.update(auth.realm.as_bytes());
    let digest = mac.finalize().into_bytes();
    if digest[..16].ct_eq(&raw[8..]).unwrap_u8() != 1 {
        return Err("invalid Digest nonce".into());
    }

    Ok(())
}

fn md5_hex(input: String) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn basic_parses_domain_user() {
        let value = STANDARD.encode(r"EXAMPLE\alice:secret");
        let creds = authenticate_basic(&value, "").unwrap();
        assert_eq!(
            creds,
            NtlmCredentials {
                username: "alice".into(),
                password: "secret".into(),
                domain: "EXAMPLE".into(),
            }
        );
    }

    #[test]
    fn digest_round_trip() {
        let auth = AuthConfig {
            users: vec![UserConfig {
                username: "alice".into(),
                password: "secret".into(),
                domain: Some("EXAMPLE".into()),
                ntlm_username: None,
            }],
            ..AuthConfig::default()
        };
        let nonce = make_nonce(&auth);
        let uri = "/docs";
        let method = Method::GET;
        let ha1 = md5_hex("alice:ntlm-bridge:secret".into());
        let ha2 = md5_hex("GET:/docs".into());
        let response = md5_hex(format!("{ha1}:{nonce}:00000001:abc:auth:{ha2}"));
        let header = format!(
            r#"Digest username="alice", realm="ntlm-bridge", nonce="{nonce}", uri="{uri}", qop=auth, nc=00000001, cnonce="abc", response="{response}""#
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&header).unwrap(),
        );
        let creds = authenticate(&headers, &method, &Uri::from_static(uri), &auth, "").unwrap();
        assert_eq!(creds.username, "alice");
        assert_eq!(creds.password, "secret");
        assert_eq!(creds.domain, "EXAMPLE");
    }
}
