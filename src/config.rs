use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub request_timeout_secs: u64,
    pub max_body_bytes: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:3002".parse().unwrap(),
            request_timeout_secs: 120,
            max_body_bytes: 10 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub base_url: String,
    pub domain: String,
    pub workstation: String,
    pub connect_timeout_secs: u64,
    pub accept_invalid_certs: bool,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:8080".into(),
            domain: String::new(),
            workstation: "ntlm-bridge".into(),
            connect_timeout_secs: 10,
            accept_invalid_certs: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub realm: String,
    pub digest_nonce_secret: String,
    pub digest_nonce_ttl_secs: u64,
    #[serde(default)]
    pub users: Vec<UserConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            realm: "ntlm-bridge".into(),
            digest_nonce_secret: "change-me".into(),
            digest_nonce_ttl_secs: 300,
            users: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub ntlm_username: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    pub level: String,
    pub log_requests: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            log_requests: false,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("reading config {}: {e}", path.display()))?;
        let raw = decode_text(&bytes)
            .map_err(|e| anyhow::anyhow!("decoding config {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("parsing config {}: {e}", path.display()))?;
        Ok(cfg)
    }

    pub fn load_default_locations() -> anyhow::Result<Self> {
        for path in default_config_locations() {
            if path.is_file() {
                return Self::load(&path);
            }
        }
        Ok(Self::default())
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        reqwest::Url::parse(&self.upstream.base_url)
            .map_err(|e| anyhow::anyhow!("invalid upstream.base_url: {e}"))?;
        if self.auth.realm.contains('"') {
            anyhow::bail!("auth.realm must not contain double quotes");
        }
        Ok(())
    }
}

fn default_config_locations() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("config.toml")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("config.toml"));
        }
    }
    paths
}

/// Decode bytes as text, tolerating the BOMs Windows tools tend to write:
/// UTF-8 with BOM, and UTF-16 LE/BE with BOM. Without a BOM, bytes are UTF-8.
fn decode_text(bytes: &[u8]) -> Result<String, String> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8(bytes[3..].to_vec())
            .map_err(|e| format!("file has UTF-8 BOM but body is not valid UTF-8: {e}"));
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16(&bytes[2..], u16::from_le_bytes)
            .map_err(|e| format!("file has UTF-16 LE BOM but body is invalid: {e}"));
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16(&bytes[2..], u16::from_be_bytes)
            .map_err(|e| format!("file has UTF-16 BE BOM but body is invalid: {e}"));
    }
    String::from_utf8(bytes.to_vec()).map_err(|e| format!("file is not valid UTF-8: {e}"))
}

fn decode_utf16(bytes: &[u8], to_u16: fn([u8; 2]) -> u16) -> Result<String, String> {
    if bytes.len() % 2 != 0 {
        return Err("odd byte length for UTF-16".into());
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| to_u16([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::decode_text;

    #[test]
    fn plain_utf8() {
        assert_eq!(decode_text(b"hello").unwrap(), "hello");
    }

    #[test]
    fn utf8_with_bom() {
        let mut v = vec![0xEF, 0xBB, 0xBF];
        v.extend_from_slice(b"hello");
        assert_eq!(decode_text(&v).unwrap(), "hello");
    }

    #[test]
    fn utf16_le_with_bom() {
        let v = [0xFF, 0xFE, b'h', 0x00, b'i', 0x00];
        assert_eq!(decode_text(&v).unwrap(), "hi");
    }

    #[test]
    fn utf16_be_with_bom() {
        let v = [0xFE, 0xFF, 0x00, b'h', 0x00, b'i'];
        assert_eq!(decode_text(&v).unwrap(), "hi");
    }
}
