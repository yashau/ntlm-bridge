use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::auth::NtlmCredentials;
use crate::error::BridgeError;

pub fn negotiate_header(workstation: &str, domain: &str) -> Result<String, BridgeError> {
    let mut flags = ntlmclient::Flags::NEGOTIATE_UNICODE
        | ntlmclient::Flags::REQUEST_TARGET
        | ntlmclient::Flags::NEGOTIATE_NTLM
        | ntlmclient::Flags::NEGOTIATE_WORKSTATION_SUPPLIED
        | ntlmclient::Flags::NEGOTIATE_NTLM2_KEY;
    if !domain.is_empty() {
        flags |= ntlmclient::Flags::NEGOTIATE_DOMAIN_SUPPLIED;
    }

    let msg = ntlmclient::Message::Negotiate(ntlmclient::NegotiateMessage {
        flags,
        supplied_domain: domain.to_string(),
        supplied_workstation: workstation.to_string(),
        os_version: Default::default(),
    });
    let bytes = msg
        .to_bytes()
        .map_err(|e| BridgeError::Ntlm(format!("encoding negotiate message: {e}")))?;
    Ok(format!("NTLM {}", STANDARD.encode(bytes)))
}

pub fn authenticate_header(
    challenge_header: &str,
    creds: &NtlmCredentials,
    workstation: &str,
) -> Result<String, BridgeError> {
    let challenge_b64 =
        extract_ntlm_payload(challenge_header).ok_or(BridgeError::MissingNtlmChallenge)?;
    let challenge_bytes = STANDARD
        .decode(challenge_b64)
        .map_err(|e| BridgeError::Ntlm(format!("decoding NTLM challenge: {e}")))?;
    let challenge = ntlmclient::Message::try_from(challenge_bytes.as_slice())
        .map_err(|e| BridgeError::Ntlm(format!("parsing NTLM challenge: {e}")))?;
    let challenge = match challenge {
        ntlmclient::Message::Challenge(c) => c,
        other => {
            return Err(BridgeError::Ntlm(format!(
                "expected challenge message, got {:?}",
                other.message_number()
            )))
        }
    };

    let target_info: Vec<u8> = challenge
        .target_information
        .iter()
        .flat_map(|entry| entry.to_bytes())
        .collect();
    let ntlm_creds = ntlmclient::Credentials {
        username: creds.username.clone(),
        password: creds.password.clone(),
        domain: creds.domain.clone(),
    };

    let challenge_response = ntlmclient::respond_challenge_ntlm_v2(
        challenge.challenge,
        &target_info,
        ntlmclient::get_ntlm_time(),
        &ntlm_creds,
    );

    let flags = ntlmclient::Flags::NEGOTIATE_UNICODE
        | ntlmclient::Flags::NEGOTIATE_NTLM
        | ntlmclient::Flags::NEGOTIATE_NTLM2_KEY;
    let msg = challenge_response.to_message(&ntlm_creds, workstation, flags);
    let bytes = msg
        .to_bytes()
        .map_err(|e| BridgeError::Ntlm(format!("encoding authenticate message: {e}")))?;
    Ok(format!("NTLM {}", STANDARD.encode(bytes)))
}

pub fn extract_ntlm_payload(header: &str) -> Option<&str> {
    header
        .split(',')
        .map(str::trim)
        .find_map(|part| {
            let prefix = part.get(..5)?;
            if prefix.eq_ignore_ascii_case("NTLM ") {
                Some(part[5..].trim())
            } else {
                None
            }
        })
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::extract_ntlm_payload;

    #[test]
    fn extracts_ntlm_payload_from_combined_header() {
        assert_eq!(
            extract_ntlm_payload("Negotiate, NTLM TlRMTVNTUAACAAA="),
            Some("TlRMTVNTUAACAAA=")
        );
    }
}
