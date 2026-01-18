use crate::errors::SeppError;
use crate::types::{AccessToken, Header};
use base64::{engine::general_purpose::STANDARD, Engine};

pub struct AuthValidator;

impl AuthValidator {
    pub fn extract_access_token(headers: &[Header]) -> Result<AccessToken, SeppError> {
        let auth_header = headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("authorization"))
            .ok_or_else(|| SeppError::InvalidAccessToken("Missing Authorization header".to_string()))?;

        let token_str = auth_header
            .value
            .strip_prefix("Bearer ")
            .ok_or_else(|| SeppError::InvalidAccessToken("Invalid Authorization header format".to_string()))?;

        Self::parse_jwt(token_str)
    }

    fn parse_jwt(token: &str) -> Result<AccessToken, SeppError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(SeppError::InvalidAccessToken(
                "Invalid JWT format: expected 3 parts".to_string(),
            ));
        }

        let payload_b64 = parts[1];
        let payload_bytes = STANDARD
            .decode(payload_b64)
            .map_err(|e| SeppError::InvalidAccessToken(format!("Failed to decode JWT payload: {}", e)))?;

        let access_token: AccessToken = serde_json::from_slice(&payload_bytes)
            .map_err(|e| SeppError::InvalidAccessToken(format!("Failed to parse JWT payload: {}", e)))?;

        Ok(access_token)
    }

    pub fn extract_plmn_id_from_token(token: &AccessToken) -> Result<String, SeppError> {
        token
            .plmn_id
            .clone()
            .ok_or_else(|| SeppError::InvalidAccessToken("Missing PLMN-ID in access token".to_string()))
    }
}
