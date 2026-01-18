use crate::crypto::JwsEngine;
use crate::errors::SeppError;
use crate::types::{AccessToken, Header};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use std::sync::Arc;

pub struct AuthValidator {
    jws_engine: Arc<JwsEngine>,
    token_issuer: String,
    expected_audience: String,
}

impl AuthValidator {
    pub fn new(jws_engine: Arc<JwsEngine>, token_issuer: String, expected_audience: String) -> Self {
        Self {
            jws_engine,
            token_issuer,
            expected_audience,
        }
    }

    pub fn extract_and_validate_token(&self, headers: &[Header]) -> Result<AccessToken, SeppError> {
        let auth_header = headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("authorization"))
            .ok_or_else(|| SeppError::InvalidAccessToken("Missing Authorization header".to_string()))?;

        let token_str = auth_header
            .value
            .strip_prefix("Bearer ")
            .ok_or_else(|| SeppError::InvalidAccessToken("Invalid Authorization header format".to_string()))?;

        self.validate_token(token_str)
    }

    pub fn validate_token(&self, token_str: &str) -> Result<AccessToken, SeppError> {
        self.verify_signature(token_str)?;

        let access_token = Self::parse_jwt(token_str)?;

        self.check_expiry(&access_token)?;
        self.validate_issuer(&access_token)?;
        self.validate_audience(&access_token)?;
        self.validate_subject(&access_token)?;

        Ok(access_token)
    }

    fn verify_signature(&self, token: &str) -> Result<(), SeppError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(SeppError::InvalidAccessToken("Invalid JWT format".to_string()));
        }

        let header_b64 = parts[0];
        let header_bytes = STANDARD
            .decode(header_b64)
            .map_err(|e| SeppError::InvalidAccessToken(format!("Failed to decode JWT header: {}", e)))?;

        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| SeppError::InvalidAccessToken(format!("Failed to parse JWT header: {}", e)))?;

        let kid = header
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SeppError::InvalidAccessToken("Missing 'kid' in JWT header".to_string()))?;

        let alg = header
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SeppError::InvalidAccessToken("Missing 'alg' in JWT header".to_string()))?;

        if alg != "ES256" {
            return Err(SeppError::InvalidAccessToken(format!(
                "Unsupported signature algorithm: {}. Only ES256 is supported.",
                alg
            )));
        }

        self.jws_engine
            .verify(token, kid)
            .map_err(|e| SeppError::InvalidAccessToken(format!("Token signature verification failed: {}", e)))?;

        Ok(())
    }

    fn check_expiry(&self, token: &AccessToken) -> Result<(), SeppError> {
        let now = Utc::now().timestamp();

        if token.exp <= now {
            return Err(SeppError::InvalidAccessToken(format!(
                "Token has expired. Expiry: {}, Current time: {}",
                token.exp, now
            )));
        }

        Ok(())
    }

    fn validate_issuer(&self, token: &AccessToken) -> Result<(), SeppError> {
        if token.iss != self.token_issuer {
            return Err(SeppError::InvalidAccessToken(format!(
                "Invalid token issuer. Expected: {}, Got: {}",
                self.token_issuer, token.iss
            )));
        }

        Ok(())
    }

    fn validate_audience(&self, token: &AccessToken) -> Result<(), SeppError> {
        if token.aud != self.expected_audience {
            return Err(SeppError::InvalidAccessToken(format!(
                "Invalid token audience. Expected: {}, Got: {}",
                self.expected_audience, token.aud
            )));
        }

        Ok(())
    }

    fn validate_subject(&self, token: &AccessToken) -> Result<(), SeppError> {
        if token.sub.is_empty() {
            return Err(SeppError::InvalidAccessToken("Token subject claim is empty".to_string()));
        }

        Ok(())
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
