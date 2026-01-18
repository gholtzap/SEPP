use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SeppError {
    #[error("N32-c error: {0}")]
    N32c(String),

    #[error("N32-f error: {0}")]
    N32f(String),

    #[error("Certificate validation failed: {0}")]
    CertificateValidation(String),

    #[error("JWE encryption failed: {0}")]
    JweEncryption(String),

    #[error("JWE decryption failed: {0}")]
    JweDecryption(String),

    #[error("JWS signature failed: {0}")]
    JwsSignature(String),

    #[error("JWS verification failed: {0}")]
    JwsVerification(String),

    #[error("Policy mismatch: {0}")]
    PolicyMismatch(String),

    #[error("PLMN-ID mismatch: expected {expected}, got {got}")]
    PlmnIdMismatch { expected: String, got: String },

    #[error("Encrypted IE misplacement detected: {0}")]
    EncryptedIeMisplacement(String),

    #[error("IPX modification policy violation: {0}")]
    IpxModificationViolation(String),

    #[error("Cryptographic material separation violation: {0}")]
    CryptographicMaterialSeparation(String),

    #[error("Connection-specific scope violation: {0}")]
    ConnectionScopeViolation(String),

    #[error("Routing error: {0}")]
    Routing(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Database error: {0}")]
    Database(#[from] mongodb::error::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    #[error("Invalid access token: {0}")]
    InvalidAccessToken(String),

    #[error("Invalid telescopic FQDN: {0}")]
    InvalidTelescopicFqdn(String),

    #[error("Trust anchor not found for PLMN-ID: {0}")]
    TrustAnchorNotFound(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
}

impl IntoResponse for SeppError {
    fn into_response(self) -> Response {
        let (status, problem_type, title) = match &self {
            SeppError::N32c(_) => (
                StatusCode::BAD_REQUEST,
                "N32C_ERROR",
                "N32-c Error",
            ),
            SeppError::N32f(_) => (
                StatusCode::BAD_REQUEST,
                "N32F_ERROR",
                "N32-f Error",
            ),
            SeppError::CertificateValidation(_) => (
                StatusCode::UNAUTHORIZED,
                "CERTIFICATE_VALIDATION_FAILED",
                "Certificate Validation Failed",
            ),
            SeppError::JweEncryption(_) | SeppError::JweDecryption(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "JWE_ERROR",
                "JWE Cryptographic Error",
            ),
            SeppError::JwsSignature(_) | SeppError::JwsVerification(_) => (
                StatusCode::UNAUTHORIZED,
                "JWS_ERROR",
                "JWS Signature Error",
            ),
            SeppError::PolicyMismatch(_) => (
                StatusCode::BAD_REQUEST,
                "POLICY_MISMATCH",
                "Protection Policy Mismatch",
            ),
            SeppError::PlmnIdMismatch { .. } => (
                StatusCode::FORBIDDEN,
                "PLMN_ID_MISMATCH",
                "PLMN-ID Mismatch",
            ),
            SeppError::EncryptedIeMisplacement(_) => (
                StatusCode::BAD_REQUEST,
                "ENCRYPTED_IE_MISPLACEMENT",
                "Encrypted IE Misplacement",
            ),
            SeppError::IpxModificationViolation(_) => (
                StatusCode::BAD_REQUEST,
                "IPX_MODIFICATION_VIOLATION",
                "IPX Modification Policy Violation",
            ),
            SeppError::CryptographicMaterialSeparation(_) => (
                StatusCode::FORBIDDEN,
                "CRYPTOGRAPHIC_MATERIAL_SEPARATION",
                "Cryptographic Material Separation Violation",
            ),
            SeppError::ConnectionScopeViolation(_) => (
                StatusCode::FORBIDDEN,
                "CONNECTION_SCOPE_VIOLATION",
                "Connection-Specific Scope Violation",
            ),
            SeppError::Routing(_) => (
                StatusCode::BAD_REQUEST,
                "ROUTING_ERROR",
                "Routing Error",
            ),
            SeppError::Configuration(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "CONFIGURATION_ERROR",
                "Configuration Error",
            ),
            SeppError::Database(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Database Error",
            ),
            SeppError::Serialization(_) => (
                StatusCode::BAD_REQUEST,
                "SERIALIZATION_ERROR",
                "Serialization Error",
            ),
            SeppError::HttpClient(_) => (
                StatusCode::BAD_GATEWAY,
                "HTTP_CLIENT_ERROR",
                "HTTP Client Error",
            ),
            SeppError::InvalidAccessToken(_) => (
                StatusCode::UNAUTHORIZED,
                "INVALID_ACCESS_TOKEN",
                "Invalid Access Token",
            ),
            SeppError::InvalidTelescopicFqdn(_) => (
                StatusCode::BAD_REQUEST,
                "INVALID_TELESCOPIC_FQDN",
                "Invalid Telescopic FQDN",
            ),
            SeppError::TrustAnchorNotFound(_) => (
                StatusCode::NOT_FOUND,
                "TRUST_ANCHOR_NOT_FOUND",
                "Trust Anchor Not Found",
            ),
            SeppError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Internal Server Error",
            ),
        };

        let problem_details = ProblemDetails {
            problem_type: format!("urn:3gpp:sepp:{}", problem_type),
            title: title.to_string(),
            status: status.as_u16(),
            detail: self.to_string(),
            instance: None,
            cause: None,
        };

        (status, Json(problem_details)).into_response()
    }
}
