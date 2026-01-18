use crate::errors::SeppError;
use base64::Engine;
use josekit::jws::{JwsHeader, ES256};
use josekit::jwk::Jwk;

#[derive(Clone)]
pub struct JwsEngine {
    private_key: Option<Jwk>,
    public_keys: Vec<(String, Jwk)>,
}

impl JwsEngine {
    pub fn new() -> Self {
        Self {
            private_key: None,
            public_keys: Vec::new(),
        }
    }

    pub fn load_private_key(&mut self, key: Jwk) {
        self.private_key = Some(key);
    }

    pub fn add_public_key(&mut self, key_id: String, key: Jwk) {
        self.public_keys.push((key_id, key));
    }

    pub fn sign(&self, payload: &[u8]) -> Result<String, SeppError> {
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| SeppError::JwsSignature("Private key not loaded".to_string()))?;

        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_algorithm(ES256.name());

        let signer = ES256
            .signer_from_jwk(private_key)
            .map_err(|e| SeppError::JwsSignature(format!("Failed to create signer: {}", e)))?;

        let jws_string = josekit::jws::serialize_compact(payload, &header, &signer)
            .map_err(|e| SeppError::JwsSignature(format!("Failed to sign: {}", e)))?;

        Ok(jws_string)
    }

    pub fn verify(&self, jws: &str, key_id: &str) -> Result<Vec<u8>, SeppError> {
        let (_, public_key) = self
            .public_keys
            .iter()
            .find(|(id, _)| id == key_id)
            .ok_or_else(|| SeppError::JwsVerification(format!("Public key {} not found", key_id)))?;

        let verifier = ES256
            .verifier_from_jwk(public_key)
            .map_err(|e| SeppError::JwsVerification(format!("Failed to create verifier: {}", e)))?;

        let (payload, _header) = josekit::jws::deserialize_compact(jws, &verifier)
            .map_err(|e| SeppError::JwsVerification(format!("Failed to verify signature: {}", e)))?;

        Ok(payload)
    }

    pub fn verify_algorithm_restriction(&self, jws: &str) -> Result<(), SeppError> {
        let parts: Vec<&str> = jws.split('.').collect();
        if parts.len() != 3 {
            return Err(SeppError::JwsVerification("Invalid JWS format".to_string()));
        }

        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| SeppError::JwsVerification(format!("Failed to decode header: {}", e)))?;

        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| SeppError::JwsVerification(format!("Failed to parse header: {}", e)))?;

        let alg = header
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SeppError::JwsVerification("Algorithm not specified in header".to_string()))?;

        if alg != "ES256" {
            return Err(SeppError::JwsVerification(format!(
                "Algorithm {} is not allowed. Only ES256 is permitted for IPX signatures",
                alg
            )));
        }

        Ok(())
    }
}

impl Default for JwsEngine {
    fn default() -> Self {
        Self::new()
    }
}
