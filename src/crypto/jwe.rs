use crate::errors::SeppError;
use crate::types::{DataToEncrypt, EncryptedBlock};
use josekit::jwe::{JweHeader, ECDH_ES_A256KW};
use josekit::jwe::enc::A256GCM;
use josekit::jwk::Jwk;

pub struct JweEngine {
    private_key: Option<Jwk>,
    public_key: Option<Jwk>,
}

impl JweEngine {
    pub fn new() -> Self {
        Self {
            private_key: None,
            public_key: None,
        }
    }

    pub fn load_private_key(&mut self, key: Jwk) {
        self.private_key = Some(key);
    }

    pub fn load_public_key(&mut self, key: Jwk) {
        self.public_key = Some(key);
    }

    pub fn encrypt_data(&self, data: &[DataToEncrypt]) -> Result<Vec<EncryptedBlock>, SeppError> {
        let public_key = self
            .public_key
            .as_ref()
            .ok_or_else(|| SeppError::JweEncryption("Public key not loaded".to_string()))?;

        let mut encrypted_blocks = Vec::new();

        for (idx, data_to_encrypt) in data.iter().enumerate() {
            let payload = serde_json::to_vec(&data_to_encrypt.ie_value)
                .map_err(|e| SeppError::JweEncryption(format!("Failed to serialize data: {}", e)))?;

            let mut header = JweHeader::new();
            header.set_token_type("JWT");
            header.set_content_encryption(A256GCM.name());

            let encrypter = ECDH_ES_A256KW
                .encrypter_from_jwk(public_key)
                .map_err(|e| SeppError::JweEncryption(format!("Failed to create encrypter: {}", e)))?;

            let jwe_string = josekit::jwe::serialize_compact(&payload, &header, &encrypter)
                .map_err(|e| SeppError::JweEncryption(format!("Failed to encrypt: {}", e)))?;

            encrypted_blocks.push(EncryptedBlock {
                enc_block_idx: idx,
                jwe: jwe_string,
            });
        }

        Ok(encrypted_blocks)
    }

    pub fn decrypt_data(&self, encrypted_blocks: &[EncryptedBlock]) -> Result<Vec<(usize, serde_json::Value)>, SeppError> {
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| SeppError::JweDecryption("Private key not loaded".to_string()))?;

        let mut decrypted_data = Vec::new();

        for block in encrypted_blocks {
            let decrypter = ECDH_ES_A256KW
                .decrypter_from_jwk(private_key)
                .map_err(|e| SeppError::JweDecryption(format!("Failed to create decrypter: {}", e)))?;

            let (payload, _header) = josekit::jwe::deserialize_compact(&block.jwe, &decrypter)
                .map_err(|e| SeppError::JweDecryption(format!("Failed to decrypt: {}", e)))?;

            let value: serde_json::Value = serde_json::from_slice(&payload)
                .map_err(|e| SeppError::JweDecryption(format!("Failed to deserialize data: {}", e)))?;

            decrypted_data.push((block.enc_block_idx, value));
        }

        Ok(decrypted_data)
    }
}

impl Default for JweEngine {
    fn default() -> Self {
        Self::new()
    }
}
