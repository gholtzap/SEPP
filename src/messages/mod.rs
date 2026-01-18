use crate::crypto::{JweEngine, JwsEngine};
use crate::errors::SeppError;
use crate::policies::PolicyEngine;
use crate::types::{DataToEncrypt, MessageDirection, ProcessedMessage, SbiMessage};
use serde_json::Value;

pub struct MessageProcessor {
    jwe_engine: JweEngine,
    jws_engine: JwsEngine,
    policy_engine: PolicyEngine,
}

impl MessageProcessor {
    pub fn new(jwe_engine: JweEngine, jws_engine: JwsEngine, policy_engine: PolicyEngine) -> Self {
        Self {
            jwe_engine,
            jws_engine,
            policy_engine,
        }
    }

    pub async fn process_outbound_message(&self, message: SbiMessage) -> Result<ProcessedMessage, SeppError> {
        let mut protected_message = message.clone();
        let mut data_to_encrypt = Vec::new();

        if let Some(body) = &message.body {
            for api_ie_mapping in &self.policy_engine.get_encryption_policy().api_ie_mappings {
                for ie in &api_ie_mapping.ie_list {
                    if ie.encryption_required {
                        if let Some(value) = body.pointer(&ie.json_path.replace('.', "/")) {
                            data_to_encrypt.push(DataToEncrypt {
                                ie_location: ie.json_path.clone(),
                                ie_value: value.clone(),
                            });
                        }
                    }
                }
            }
        }

        let encrypted_blocks = if !data_to_encrypt.is_empty() {
            self.jwe_engine.encrypt_data(&data_to_encrypt)?
        } else {
            vec![]
        };

        if let Some(body) = &mut protected_message.body {
            for (idx, data) in data_to_encrypt.iter().enumerate() {
                let pointer = data.ie_location.replace('.', "/");
                self.replace_with_enc_block_idx(body, &pointer, idx)?;
            }
        }

        let payload = serde_json::to_vec(&protected_message)?;
        let signature = self.jws_engine.sign(&payload)?;

        Ok(ProcessedMessage {
            original: message,
            protected: Some(crate::types::ProtectedMessageData {
                encrypted_blocks: encrypted_blocks.iter().map(|b| (b.enc_block_idx, b.jwe.as_bytes().to_vec())).collect(),
                signature: signature.as_bytes().to_vec(),
                ipx_signatures: vec![],
            }),
            direction: MessageDirection::Outbound,
        })
    }

    pub async fn process_inbound_message(
        &self,
        message: SbiMessage,
        encrypted_blocks: Vec<crate::types::EncryptedBlock>,
        signature: &str,
    ) -> Result<ProcessedMessage, SeppError> {
        self.jws_engine.verify(signature, "peer-sepp")?;

        let decrypted_data = self.jwe_engine.decrypt_data(&encrypted_blocks)?;

        let mut restored_message = message.clone();
        if let Some(body) = &mut restored_message.body {
            for (idx, value) in decrypted_data {
                if let Some(location) = self.find_enc_block_idx_location(body, idx) {
                    self.restore_encrypted_value(body, &location, value)?;
                }
            }
        }

        Ok(ProcessedMessage {
            original: restored_message,
            protected: None,
            direction: MessageDirection::Inbound,
        })
    }

    fn replace_with_enc_block_idx(&self, body: &mut Value, pointer: &str, idx: usize) -> Result<(), SeppError> {
        let parts: Vec<&str> = pointer.split('/').filter(|s| !s.is_empty()).collect();

        if parts.is_empty() {
            return Ok(());
        }

        let mut current = body;
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                if let Some(obj) = current.as_object_mut() {
                    obj.insert(
                        part.to_string(),
                        serde_json::json!({ "encBlockIdx": idx }),
                    );
                }
                break;
            } else {
                let next = current.as_object_mut()
                    .and_then(|obj| obj.get_mut(*part))
                    .ok_or_else(|| SeppError::Internal(format!("Path {} not found", pointer)))?;
                current = next;
            }
        }

        Ok(())
    }

    fn find_enc_block_idx_location(&self, body: &Value, idx: usize) -> Option<String> {
        self.find_enc_block_idx_recursive(body, idx, "")
    }

    fn find_enc_block_idx_recursive(&self, value: &Value, idx: usize, path: &str) -> Option<String> {
        match value {
            Value::Object(obj) => {
                if let Some(enc_idx) = obj.get("encBlockIdx") {
                    if enc_idx.as_u64() == Some(idx as u64) {
                        return Some(path.to_string());
                    }
                }
                for (key, val) in obj {
                    let new_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}/{}", path, key)
                    };
                    if let Some(result) = self.find_enc_block_idx_recursive(val, idx, &new_path) {
                        return Some(result);
                    }
                }
                None
            }
            Value::Array(arr) => {
                for (i, val) in arr.iter().enumerate() {
                    let new_path = format!("{}/{}", path, i);
                    if let Some(result) = self.find_enc_block_idx_recursive(val, idx, &new_path) {
                        return Some(result);
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn restore_encrypted_value(&self, body: &mut Value, pointer: &str, value: Value) -> Result<(), SeppError> {
        let parts: Vec<&str> = pointer.split('/').filter(|s| !s.is_empty()).collect();

        if parts.is_empty() {
            return Ok(());
        }

        let mut current = body;
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                if let Some(obj) = current.as_object_mut() {
                    obj.insert(part.to_string(), value);
                }
                break;
            } else {
                let next = current.as_object_mut()
                    .and_then(|obj| obj.get_mut(*part))
                    .ok_or_else(|| SeppError::Internal(format!("Path {} not found", pointer)))?;
                current = next;
            }
        }

        Ok(())
    }
}
