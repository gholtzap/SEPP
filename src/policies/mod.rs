use crate::errors::SeppError;
use crate::types::{DataTypeEncryptionPolicy, ModificationPolicy, ProtectionPolicy};
use json_patch::PatchOperation;
use serde_json::Value;

#[derive(Clone)]
pub struct PolicyEngine {
    protection_policy: ProtectionPolicy,
}

impl PolicyEngine {
    pub fn new(protection_policy: ProtectionPolicy) -> Self {
        Self { protection_policy }
    }

    pub fn get_encryption_policy(&self) -> &DataTypeEncryptionPolicy {
        &self.protection_policy.data_type_enc_policy
    }

    pub fn get_modification_policy(&self) -> &ModificationPolicy {
        &self.protection_policy.modification_policy
    }

    pub fn compare_policies(&self, peer_policy: &ProtectionPolicy) -> Result<(), SeppError> {
        let local_api_count = self.protection_policy.data_type_enc_policy.api_ie_mappings.len();
        let peer_api_count = peer_policy.data_type_enc_policy.api_ie_mappings.len();

        if local_api_count != peer_api_count {
            return Err(SeppError::PolicyMismatch(format!(
                "API IE mapping count mismatch: local={}, peer={}",
                local_api_count, peer_api_count
            )));
        }

        for local_mapping in &self.protection_policy.data_type_enc_policy.api_ie_mappings {
            let peer_mapping = peer_policy
                .data_type_enc_policy
                .api_ie_mappings
                .iter()
                .find(|m| m.api_name == local_mapping.api_name);

            if let Some(peer_mapping) = peer_mapping {
                if local_mapping.ie_list.len() != peer_mapping.ie_list.len() {
                    return Err(SeppError::PolicyMismatch(format!(
                        "IE list count mismatch for API {}: local={}, peer={}",
                        local_mapping.api_name,
                        local_mapping.ie_list.len(),
                        peer_mapping.ie_list.len()
                    )));
                }

                for local_ie in &local_mapping.ie_list {
                    let peer_ie = peer_mapping
                        .ie_list
                        .iter()
                        .find(|ie| ie.ie_type == local_ie.ie_type);

                    if let Some(peer_ie) = peer_ie {
                        if local_ie.encryption_required != peer_ie.encryption_required {
                            return Err(SeppError::PolicyMismatch(format!(
                                "Encryption requirement mismatch for IE {}: local={}, peer={}",
                                local_ie.ie_type, local_ie.encryption_required, peer_ie.encryption_required
                            )));
                        }
                    } else {
                        return Err(SeppError::PolicyMismatch(format!(
                            "IE {} not found in peer policy for API {}",
                            local_ie.ie_type, local_mapping.api_name
                        )));
                    }
                }
            } else {
                return Err(SeppError::PolicyMismatch(format!(
                    "API {} not found in peer policy",
                    local_mapping.api_name
                )));
            }
        }

        Ok(())
    }

    pub fn validate_ipx_modifications(
        &self,
        ipx_provider_id: &str,
        modifications: &[PatchOperation],
    ) -> Result<(), SeppError> {
        for modification in modifications {
            let path = match modification {
                PatchOperation::Add(op) => &op.path,
                PatchOperation::Remove(op) => &op.path,
                PatchOperation::Replace(op) => &op.path,
                PatchOperation::Move(op) => &op.path,
                PatchOperation::Copy(op) => &op.path,
                PatchOperation::Test(op) => &op.path,
            };

            let is_allowed = self
                .protection_policy
                .modification_policy
                .allowed_modifications
                .iter()
                .any(|allowed| {
                    allowed.ipx_provider_id == ipx_provider_id
                        && self.path_matches_ie_type(path, &allowed.ie_type)
                });

            if !is_allowed {
                return Err(SeppError::IpxModificationViolation(format!(
                    "IPX provider {} is not allowed to modify path {}",
                    ipx_provider_id, path
                )));
            }
        }

        Ok(())
    }

    pub fn detect_encrypted_ie_misplacement(
        &self,
        original_locations: &[String],
        modified_message: &Value,
    ) -> Result<(), SeppError> {
        for location in original_locations {
            let pointer = location.replace('.', "/");
            if let Some(value) = modified_message.pointer(&pointer) {
                if self.is_encrypted_ie_reference(value) {
                    return Ok(());
                }
            } else {
                return Err(SeppError::EncryptedIeMisplacement(format!(
                    "Encrypted IE at location {} was moved or removed",
                    location
                )));
            }
        }

        Ok(())
    }

    fn path_matches_ie_type(&self, path: &str, ie_type: &str) -> bool {
        path.contains(ie_type)
    }

    fn is_encrypted_ie_reference(&self, value: &Value) -> bool {
        if let Some(obj) = value.as_object() {
            obj.contains_key("encBlockIdx")
        } else {
            false
        }
    }
}
