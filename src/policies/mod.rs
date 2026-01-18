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
        let mut allowed_locations: std::collections::HashSet<String> = original_locations
            .iter()
            .map(|loc| loc.replace('.', "/"))
            .collect();

        for api_ie_mapping in &self.protection_policy.data_type_enc_policy.api_ie_mappings {
            for ie in &api_ie_mapping.ie_list {
                if ie.encryption_required {
                    allowed_locations.insert(ie.json_path.replace('.', "/"));
                }
            }
        }

        let mut found_enc_block_refs = Vec::new();
        self.collect_enc_block_idx_locations(modified_message, "", &mut found_enc_block_refs);

        for found_location in &found_enc_block_refs {
            let normalized_location = if found_location.starts_with('/') {
                found_location[1..].to_string()
            } else {
                found_location.clone()
            };

            let location_allowed = allowed_locations.iter().any(|allowed| {
                let normalized_allowed = if allowed.starts_with('/') {
                    &allowed[1..]
                } else {
                    allowed
                };
                normalized_location == normalized_allowed
            });

            if !location_allowed {
                tracing::error!(
                    event = "ENCRYPTED_IE_MISPLACEMENT_DETECTED",
                    location = found_location,
                    "Unauthorized encBlockIdx reference found at location"
                );
                return Err(SeppError::EncryptedIeMisplacement(format!(
                    "Unauthorized encBlockIdx reference at location: {}. Allowed locations: {:?}",
                    found_location, allowed_locations
                )));
            }
        }

        for original_location in original_locations {
            let pointer = original_location.replace('.', "/");
            if let Some(value) = modified_message.pointer(&pointer) {
                if !self.is_encrypted_ie_reference(value) {
                    tracing::error!(
                        event = "ENCRYPTED_IE_REMOVED",
                        location = original_location,
                        "Encrypted IE was removed or replaced from original location"
                    );
                    return Err(SeppError::EncryptedIeMisplacement(format!(
                        "Encrypted IE at location {} was removed or replaced",
                        original_location
                    )));
                }
            } else {
                tracing::error!(
                    event = "ENCRYPTED_IE_LOCATION_MISSING",
                    location = original_location,
                    "Original encrypted IE location no longer exists"
                );
                return Err(SeppError::EncryptedIeMisplacement(format!(
                    "Encrypted IE location {} no longer exists in message",
                    original_location
                )));
            }
        }

        Ok(())
    }

    fn collect_enc_block_idx_locations(
        &self,
        value: &Value,
        current_path: &str,
        locations: &mut Vec<String>,
    ) {
        match value {
            Value::Object(obj) => {
                if obj.contains_key("encBlockIdx") {
                    locations.push(current_path.to_string());
                    return;
                }
                for (key, val) in obj {
                    let new_path = if current_path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}/{}", current_path, key)
                    };
                    self.collect_enc_block_idx_locations(val, &new_path, locations);
                }
            }
            Value::Array(arr) => {
                for (i, val) in arr.iter().enumerate() {
                    let new_path = format!("{}/{}", current_path, i);
                    self.collect_enc_block_idx_locations(val, &new_path, locations);
                }
            }
            _ => {}
        }
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
