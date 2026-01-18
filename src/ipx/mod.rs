use crate::crypto::JwsEngine;
use crate::errors::SeppError;
use crate::policies::PolicyEngine;
use crate::types::{IpxProviderSecInfo, MessageModification};
use dashmap::DashMap;
use json_patch::{Patch, PatchOperation};
use std::sync::Arc;

pub struct IpxManager {
    provider_sec_info: Arc<DashMap<String, IpxProviderSecInfo>>,
    jws_engine: Arc<JwsEngine>,
    policy_engine: Arc<PolicyEngine>,
}

impl IpxManager {
    pub fn new(jws_engine: Arc<JwsEngine>, policy_engine: Arc<PolicyEngine>) -> Self {
        Self {
            provider_sec_info: Arc::new(DashMap::new()),
            jws_engine,
            policy_engine,
        }
    }

    pub fn register_provider(&self, connection_id: &str, sec_info: IpxProviderSecInfo) -> Result<(), SeppError> {
        if self.provider_sec_info.contains_key(&sec_info.ipx_provider_id) {
            let existing = self.provider_sec_info.get(&sec_info.ipx_provider_id).unwrap();
            if existing.connection_id != connection_id {
                return Err(SeppError::ConnectionScopeViolation(format!(
                    "IPX provider {} already registered for a different connection",
                    sec_info.ipx_provider_id
                )));
            }
        }

        self.provider_sec_info.insert(sec_info.ipx_provider_id.clone(), sec_info);
        Ok(())
    }

    pub fn verify_provider_scope(&self, provider_id: &str, connection_id: &str) -> Result<(), SeppError> {
        let sec_info = self
            .provider_sec_info
            .get(provider_id)
            .ok_or_else(|| SeppError::Configuration(format!("IPX provider {} not found", provider_id)))?;

        if sec_info.connection_id != connection_id {
            return Err(SeppError::ConnectionScopeViolation(format!(
                "IPX provider {} cryptographic material does not belong to connection {}",
                provider_id, connection_id
            )));
        }

        Ok(())
    }

    pub fn validate_modifications(
        &self,
        modifications_list: &[MessageModification],
        connection_id: &str,
    ) -> Result<(), SeppError> {
        for modification in modifications_list {
            self.verify_provider_scope(&modification.ipx_provider_id, connection_id)?;

            let operations: Vec<PatchOperation> = modification
                .modifications
                .iter()
                .map(|m| {
                    let op_str = serde_json::to_string(m).unwrap();
                    serde_json::from_str(&op_str).unwrap()
                })
                .collect();

            self.policy_engine
                .validate_ipx_modifications(&modification.ipx_provider_id, &operations)?;
        }

        Ok(())
    }

    pub fn verify_ipx_signatures(
        &self,
        payload: &[u8],
        modifications_list: &[MessageModification],
    ) -> Result<(), SeppError> {
        for modification in modifications_list {
            let jws = std::str::from_utf8(payload)
                .map_err(|e| SeppError::JwsVerification(format!("Invalid UTF-8 in payload: {}", e)))?;

            self.jws_engine.verify_algorithm_restriction(jws)?;

            self.jws_engine.verify(jws, &modification.ipx_provider_id)?;

            tracing::info!(
                "Successfully verified IPX signature for provider {}",
                modification.ipx_provider_id
            );
        }

        Ok(())
    }

    pub fn apply_modifications(
        &self,
        message: &mut serde_json::Value,
        modifications_list: &[MessageModification],
    ) -> Result<(), SeppError> {
        for modification in modifications_list {
            let patch_json = serde_json::to_value(&modification.modifications)?;
            let patch: Patch = serde_json::from_value(patch_json)
                .map_err(|e| SeppError::IpxModificationViolation(format!("Invalid patch: {}", e)))?;

            json_patch::patch(message, &patch)
                .map_err(|e| SeppError::IpxModificationViolation(format!("Failed to apply patch: {}", e)))?;
        }

        Ok(())
    }

    pub fn get_provider_info(&self, provider_id: &str) -> Option<IpxProviderSecInfo> {
        self.provider_sec_info.get(provider_id).map(|entry| entry.value().clone())
    }
}
