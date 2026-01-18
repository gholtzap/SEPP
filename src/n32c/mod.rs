use crate::errors::SeppError;
use crate::policies::PolicyEngine;
use crate::types::{N32Context, N32ContextStatus, N32HandshakeRequest, N32HandshakeResponse, PlmnId, ProtectionPolicy};
use dashmap::DashMap;
use std::sync::Arc;

pub struct N32cManager {
    contexts: Arc<DashMap<String, N32Context>>,
    local_policy: ProtectionPolicy,
}

impl N32cManager {
    pub fn new(local_policy: ProtectionPolicy) -> Self {
        Self {
            contexts: Arc::new(DashMap::new()),
            local_policy,
        }
    }

    pub async fn initiate_handshake(
        &self,
        local_plmn_id: PlmnId,
        remote_plmn_id: PlmnId,
        request: N32HandshakeRequest,
    ) -> Result<N32Context, SeppError> {
        let mut context = N32Context::new(local_plmn_id.clone(), remote_plmn_id.clone());
        context.security_capability = request.security_capability;
        context.protection_policy = request.protection_policy;
        context.ipx_provider_sec_info_list = request.ipx_provider_sec_info_list;

        self.contexts.insert(context.context_id.clone(), context.clone());

        Ok(context)
    }

    pub async fn handle_handshake_request(
        &self,
        local_plmn_id: PlmnId,
        request: N32HandshakeRequest,
    ) -> Result<N32HandshakeResponse, SeppError> {
        let remote_plmn_id = request.local_plmn_id.clone();

        tracing::info!(
            event = "N32C_POLICY_VALIDATION",
            remote_plmn = %remote_plmn_id,
            "Validating protection policy from peer SEPP"
        );

        let policy_engine = PolicyEngine::new(self.local_policy.clone());
        if let Err(e) = policy_engine.compare_policies(&request.protection_policy) {
            tracing::error!(
                event = "POLICY_MISMATCH_DETECTED",
                remote_plmn = %remote_plmn_id,
                error = %e,
                "Protection policy mismatch detected during N32-c handshake"
            );
            return Err(e);
        }

        tracing::info!(
            event = "N32C_POLICY_VALIDATION_SUCCESS",
            remote_plmn = %remote_plmn_id,
            "Protection policy validation successful"
        );

        let mut context = N32Context::new(local_plmn_id.clone(), remote_plmn_id.clone());
        context.security_capability = request.security_capability.clone();
        context.protection_policy = request.protection_policy.clone();
        context.ipx_provider_sec_info_list = request.ipx_provider_sec_info_list.clone();
        context.status = N32ContextStatus::Active;

        self.contexts.insert(context.context_id.clone(), context.clone());

        Ok(N32HandshakeResponse {
            remote_plmn_id: local_plmn_id,
            security_capability: request.security_capability,
            protection_policy: self.local_policy.clone(),
            ipx_provider_sec_info_list: request.ipx_provider_sec_info_list,
            selected_security_method: "TLS".to_string(),
        })
    }

    pub fn get_context(&self, context_id: &str) -> Result<N32Context, SeppError> {
        self.contexts
            .get(context_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| SeppError::N32c(format!("Context {} not found", context_id)))
    }

    pub fn get_context_by_plmn(&self, remote_plmn_id: &PlmnId) -> Result<N32Context, SeppError> {
        self.contexts
            .iter()
            .find(|entry| &entry.value().remote_plmn_id == remote_plmn_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| SeppError::N32c(format!("No context found for PLMN {}", remote_plmn_id)))
    }

    pub fn update_context_status(&self, context_id: &str, status: N32ContextStatus) -> Result<(), SeppError> {
        if let Some(mut entry) = self.contexts.get_mut(context_id) {
            entry.status = status;
            Ok(())
        } else {
            Err(SeppError::N32c(format!("Context {} not found", context_id)))
        }
    }

    pub fn terminate_context(&self, context_id: &str) -> Result<(), SeppError> {
        self.contexts
            .remove(context_id)
            .ok_or_else(|| SeppError::N32c(format!("Context {} not found", context_id)))?;
        Ok(())
    }

    pub fn list_active_contexts(&self) -> Vec<N32Context> {
        self.contexts
            .iter()
            .filter(|entry| matches!(entry.value().status, N32ContextStatus::Active))
            .map(|entry| entry.value().clone())
            .collect()
    }
}

impl Default for N32cManager {
    fn default() -> Self {
        use crate::types::{DataTypeEncryptionPolicy, ModificationPolicy};

        let default_policy = ProtectionPolicy {
            data_type_enc_policy: DataTypeEncryptionPolicy {
                api_ie_mappings: vec![],
            },
            modification_policy: ModificationPolicy {
                allowed_modifications: vec![],
                prohibited_operations: vec![],
            },
        };

        Self::new(default_policy)
    }
}
