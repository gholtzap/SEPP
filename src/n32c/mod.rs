use crate::clients::SeppClient;
use crate::errors::SeppError;
use crate::policies::PolicyEngine;
use crate::types::{N32Context, N32ContextStatus, N32ErrorNotification, N32ErrorType, N32HandshakeRequest, N32HandshakeResponse, PlmnId, ProtectionPolicy};
use chrono::Utc;
use dashmap::DashMap;
use std::sync::Arc;

pub struct N32cManager {
    contexts: Arc<DashMap<String, N32Context>>,
    local_policy: ProtectionPolicy,
    sepp_client: SeppClient,
    peer_endpoints: Arc<DashMap<String, String>>,
}

impl N32cManager {
    pub fn new(local_policy: ProtectionPolicy) -> Self {
        Self {
            contexts: Arc::new(DashMap::new()),
            local_policy,
            sepp_client: SeppClient::new(),
            peer_endpoints: Arc::new(DashMap::new()),
        }
    }

    pub fn register_peer_endpoint(&self, plmn_id: &PlmnId, n32c_endpoint: String) {
        self.peer_endpoints.insert(plmn_id.to_string(), n32c_endpoint);
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

        let mut context = N32Context::new(local_plmn_id.clone(), remote_plmn_id.clone());
        context.security_capability = request.security_capability.clone();
        context.protection_policy = request.protection_policy.clone();
        context.ipx_provider_sec_info_list = request.ipx_provider_sec_info_list.clone();

        let policy_engine = PolicyEngine::new(self.local_policy.clone());
        if let Err(e) = policy_engine.compare_policies(&request.protection_policy) {
            tracing::error!(
                event = "POLICY_MISMATCH_DETECTED",
                remote_plmn = %remote_plmn_id,
                error = %e,
                "Protection policy mismatch detected during N32-c handshake"
            );

            let temp_context_id = context.context_id.clone();
            self.contexts.insert(temp_context_id.clone(), context);

            let _ = self.send_error_to_peer(
                &temp_context_id,
                N32ErrorType::PolicyMismatch,
                e.to_string(),
                None,
            ).await;

            return Err(e);
        }

        tracing::info!(
            event = "N32C_POLICY_VALIDATION_SUCCESS",
            remote_plmn = %remote_plmn_id,
            "Protection policy validation successful"
        );

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

    pub fn create_error_notification(
        &self,
        context_id: String,
        error_type: N32ErrorType,
        error_detail: String,
        affected_message_id: Option<String>,
    ) -> N32ErrorNotification {
        N32ErrorNotification {
            context_id,
            error_type,
            error_detail,
            timestamp: Utc::now(),
            affected_message_id,
        }
    }

    pub async fn send_error_to_peer(
        &self,
        context_id: &str,
        error_type: N32ErrorType,
        error_detail: String,
        affected_message_id: Option<String>,
    ) -> Result<(), SeppError> {
        let context = self.get_context(context_id)?;

        let peer_endpoint = self
            .peer_endpoints
            .get(&context.remote_plmn_id.to_string())
            .ok_or_else(|| {
                SeppError::N32c(format!(
                    "No N32-c endpoint registered for PLMN {}",
                    context.remote_plmn_id
                ))
            })?;

        let notification = self.create_error_notification(
            context_id.to_string(),
            error_type,
            error_detail,
            affected_message_id,
        );

        self.sepp_client
            .send_error_notification(&peer_endpoint, notification)
            .await?;

        Ok(())
    }

    pub async fn handle_error_notification(
        &self,
        notification: N32ErrorNotification,
    ) -> Result<(), SeppError> {
        tracing::error!(
            event = "N32C_ERROR_RECEIVED",
            context_id = %notification.context_id,
            error_type = ?notification.error_type,
            error_detail = %notification.error_detail,
            "Received error notification from peer SEPP"
        );

        if let Some(mut entry) = self.contexts.get_mut(&notification.context_id) {
            match notification.error_type {
                N32ErrorType::PolicyMismatch => {
                    tracing::warn!(
                        context_id = %notification.context_id,
                        "Peer SEPP reported policy mismatch"
                    );
                }
                N32ErrorType::PlmnIdMismatch => {
                    tracing::error!(
                        context_id = %notification.context_id,
                        "Peer SEPP reported PLMN-ID mismatch"
                    );
                    entry.status = N32ContextStatus::Suspended;
                }
                N32ErrorType::CertificateValidationFailure => {
                    tracing::error!(
                        context_id = %notification.context_id,
                        "Peer SEPP reported certificate validation failure"
                    );
                    entry.status = N32ContextStatus::Suspended;
                }
                N32ErrorType::EncryptedIeMisplacement => {
                    tracing::error!(
                        context_id = %notification.context_id,
                        "Peer SEPP detected encrypted IE misplacement"
                    );
                }
                N32ErrorType::IpxModificationViolation => {
                    tracing::error!(
                        context_id = %notification.context_id,
                        "Peer SEPP detected IPX modification violation"
                    );
                }
                N32ErrorType::JwsVerificationFailure => {
                    tracing::error!(
                        context_id = %notification.context_id,
                        "Peer SEPP reported JWS verification failure"
                    );
                    entry.status = N32ContextStatus::Suspended;
                }
                N32ErrorType::ContextNotFound => {
                    tracing::warn!(
                        context_id = %notification.context_id,
                        "Peer SEPP reported context not found"
                    );
                }
                N32ErrorType::SecurityCapabilityNegotiationFailure => {
                    tracing::error!(
                        context_id = %notification.context_id,
                        "Peer SEPP reported security capability negotiation failure"
                    );
                    entry.status = N32ContextStatus::Terminated;
                }
            }
        }

        Ok(())
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

        Self {
            contexts: Arc::new(DashMap::new()),
            local_policy: default_policy,
            sepp_client: SeppClient::new(),
            peer_endpoints: Arc::new(DashMap::new()),
        }
    }
}
