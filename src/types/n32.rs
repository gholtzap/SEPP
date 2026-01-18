use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::PlmnId;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32Context {
    pub context_id: String,
    pub local_plmn_id: PlmnId,
    pub remote_plmn_id: PlmnId,
    pub security_capability: SecurityCapability,
    pub protection_policy: ProtectionPolicy,
    pub ipx_provider_sec_info_list: Vec<IpxProviderSecInfo>,
    pub status: N32ContextStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum N32ContextStatus {
    Establishing,
    Active,
    Suspended,
    Terminated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityCapability {
    pub tls_version: String,
    pub cipher_suites: Vec<String>,
    pub supported_features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionPolicy {
    pub data_type_enc_policy: DataTypeEncryptionPolicy,
    pub modification_policy: ModificationPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataTypeEncryptionPolicy {
    pub api_ie_mappings: Vec<ApiIeMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiIeMapping {
    pub api_name: String,
    pub ie_list: Vec<InformationElement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InformationElement {
    pub ie_type: String,
    pub json_path: String,
    pub encryption_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModificationPolicy {
    pub allowed_modifications: Vec<AllowedModification>,
    pub prohibited_operations: Vec<ProhibitedOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowedModification {
    pub ipx_provider_id: String,
    pub ie_type: String,
    pub operation: ModificationOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModificationOperation {
    Add,
    Remove,
    Replace,
    Move,
    Copy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProhibitedOperation {
    pub ie_type: String,
    pub operation: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpxProviderSecInfo {
    pub ipx_provider_id: String,
    pub public_key_id: String,
    pub public_key: Vec<u8>,
    pub certificate: Option<Vec<u8>>,
    pub connection_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32HandshakeRequest {
    pub local_plmn_id: PlmnId,
    pub security_capability: SecurityCapability,
    pub protection_policy: ProtectionPolicy,
    pub ipx_provider_sec_info_list: Vec<IpxProviderSecInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32HandshakeResponse {
    pub remote_plmn_id: PlmnId,
    pub security_capability: SecurityCapability,
    pub protection_policy: ProtectionPolicy,
    pub ipx_provider_sec_info_list: Vec<IpxProviderSecInfo>,
    pub selected_security_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32fMessage {
    pub message_id: String,
    pub context_id: String,
    pub method: String,
    pub uri: String,
    pub headers: Vec<HttpHeader>,
    pub body: Option<serde_json::Value>,
    pub modifications_list: Option<Vec<MessageModification>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageModification {
    pub ipx_provider_id: String,
    pub modifications: Vec<JsonPatchOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonPatchOperation {
    pub op: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

impl N32Context {
    pub fn new(local_plmn_id: PlmnId, remote_plmn_id: PlmnId) -> Self {
        Self {
            context_id: Uuid::new_v4().to_string(),
            local_plmn_id,
            remote_plmn_id,
            security_capability: SecurityCapability {
                tls_version: "1.2".to_string(),
                cipher_suites: vec![],
                supported_features: vec![],
            },
            protection_policy: ProtectionPolicy {
                data_type_enc_policy: DataTypeEncryptionPolicy {
                    api_ie_mappings: vec![],
                },
                modification_policy: ModificationPolicy {
                    allowed_modifications: vec![],
                    prohibited_operations: vec![],
                },
            },
            ipx_provider_sec_info_list: vec![],
            status: N32ContextStatus::Establishing,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}
