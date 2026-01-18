use crate::types::PlmnId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeppConfig {
    pub sepp: SeppInstanceConfig,
    pub database: DatabaseConfig,
    pub roaming_partners: HashMap<String, RoamingPartnerConfig>,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeppInstanceConfig {
    pub fqdn: String,
    pub plmn_id: PlmnId,
    pub n32c_port: u16,
    pub n32f_port: u16,
    pub sbi_port: u16,
    pub supported_security_methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub uri: String,
    pub database_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoamingPartnerConfig {
    pub plmn_id: PlmnId,
    pub sepp_fqdn: String,
    pub n32c_endpoint: String,
    pub n32f_endpoint: String,
    pub data_type_encryption_policy: DataTypeEncryptionPolicyConfig,
    pub modification_policy: ModificationPolicyConfig,
    pub trust_anchor_path: String,
    pub ipx_providers: Vec<IpxProviderConfig>,
    pub policy_mismatch_action: PolicyMismatchAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypeEncryptionPolicyConfig {
    pub api_ie_mappings: Vec<ApiIeMappingConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiIeMappingConfig {
    pub api_name: String,
    pub ie_list: Vec<IeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IeConfig {
    pub ie_type: String,
    pub json_path: String,
    pub encryption_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModificationPolicyConfig {
    pub allowed_modifications: Vec<AllowedModificationConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedModificationConfig {
    pub ipx_provider_id: String,
    pub ie_type: String,
    pub operations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpxProviderConfig {
    pub provider_id: String,
    pub certificate_path: String,
    pub public_key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyMismatchAction {
    Error,
    Warning,
    Ignore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub sepp_certificate_path: String,
    pub sepp_private_key_path: String,
    pub tls_version: String,
    pub cipher_suites: Vec<String>,
    pub jwt_signing_algorithm: String,
    pub jwe_encryption_algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub security_events: bool,
    pub performance_metrics: bool,
    pub gdpr_compliance: bool,
}

impl SeppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();

        let default_config = Self {
            sepp: SeppInstanceConfig {
                fqdn: std::env::var("SEPP_FQDN")
                    .unwrap_or_else(|_| "sepp.5gc.mnc001.mcc001.3gppnetwork.org".to_string()),
                plmn_id: PlmnId::new(
                    std::env::var("PLMN_MCC").unwrap_or_else(|_| "001".to_string()),
                    std::env::var("PLMN_MNC").unwrap_or_else(|_| "001".to_string()),
                ),
                n32c_port: std::env::var("N32C_PORT")
                    .unwrap_or_else(|_| "7070".to_string())
                    .parse()?,
                n32f_port: std::env::var("N32F_PORT")
                    .unwrap_or_else(|_| "7071".to_string())
                    .parse()?,
                sbi_port: std::env::var("SBI_PORT")
                    .unwrap_or_else(|_| "7072".to_string())
                    .parse()?,
                supported_security_methods: vec!["TLS".to_string(), "PRINS".to_string()],
            },
            database: DatabaseConfig {
                uri: std::env::var("MONGODB_URI")?,
                database_name: std::env::var("MONGODB_DB_NAME")
                    .unwrap_or_else(|_| "sepp".to_string()),
            },
            roaming_partners: HashMap::new(),
            security: SecurityConfig {
                sepp_certificate_path: std::env::var("SEPP_CERT_PATH")
                    .unwrap_or_else(|_| "./certs/sepp.crt".to_string()),
                sepp_private_key_path: std::env::var("SEPP_KEY_PATH")
                    .unwrap_or_else(|_| "./certs/sepp.key".to_string()),
                tls_version: "1.2".to_string(),
                cipher_suites: vec![],
                jwt_signing_algorithm: "ES256".to_string(),
                jwe_encryption_algorithm: "A256GCM".to_string(),
            },
            logging: LoggingConfig {
                level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
                security_events: true,
                performance_metrics: true,
                gdpr_compliance: true,
            },
        };

        Ok(default_config)
    }
}
