use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JweProtectedMessage {
    pub protected_payload: String,
    pub enc_block: Vec<EncryptedBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedBlock {
    pub enc_block_idx: usize,
    pub jwe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwsProtectedMessage {
    pub payload: String,
    pub signatures: Vec<JwsSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsSignature {
    #[serde(rename = "protected")]
    pub protected_header: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataToIntegrityProtectAndCipher {
    pub data_to_encrypt: Vec<DataToEncrypt>,
    pub modifications_list: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataToEncrypt {
    pub ie_location: String,
    pub ie_value: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct CertificateStore {
    pub sepp_certificates: Vec<Certificate>,
    pub ipx_certificates: Vec<Certificate>,
    pub trust_anchors: Vec<TrustAnchor>,
}

#[derive(Debug, Clone)]
pub struct Certificate {
    pub id: String,
    pub certificate_type: CertificateType,
    pub der: Vec<u8>,
    pub plmn_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CertificateType {
    Sepp,
    Ipx,
}

#[derive(Debug, Clone)]
pub struct TrustAnchor {
    pub plmn_id: String,
    pub certificates: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessToken {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plmn_id: Option<String>,
}
