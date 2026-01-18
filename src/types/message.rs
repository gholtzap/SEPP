use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SbiMessage {
    pub method: String,
    pub uri: String,
    pub headers: Vec<Header>,
    pub body: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub enum MessageDirection {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone)]
pub struct ProcessedMessage {
    pub original: SbiMessage,
    pub protected: Option<ProtectedMessageData>,
    pub direction: MessageDirection,
}

#[derive(Debug, Clone)]
pub struct ProtectedMessageData {
    pub encrypted_blocks: Vec<(usize, Vec<u8>)>,
    pub signature: Vec<u8>,
    pub ipx_signatures: Vec<IpxSignature>,
}

#[derive(Debug, Clone)]
pub struct IpxSignature {
    pub provider_id: String,
    pub signature: Vec<u8>,
}

pub const HEADER_3GPP_SBI_TARGET_APIROOT: &str = "3gpp-Sbi-Target-apiRoot";
pub const HEADER_AUTHORIZATION: &str = "Authorization";
pub const HEADER_CONTENT_TYPE: &str = "Content-Type";
