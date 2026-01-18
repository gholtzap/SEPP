use crate::errors::SeppError;
use crate::messages::MessageProcessor;
use crate::n32f::N32fManager;
use crate::types::{EncryptedBlock, Header, SbiMessage};
use axum::{body::Body, extract::State, http::Request, response::Response};
use http_body_util::BodyExt;
use std::sync::Arc;

pub struct N32fHandlers {
    n32f_manager: Arc<N32fManager>,
    message_processor: Arc<MessageProcessor>,
    nf_client: reqwest::Client,
}

impl N32fHandlers {
    pub fn new(n32f_manager: Arc<N32fManager>, message_processor: Arc<MessageProcessor>) -> Self {
        let nf_client = reqwest::Client::builder()
            .build()
            .expect("Failed to create HTTP client");

        Self {
            n32f_manager,
            message_processor,
            nf_client,
        }
    }

    pub async fn handle_forward_message(
        State(handlers): State<Arc<Self>>,
        request: Request<Body>,
    ) -> Result<Response, SeppError> {
        let method = request.method().to_string();
        let uri = request.uri().to_string();

        tracing::info!("Received N32-f message: {} {}", method, uri);

        let headers: Vec<Header> = request
            .headers()
            .iter()
            .map(|(name, value)| Header {
                name: name.as_str().to_string(),
                value: value.to_str().unwrap_or("").to_string(),
            })
            .collect();

        let mut encrypted_blocks = Vec::new();
        let mut signature = None;

        for header in &headers {
            if header.name.starts_with("X-Enc-Block-") {
                if let Some(idx_str) = header.name.strip_prefix("X-Enc-Block-") {
                    if let Ok(idx) = idx_str.parse::<usize>() {
                        let decoded = base64::Engine::decode(
                            &base64::engine::general_purpose::STANDARD,
                            &header.value,
                        )
                        .map_err(|e| {
                            SeppError::JweDecryption(format!("Failed to decode encrypted block: {}", e))
                        })?;

                        encrypted_blocks.push(EncryptedBlock {
                            enc_block_idx: idx,
                            jwe: String::from_utf8(decoded).map_err(|e| {
                                SeppError::JweDecryption(format!("Invalid UTF-8 in encrypted block: {}", e))
                            })?,
                        });
                    }
                }
            } else if header.name == "X-JWS-Signature" {
                let decoded = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &header.value,
                )
                .map_err(|e| SeppError::JwsVerification(format!("Failed to decode signature: {}", e)))?;

                signature = Some(
                    String::from_utf8(decoded)
                        .map_err(|e| SeppError::JwsVerification(format!("Invalid UTF-8 in signature: {}", e)))?,
                );
            }
        }

        let signature = signature.ok_or_else(|| {
            SeppError::JwsVerification("Missing JWS signature in N32-f message".to_string())
        })?;

        let body_bytes = request
            .into_body()
            .collect()
            .await
            .map_err(|e| SeppError::Internal(format!("Failed to read request body: {}", e)))?
            .to_bytes();

        let body_json = if !body_bytes.is_empty() {
            Some(serde_json::from_slice(&body_bytes)?)
        } else {
            None
        };

        let sbi_message = SbiMessage {
            method: method.clone(),
            uri: uri.clone(),
            headers,
            body: body_json,
        };

        let processed_message = handlers
            .message_processor
            .process_inbound_message(sbi_message, encrypted_blocks, &signature)
            .await?;

        let target_nf_uri = processed_message.original.uri.clone();

        tracing::info!("Forwarding decrypted message to internal NF: {}", target_nf_uri);

        let mut nf_request = handlers
            .nf_client
            .request(
                processed_message.original.method.parse().map_err(|_| {
                    SeppError::Internal("Invalid HTTP method".to_string())
                })?,
                &target_nf_uri,
            );

        for header in &processed_message.original.headers {
            nf_request = nf_request.header(&header.name, &header.value);
        }

        if let Some(body) = processed_message.original.body {
            nf_request = nf_request.json(&body);
        }

        let nf_response = nf_request
            .send()
            .await
            .map_err(|e| SeppError::Internal(format!("Failed to forward to NF: {}", e)))?;

        let status = nf_response.status();
        let response_body = nf_response
            .bytes()
            .await
            .map_err(|e| SeppError::Internal(format!("Failed to read NF response: {}", e)))?;

        tracing::info!("Received response from internal NF: {}", status);

        Ok(Response::builder()
            .status(status)
            .body(Body::from(response_body))
            .unwrap())
    }
}
