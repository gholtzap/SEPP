use crate::auth::AuthValidator;
use crate::errors::SeppError;
use crate::messages::MessageProcessor;
use crate::n32c::N32cManager;
use crate::n32f::N32fManager;
use crate::routing::Router;
use crate::types::{EncryptedBlock, Header, PlmnId, SbiMessage};
use axum::{body::Body, extract::State, http::Request, response::Response};
use http_body_util::BodyExt;
use std::sync::Arc;

pub struct N32fHandlers {
    n32f_manager: Arc<N32fManager>,
    n32c_manager: Arc<N32cManager>,
    message_processor: Arc<MessageProcessor>,
    router: Arc<Router>,
    nf_client: reqwest::Client,
}

impl N32fHandlers {
    pub fn new(
        n32f_manager: Arc<N32fManager>,
        n32c_manager: Arc<N32cManager>,
        message_processor: Arc<MessageProcessor>,
        router: Arc<Router>,
    ) -> Self {
        let nf_client = reqwest::Client::builder()
            .build()
            .expect("Failed to create HTTP client");

        Self {
            n32f_manager,
            n32c_manager,
            message_processor,
            router,
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
        let mut ipx_signatures = Vec::new();

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
            } else if header.name.starts_with("X-IPX-Signature-") {
                if let Some(provider_id) = header.name.strip_prefix("X-IPX-Signature-") {
                    let decoded = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        &header.value,
                    )
                    .map_err(|e| SeppError::JwsVerification(format!("Failed to decode IPX signature: {}", e)))?;

                    ipx_signatures.push(crate::types::IpxSignature {
                        provider_id: provider_id.to_string(),
                        signature: decoded,
                    });
                }
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

        let body_json: Option<serde_json::Value> = if !body_bytes.is_empty() {
            Some(serde_json::from_slice(&body_bytes)?)
        } else {
            None
        };

        let modifications_list: Option<Vec<crate::types::MessageModification>> = if let Some(body) = &body_json {
            if let Some(mods) = body.get("modificationsList") {
                serde_json::from_value(mods.clone()).ok()
            } else {
                None
            }
        } else {
            None
        };

        let sbi_message = SbiMessage {
            method: method.clone(),
            uri: uri.clone(),
            headers: headers.clone(),
            body: body_json,
        };

        let access_token = AuthValidator::extract_access_token(&headers)?;
        let token_plmn_str = AuthValidator::extract_plmn_id_from_token(&access_token)?;
        let token_plmn_id = PlmnId::from_string(&token_plmn_str).ok_or_else(|| {
            tracing::error!(
                event = "INVALID_PLMN_ID_FORMAT",
                plmn_id = token_plmn_str,
                "Invalid PLMN-ID format in access token"
            );
            SeppError::InvalidAccessToken(format!("Invalid PLMN-ID format in token: {}", token_plmn_str))
        })?;

        let n32_context = handlers.n32c_manager.get_context_by_plmn(&token_plmn_id);

        match n32_context {
            Ok(context) => {
                if let Err(e) = handlers.router.validate_plmn_id_in_token(&access_token, &context.remote_plmn_id) {
                    tracing::error!(
                        event = "PLMN_ID_MISMATCH",
                        token_plmn = %token_plmn_id,
                        context_plmn = %context.remote_plmn_id,
                        context_id = context.context_id,
                        method = method,
                        uri = uri,
                        "SECURITY EVENT: PLMN-ID mismatch detected"
                    );
                    return Err(e);
                }
                tracing::info!(
                    event = "PLMN_ID_VALIDATION_SUCCESS",
                    token_plmn = %token_plmn_id,
                    context_plmn = %context.remote_plmn_id,
                    context_id = context.context_id,
                    "PLMN-ID validation successful"
                );
            }
            Err(_) => {
                tracing::warn!(
                    event = "NO_N32_CONTEXT",
                    plmn_id = %token_plmn_id,
                    "No N32-f context found for PLMN-ID, proceeding without context validation"
                );
            }
        }

        let processed_message = handlers
            .message_processor
            .process_inbound_message(
                sbi_message,
                encrypted_blocks,
                &signature,
                ipx_signatures,
                modifications_list,
            )
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
