use crate::config::SeppConfig;
use crate::errors::SeppError;
use crate::messages::MessageProcessor;
use crate::n32f::N32fManager;
use crate::routing::Router;
use crate::types::{Header, N32fMessage, SbiMessage};
use axum::{body::Body, extract::State, http::Request, response::Response};
use http_body_util::BodyExt;
use std::sync::Arc;
use uuid::Uuid;

pub struct SbiHandlers {
    router: Arc<Router>,
    message_processor: Arc<MessageProcessor>,
    n32f_manager: Arc<N32fManager>,
    config: Arc<SeppConfig>,
}

impl SbiHandlers {
    pub fn new(
        router: Arc<Router>,
        message_processor: Arc<MessageProcessor>,
        n32f_manager: Arc<N32fManager>,
        config: Arc<SeppConfig>,
    ) -> Self {
        Self {
            router,
            message_processor,
            n32f_manager,
            config,
        }
    }

    pub async fn handle_sbi_request(
        State(handlers): State<Arc<Self>>,
        request: Request<Body>,
    ) -> Result<Response, SeppError> {
        let method = request.method().to_string();
        let uri = request.uri().to_string();

        tracing::info!("Received SBI request: {} {}", method, uri);

        let headers: Vec<(String, String)> = request
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();

        let (target_plmn_id, _target_apiroot) =
            handlers.router.determine_routing_target(&uri, &headers)?;

        tracing::info!("Routing to PLMN: {}", target_plmn_id);

        let _roaming_partner = handlers
            .config
            .roaming_partners
            .get(&target_plmn_id.to_string())
            .ok_or_else(|| {
                SeppError::Routing(format!("No roaming partner configured for PLMN {}", target_plmn_id))
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
            headers: headers.iter().map(|(name, value)| Header {
                name: name.clone(),
                value: value.clone(),
            }).collect(),
            body: body_json,
        };

        let processed_message = handlers
            .message_processor
            .process_outbound_message(sbi_message)
            .await?;

        let protected_data = processed_message.protected.ok_or_else(|| {
            SeppError::Internal("Failed to create protected message".to_string())
        })?;

        let mut n32f_headers = vec![
            crate::types::HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
        ];

        for (enc_idx, enc_block) in &protected_data.encrypted_blocks {
            n32f_headers.push(crate::types::HttpHeader {
                name: format!("X-Enc-Block-{}", enc_idx),
                value: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, enc_block),
            });
        }

        n32f_headers.push(crate::types::HttpHeader {
            name: "X-JWS-Signature".to_string(),
            value: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &protected_data.signature),
        });

        let context_id = format!("{}-{}", handlers.config.sepp.plmn_id, target_plmn_id);

        let n32f_message = N32fMessage {
            message_id: Uuid::new_v4().to_string(),
            context_id: context_id.clone(),
            method,
            uri,
            headers: n32f_headers,
            body: processed_message.original.body,
            modifications_list: None,
        };

        handlers
            .n32f_manager
            .enqueue_message(&context_id, n32f_message)
            .await?;

        tracing::info!("Message forwarded to peer SEPP for PLMN {}", target_plmn_id);

        Ok(Response::builder()
            .status(202)
            .body(Body::from("Message accepted for forwarding"))
            .unwrap())
    }
}
