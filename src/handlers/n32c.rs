use crate::errors::SeppError;
use crate::n32c::N32cManager;
use crate::types::{N32HandshakeRequest, N32HandshakeResponse, PlmnId};
use axum::{extract::State, Json};
use std::sync::Arc;

pub struct N32cHandlers {
    n32c_manager: Arc<N32cManager>,
    local_plmn_id: PlmnId,
}

impl N32cHandlers {
    pub fn new(n32c_manager: Arc<N32cManager>, local_plmn_id: PlmnId) -> Self {
        Self {
            n32c_manager,
            local_plmn_id,
        }
    }

    pub async fn handle_exchange_capability(
        State(handlers): State<Arc<Self>>,
        Json(request): Json<N32HandshakeRequest>,
    ) -> Result<Json<N32HandshakeResponse>, SeppError> {
        tracing::info!("Received N32-c handshake request from PLMN {}", request.local_plmn_id);

        let response = handlers
            .n32c_manager
            .handle_handshake_request(handlers.local_plmn_id.clone(), request)
            .await?;

        tracing::info!("N32-c handshake successful");

        Ok(Json(response))
    }
}
