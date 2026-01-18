use crate::errors::SeppError;
use crate::messages::MessageProcessor;
use crate::n32f::N32fManager;
use axum::{body::Body, extract::State, http::Request, response::Response};
use std::sync::Arc;

pub struct N32fHandlers {
    n32f_manager: Arc<N32fManager>,
    message_processor: Arc<MessageProcessor>,
}

impl N32fHandlers {
    pub fn new(n32f_manager: Arc<N32fManager>, message_processor: Arc<MessageProcessor>) -> Self {
        Self {
            n32f_manager,
            message_processor,
        }
    }

    pub async fn handle_forward_message(
        State(_handlers): State<Arc<Self>>,
        _request: Request<Body>,
    ) -> Result<Response, SeppError> {
        tracing::info!("Received N32-f message");

        Ok(Response::new(Body::empty()))
    }
}
