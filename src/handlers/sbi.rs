use crate::errors::SeppError;
use crate::routing::Router;
use axum::{body::Body, extract::State, http::Request, response::Response};
use std::sync::Arc;

pub struct SbiHandlers {
    router: Arc<Router>,
}

impl SbiHandlers {
    pub fn new(router: Arc<Router>) -> Self {
        Self { router }
    }

    pub async fn handle_sbi_request(
        State(_handlers): State<Arc<Self>>,
        request: Request<Body>,
    ) -> Result<Response, SeppError> {
        tracing::info!("Received SBI request: {} {}", request.method(), request.uri());

        Ok(Response::new(Body::empty()))
    }
}
