use axum::{
    body::Body,
    extract::Request,
    middleware::Next,
    response::Response,
};

pub async fn security_event_logging_middleware(
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();

    tracing::info!("Security event: {} {}", method, uri);

    let response = next.run(request).await;

    tracing::info!("Response status: {}", response.status());

    response
}

pub async fn performance_metrics_middleware(
    request: Request<Body>,
    next: Next,
) -> Response {
    let start = std::time::Instant::now();

    let response = next.run(request).await;

    let elapsed = start.elapsed();
    tracing::debug!("Request processed in {:?}", elapsed);

    response
}
