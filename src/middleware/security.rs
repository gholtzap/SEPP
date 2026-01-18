use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};

pub async fn tls_mutual_auth_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    Ok(next.run(request).await)
}

pub async fn access_token_validation_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok());

    if let Some(auth) = auth_header {
        if auth.starts_with("Bearer ") {
            tracing::debug!("Access token present in request");
        }
    }

    Ok(next.run(request).await)
}
