mod auth;
mod certificates;
mod clients;
mod config;
mod crypto;
mod errors;
mod handlers;
mod ipx;
mod messages;
mod middleware;
mod n32c;
mod n32f;
mod policies;
mod routing;
mod types;

use axum::{
    middleware as axum_middleware,
    routing::{get, post},
    Router,
};
use certificates::CertificateManager;
use config::SeppConfig;
use crypto::{JweEngine, JwsEngine};
use handlers::{N32cHandlers, N32fHandlers, SbiHandlers};
use messages::MessageProcessor;
use n32c::N32cManager;
use n32f::N32fManager;
use policies::PolicyEngine;
use routing::Router as SeppRouter;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sepp=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting SEPP (Security Edge Protection Proxy)");

    let config = SeppConfig::from_env()?;
    tracing::info!("Loaded configuration for PLMN {}", config.sepp.plmn_id);

    let protection_policy = types::ProtectionPolicy {
        data_type_enc_policy: types::DataTypeEncryptionPolicy {
            api_ie_mappings: vec![],
        },
        modification_policy: types::ModificationPolicy {
            allowed_modifications: vec![],
            prohibited_operations: vec![],
        },
    };

    let certificate_manager = Arc::new(CertificateManager::new());

    tracing::info!("Loading SEPP certificates and keys");
    certificate_manager
        .load_sepp_certificate(&config.security.sepp_certificate_path)
        .await?;

    tracing::info!("Loading trust anchors for roaming partners");
    for (plmn_id, partner_config) in &config.roaming_partners {
        tracing::info!("Loading trust anchor for PLMN {}", plmn_id);
        certificate_manager
            .load_trust_anchor(plmn_id, &partner_config.trust_anchor_path)
            .await?;

        for ipx_provider in &partner_config.ipx_providers {
            let connection_id = format!("{}-{}", config.sepp.plmn_id, plmn_id);
            tracing::info!(
                "Loading IPX certificate for provider {} on connection {}",
                ipx_provider.provider_id,
                connection_id
            );
            certificate_manager
                .load_ipx_certificate(&ipx_provider.certificate_path, &connection_id)
                .await?;
        }
    }

    let n32c_manager = Arc::new(N32cManager::new(protection_policy.clone()));
    let n32f_manager = Arc::new(N32fManager::new());

    let jwe_engine = JweEngine::new();
    let jws_engine = Arc::new(JwsEngine::new());

    let policy_engine = Arc::new(PolicyEngine::new(protection_policy));
    let ipx_manager = Arc::new(ipx::IpxManager::new(jws_engine.clone(), policy_engine.clone()));

    let message_processor = Arc::new(
        MessageProcessor::new(
            jwe_engine,
            (*jws_engine).clone(),
            (*policy_engine).clone(),
        )
        .with_ipx_manager(ipx_manager.clone())
        .with_certificate_manager(certificate_manager.clone())
    );

    let sepp_router = Arc::new(SeppRouter::new());

    let n32c_handlers = Arc::new(N32cHandlers::new(
        n32c_manager.clone(),
        config.sepp.plmn_id.clone(),
    ));

    let n32f_handlers = Arc::new(N32fHandlers::new(
        n32f_manager.clone(),
        n32c_manager.clone(),
        message_processor.clone(),
        sepp_router.clone(),
    ));

    let sbi_handlers = Arc::new(SbiHandlers::new(
        sepp_router.clone(),
        message_processor.clone(),
        n32f_manager.clone(),
        Arc::new(config.clone()),
    ));

    for (plmn_id, partner_config) in &config.roaming_partners {
        let context_id = format!("{}-{}", config.sepp.plmn_id, plmn_id);
        tracing::info!("Creating N32-f connection to {} ({})", partner_config.sepp_fqdn, context_id);

        n32f_manager
            .create_connection(context_id, partner_config.n32f_endpoint.clone())
            .await?;
    }

    let n32c_app = Router::new()
        .route(
            "/n32c-handshake/v1/exchange-capability",
            post(handlers::N32cHandlers::handle_exchange_capability),
        )
        .with_state(n32c_handlers)
        .layer(TraceLayer::new_for_http())
        .layer(axum_middleware::from_fn(
            middleware::security_event_logging_middleware,
        ));

    let n32f_app = Router::new()
        .route(
            "/n32f-forward/*path",
            post(handlers::N32fHandlers::handle_forward_message),
        )
        .with_state(n32f_handlers)
        .layer(TraceLayer::new_for_http())
        .layer(axum_middleware::from_fn(
            middleware::performance_metrics_middleware,
        ));

    let sbi_app = Router::new()
        .route(
            "/*path",
            get(handlers::SbiHandlers::handle_sbi_request)
                .post(handlers::SbiHandlers::handle_sbi_request),
        )
        .with_state(sbi_handlers)
        .layer(TraceLayer::new_for_http());

    let n32c_addr = format!("0.0.0.0:{}", config.sepp.n32c_port);
    let n32f_addr = format!("0.0.0.0:{}", config.sepp.n32f_port);
    let sbi_addr = format!("0.0.0.0:{}", config.sepp.sbi_port);

    tracing::info!("N32-c listening on {}", n32c_addr);
    tracing::info!("N32-f listening on {}", n32f_addr);
    tracing::info!("SBI listening on {}", sbi_addr);

    let n32c_listener = tokio::net::TcpListener::bind(&n32c_addr).await?;
    let n32f_listener = tokio::net::TcpListener::bind(&n32f_addr).await?;
    let sbi_listener = tokio::net::TcpListener::bind(&sbi_addr).await?;

    tokio::try_join!(
        async {
            axum::serve(n32c_listener, n32c_app)
                .await
                .map_err(anyhow::Error::from)
        },
        async {
            axum::serve(n32f_listener, n32f_app)
                .await
                .map_err(anyhow::Error::from)
        },
        async {
            axum::serve(sbi_listener, sbi_app)
                .await
                .map_err(anyhow::Error::from)
        },
    )?;

    Ok(())
}
