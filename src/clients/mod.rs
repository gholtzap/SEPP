use crate::errors::SeppError;
use reqwest::Client;
use std::sync::Arc;

pub struct NrfClient {
    client: Arc<Client>,
    nrf_endpoint: String,
}

impl NrfClient {
    pub fn new(nrf_endpoint: String) -> Self {
        let client = Client::builder()
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client: Arc::new(client),
            nrf_endpoint,
        }
    }

    pub async fn register_sepp(&self, sepp_fqdn: &str, plmn_id: &str) -> Result<(), SeppError> {
        let registration_data = serde_json::json!({
            "nfInstanceId": uuid::Uuid::new_v4().to_string(),
            "nfType": "SEPP",
            "nfStatus": "REGISTERED",
            "plmnList": [{
                "mcc": plmn_id.split('-').next().unwrap_or("001"),
                "mnc": plmn_id.split('-').nth(1).unwrap_or("001")
            }],
            "fqdn": sepp_fqdn,
            "seppInfo": {
                "seppCapability": ["N32", "PRINS", "TLS"]
            }
        });

        let response = self
            .client
            .post(format!("{}/nnrf-nfm/v1/nf-instances", self.nrf_endpoint))
            .json(&registration_data)
            .send()
            .await
            .map_err(|e| SeppError::HttpClient(e))?;

        if !response.status().is_success() {
            return Err(SeppError::Internal(format!(
                "Failed to register SEPP with NRF: {}",
                response.status()
            )));
        }

        Ok(())
    }

    pub async fn discover_nf(&self, nf_type: &str, target_plmn: &str) -> Result<serde_json::Value, SeppError> {
        let response = self
            .client
            .get(format!(
                "{}/nnrf-disc/v1/nf-instances?target-nf-type={}&requester-plmn-id={}",
                self.nrf_endpoint, nf_type, target_plmn
            ))
            .send()
            .await
            .map_err(|e| SeppError::HttpClient(e))?;

        if !response.status().is_success() {
            return Err(SeppError::Internal(format!(
                "Failed to discover NF: {}",
                response.status()
            )));
        }

        let nf_profile = response.json().await.map_err(|e| SeppError::HttpClient(e))?;
        Ok(nf_profile)
    }
}

pub struct SeppClient {
    client: Arc<Client>,
}

impl SeppClient {
    pub fn new() -> Self {
        let client = Client::builder()
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client: Arc::new(client),
        }
    }

    pub async fn send_n32c_handshake(
        &self,
        peer_endpoint: &str,
        request: crate::types::N32HandshakeRequest,
    ) -> Result<crate::types::N32HandshakeResponse, SeppError> {
        let response = self
            .client
            .post(format!("{}/n32c-handshake/v1/exchange-capability", peer_endpoint))
            .json(&request)
            .send()
            .await
            .map_err(|e| SeppError::HttpClient(e))?;

        if !response.status().is_success() {
            return Err(SeppError::N32c(format!(
                "N32-c handshake failed: {}",
                response.status()
            )));
        }

        let handshake_response = response.json().await.map_err(|e| SeppError::HttpClient(e))?;
        Ok(handshake_response)
    }

    pub async fn send_error_notification(
        &self,
        peer_endpoint: &str,
        notification: crate::types::N32ErrorNotification,
    ) -> Result<(), SeppError> {
        tracing::info!(
            context_id = %notification.context_id,
            error_type = ?notification.error_type,
            "Sending error notification to peer SEPP"
        );

        let response = self
            .client
            .post(format!("{}/n32c-handshake/v1/error-notification", peer_endpoint))
            .json(&notification)
            .send()
            .await
            .map_err(|e| SeppError::HttpClient(e))?;

        if !response.status().is_success() {
            tracing::warn!(
                peer_endpoint = %peer_endpoint,
                status = %response.status(),
                "Failed to send error notification to peer SEPP"
            );
            return Err(SeppError::N32c(format!(
                "Error notification failed: {}",
                response.status()
            )));
        }

        tracing::info!(
            context_id = %notification.context_id,
            "Successfully sent error notification to peer SEPP"
        );

        Ok(())
    }
}

impl Default for SeppClient {
    fn default() -> Self {
        Self::new()
    }
}
