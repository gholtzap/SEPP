use crate::errors::SeppError;
use crate::types::N32fMessage;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct N32fManager {
    message_queue: Arc<DashMap<String, mpsc::Sender<N32fMessage>>>,
    connection_pool: Arc<DashMap<String, reqwest::Client>>,
}

impl N32fManager {
    pub fn new() -> Self {
        Self {
            message_queue: Arc::new(DashMap::new()),
            connection_pool: Arc::new(DashMap::new()),
        }
    }

    pub async fn create_connection(&self, context_id: String, endpoint: String) -> Result<(), SeppError> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| SeppError::N32f(format!("Failed to create HTTP/2 client: {}", e)))?;

        self.connection_pool.insert(context_id.clone(), client);

        let (tx, mut rx) = mpsc::channel::<N32fMessage>(100);
        self.message_queue.insert(context_id.clone(), tx);

        let pool = self.connection_pool.clone();
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let Some(client) = pool.get(&context_id) {
                    let result = Self::forward_message(&client, &endpoint, message).await;
                    if let Err(e) = result {
                        tracing::error!("Failed to forward message: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    async fn forward_message(
        client: &reqwest::Client,
        endpoint: &str,
        message: N32fMessage,
    ) -> Result<(), SeppError> {
        let url = format!("{}{}", endpoint, message.uri);

        let mut request = client.request(
            message.method.parse().map_err(|_| SeppError::N32f("Invalid HTTP method".to_string()))?,
            &url,
        );

        for header in &message.headers {
            request = request.header(&header.name, &header.value);
        }

        if let Some(body) = message.body {
            request = request.json(&body);
        }

        let response = request
            .send()
            .await
            .map_err(|e| SeppError::N32f(format!("Failed to send request: {}", e)))?;

        if !response.status().is_success() {
            return Err(SeppError::N32f(format!(
                "Request failed with status: {}",
                response.status()
            )));
        }

        Ok(())
    }

    pub async fn enqueue_message(&self, context_id: &str, message: N32fMessage) -> Result<(), SeppError> {
        let sender = self
            .message_queue
            .get(context_id)
            .ok_or_else(|| SeppError::N32f(format!("No connection for context {}", context_id)))?;

        sender
            .send(message)
            .await
            .map_err(|e| SeppError::N32f(format!("Failed to enqueue message: {}", e)))?;

        Ok(())
    }

    pub fn close_connection(&self, context_id: &str) -> Result<(), SeppError> {
        self.message_queue.remove(context_id);
        self.connection_pool.remove(context_id);
        Ok(())
    }
}

impl Default for N32fManager {
    fn default() -> Self {
        Self::new()
    }
}
