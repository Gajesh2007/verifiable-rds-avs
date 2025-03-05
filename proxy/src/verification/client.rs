use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use log::{debug, error};
use crate::error::ProxyError;
use crate::error::Result;

/// Response for state root endpoint
#[derive(Debug, Deserialize)]
struct StateRootResponse {
    block_number: u64,
    state_root: String,
    timestamp: u64,
    version: u64,
}

/// API response wrapper
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ApiResponse<T> {
    Success(T),
    Error { error: String },
}

/// Request for verifying a transaction
#[derive(Debug, Serialize)]
struct VerifyTransactionRequest {
    transaction_id: u64,
    query: String,
    pre_state_root: String,
    block_number: u64,
}

/// Client for interacting with the verification service
#[derive(Debug)]
pub struct VerificationServiceClient {
    /// Base URL of the verification service
    base_url: String,
    
    /// HTTP client for making requests
    client: reqwest::Client,
    
    /// Timeout for requests
    timeout: Duration,
}

impl VerificationServiceClient {
    /// Create a new verification client
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            client: Client::new(),
            timeout: Duration::from_secs(30),
        }
    }
    
    /// Set the timeout for requests
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
    
    /// Get the current state root
    pub async fn get_state_root(&self) -> Result<String> {
        let url = format!("{}/api/v1/state-root/latest", self.base_url);
        debug!("Fetching latest state root from {}", url);
        
        let response = self.client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| ProxyError::Verification(format!("Failed to get state root: {}", e)))?;
            
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_else(|_| "Unable to read error response".to_string());
            return Err(ProxyError::Verification(format!("Server error: {} - {}", status, text)));
        }
        
        let response_data: ApiResponse<StateRootResponse> = response.json().await
            .map_err(|e| ProxyError::Verification(format!("Failed to parse state root response: {}", e)))?;
            
        match response_data {
            ApiResponse::Success(data) => Ok(data.state_root),
            ApiResponse::Error { error } => Err(ProxyError::Verification(format!("Verification service error: {}", error))),
        }
    }
    
    /// Verify a transaction
    pub async fn verify_transaction(&self, transaction_id: u64, query: &str, pre_state_root: &[u8; 32]) -> Result<()> {
        let url = format!("{}/api/v1/verify/transaction", self.base_url);
        debug!("Verifying transaction {} at {}", transaction_id, url);
        
        let request = VerifyTransactionRequest {
            transaction_id,
            query: query.to_string(),
            pre_state_root: hex::encode(pre_state_root),
            block_number: 0, // This would need to be determined by the service
        };
        
        let response = self.client
            .post(&url)
            .timeout(self.timeout)
            .json(&request)
            .send()
            .await
            .map_err(|e| ProxyError::Verification(format!("Failed to verify transaction: {}", e)))?;
            
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_else(|_| "Unable to read error response".to_string());
            return Err(ProxyError::Verification(format!("Server error during transaction verification: {} - {}", status, text)));
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;
    
    #[test]
    async fn test_get_state_root() {
        // This test would normally mock the HTTP client
        // For now, we'll just test the construction
        let client = VerificationServiceClient::new("http://localhost:8080");
        assert_eq!(client.base_url, "http://localhost:8080");
    }
} 