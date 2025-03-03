//! Verification client for interacting with the verification system
//!
//! This module provides a client for interacting with the verification
//! features of the Verifiable Database system.

use std::collections::HashMap;
use std::time::{Duration};
use reqwest::Client;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use base64::{Engine as _, engine::general_purpose::STANDARD};

/// Error type for verification operations
#[derive(Error, Debug)]
pub enum VerificationError {
    /// Network error
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    
    /// Server error
    #[error("Server error: {0}")]
    Server(String),
    
    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    /// Verification error
    #[error("Verification error: {0}")]
    Verification(String),
    
    /// Other error
    #[error("Other error: {0}")]
    Other(String),
}

/// Result type for verification operations
pub type Result<T> = std::result::Result<T, VerificationError>;

/// Transaction verification status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Transaction has not been verified
    #[serde(rename = "not_verified")]
    NotVerified,
    
    /// Transaction is in the process of being verified
    #[serde(rename = "in_progress")]
    InProgress,
    
    /// Transaction has been verified successfully
    #[serde(rename = "verified")]
    Verified,
    
    /// Transaction verification failed
    #[serde(rename = "failed")]
    Failed,
    
    /// Transaction verification was skipped
    #[serde(rename = "skipped")]
    Skipped,
}

/// Transaction verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Transaction ID
    pub transaction_id: u64,
    
    /// Verification status
    pub status: VerificationStatus,
    
    /// Pre-state root
    pub pre_state_root: Option<String>,
    
    /// Post-state root
    pub post_state_root: Option<String>,
    
    /// Verification time in milliseconds
    pub verification_time_ms: u64,
    
    /// Error message (if verification failed)
    pub error: Option<String>,
    
    /// Verification metadata
    pub metadata: HashMap<String, String>,
}

/// State commitment structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateCommitment {
    /// Commitment ID
    pub id: u64,
    
    /// State root
    pub state_root: String,
    
    /// Block number
    pub block_number: u64,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// Committer address
    pub committer: String,
    
    /// Transaction ID that created this commitment
    pub transaction_id: Option<u64>,
    
    /// Whether this commitment has been submitted to EigenLayer
    pub submitted: bool,
    
    /// EigenLayer transaction hash (if submitted)
    pub tx_hash: Option<String>,
}

/// Challenge status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeStatus {
    /// Challenge is active
    #[serde(rename = "active")]
    Active,
    
    /// Challenge has been resolved
    #[serde(rename = "resolved")]
    Resolved,
    
    /// Challenge has expired
    #[serde(rename = "expired")]
    Expired,
    
    /// Challenge has been slashed
    #[serde(rename = "slashed")]
    Slashed,
}

/// Challenge structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Challenge ID
    pub id: String,
    
    /// State root challenged
    pub state_root: String,
    
    /// Block number
    pub block_number: u64,
    
    /// Challenger address
    pub challenger: String,
    
    /// Operator address
    pub operator: String,
    
    /// Challenge status
    pub status: ChallengeStatus,
    
    /// Bond amount
    pub bond: String,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// Evidence (if any)
    pub evidence: Option<String>,
}

/// Row proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowProof {
    /// Table name
    pub table_name: String,
    
    /// Row ID
    pub row_id: HashMap<String, String>,
    
    /// Merkle proof
    pub proof: String,
    
    /// State root
    pub state_root: String,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// Verification status
    pub verified: bool,
}

/// Verification client for interacting with the verification system
pub struct VerificationClient {
    /// Base URL for the verification API
    base_url: String,
    
    /// HTTP client
    client: Client,
    
    /// Timeout for requests
    timeout: Duration,
}

impl VerificationClient {
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
        let url = format!("{}/api/v1/state-root/current", self.base_url);
        let response = self.client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await?;
            
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(VerificationError::Server(error));
        }
        
        let state_root: String = response.json().await?;
        Ok(state_root)
    }
    
    /// Get the state root for a specific block
    pub async fn get_state_root_by_block(&self, block_number: u64) -> Result<String> {
        let url = format!("{}/api/v1/state-root/{}", self.base_url, block_number);
        let response = self.client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await?;
            
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(VerificationError::Server(error));
        }
        
        let state_root: String = response.json().await?;
        Ok(state_root)
    }
    
    /// Get a transaction
    pub async fn get_transaction(&self, transaction_id: u64) -> Result<VerificationResult> {
        let url = format!("{}/api/v1/transaction/{}", self.base_url, transaction_id);
        let response = self.client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await?;
            
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(VerificationError::Server(error));
        }
        
        let result: VerificationResult = response.json().await?;
        Ok(result)
    }
    
    /// Get all transactions
    pub async fn get_transactions(&self) -> Result<Vec<VerificationResult>> {
        let url = format!("{}/api/v1/transactions", self.base_url);
        let response = self.client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await?;
            
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(VerificationError::Server(error));
        }
        
        let results: Vec<VerificationResult> = response.json().await?;
        Ok(results)
    }
    
    /// Get a proof for a specific row
    pub async fn get_row_proof(&self, table_name: &str, condition: &str) -> Result<RowProof> {
        let url = format!("{}/api/v1/proof/row", self.base_url);
        let response = self.client
            .post(&url)
            .timeout(self.timeout)
            .json(&serde_json::json!({
                "table_name": table_name,
                "condition": condition,
            }))
            .send()
            .await?;
            
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(VerificationError::Server(error));
        }
        
        let proof: RowProof = response.json().await?;
        Ok(proof)
    }
    
    /// Verify a proof for a specific row
    pub async fn verify_row_proof(&self, proof: &RowProof) -> Result<bool> {
        let url = format!("{}/api/v1/verify/proof/row", self.base_url);
        let response = self.client
            .post(&url)
            .timeout(self.timeout)
            .json(proof)
            .send()
            .await?;
            
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(VerificationError::Server(error));
        }
        
        let result: bool = response.json().await?;
        Ok(result)
    }
    
    /// Get a proof for a specific transaction
    pub async fn get_transaction_proof(&self, transaction_id: u64) -> Result<Vec<u8>> {
        let url = format!("{}/api/v1/proof/transaction/{}", self.base_url, transaction_id);
        let response = self.client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await?;
            
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(VerificationError::Server(error));
        }
        
        let proof = response.bytes().await?;
        Ok(proof.to_vec())
    }
    
    /// Verify a transaction
    pub async fn verify_transaction(&self, transaction_id: u64) -> Result<VerificationResult> {
        let url = format!("{}/api/v1/verify/transaction/{}", self.base_url, transaction_id);
        let response = self.client
            .post(&url)
            .timeout(self.timeout)
            .send()
            .await?;
            
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(VerificationError::Server(error));
        }
        
        let result: VerificationResult = response.json().await?;
        Ok(result)
    }
    
    /// Get all state commitments
    pub async fn get_state_commitments(&self) -> Result<Vec<StateCommitment>> {
        let url = format!("{}/api/v1/state-commitments", self.base_url);
        let response = self.client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await?;
            
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(VerificationError::Server(error));
        }
        
        let commitments: Vec<StateCommitment> = response.json().await?;
        Ok(commitments)
    }
    
    /// Get all challenges
    pub async fn get_challenges(&self) -> Result<Vec<Challenge>> {
        let url = format!("{}/api/v1/challenges", self.base_url);
        let response = self.client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await?;
            
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(VerificationError::Server(error));
        }
        
        let challenges: Vec<Challenge> = response.json().await?;
        Ok(challenges)
    }
    
    /// Submit a challenge
    pub async fn submit_challenge(&self, state_root: &str, block_number: u64, evidence: &[u8]) -> Result<Challenge> {
        let url = format!("{}/api/v1/challenge", self.base_url);
        let response = self.client
            .post(&url)
            .timeout(self.timeout)
            .json(&serde_json::json!({
                "state_root": state_root,
                "block_number": block_number,
                "evidence": STANDARD.encode(evidence),
            }))
            .send()
            .await?;
            
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(VerificationError::Server(error));
        }
        
        let challenge: Challenge = response.json().await?;
        Ok(challenge)
    }
    
    /// Get a challenge
    pub async fn get_challenge(&self, challenge_id: &str) -> Result<Challenge> {
        let url = format!("{}/api/v1/challenge/{}", self.base_url, challenge_id);
        let response = self.client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await?;
            
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(VerificationError::Server(error));
        }
        
        let challenge: Challenge = response.json().await?;
        Ok(challenge)
    }
    
    /// Get the latest block number
    pub async fn get_latest_block_number(&self) -> Result<u64> {
        let url = format!("{}/api/v1/block/latest", self.base_url);
        let response = self.client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await?;
            
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(VerificationError::Server(error));
        }
        
        let block_number: u64 = response.json().await?;
        Ok(block_number)
    }
} 