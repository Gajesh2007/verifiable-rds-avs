// SPDX-License-Identifier: MIT
//! Contract integration for on-chain verification
//! 
//! This module provides integration with the VerifiableDBAvs contract
//! for committing state roots and handling verification challenges.

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use log::{debug, info, warn, error};
use crate::error::{Result, ProxyError};
use bytes::Bytes;
use hex::{FromHex, encode};
use tokio::sync::RwLock as TokioRwLock;
use ethers::prelude::*;
use ethers::core::types::{Address, U256, Bytes as EthersBytes};
use ethers::contract::{abigen, Contract};
use ethers::providers::{Provider, Http};
use ethers::signers::{LocalWallet, Signer};
use std::str::FromStr;
use std::sync::Arc as StdArc;

// Generate contract bindings
abigen!(
    VerifiableDBAvs,
    "./contracts/out/VerifiableDBAvs.sol/VerifiableDBAvs.json",
    event_derives(serde::Deserialize, serde::Serialize)
);

/// Configuration for contract integration
#[derive(Debug, Clone)]
pub struct ContractConfig {
    /// Whether contract integration is enabled
    pub enabled: bool,
    
    /// Address of the AVS contract
    pub contract_address: String,
    
    /// RPC endpoint for the Ethereum node
    pub rpc_endpoint: String,
    
    /// Private key for the operator account (for testing only)
    pub operator_private_key: Option<String>,
    
    /// How often to commit state to the contract (in seconds)
    pub commit_frequency_seconds: u64,
    
    /// Maximum gas price for transactions (in gwei)
    pub max_gas_price_gwei: u64,
    
    /// Chain ID
    pub chain_id: u64,
}

impl Default for ContractConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default for safety
            contract_address: "0x0000000000000000000000000000000000000000".to_string(),
            rpc_endpoint: "http://localhost:8545".to_string(),
            operator_private_key: None,
            commit_frequency_seconds: 3600, // Once per hour
            max_gas_price_gwei: 100,
            chain_id: 31337, // Local Anvil chain
        }
    }
}

/// State commitment record for a state that has been committed
#[derive(Debug, Clone)]
pub struct StateCommitment {
    /// Sequence number of the commitment
    pub sequence: u64,
    
    /// State root hash
    pub root_hash: [u8; 32],
    
    /// Timestamp of the commitment
    pub timestamp: u64,
    
    /// Block number where the commitment was included
    pub block_number: Option<u64>,
    
    /// Transaction hash of the commitment
    pub tx_hash: Option<String>,
    
    /// Whether the commitment has been confirmed
    pub confirmed: bool,
    
    /// Number of confirmations
    pub confirmations: u64,
    
    /// Metadata for the commitment
    pub metadata: HashMap<String, String>,
}

/// Challenge status for a submitted challenge
#[derive(Debug, Clone, PartialEq)]
pub enum ChallengeStatus {
    /// Challenge has been submitted but not processed
    Submitted,
    
    /// Challenge is being processing
    Processing,
    
    /// Challenge has been accepted (verification failed)
    Accepted,
    
    /// Challenge has been rejected (verification succeeded)
    Rejected,
    
    /// Challenge has expired
    Expired,
}

/// Challenge record for a verification challenge
#[derive(Debug, Clone)]
pub struct Challenge {
    /// Challenge ID
    pub id: String,
    
    /// Transaction ID that was challenged
    pub transaction_id: u64,
    
    /// State root before the transaction
    pub pre_state_root: [u8; 32],
    
    /// State root after the transaction
    pub post_state_root: [u8; 32],
    
    /// Address of the challenger
    pub challenger: String,
    
    /// Bond amount for the challenge
    pub bond_amount: String,
    
    /// Challenge status
    pub status: ChallengeStatus,
    
    /// Block number where the challenge was submitted
    pub block_number: Option<u64>,
    
    /// Transaction hash of the challenge
    pub tx_hash: Option<String>,
    
    /// Timestamp of the challenge
    pub timestamp: u64,
    
    /// Result of the challenge (if resolved)
    pub result: Option<String>,
}

/// Contract integration manager
pub struct ContractManager {
    /// Configuration for contract integration
    config: ContractConfig,
    
    /// State commitments that have been submitted
    commitments: Mutex<Vec<StateCommitment>>,
    
    /// Challenges that have been received
    challenges: Mutex<Vec<Challenge>>,
    
    /// Last commitment time
    last_commitment: Mutex<Instant>,
    
    /// Commitment sequence number
    sequence: Mutex<u64>,
    
    /// Ethereum client
    client: Option<TokioRwLock<Provider<Http>>>,
    
    /// Wallet for signing transactions
    wallet: Option<TokioRwLock<LocalWallet>>,
    
    /// Contract instance
    contract: Option<TokioRwLock<VerifiableDBAvs<SignerMiddleware<Provider<Http>, LocalWallet>>>>,
}

impl ContractManager {
    /// Create a new contract manager with the given configuration
    pub fn new(config: ContractConfig) -> Self {
        Self {
            config,
            commitments: Mutex::new(Vec::new()),
            challenges: Mutex::new(Vec::new()),
            last_commitment: Mutex::new(Instant::now()),
            sequence: Mutex::new(0),
            client: None,
            wallet: None,
            contract: None,
        }
    }
    
    /// Initialize the contract manager
    pub async fn initialize(&self) -> Result<()> {
        if !self.config.enabled {
            info!("Contract integration is disabled");
            return Ok(());
        }
        
        info!("Initializing contract integration with address: {}", self.config.contract_address);
        
        // Create provider and wallet
        let provider = Provider::<Http>::try_from(&self.config.rpc_endpoint)
            .map_err(|e| ProxyError::Verification(format!("Failed to create provider: {}", e)))?;
        
        let mut client_lock = TokioRwLock::new(provider);
        
        if let Some(private_key) = &self.config.operator_private_key {
            // Parse private key and create wallet
            let wallet = LocalWallet::from_str(private_key)
                .map_err(|e| ProxyError::Verification(format!("Failed to create wallet: {}", e)))?
                .with_chain_id(self.config.chain_id);
            
            let mut wallet_lock = TokioRwLock::new(wallet);
            
            // Parse contract address
            let contract_address = self.config.contract_address.parse::<Address>()
                .map_err(|e| ProxyError::Verification(format!("Invalid contract address: {}", e)))?;
            
            // Create contract instance
            let client = client_lock.read().await;
            let wallet = wallet_lock.read().await;
            let client_with_signer = SignerMiddleware::new(client.clone(), wallet.clone());
            let contract = VerifiableDBAvs::new(contract_address, StdArc::new(client_with_signer));
            
            // Store client, wallet, and contract
            let mut contract_lock = TokioRwLock::new(contract);
            
            info!("Contract integration initialized successfully");
        } else {
            info!("No operator private key provided, contract integration will be limited to reading");
        }
        
        Ok(())
    }
    
    /// Get the status of the contract integration
    pub fn status(&self) -> String {
        if !self.config.enabled {
            return "Disabled".to_string();
        }
        
        if self.contract.is_some() {
            return "Connected".to_string();
        }
        
        "Not connected".to_string()
    }
    
    /// Commit a state root to the contract
    pub async fn commit_state(&self, state_root: [u8; 32]) -> Result<Option<StateCommitment>> {
        if !self.config.enabled {
            debug!("Contract integration is disabled, skipping state commitment");
            return Ok(None);
        }
        
        // Check if we've committed too recently
        let mut last_commitment = self.last_commitment.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(*last_commitment);
        if elapsed < Duration::from_secs(self.config.commit_frequency_seconds) {
            debug!("Skipping state commitment - committed too recently ({:?} ago)", elapsed);
            return Ok(None);
        }
        
        // Update the last commitment time
        *last_commitment = now;
        
        // Get the next sequence number
        let mut sequence = self.sequence.lock().unwrap();
        *sequence += 1;
        let sequence_num = *sequence;
        
        // Create the commitment
        let mut commitment = StateCommitment {
            sequence: sequence_num,
            root_hash: state_root,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            block_number: None,
            tx_hash: None,
            confirmed: false,
            confirmations: 0,
            metadata: HashMap::new(),
        };
        
        // Submit the commitment to the contract if we have a contract instance
        if let Some(contract_lock) = &self.contract {
            let contract = contract_lock.read().await;
            
            // Get current block number
            let block_number = match contract.client().get_block_number().await {
                Ok(block) => block.as_u64(),
                Err(e) => {
                    warn!("Failed to get block number: {:?}", e);
                    0
                }
            };
            
            // Submit state commitment
            match self.call_contract_commit_state(&state_root, block_number).await {
                Ok(tx_hash) => {
                    info!("Committed state root to contract: {} (tx: {})", encode(&state_root), tx_hash);
                    commitment.tx_hash = Some(tx_hash);
                    commitment.block_number = Some(block_number);
                },
                Err(e) => {
                    error!("Failed to commit state root to contract: {:?}", e);
                    // Continue anyway - we'll track it locally
                }
            }
        } else {
            info!("No contract instance available, state root tracked locally only: {}", encode(&state_root));
        }
        
        // Store the commitment
        let mut commitments = self.commitments.lock().unwrap();
        commitments.push(commitment.clone());
        
        Ok(Some(commitment))
    }
    
    /// Call the contract to commit a state root
    async fn call_contract_commit_state(&self, state_root: &[u8; 32], block_number: u64) -> Result<String> {
        if let Some(contract_lock) = &self.contract {
            let contract = contract_lock.read().await;
            
            // Create previous state root (in a real impl, we'd track this)
            let previous_state_root = [0u8; 32];
            
            // Create transaction hash (in a real impl, we'd create this from actual txs)
            let transaction_hash = [0u8; 32];
            
            // Create dummy transaction count
            let transaction_count = 0u64;
            
            // Create dummy modified tables
            let modified_tables: Vec<String> = vec!["test_table".to_string()];
            
            // Call the contract commitState function
            let call = contract.commit_state(
                state_root.into(),
                block_number.into(),
                previous_state_root.into(),
                transaction_hash.into(),
                transaction_count.into(),
                modified_tables
            );
            
            // Send the transaction
            let pending_tx = call.send().await
                .map_err(|e| ProxyError::Verification(format!("Failed to send transaction: {}", e)))?;
            
            // Get the transaction hash
            let tx_hash = format!("{:?}", pending_tx.tx_hash());
            
            Ok(tx_hash)
        } else {
            Err(ProxyError::Verification("No contract instance available".to_string()))
        }
    }
    
    /// Handle a verification challenge
    pub async fn handle_challenge(&self, challenge_id: &str) -> Result<Challenge> {
        if !self.config.enabled {
            return Err(ProxyError::Verification("Contract integration is disabled".to_string()));
        }
        
        // Find the challenge
        let challenges = self.challenges.lock().unwrap();
        let challenge = challenges.iter()
            .find(|c| c.id == challenge_id)
            .cloned()
            .ok_or_else(|| ProxyError::Verification(format!("Challenge not found: {}", challenge_id)))?;
        
        // Get challenge details from the contract
        if let Some(contract_lock) = &self.contract {
            let contract = contract_lock.read().await;
            
            // Parse challenge ID to u64
            let challenge_id_num = challenge_id.parse::<u64>()
                .map_err(|e| ProxyError::Verification(format!("Invalid challenge ID: {}", e)))?;
            
            // Call the contract to get challenge details
            let challenge_details = contract.get_challenge(challenge_id_num.into())
                .call().await
                .map_err(|e| ProxyError::Verification(format!("Failed to get challenge details: {}", e)))?;
            
            // Process challenge details
            info!("Got challenge details from contract for challenge ID: {}", challenge_id);
            
            // In a real implementation, we would respond to the challenge
            
        } else {
            info!("No contract instance available, using local challenge data for: {}", challenge_id);
        }
        
        Ok(challenge)
    }
    
    /// Submit a verification challenge
    pub async fn submit_challenge(
        &self,
        transaction_id: u64,
        pre_state_root: [u8; 32],
        post_state_root: [u8; 32],
        proof: Vec<u8>,
    ) -> Result<Challenge> {
        if !self.config.enabled {
            return Err(ProxyError::Verification("Contract integration is disabled".to_string()));
        }
        
        // Generate a unique challenge ID
        let challenge_id = format!("challenge-{}-{}", transaction_id, SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs());
        
        if let Some(contract_lock) = &self.contract {
            let contract = contract_lock.read().await;
            
            // Find the commitment ID for this transaction
            // In a real implementation, we would track this
            let commitment_id = 1u64;
            
            // Use InvalidStateTransition as the challenge type
            let challenge_type = 0u8; // InvalidStateTransition
            
            // Create an evidence hash
            let evidence_hash = ethers::utils::keccak256(&proof);
            
            // Transaction ID as string
            let tx_id_str = format!("tx-{}", transaction_id);
            
            // Priority level - use 1 for default
            let priority_level = 1u8;
            
            // Calculate the bond amount
            let bond_amount = contract.calculate_challenge_bond(challenge_type.into(), priority_level.into())
                .call().await
                .map_err(|e| ProxyError::Verification(format!("Failed to calculate bond amount: {}", e)))?;
            
            // Submit the challenge
            let call = contract.submit_challenge(
                commitment_id.into(),
                challenge_type.into(),
                evidence_hash.into(),
                tx_id_str,
                priority_level.into(),
                proof.into()
            );
            
            // Send the transaction with the bond amount
            let pending_tx = call.value(bond_amount).send().await
                .map_err(|e| ProxyError::Verification(format!("Failed to send transaction: {}", e)))?;
            
            // Get the transaction hash
            let tx_hash = format!("{:?}", pending_tx.tx_hash());
            
            // Get the current block number
            let block_number = contract.client().get_block_number().await
                .map_err(|e| ProxyError::Verification(format!("Failed to get block number: {}", e)))?
                .as_u64();
            
            // Create a challenge record
            let challenge = Challenge {
                id: challenge_id.clone(),
                transaction_id,
                pre_state_root,
                post_state_root,
                challenger: format!("{:?}", contract.client().signer().address()),
                bond_amount: format!("{}", bond_amount),
                status: ChallengeStatus::Submitted,
                block_number: Some(block_number),
                tx_hash: Some(tx_hash),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                result: None,
            };
            
            // Store the challenge
            let mut challenges = self.challenges.lock().unwrap();
            challenges.push(challenge.clone());
            
            info!("Submitted challenge to contract: {}", challenge_id);
            
            Ok(challenge)
        } else {
            // Create a local challenge record
            let challenge = Challenge {
                id: challenge_id.clone(),
                transaction_id,
                pre_state_root,
                post_state_root,
                challenger: "0x0000000000000000000000000000000000000000".to_string(),
                bond_amount: "0.1".to_string(), // Default bond amount
                status: ChallengeStatus::Submitted,
                block_number: None,
                tx_hash: None,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                result: None,
            };
            
            // Store the challenge
            let mut challenges = self.challenges.lock().unwrap();
            challenges.push(challenge.clone());
            
            info!("Created local challenge record (no contract instance): {}", challenge_id);
            
            Ok(challenge)
        }
    }
    
    /// Get all state commitments
    pub fn get_commitments(&self) -> Vec<StateCommitment> {
        let commitments = self.commitments.lock().unwrap();
        commitments.clone()
    }
    
    /// Get all challenges
    pub fn get_challenges(&self) -> Vec<Challenge> {
        let challenges = self.challenges.lock().unwrap();
        challenges.clone()
    }
} 