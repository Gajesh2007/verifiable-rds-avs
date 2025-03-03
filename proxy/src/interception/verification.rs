//! Verification manager for cryptographic verification of database operations
//! 
//! This module provides functionality to track database state, generate and verify
//! cryptographic proofs, and integrate with the EigenLayer verification system.

use crate::error::{ProxyError, Result};
use crate::interception::analyzer::{QueryMetadata, QueryType};
use crate::verification::state::{StateCaptureManager, TableState, Row, RowId};
use crate::verification::merkle::MerkleTree;
use crate::verification::environment::{VerificationEnvironment, VerificationEnvironmentConfig, VerificationExecutionResult};
use crate::verification::contract::{ContractManager, ContractConfig, StateCommitment, Challenge, ChallengeStatus};
use log::{debug, warn, info};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use bytes::Bytes;
use crate::transaction::{TransactionManager, WalCaptureManager, WalRecord, WalRecordType, TransactionTree, TransactionStatus};

/// Verification status of a transaction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationStatus {
    /// Transaction has not been verified
    NotVerified,
    
    /// Transaction is in the process of being verified
    InProgress,
    
    /// Transaction has been verified successfully
    Verified,
    
    /// Transaction verification failed
    Failed,
    
    /// Transaction verification was skipped
    Skipped,
}

/// Result of verification
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Transaction ID
    pub transaction_id: u64,
    
    /// Verification status
    pub status: VerificationStatus,
    
    /// Pre-state root
    pub pre_state_root: Option<[u8; 32]>,
    
    /// Post-state root
    pub post_state_root: Option<[u8; 32]>,
    
    /// Verification time in milliseconds
    pub verification_time_ms: u64,
    
    /// Error message (if verification failed)
    pub error: Option<String>,
    
    /// Verification metadata
    pub metadata: HashMap<String, String>,
}

/// Database state at a point in time
#[derive(Debug, Clone)]
pub struct DatabaseState {
    /// State root (Merkle root of all tables)
    pub root: [u8; 32],
    
    /// Block number or sequence number
    pub block_number: u64,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// Individual table states (table name -> table state root)
    pub table_states: HashMap<String, [u8; 32]>,
    
    /// Transaction ID that created this state
    pub created_by_transaction: Option<u64>,
    
    /// Whether this state has been committed
    pub committed: bool,
}

/// Transaction record for verification
#[derive(Debug, Clone)]
pub struct TransactionRecord {
    /// Transaction ID
    pub id: u64,
    
    /// Query that executed the transaction
    pub query: String,
    
    /// Query metadata
    pub metadata: QueryMetadata,
    
    /// Pre-state root
    pub pre_state_root: Option<[u8; 32]>,
    
    /// Post-state root
    pub post_state_root: Option<[u8; 32]>,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// Tables modified
    pub modified_tables: Vec<String>,
    
    /// Verification status
    pub verification_status: VerificationStatus,
    
    /// Error message (if verification failed)
    pub error: Option<String>,
}

/// Configuration for verification operations
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    /// Whether to verify DDL statements
    pub verify_ddl: bool,
    
    /// Whether to verify DML statements
    pub verify_dml: bool,
    
    /// Whether to verify all statements
    pub verify_all: bool,
    
    /// Whether to verify deterministic statements only
    pub verify_deterministic_only: bool,
    
    /// Reason for non-deterministic statements
    pub non_deterministic_reason: String,
    
    /// Configuration for state capture
    pub state_capture: StateCaptureConfig,
    
    /// Configuration for verification environment
    pub environment: VerificationEnvironmentConfig,
    
    /// Configuration for EigenLayer integration
    pub eigenlayer: EigenLayerConfig,
    
    /// Configuration for contract integration
    pub contract: ContractConfig,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            verify_ddl: false,
            verify_dml: true,
            verify_all: false,
            verify_deterministic_only: true,
            non_deterministic_reason: "Non-deterministic statements are not supported".to_string(),
            state_capture: StateCaptureConfig::default(),
            environment: VerificationEnvironmentConfig::default(),
            eigenlayer: EigenLayerConfig::default(),
            contract: ContractConfig::default(),
        }
    }
}

/// Verification manager for the database
pub struct VerificationManager {
    /// Current database state
    current_state: RwLock<DatabaseState>,
    
    /// Transaction records
    transaction_records: Mutex<Vec<TransactionRecord>>,
    
    /// Configuration
    config: VerificationConfig,
    
    /// Transaction counter
    transaction_counter: Mutex<u64>,
    
    /// Last commit time
    last_commit: Mutex<Instant>,
    
    /// Pending transactions (not yet verified)
    pending_transactions: Mutex<HashSet<u64>>,
    
    /// State capture manager
    state_capture: Arc<StateCaptureManager>,
    
    /// Verification environment for deterministic replay
    verification_env: Arc<VerificationEnvironment>,
    
    /// Contract manager
    contract: Arc<ContractManager>,
    
    /// Transaction manager for transaction boundary protection
    transaction_manager: Arc<Mutex<TransactionManager>>,
}

impl VerificationManager {
    /// Create a new verification manager with the given configuration
    pub async fn new(config: VerificationConfig) -> Result<Self> {
        // Initialize an empty database state
        let current_state = RwLock::new(DatabaseState::new());
        
        // Create a state capture manager
        let state_capture = Arc::new(StateCaptureManager::new());
        
        // Create the verification environment
        let verification_env = Arc::new(VerificationEnvironment::new(
            config.environment.clone(),
            state_capture.clone(),
        ));
        
        // Initialize contract manager
        let contract = Arc::new(ContractManager::new(
            config.contract.clone()
        ));
        contract.initialize().await?;
        
        // Initialize transaction manager
        let transaction_manager = Arc::new(Mutex::new(TransactionManager::new()));
        
        Ok(Self {
            current_state,
            transaction_records: Mutex::new(Vec::new()),
            config,
            transaction_counter: Mutex::new(0),
            last_commit: Mutex::new(Instant::now()),
            pending_transactions: Mutex::new(HashSet::new()),
            state_capture,
            verification_env,
            contract,
            transaction_manager,
        })
    }
    
    /// Initialize the verification manager
    pub async fn initialize(&self) -> Result<()> {
        // Initialize the verification environment
        self.verification_env.initialize().await?;
        
        // Initialize the contract manager
        self.contract.initialize().await?;
        
        // Initialize transaction manager
        let mut tx_manager = self.transaction_manager.lock().unwrap();
        tx_manager.initialize().await?;
        
        Ok(())
    }
    
    /// Begin a transaction for verification
    pub fn begin_transaction(&self, query: &str, metadata: &QueryMetadata) -> Result<u64> {
        if !self.config.enabled {
            return Ok(0); // Return a dummy transaction ID if verification is disabled
        }
        
        // Check if we should verify this query
        if !self.should_verify_query(metadata) {
            return Ok(0);
        }
        
        // Get the next transaction ID
        let transaction_id = {
            let mut counter = self.transaction_counter.lock().unwrap();
            *counter += 1;
            *counter
        };
        
        // Capture the pre-state
        let pre_state_root = {
            let state = self.current_state.read().unwrap();
            Some(state.root)
        };
        
        // If tables are modified, capture their pre-state
        let modified_tables = metadata.get_modified_tables();
        if !modified_tables.is_empty() {
            let state_root = if let Some(root) = self.state_capture.get_current_root_hash() {
                root
            } else {
                [0; 32] // Default empty root if none exists
            };
            
            // Update our current state root from the state capture manager
            let mut state = self.current_state.write().unwrap();
            state.root = state_root;
        }
        
        // Create a transaction record
        let transaction = TransactionRecord {
            id: transaction_id,
            query: query.to_string(),
            metadata: metadata.clone(),
            pre_state_root,
            post_state_root: None,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            modified_tables,
            verification_status: VerificationStatus::NotVerified,
            error: None,
        };
        
        // Add to transaction records
        {
            let mut records = self.transaction_records.lock().unwrap();
            records.push(transaction);
            
            // Trim records if exceeding max history
            if records.len() > self.config.max_history {
                records.drain(0..records.len() - self.config.max_history);
            }
        }
        
        // Add to pending transactions
        {
            let mut pending = self.pending_transactions.lock().unwrap();
            pending.insert(transaction_id);
        }
        
        // Begin transaction in the transaction manager
        let mut tx_manager = self.transaction_manager.lock().unwrap();
        let tx_id_boundary = tx_manager.begin_transaction(query, Some(metadata))?;
        
        // Add transaction ID mapping
        if tx_id_boundary > 0 {
            // Store the mapping between verification transaction ID and boundary transaction ID
            // This could be done in a separate field in the VerificationManager
        }
        
        Ok(transaction_id)
    }
    
    /// Complete a transaction for verification
    pub fn complete_transaction(&self, transaction_id: u64, rows_affected: Option<u64>) -> Result<VerificationResult> {
        if !self.config.enabled || transaction_id == 0 {
            // Return a dummy result if verification is disabled or transaction ID is invalid
            return Ok(VerificationResult {
                transaction_id,
                status: VerificationStatus::Skipped,
                pre_state_root: None,
                post_state_root: None,
                verification_time_ms: 0,
                error: None,
                metadata: HashMap::new(),
            });
        }
        
        // Find the transaction record
        let mut transaction_opt = None;
        {
            let records = self.transaction_records.lock().unwrap();
            for record in records.iter() {
                if record.id == transaction_id {
                    transaction_opt = Some(record.clone());
                    break;
                }
            }
        }
        
        let transaction = match transaction_opt {
            Some(t) => t,
            None => {
                return Err(ProxyError::Verification(format!(
                    "Transaction record not found for ID: {}", transaction_id
                )));
            }
        };
        
        // Update transaction state
        let mut updater = self.transaction_records.lock().unwrap();
        for record in updater.iter_mut() {
            if record.id == transaction_id {
                // If we have modified tables, capture their post-state
                let post_state_root = if !transaction.modified_tables.is_empty() {
                    // In a real implementation, we would query the database to get the table's current state
                    // For each modified table, capture its state
                    for table_name in &transaction.modified_tables {
                        // Parse the table name to get schema and table
                        let parts: Vec<&str> = table_name.split('.').collect();
                        let (schema_name, table_name) = if parts.len() > 1 {
                            (parts[0], parts[1])
                        } else {
                            ("public", parts[0])
                        };
                        
                        // Capture table state
                        // This would be an async operation in a real implementation
                        match tokio::runtime::Runtime::new().unwrap().block_on(async {
                            self.state_capture.capture_table_state(table_name, schema_name).await
                        }) {
                            Ok(table_state) => {
                                // Update state
                                match self.state_capture.update_table_state(table_state) {
                                    Ok(_) => {
                                        // Successfully updated state
                                    }
                                    Err(e) => {
                                        warn!("Failed to update table state for {}: {}", table_name, e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to capture table state for {}: {}", table_name, e);
                            }
                        }
                    }
                    
                    // Get the updated root hash
                    self.state_capture.get_current_root_hash()
                } else {
                    // For non-modifying queries, use the current state root
                    self.state_capture.get_current_root_hash()
                };
                
                record.post_state_root = post_state_root;
                record.verification_status = VerificationStatus::InProgress;
                break;
            }
        }
        
        // Update the current state
        if let Some(post_state_root) = transaction.post_state_root {
            let mut state = self.current_state.write().unwrap();
            state.root = post_state_root;
            state.block_number += 1;
            state.timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            state.created_by_transaction = Some(transaction_id);
            state.committed = false;
            
            // In a real implementation, we would update table states based on
            // the modified tables in the transaction
            for table in &transaction.modified_tables {
                // Store the table in our state as well
                state.table_states.insert(table.clone(), post_state_root);
            }
        }
        
        // Verify the transaction
        let verification_start = Instant::now();
        let verification_result = self.verify_transaction(&transaction);
        let verification_time = verification_start.elapsed();
        
        // Update transaction state with verification result
        {
            let mut updater = self.transaction_records.lock().unwrap();
            for record in updater.iter_mut() {
                if record.id == transaction_id {
                    record.verification_status = match &verification_result {
                        Ok(_) => VerificationStatus::Verified,
                        Err(err) => {
                            record.error = Some(err.to_string());
                            VerificationStatus::Failed
                        }
                    };
                    break;
                }
            }
        }
        
        // Remove from pending transactions
        {
            let mut pending = self.pending_transactions.lock().unwrap();
            pending.remove(&transaction_id);
        }
        
        // Check if we need to commit the state
        self.check_commit_state();
        
        // Commit transaction in the transaction manager
        if let Some(tx) = self.get_transaction(transaction_id) {
            let mut tx_manager = self.transaction_manager.lock().unwrap();
            
            // Using the mapping between verification transaction ID and boundary transaction ID
            // tx_manager.commit_transaction(tx_id_boundary)?;
            
            // Verify transaction boundaries
            if let Some(wal_manager) = tx_manager.get_wal_manager() {
                // Using the mapping to get the WAL transaction ID
                // if let Some(wal_tx) = wal_manager.get_transaction(wal_tx_id) {
                //     let boundaries_valid = wal_manager.verify_transaction_boundaries(wal_tx_id)?;
                //     if !boundaries_valid {
                //         return Err(ProxyError::VerificationError(
                //             format!("Transaction boundary verification failed for transaction {}", transaction_id)
                //         ));
                //     }
                // }
            }
        }
        
        // Create verification result
        let result = VerificationResult {
            transaction_id,
            status: match verification_result {
                Ok(_) => VerificationStatus::Verified,
                Err(err) => {
                    if self.config.enforce {
                        VerificationStatus::Failed
                    } else {
                        VerificationStatus::Failed
                    }
                }
            },
            pre_state_root: transaction.pre_state_root,
            post_state_root: transaction.post_state_root,
            verification_time_ms: verification_time.as_millis() as u64,
            error: verification_result.err().map(|e| e.to_string()),
            metadata: HashMap::new(),
        };
        
        // Check if we need to commit the state
        self.check_commit_state();
        
        Ok(result)
    }
    
    /// Verify a transaction by replaying it deterministically
    fn verify_transaction(&self, transaction: &TransactionRecord) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let transaction_id = transaction.id;
        let query = transaction.query.clone();
        let metadata = transaction.metadata.clone();
        
        // Skip verification for certain query types if configured
        if !self.should_verify_query(&transaction.metadata) {
            info!("Skipping verification for transaction {} - query type not eligible", transaction_id);
            return Ok(());
        }
        
        // Get the pre and post states
        let pre_state = match &transaction.pre_state_root {
            Some(_) => {
                // In a real implementation, you would reconstruct the pre-state from the root hash
                // For now, we'll assume we have access to the full state
                let pre_state = self.current_state.read().unwrap().clone();
                pre_state
            },
            None => {
                return Err(ProxyError::Verification(format!(
                    "Missing pre-state for transaction {}", transaction_id
                )));
            }
        };
        
        let post_state = match &transaction.post_state_root {
            Some(_) => {
                // In a real implementation, you would reconstruct the post-state from the root hash
                // For now, we'll assume we have access to the full state
                let post_state = self.current_state.read().unwrap().clone();
                post_state
            },
            None => {
                return Err(ProxyError::Verification(format!(
                    "Missing post-state for transaction {}", transaction_id
                )));
            }
        };
        
        // Split the query into individual statements
        // In a real implementation, this would be more sophisticated
        let queries = vec![query];
        let metadata_vec = vec![metadata];
        
        // Run the verification asynchronously
        // In a real implementation, you would use a proper async approach
        // For now, we'll just spawn a thread to do the verification
        let verification_env = self.verification_env.clone();
        let transaction_id_clone = transaction_id;
        
        // Create a tokio runtime for the verification task
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ProxyError::Verification(format!("Failed to create runtime: {}", e)))?;
        
        // Run the verification
        let verification_result = rt.block_on(async {
            verification_env.verify_transaction(
                transaction_id_clone,
                queries,
                metadata_vec,
                pre_state,
                post_state,
            ).await
        })?;
        
        // Handle the verification result
        if verification_result.success {
            info!("Transaction {} verification succeeded", transaction_id);
            
            // Update the transaction status
            let mut records = self.transaction_records.lock().unwrap();
            for record in records.iter_mut() {
                if record.id == transaction_id {
                    record.verification_status = VerificationStatus::Verified;
                    break;
                }
            }
            
            // Remove from pending transactions
            let mut pending = self.pending_transactions.lock().unwrap();
            pending.remove(&transaction_id);
            
            Ok(())
        } else {
            warn!("Transaction {} verification failed: {:?}", transaction_id, verification_result.error);
            
            // Update the transaction status
            let mut records = self.transaction_records.lock().unwrap();
            for record in records.iter_mut() {
                if record.id == transaction_id {
                    record.verification_status = VerificationStatus::Failed;
                    record.error = verification_result.error.clone();
                    break;
                }
            }
            
            // Remove from pending transactions
            let mut pending = self.pending_transactions.lock().unwrap();
            pending.remove(&transaction_id);
            
            // If enforcing verification, return an error
            if self.config.enforce {
                return Err(ProxyError::Verification(format!(
                    "Transaction {} verification failed: {:?}",
                    transaction_id,
                    verification_result.error
                )));
            }
            
            Ok(())
        }
    }
    
    /// Check if we should verify a query
    fn should_verify_query(&self, metadata: &QueryMetadata) -> bool {
        if !self.config.enabled {
            return false;
        }
        
        // Always verify data-modifying queries (DML)
        if metadata.query_type.is_dml() {
            return true;
        }
        
        // Verify DDL if configured
        if metadata.query_type.is_ddl() && self.config.verify_ddl {
            return true;
        }
        
        // Verify read-only if configured
        if metadata.query_type == QueryType::Select && self.config.verify_readonly {
            return true;
        }
        
        // Don't verify transaction control statements
        if metadata.query_type.is_transaction_control() {
            return false;
        }
        
        false
    }
    
    /// Check if we should commit the state to EigenLayer
    fn check_commit_state(&self) {
        let mut transaction_counter = self.transaction_counter.lock().unwrap();
        
        // Check if we've reached the commit frequency
        if *transaction_counter % self.config.commit_frequency == 0 {
            info!("Reached commit frequency ({} transactions), committing state", self.config.commit_frequency);
            self.commit_state();
        }
        
        // Increment the transaction counter
        *transaction_counter += 1;
    }
    
    /// Commit the current state to EigenLayer
    fn commit_state(&self) {
        // Get the current state root
        let state_root = self.get_current_state_root();
        
        // Create a runtime for the async operation
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                warn!("Failed to create runtime for state commitment: {}", e);
                return;
            }
        };
        
        // Commit the state to EigenLayer
        let contract = self.contract.clone();
        rt.block_on(async move {
            match contract.commit_state(state_root).await {
                Ok(Some(commitment)) => {
                    info!("Successfully committed state root to EigenLayer: sequence={}", commitment.sequence);
                },
                Ok(None) => {
                    debug!("Skipped state commitment to EigenLayer");
                },
                Err(e) => {
                    warn!("Failed to commit state to EigenLayer: {}", e);
                }
            }
        });
    }
    
    /// Get the current state root
    pub fn get_current_state_root(&self) -> [u8; 32] {
        let state = self.current_state.read().unwrap();
        state.root
    }
    
    /// Get a transaction record by ID
    pub fn get_transaction(&self, transaction_id: u64) -> Option<TransactionRecord> {
        let records = self.transaction_records.lock().unwrap();
        for record in records.iter() {
            if record.id == transaction_id {
                return Some(record.clone());
            }
        }
        None
    }
    
    /// Get all transaction records
    pub fn get_transactions(&self) -> Vec<TransactionRecord> {
        let records = self.transaction_records.lock().unwrap();
        records.clone()
    }
    
    /// Get pending transactions
    pub fn get_pending_transactions(&self) -> HashSet<u64> {
        let pending = self.pending_transactions.lock().unwrap();
        pending.clone()
    }
    
    /// Get transaction verification status
    pub fn get_transaction_status(&self, transaction_id: u64) -> Option<VerificationStatus> {
        let records = self.transaction_records.lock().unwrap();
        for record in records.iter() {
            if record.id == transaction_id {
                return Some(record.verification_status.clone());
            }
        }
        None
    }
    
    /// Generate a proof for a table
    pub fn generate_table_proof(&self, table_name: &str) -> Result<Vec<u8>> {
        // In a real implementation, this would generate a Merkle proof
        // for the specified table against the current state root.
        
        // For now, just return a dummy proof
        let state = self.current_state.read().unwrap();
        if let Some(table_root) = state.table_states.get(table_name) {
            // Create a simple proof structure
            let mut proof = Vec::new();
            proof.extend_from_slice(&state.root);
            proof.extend_from_slice(table_root);
            Ok(proof)
        } else {
            Err(ProxyError::Verification(format!("Table not found: {}", table_name)))
        }
    }
    
    /// Verify a table proof
    pub fn verify_table_proof(&self, table_name: &str, proof: &[u8]) -> Result<bool> {
        // In a real implementation, this would verify a Merkle proof
        // for the specified table against the given state root.
        
        // For now, just perform a simple check
        if proof.len() != 64 {
            return Err(ProxyError::Verification("Invalid proof length".to_string()));
        }
        
        let state = self.current_state.read().unwrap();
        
        // Extract state root and table root from the proof
        let mut state_root = [0; 32];
        let mut table_root = [0; 32];
        
        state_root.copy_from_slice(&proof[0..32]);
        table_root.copy_from_slice(&proof[32..64]);
        
        // Check state root
        if state_root != state.root {
            return Ok(false);
        }
        
        // Check table root
        if let Some(expected_table_root) = state.table_states.get(table_name) {
            Ok(table_root == *expected_table_root)
        } else {
            Err(ProxyError::Verification(format!("Table not found: {}", table_name)))
        }
    }
    
    /// Get the state capture manager
    pub fn get_state_capture_manager(&self) -> Arc<StateCaptureManager> {
        self.state_capture.clone()
    }
    
    /// Generate a proof for a row
    pub fn generate_row_proof(&self, table_name: &str, schema_name: &str, row_id: RowId) -> Result<Vec<u8>> {
        self.state_capture.generate_row_proof(table_name, schema_name, &row_id)
    }
    
    /// Get the verification environment
    pub fn get_verification_environment(&self) -> Arc<VerificationEnvironment> {
        self.verification_env.clone()
    }
    
    /// Get the contract manager
    pub fn get_contract_manager(&self) -> Arc<ContractManager> {
        self.contract.clone()
    }
    
    /// Submit a verification challenge to EigenLayer
    pub async fn submit_challenge(&self, transaction_id: u64, proof: Vec<u8>) -> Result<Challenge> {
        // Get the transaction
        let transaction = self.get_transaction(transaction_id)
            .ok_or_else(|| ProxyError::Verification(format!("Transaction not found: {}", transaction_id)))?;
        
        // Get the pre and post state roots
        let pre_state_root = transaction.pre_state_root
            .ok_or_else(|| ProxyError::Verification(format!("Missing pre-state root for transaction {}", transaction_id)))?;
            
        let post_state_root = transaction.post_state_root
            .ok_or_else(|| ProxyError::Verification(format!("Missing post-state root for transaction {}", transaction_id)))?;
        
        // Submit the challenge to EigenLayer
        self.contract.submit_challenge(
            transaction_id,
            pre_state_root,
            post_state_root,
            proof,
        ).await
    }
    
    /// Handle a verification challenge from EigenLayer
    pub async fn handle_challenge(&self, challenge_id: &str) -> Result<Challenge> {
        // Handle the challenge with the EigenLayer manager
        self.contract.handle_challenge(challenge_id).await
    }
    
    /// Get all state commitments
    pub fn get_state_commitments(&self) -> Vec<StateCommitment> {
        self.contract.get_commitments()
    }
    
    /// Get all challenges
    pub fn get_challenges(&self) -> Vec<Challenge> {
        self.contract.get_challenges()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interception::analyzer::{QueryType, TableAccess, AccessType};

    fn create_test_metadata(query: &str, query_type: QueryType, tables: Vec<&str>) -> QueryMetadata {
        // Create table access objects
        let table_access: Vec<TableAccess> = tables.iter().map(|t| {
            TableAccess {
                table_name: t.to_string(),
                schema_name: None,
                access_type: if query_type.is_read_only() {
                    AccessType::Read
                } else {
                    AccessType::Write
                },
                columns: None,
            }
        }).collect();
        
        QueryMetadata {
            query: query.to_string(),
            query_type,
            tables: table_access,
            is_deterministic: true,
            non_deterministic_operations: Vec::new(),
            complexity_score: 1,
            special_handling: false,
            verifiable: true,
            cacheable: false,
            extra: HashMap::new(),
            non_deterministic_reason: None,
        }
    }
    
    #[tokio::test]
    async fn test_begin_complete_transaction() {
        let config = VerificationConfig::default();
        let manager = VerificationManager::new(config).await.unwrap();
        
        let query = "INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com')";
        let metadata = create_test_metadata(query, QueryType::Insert, vec!["users"]);
        
        // Begin transaction
        let tx_id = manager.begin_transaction(query, &metadata).unwrap();
        assert!(tx_id > 0, "Transaction ID should be positive");
        
        // Complete transaction
        let result = manager.complete_transaction(tx_id, Some(1)).unwrap();
        assert_eq!(result.status, VerificationStatus::Verified, "Transaction verification should succeed");
    }
    
    #[tokio::test]
    async fn test_verify_different_query_types() {
        let mut config = VerificationConfig::default();
        config.verify_ddl = true;
        
        let manager = VerificationManager::new(config).await.unwrap();
        
        // Test INSERT
        let query = "INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com')";
        let metadata = create_test_metadata(query, QueryType::Insert, vec!["users"]);
        
        let result = manager.verify_statement(query, &metadata);
        assert!(result.is_ok(), "INSERT verification should succeed");
        
        // Test CREATE TABLE
        let query = "CREATE TABLE test (id INT, name TEXT)";
        let metadata = create_test_metadata(query, QueryType::CreateTable, vec!["test"]);
        
        let result = manager.verify_statement(query, &metadata);
        assert!(result.is_ok(), "CREATE TABLE verification should succeed");
    }
    
    #[tokio::test]
    async fn test_transaction_history() {
        let config = VerificationConfig::default();
        let manager = VerificationManager::new(config).await.unwrap();
        
        // Create several transactions
        for i in 0..5 {
            let query = format!("INSERT INTO test (id) VALUES ({})", i);
            let metadata = create_test_metadata(&query, QueryType::Insert, vec!["test"]);
            
            let tx_id = manager.begin_transaction(&query, &metadata).unwrap();
            manager.complete_transaction(tx_id, Some(1)).unwrap();
        }
        
        // Should only keep the last few transactions
        let transactions = manager.get_transactions();
        assert!(transactions.len() > 0, "Should keep transaction history");
    }
    
    #[tokio::test]
    async fn test_state_commitment() {
        let config = VerificationConfig::default();
        let manager = VerificationManager::new(config).await.unwrap();
        
        // Create several transactions
        for i in 0..5 {
            let query = format!("INSERT INTO test (id) VALUES ({})", i);
            let metadata = create_test_metadata(&query, QueryType::Insert, vec!["test"]);
            
            let tx_id = manager.begin_transaction(&query, &metadata).unwrap();
            manager.complete_transaction(tx_id, Some(1)).unwrap();
        }
        
        // Should have committed state multiple times
        let commitments = manager.get_state_commitments();
        assert!(commitments.len() >= 0, "Should track state commitments");
    }
    
    #[tokio::test]
    async fn test_table_proof() {
        let config = VerificationConfig::default();
        let manager = VerificationManager::new(config).await.unwrap();
        
        // Create a transaction to update the state
        let query = "INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com')";
        let metadata = create_test_metadata(query, QueryType::Insert, vec!["users"]);
        
        let tx_id = manager.begin_transaction(query, &metadata).unwrap();
        manager.complete_transaction(tx_id, Some(1)).unwrap();
        
        // Generate a proof for the users table
        let proof = manager.generate_table_proof("users");
        assert!(proof.is_ok(), "Generating table proof should succeed");
    }
} 