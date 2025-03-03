//! WAL (Write-Ahead Log) capture and analysis module
//! 
//! This module provides functionality to capture and analyze PostgreSQL WAL records
//! for complete transaction boundary protection and verification.

use crate::error::{ProxyError, Result};
use crate::transaction::Transaction;
use log::{debug, info, warn, error};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

/// Types of WAL records
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalRecordType {
    /// Begin transaction
    Begin,
    /// Commit transaction
    Commit,
    /// Abort transaction
    Abort,
    /// Insert tuple
    Insert,
    /// Update tuple
    Update,
    /// Delete tuple
    Delete,
    /// Truncate table
    Truncate,
    /// Create savepoint
    Savepoint,
    /// Release savepoint
    ReleaseSavepoint,
    /// Rollback to savepoint
    RollbackToSavepoint,
    /// DDL operation
    Ddl,
    /// Other operation
    Other(String),
}

/// WAL record structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalRecord {
    /// Log sequence number
    pub lsn: u64,
    
    /// Transaction ID
    pub txid: u64,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// Record type
    pub record_type: WalRecordType,
    
    /// Relation ID (table OID)
    pub relation_id: Option<u32>,
    
    /// Relation name
    pub relation_name: Option<String>,
    
    /// Record data (serialized)
    pub data: Vec<u8>,
    
    /// Record checksum
    pub checksum: [u8; 32],
    
    /// Whether this is a savepoint-related record
    pub is_savepoint: bool,
    
    /// Savepoint name (if relevant)
    pub savepoint_name: Option<String>,
}

/// Savepoint record structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavepointRecord {
    /// Savepoint name
    pub name: String,
    
    /// Savepoint ID
    pub id: u64,
    
    /// Parent transaction ID
    pub txid: u64,
    
    /// Whether the savepoint has been released
    pub released: bool,
    
    /// Whether the transaction has rolled back to this savepoint
    pub rolled_back: bool,
    
    /// LSN at which the savepoint was created
    pub start_lsn: u64,
    
    /// LSN at which the savepoint was released or rolled back (if applicable)
    pub end_lsn: Option<u64>,
    
    /// WAL records within this savepoint
    pub records: Vec<WalRecord>,
}

/// Transaction tree structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionTree {
    /// Transaction ID
    pub txid: u64,
    
    /// Transaction LSN range
    pub start_lsn: u64,
    pub end_lsn: Option<u64>,
    
    /// Transaction status
    pub status: TransactionStatus,
    
    /// WAL records in this transaction
    pub records: Vec<WalRecord>,
    
    /// Savepoints in this transaction
    pub savepoints: HashMap<String, SavepointRecord>,
    
    /// Checksum of all WAL records
    pub records_checksum: [u8; 32],
}

/// Transaction status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Transaction is in progress
    InProgress,
    /// Transaction has been committed
    Committed,
    /// Transaction has been aborted
    Aborted,
}

/// WAL capture manager
#[derive(Debug)]
pub struct WalCaptureManager {
    /// Connection to PostgreSQL for WAL streaming
    // In a real implementation, this would connect to PostgreSQL's logical replication
    // For now, we'll simulate it
    // conn: PgReplicationConnection,
    
    /// Current transactions (indexed by transaction ID)
    transactions: Mutex<HashMap<u64, TransactionTree>>,
    
    /// Maximum number of transactions to keep in memory
    max_transactions: usize,
    
    /// Active transaction IDs
    active_transactions: Mutex<HashSet<u64>>,
    
    /// Completed transaction queue (for cleanup)
    completed_transactions: Mutex<VecDeque<u64>>,
    
    /// LSN watermark (earliest LSN needed for active transactions)
    lsn_watermark: Mutex<u64>,
    
    /// Whether WAL capture is enabled
    enabled: bool,
}

impl WalCaptureManager {
    /// Create a new WAL capture manager
    pub fn new(max_transactions: usize) -> Self {
        Self {
            transactions: Mutex::new(HashMap::new()),
            max_transactions,
            active_transactions: Mutex::new(HashSet::new()),
            completed_transactions: Mutex::new(VecDeque::new()),
            lsn_watermark: Mutex::new(0),
            enabled: true,
        }
    }
    
    /// Initialize the WAL capture manager
    pub async fn initialize(&self) -> Result<()> {
        // In a real implementation, this would set up logical replication
        // For now, we'll simulate it
        info!("Initializing WAL capture manager");
        
        Ok(())
    }
    
    /// Start capturing WAL records
    pub async fn start(&self) -> Result<()> {
        // In a real implementation, this would start WAL streaming
        // For now, we'll simulate it
        info!("Starting WAL capture");
        
        Ok(())
    }
    
    /// Stop capturing WAL records
    pub async fn stop(&self) -> Result<()> {
        // In a real implementation, this would stop WAL streaming
        // For now, we'll simulate it
        info!("Stopping WAL capture");
        
        Ok(())
    }
    
    /// Process a WAL record
    pub fn process_record(&self, record: WalRecord) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        
        match record.record_type {
            WalRecordType::Begin => {
                // Start tracking a new transaction
                let mut active_txns = self.active_transactions.lock().unwrap();
                active_txns.insert(record.txid);
                
                let mut txns = self.transactions.lock().unwrap();
                txns.insert(record.txid, TransactionTree {
                    txid: record.txid,
                    start_lsn: record.lsn,
                    end_lsn: None,
                    status: TransactionStatus::InProgress,
                    records: vec![record.clone()],
                    savepoints: HashMap::new(),
                    records_checksum: [0; 32],
                });
            },
            WalRecordType::Commit => {
                // Mark transaction as committed
                let mut txns = self.transactions.lock().unwrap();
                if let Some(tx) = txns.get_mut(&record.txid) {
                    tx.status = TransactionStatus::Committed;
                    tx.end_lsn = Some(record.lsn);
                    tx.records.push(record.clone());
                    
                    // Update checksum
                    let mut hasher = Sha256::new();
                    for rec in &tx.records {
                        hasher.update(&rec.checksum);
                    }
                    tx.records_checksum = hasher.finalize().into();
                }
                
                // Remove from active transactions
                let mut active_txns = self.active_transactions.lock().unwrap();
                active_txns.remove(&record.txid);
                
                // Add to completed transactions for cleanup
                let mut completed = self.completed_transactions.lock().unwrap();
                completed.push_back(record.txid);
                
                // Cleanup if needed
                self.cleanup()?;
            },
            WalRecordType::Abort => {
                // Mark transaction as aborted
                let mut txns = self.transactions.lock().unwrap();
                if let Some(tx) = txns.get_mut(&record.txid) {
                    tx.status = TransactionStatus::Aborted;
                    tx.end_lsn = Some(record.lsn);
                    tx.records.push(record.clone());
                    
                    // Update checksum
                    let mut hasher = Sha256::new();
                    for rec in &tx.records {
                        hasher.update(&rec.checksum);
                    }
                    tx.records_checksum = hasher.finalize().into();
                }
                
                // Remove from active transactions
                let mut active_txns = self.active_transactions.lock().unwrap();
                active_txns.remove(&record.txid);
                
                // Add to completed transactions for cleanup
                let mut completed = self.completed_transactions.lock().unwrap();
                completed.push_back(record.txid);
                
                // Cleanup if needed
                self.cleanup()?;
            },
            WalRecordType::Savepoint => {
                // Track savepoint
                let mut txns = self.transactions.lock().unwrap();
                if let Some(tx) = txns.get_mut(&record.txid) {
                    tx.records.push(record.clone());
                    
                    if let Some(savepoint_name) = &record.savepoint_name {
                        tx.savepoints.insert(savepoint_name.clone(), SavepointRecord {
                            name: savepoint_name.clone(),
                            id: tx.savepoints.len() as u64,
                            txid: record.txid,
                            released: false,
                            rolled_back: false,
                            start_lsn: record.lsn,
                            end_lsn: None,
                            records: vec![record.clone()],
                        });
                    }
                }
            },
            WalRecordType::ReleaseSavepoint => {
                // Mark savepoint as released
                let mut txns = self.transactions.lock().unwrap();
                if let Some(tx) = txns.get_mut(&record.txid) {
                    tx.records.push(record.clone());
                    
                    if let Some(savepoint_name) = &record.savepoint_name {
                        if let Some(savepoint) = tx.savepoints.get_mut(savepoint_name) {
                            savepoint.released = true;
                            savepoint.end_lsn = Some(record.lsn);
                            savepoint.records.push(record.clone());
                        }
                    }
                }
            },
            WalRecordType::RollbackToSavepoint => {
                // Mark savepoint as rolled back
                let mut txns = self.transactions.lock().unwrap();
                if let Some(tx) = txns.get_mut(&record.txid) {
                    tx.records.push(record.clone());
                    
                    if let Some(savepoint_name) = &record.savepoint_name {
                        if let Some(savepoint) = tx.savepoints.get_mut(savepoint_name) {
                            savepoint.rolled_back = true;
                            savepoint.end_lsn = Some(record.lsn);
                            savepoint.records.push(record.clone());
                        }
                    }
                }
            },
            _ => {
                // Add record to transaction
                let mut txns = self.transactions.lock().unwrap();
                if let Some(tx) = txns.get_mut(&record.txid) {
                    tx.records.push(record.clone());
                    
                    // If this record belongs to a savepoint, add it there too
                    for savepoint in tx.savepoints.values_mut() {
                        if !savepoint.released && !savepoint.rolled_back && record.lsn >= savepoint.start_lsn {
                            savepoint.records.push(record.clone());
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Get a completed transaction
    pub fn get_transaction(&self, txid: u64) -> Option<TransactionTree> {
        let txns = self.transactions.lock().unwrap();
        txns.get(&txid).cloned()
    }
    
    /// Get all active transaction IDs
    pub fn get_active_transactions(&self) -> HashSet<u64> {
        self.active_transactions.lock().unwrap().clone()
    }
    
    /// Verify transaction boundaries
    /// This checks that all savepoints are properly handled and that
    /// the transaction tree is consistent
    pub fn verify_transaction_boundaries(&self, txid: u64) -> Result<bool> {
        let txns = self.transactions.lock().unwrap();
        
        if let Some(tx) = txns.get(&txid) {
            // Transaction must be committed or aborted
            if tx.status == TransactionStatus::InProgress {
                return Ok(false);
            }
            
            // All savepoints must be released or rolled back
            for savepoint in tx.savepoints.values() {
                if !savepoint.released && !savepoint.rolled_back {
                    warn!("Savepoint {} in transaction {} was neither released nor rolled back", 
                          savepoint.name, txid);
                    return Ok(false);
                }
            }
            
            // Verify transaction record ordering - all records must be in LSN order
            let mut prev_lsn = 0;
            for record in &tx.records {
                if record.lsn < prev_lsn {
                    warn!("Transaction {} has out-of-order WAL records", txid);
                    return Ok(false);
                }
                prev_lsn = record.lsn;
            }
            
            Ok(true)
        } else {
            // Transaction not found
            warn!("Transaction {} not found for boundary verification", txid);
            Ok(false)
        }
    }
    
    /// Clean up old transactions
    fn cleanup(&self) -> Result<()> {
        let mut completed = self.completed_transactions.lock().unwrap();
        let mut txns = self.transactions.lock().unwrap();
        
        // Keep track of the minimum LSN we need to retain
        let mut min_lsn = u64::MAX;
        
        // Calculate minimum LSN from active transactions
        for txid in self.active_transactions.lock().unwrap().iter() {
            if let Some(tx) = txns.get(txid) {
                if tx.start_lsn < min_lsn {
                    min_lsn = tx.start_lsn;
                }
            }
        }
        
        // Update LSN watermark
        *self.lsn_watermark.lock().unwrap() = min_lsn;
        
        // Remove completed transactions if we have too many
        while txns.len() > self.max_transactions && !completed.is_empty() {
            if let Some(txid) = completed.pop_front() {
                txns.remove(&txid);
            }
        }
        
        Ok(())
    }
    
    /// Enable WAL capture
    pub fn enable(&mut self) {
        self.enabled = true;
    }
    
    /// Disable WAL capture
    pub fn disable(&mut self) {
        self.enabled = false;
    }
    
    /// Check if WAL capture is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Create a checksum for a WAL record
fn calculate_wal_record_checksum(record: &WalRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(record.txid.to_le_bytes());
    hasher.update(record.lsn.to_le_bytes());
    hasher.update(record.timestamp.to_le_bytes());
    
    // Record type
    let record_type_str = format!("{:?}", record.record_type);
    hasher.update(record_type_str.as_bytes());
    
    // Relation info
    if let Some(rel_id) = record.relation_id {
        hasher.update(rel_id.to_le_bytes());
    }
    if let Some(rel_name) = &record.relation_name {
        hasher.update(rel_name.as_bytes());
    }
    
    // Data
    hasher.update(&record.data);
    
    // Savepoint info
    if record.is_savepoint {
        hasher.update(&[1]);
        if let Some(savepoint_name) = &record.savepoint_name {
            hasher.update(savepoint_name.as_bytes());
        }
    } else {
        hasher.update(&[0]);
    }
    
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    
    /// Create a test WAL record
    fn create_test_record(txid: u64, lsn: u64, record_type: WalRecordType) -> WalRecord {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        let mut record = WalRecord {
            lsn,
            txid,
            timestamp,
            record_type,
            relation_id: None,
            relation_name: None,
            data: vec![],
            checksum: [0; 32],
            is_savepoint: false,
            savepoint_name: None,
        };
        
        record.checksum = calculate_wal_record_checksum(&record);
        record
    }
    
    #[test]
    fn test_wal_capture_normal_transaction() {
        let manager = WalCaptureManager::new(100);
        
        // Begin transaction
        manager.process_record(create_test_record(1, 100, WalRecordType::Begin)).unwrap();
        
        // Add some records
        manager.process_record(create_test_record(1, 101, WalRecordType::Insert)).unwrap();
        manager.process_record(create_test_record(1, 102, WalRecordType::Update)).unwrap();
        manager.process_record(create_test_record(1, 103, WalRecordType::Delete)).unwrap();
        
        // Commit
        manager.process_record(create_test_record(1, 104, WalRecordType::Commit)).unwrap();
        
        // Check transaction
        let tx = manager.get_transaction(1).unwrap();
        assert_eq!(tx.status, TransactionStatus::Committed);
        assert_eq!(tx.records.len(), 5);
        assert_eq!(tx.start_lsn, 100);
        assert_eq!(tx.end_lsn, Some(104));
        
        // Verify transaction boundaries
        assert!(manager.verify_transaction_boundaries(1).unwrap());
    }
    
    #[test]
    fn test_wal_capture_with_savepoints() {
        let manager = WalCaptureManager::new(100);
        
        // Begin transaction
        manager.process_record(create_test_record(1, 100, WalRecordType::Begin)).unwrap();
        
        // Add some records
        manager.process_record(create_test_record(1, 101, WalRecordType::Insert)).unwrap();
        
        // Create savepoint
        let mut savepoint_record = create_test_record(1, 102, WalRecordType::Savepoint);
        savepoint_record.is_savepoint = true;
        savepoint_record.savepoint_name = Some("sp1".to_string());
        manager.process_record(savepoint_record).unwrap();
        
        // Add more records
        manager.process_record(create_test_record(1, 103, WalRecordType::Update)).unwrap();
        manager.process_record(create_test_record(1, 104, WalRecordType::Update)).unwrap();
        
        // Release savepoint
        let mut release_record = create_test_record(1, 105, WalRecordType::ReleaseSavepoint);
        release_record.is_savepoint = true;
        release_record.savepoint_name = Some("sp1".to_string());
        manager.process_record(release_record).unwrap();
        
        // Add final record
        manager.process_record(create_test_record(1, 106, WalRecordType::Delete)).unwrap();
        
        // Commit
        manager.process_record(create_test_record(1, 107, WalRecordType::Commit)).unwrap();
        
        // Check transaction
        let tx = manager.get_transaction(1).unwrap();
        assert_eq!(tx.status, TransactionStatus::Committed);
        assert_eq!(tx.records.len(), 8);
        assert_eq!(tx.savepoints.len(), 1);
        
        // Check savepoint
        let savepoint = tx.savepoints.get("sp1").unwrap();
        assert_eq!(savepoint.name, "sp1");
        assert!(savepoint.released);
        assert!(!savepoint.rolled_back);
        assert_eq!(savepoint.records.len(), 4); // savepoint + 2 updates + release
        
        // Verify transaction boundaries
        assert!(manager.verify_transaction_boundaries(1).unwrap());
    }
    
    #[test]
    fn test_wal_capture_rollback_savepoint() {
        let manager = WalCaptureManager::new(100);
        
        // Begin transaction
        manager.process_record(create_test_record(1, 100, WalRecordType::Begin)).unwrap();
        
        // Add some records
        manager.process_record(create_test_record(1, 101, WalRecordType::Insert)).unwrap();
        
        // Create savepoint
        let mut savepoint_record = create_test_record(1, 102, WalRecordType::Savepoint);
        savepoint_record.is_savepoint = true;
        savepoint_record.savepoint_name = Some("sp1".to_string());
        manager.process_record(savepoint_record).unwrap();
        
        // Add more records
        manager.process_record(create_test_record(1, 103, WalRecordType::Update)).unwrap();
        manager.process_record(create_test_record(1, 104, WalRecordType::Update)).unwrap();
        
        // Rollback to savepoint
        let mut rollback_record = create_test_record(1, 105, WalRecordType::RollbackToSavepoint);
        rollback_record.is_savepoint = true;
        rollback_record.savepoint_name = Some("sp1".to_string());
        manager.process_record(rollback_record).unwrap();
        
        // Add final record
        manager.process_record(create_test_record(1, 106, WalRecordType::Delete)).unwrap();
        
        // Commit
        manager.process_record(create_test_record(1, 107, WalRecordType::Commit)).unwrap();
        
        // Check transaction
        let tx = manager.get_transaction(1).unwrap();
        assert_eq!(tx.status, TransactionStatus::Committed);
        assert_eq!(tx.records.len(), 8);
        assert_eq!(tx.savepoints.len(), 1);
        
        // Check savepoint
        let savepoint = tx.savepoints.get("sp1").unwrap();
        assert_eq!(savepoint.name, "sp1");
        assert!(!savepoint.released);
        assert!(savepoint.rolled_back);
        assert_eq!(savepoint.records.len(), 4); // savepoint + 2 updates + rollback
        
        // Verify transaction boundaries
        assert!(manager.verify_transaction_boundaries(1).unwrap());
    }
    
    #[test]
    fn test_incomplete_savepoint() {
        let manager = WalCaptureManager::new(100);
        
        // Begin transaction
        manager.process_record(create_test_record(1, 100, WalRecordType::Begin)).unwrap();
        
        // Create savepoint
        let mut savepoint_record = create_test_record(1, 101, WalRecordType::Savepoint);
        savepoint_record.is_savepoint = true;
        savepoint_record.savepoint_name = Some("sp1".to_string());
        manager.process_record(savepoint_record).unwrap();
        
        // Add some records
        manager.process_record(create_test_record(1, 102, WalRecordType::Insert)).unwrap();
        
        // Commit without releasing/rolling back savepoint
        manager.process_record(create_test_record(1, 103, WalRecordType::Commit)).unwrap();
        
        // Verify transaction boundaries - should fail
        assert!(!manager.verify_transaction_boundaries(1).unwrap());
    }
} 