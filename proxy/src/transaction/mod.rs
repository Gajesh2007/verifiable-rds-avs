//! Transaction management module
//! 
//! This module provides functionality to track, manage, and verify database
//! transactions, including transaction boundary protection.

// Re-export the WAL submodule
pub mod wal;
pub use wal::{WalCaptureManager, WalRecord, WalRecordType, TransactionTree, TransactionStatus, SavepointRecord};

use crate::error::{ProxyError, Result};
use crate::interception::analyzer::QueryMetadata;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use log::{debug, info, warn, error};

/// Transaction structure
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Transaction ID
    pub id: u64,
    
    /// Original SQL query
    pub query: String,
    
    /// Query metadata
    pub metadata: Option<QueryMetadata>,
    
    /// Transaction start time
    pub start_time: u64,
    
    /// Transaction end time
    pub end_time: Option<u64>,
    
    /// Whether the transaction has been committed
    pub committed: bool,
    
    /// Whether the transaction has been rolled back
    pub rolled_back: bool,
    
    /// Tables affected by this transaction
    pub affected_tables: Vec<String>,
    
    /// Transaction savepoints
    pub savepoints: HashMap<String, Savepoint>,
    
    /// Parent transaction ID (if this is a nested transaction)
    pub parent_id: Option<u64>,
    
    /// Child transactions
    pub child_ids: Vec<u64>,
    
    /// WAL records associated with this transaction
    pub wal_records: Vec<WalRecord>,
}

/// Savepoint structure
#[derive(Debug, Clone)]
pub struct Savepoint {
    /// Savepoint name
    pub name: String,
    
    /// Savepoint creation time
    pub creation_time: u64,
    
    /// Whether the savepoint has been released
    pub released: bool,
    
    /// Whether the transaction has rolled back to this savepoint
    pub rolled_back: bool,
    
    /// Statements executed after this savepoint
    pub statements: Vec<String>,
}

/// Transaction manager
pub struct TransactionManager {
    /// Transaction counter
    counter: AtomicU64,
    
    /// Active transactions
    active_transactions: HashMap<u64, Transaction>,
    
    /// WAL capture manager
    wal_manager: Option<WalCaptureManager>,
    
    /// Whether the manager is enabled
    enabled: bool,
}

impl TransactionManager {
    /// Create a new transaction manager
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(1),
            active_transactions: HashMap::new(),
            wal_manager: None,
            enabled: true,
        }
    }
    
    /// Initialize the transaction manager
    pub async fn initialize(&mut self) -> Result<()> {
        // Initialize the WAL capture manager if configured
        let wal_manager = WalCaptureManager::new(1000);
        wal_manager.initialize().await?;
        wal_manager.start().await?;
        self.wal_manager = Some(wal_manager);
        
        Ok(())
    }
    
    /// Begin a new transaction
    pub fn begin_transaction(&mut self, query: &str, metadata: Option<&QueryMetadata>) -> Result<u64> {
        if !self.enabled {
            return Ok(0);
        }
        
        let tx_id = self.counter.fetch_add(1, Ordering::SeqCst);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let affected_tables = if let Some(meta) = metadata {
            meta.affected_tables.clone()
        } else {
            vec![]
        };
            
        let transaction = Transaction {
            id: tx_id,
            query: query.to_string(),
            metadata: metadata.cloned(),
            start_time: now,
            end_time: None,
            committed: false,
            rolled_back: false,
            affected_tables,
            savepoints: HashMap::new(),
            parent_id: None,
            child_ids: vec![],
            wal_records: vec![],
        };
        
        self.active_transactions.insert(tx_id, transaction);
        
        debug!("Started transaction {}", tx_id);
        
        Ok(tx_id)
    }
    
    /// Commit a transaction
    pub fn commit_transaction(&mut self, tx_id: u64) -> Result<()> {
        if !self.enabled || tx_id == 0 {
            return Ok(());
        }
        
        let transaction = self.active_transactions.get_mut(&tx_id)
            .ok_or_else(|| ProxyError::Unknown(format!("Transaction {} not found", tx_id)))?;
            
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        transaction.end_time = Some(now);
        transaction.committed = true;
        
        // Check for incomplete savepoints
        let has_incomplete_savepoints = transaction.savepoints.values()
            .any(|sp| !sp.released && !sp.rolled_back);
            
        if has_incomplete_savepoints {
            warn!("Transaction {} has incomplete savepoints on commit", tx_id);
        }
        
        debug!("Committed transaction {}", tx_id);
        
        Ok(())
    }
    
    /// Roll back a transaction
    pub fn rollback_transaction(&mut self, tx_id: u64) -> Result<()> {
        if !self.enabled || tx_id == 0 {
            return Ok(());
        }
        
        let transaction = self.active_transactions.get_mut(&tx_id)
            .ok_or_else(|| ProxyError::Unknown(format!("Transaction {} not found", tx_id)))?;
            
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        transaction.end_time = Some(now);
        transaction.rolled_back = true;
        
        debug!("Rolled back transaction {}", tx_id);
        
        Ok(())
    }
    
    /// Create a savepoint
    pub fn create_savepoint(&mut self, tx_id: u64, savepoint_name: &str) -> Result<()> {
        if !self.enabled || tx_id == 0 {
            return Ok(());
        }
        
        let transaction = self.active_transactions.get_mut(&tx_id)
            .ok_or_else(|| ProxyError::Unknown(format!("Transaction {} not found", tx_id)))?;
            
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let savepoint = Savepoint {
            name: savepoint_name.to_string(),
            creation_time: now,
            released: false,
            rolled_back: false,
            statements: vec![],
        };
        
        transaction.savepoints.insert(savepoint_name.to_string(), savepoint);
        
        debug!("Created savepoint {} in transaction {}", savepoint_name, tx_id);
        
        Ok(())
    }
    
    /// Release a savepoint
    pub fn release_savepoint(&mut self, tx_id: u64, savepoint_name: &str) -> Result<()> {
        if !self.enabled || tx_id == 0 {
            return Ok(());
        }
        
        let transaction = self.active_transactions.get_mut(&tx_id)
            .ok_or_else(|| ProxyError::Unknown(format!("Transaction {} not found", tx_id)))?;
            
        if let Some(savepoint) = transaction.savepoints.get_mut(savepoint_name) {
            savepoint.released = true;
            debug!("Released savepoint {} in transaction {}", savepoint_name, tx_id);
            Ok(())
        } else {
            Err(ProxyError::Unknown(format!("Savepoint {} not found in transaction {}", savepoint_name, tx_id)))
        }
    }
    
    /// Roll back to a savepoint
    pub fn rollback_to_savepoint(&mut self, tx_id: u64, savepoint_name: &str) -> Result<()> {
        if !self.enabled || tx_id == 0 {
            return Ok(());
        }
        
        let transaction = self.active_transactions.get_mut(&tx_id)
            .ok_or_else(|| ProxyError::Unknown(format!("Transaction {} not found", tx_id)))?;
            
        if let Some(savepoint) = transaction.savepoints.get_mut(savepoint_name) {
            savepoint.rolled_back = true;
            debug!("Rolled back to savepoint {} in transaction {}", savepoint_name, tx_id);
            Ok(())
        } else {
            Err(ProxyError::Unknown(format!("Savepoint {} not found in transaction {}", savepoint_name, tx_id)))
        }
    }
    
    /// Add a statement to a transaction
    pub fn add_statement(&mut self, tx_id: u64, statement: &str) -> Result<()> {
        if !self.enabled || tx_id == 0 {
            return Ok(());
        }
        
        if let Some(transaction) = self.active_transactions.get_mut(&tx_id) {
            // Add statement to active savepoints
            for savepoint in transaction.savepoints.values_mut() {
                if !savepoint.released && !savepoint.rolled_back {
                    savepoint.statements.push(statement.to_string());
                }
            }
            
            Ok(())
        } else {
            Err(ProxyError::Unknown(format!("Transaction {} not found", tx_id)))
        }
    }
    
    /// Get a transaction
    pub fn get_transaction(&self, tx_id: u64) -> Option<&Transaction> {
        self.active_transactions.get(&tx_id)
    }
    
    /// Get a mutable reference to a transaction
    pub fn get_transaction_mut(&mut self, tx_id: u64) -> Option<&mut Transaction> {
        self.active_transactions.get_mut(&tx_id)
    }
    
    /// Get the WAL manager
    pub fn get_wal_manager(&self) -> Option<&WalCaptureManager> {
        self.wal_manager.as_ref()
    }
    
    /// Enable the transaction manager
    pub fn enable(&mut self) {
        self.enabled = true;
    }
    
    /// Disable the transaction manager
    pub fn disable(&mut self) {
        self.enabled = false;
    }
    
    /// Check if the transaction manager is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_transaction_lifecycle() {
        let mut manager = TransactionManager::new();
        
        // Begin transaction
        let tx_id = manager.begin_transaction("SELECT 1", None).unwrap();
        assert!(tx_id > 0);
        
        // Create savepoint
        manager.create_savepoint(tx_id, "sp1").unwrap();
        
        // Add statement
        manager.add_statement(tx_id, "INSERT INTO tbl VALUES (1)").unwrap();
        
        // Release savepoint
        manager.release_savepoint(tx_id, "sp1").unwrap();
        
        // Commit transaction
        manager.commit_transaction(tx_id).unwrap();
        
        // Check transaction state
        let tx = manager.get_transaction(tx_id).unwrap();
        assert!(tx.committed);
        assert!(!tx.rolled_back);
        assert_eq!(tx.savepoints.len(), 1);
        
        let savepoint = tx.savepoints.get("sp1").unwrap();
        assert!(savepoint.released);
        assert!(!savepoint.rolled_back);
        assert_eq!(savepoint.statements.len(), 1);
        assert_eq!(savepoint.statements[0], "INSERT INTO tbl VALUES (1)");
    }
    
    #[test]
    fn test_transaction_rollback() {
        let mut manager = TransactionManager::new();
        
        // Begin transaction
        let tx_id = manager.begin_transaction("SELECT 1", None).unwrap();
        
        // Create savepoint
        manager.create_savepoint(tx_id, "sp1").unwrap();
        
        // Add statement
        manager.add_statement(tx_id, "INSERT INTO tbl VALUES (1)").unwrap();
        
        // Rollback to savepoint
        manager.rollback_to_savepoint(tx_id, "sp1").unwrap();
        
        // Add another statement
        manager.add_statement(tx_id, "INSERT INTO tbl VALUES (2)").unwrap();
        
        // Rollback transaction
        manager.rollback_transaction(tx_id).unwrap();
        
        // Check transaction state
        let tx = manager.get_transaction(tx_id).unwrap();
        assert!(!tx.committed);
        assert!(tx.rolled_back);
        assert_eq!(tx.savepoints.len(), 1);
        
        let savepoint = tx.savepoints.get("sp1").unwrap();
        assert!(!savepoint.released);
        assert!(savepoint.rolled_back);
        assert_eq!(savepoint.statements.len(), 1);
        assert_eq!(savepoint.statements[0], "INSERT INTO tbl VALUES (1)");
    }
} 