//! Database block representation
//!
//! This module provides data structures for representing blocks of transactions
//! and database state.

use std::collections::HashMap;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::crypto;
use super::domains;
use super::transaction::TransactionRecord;

/// Metadata for a block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMetadata {
    /// PostgreSQL version
    pub postgres_version: String,
    
    /// Protocol version
    pub protocol_version: String,
    
    /// Operator identifier
    pub operator_id: String,
    
    /// Operator signature of the block (hex encoded)
    pub operator_signature: Option<String>,
    
    /// Operator public key (hex encoded)
    pub operator_public_key: Option<String>,
    
    /// Additional metadata (JSON serialized)
    pub additional_data: Option<String>,
}

/// Header for a block
#[derive(Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block number
    pub number: u64,
    
    /// Previous block hash
    pub previous_hash: [u8; 32],
    
    /// Merkle root of all transactions in this block
    pub transactions_root: [u8; 32],
    
    /// State root after all transactions in this block
    pub state_root: [u8; 32],
    
    /// Block creation timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Block metadata
    pub metadata: BlockMetadata,
    
    /// Block hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<[u8; 32]>,
}

impl Debug for BlockHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("BlockHeader")
            .field("number", &self.number)
            .field("previous_hash", &hex::encode(&self.previous_hash[0..4]))
            .field("transactions_root", &hex::encode(&self.transactions_root[0..4]))
            .field("state_root", &hex::encode(&self.state_root[0..4]))
            .field("timestamp", &self.timestamp)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl BlockHeader {
    /// Create a new block header
    pub fn new(
        number: u64,
        previous_hash: [u8; 32],
        transactions_root: [u8; 32],
        state_root: [u8; 32],
        timestamp: DateTime<Utc>,
        metadata: BlockMetadata,
    ) -> Self {
        let mut header = BlockHeader {
            number,
            previous_hash,
            transactions_root,
            state_root,
            timestamp,
            metadata,
            hash: None,
        };
        
        // Calculate the hash
        header.hash = Some(header.calculate_hash());
        
        header
    }
    
    /// Calculate the hash of the block header with domain separation
    pub fn calculate_hash(&self) -> [u8; 32] {
        // Collect data for hashing
        let number_bytes = self.number.to_be_bytes();
        let timestamp_bytes = self.timestamp.timestamp_millis().to_be_bytes();
        
        // Serialize metadata to JSON for hashing
        let metadata_json = serde_json::to_string(&self.metadata).unwrap_or_default();
        let metadata_bytes = metadata_json.as_bytes();
        
        // Hash with domain separation
        crypto::secure_hash_multiple(
            domains::BLOCK,
            &[
                &number_bytes,
                &self.previous_hash,
                &self.transactions_root,
                &self.state_root,
                &timestamp_bytes,
                metadata_bytes,
            ]
        )
    }
    
    /// Verify the hash of the block header
    pub fn verify_hash(&self) -> bool {
        match self.hash {
            Some(hash) => hash == self.calculate_hash(),
            None => true, // No hash to verify
        }
    }
}

/// A block of transactions
#[derive(Clone, Serialize, Deserialize)]
pub struct BlockState {
    /// Block header
    pub header: BlockHeader,
    
    /// Transactions in this block, keyed by transaction ID
    pub transactions: HashMap<Uuid, TransactionRecord>,
    
    /// Table state roots after this block
    pub table_state_roots: HashMap<String, [u8; 32]>,
    
    /// Number of transactions
    pub transaction_count: usize,
}

impl Debug for BlockState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("BlockState")
            .field("header", &self.header)
            .field("transaction_count", &self.transaction_count)
            .field("tables", &self.table_state_roots.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl BlockState {
    /// Create a new block
    pub fn new(
        header: BlockHeader,
        transactions: HashMap<Uuid, TransactionRecord>,
        table_state_roots: HashMap<String, [u8; 32]>,
    ) -> Self {
        BlockState {
            header,
            transaction_count: transactions.len(),
            transactions,
            table_state_roots,
        }
    }
    
    /// Create a genesis block
    pub fn genesis(
        state_root: [u8; 32],
        timestamp: DateTime<Utc>,
        metadata: BlockMetadata,
        table_state_roots: HashMap<String, [u8; 32]>,
    ) -> Self {
        // For genesis block, all roots are the same and previous hash is zeros
        let header = BlockHeader::new(
            0, // Genesis block is always block 0
            [0; 32], // No previous block
            state_root, // No transactions, so use state root
            state_root,
            timestamp,
            metadata,
        );
        
        BlockState {
            header,
            transactions: HashMap::new(),
            table_state_roots,
            transaction_count: 0,
        }
    }
    
    /// Get a transaction by ID
    pub fn get_transaction(&self, id: &Uuid) -> Option<&TransactionRecord> {
        self.transactions.get(id)
    }
    
    /// Get the state root for a specific table
    pub fn get_table_state_root(&self, table_name: &str) -> Option<[u8; 32]> {
        self.table_state_roots.get(table_name).copied()
    }
    
    /// Verify all transactions in the block
    pub fn verify_transactions(&self) -> bool {
        self.transactions.values().all(|tx| tx.verify_hash())
    }
    
    /// Calculate the Merkle root of all transactions
    pub fn calculate_transactions_root(&self) -> [u8; 32] {
        if self.transactions.is_empty() {
            return [0; 32]; // Empty tree has zero hash
        }
        
        // Collect transaction hashes in sorted order for determinism
        let mut tx_ids: Vec<&Uuid> = self.transactions.keys().collect();
        tx_ids.sort();
        
        let tx_hashes: Vec<Vec<u8>> = tx_ids
            .iter()
            .filter_map(|id| {
                self.transactions.get(*id).map(|tx| {
                    match tx.hash {
                        Some(hash) => hash.to_vec(),
                        None => panic!("Transaction missing hash"), // This should never happen
                    }
                })
            })
            .collect();
        
        // Create slices to the transaction hashes
        let tx_hash_slices: Vec<&[u8]> = tx_hashes.iter().map(|h| h.as_slice()).collect();
        
        // Hash the transactions with domain separation
        if tx_hash_slices.is_empty() {
            return [0; 32]; // Empty transactions hash
        }
        
        crypto::secure_hash_multiple(domains::BLOCK, &tx_hash_slices)
    }
    
    /// Verify the transactions root matches the calculated root
    pub fn verify_transactions_root(&self) -> bool {
        // For genesis blocks, the transactions_root is set to the state_root
        if self.is_genesis() {
            return true;
        }
        
        let calculated_root = self.calculate_transactions_root();
        calculated_root == self.header.transactions_root
    }
    
    /// Check if this is a genesis block
    pub fn is_genesis(&self) -> bool {
        self.header.number == 0
    }
    
    /// Verify the entire block (header hash and all transactions)
    pub fn verify(&self) -> bool {
        self.header.verify_hash()
            && self.verify_transactions()
            && self.verify_transactions_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use uuid::Uuid;
    use crate::models::transaction::{TransactionRecord, TransactionType, Operation, OperationType};
    
    #[test]
    fn test_block_header_hash() {
        // Create a block header
        let metadata = BlockMetadata {
            postgres_version: "14.0".to_string(),
            protocol_version: "1.0".to_string(),
            operator_id: "operator1".to_string(),
            operator_signature: None,
            operator_public_key: None,
            additional_data: None,
        };
        
        let header = BlockHeader::new(
            1,
            [0; 32],
            [1; 32],
            [2; 32],
            Utc::now(),
            metadata,
        );
        
        // Verify the hash
        assert!(header.verify_hash());
        
        // Create a modified header
        let mut modified_header = header.clone();
        modified_header.number = 2;
        
        // Calculate the hash for the modified header
        let modified_hash = modified_header.calculate_hash();
        
        // The hashes should be different
        assert_ne!(header.hash.unwrap(), modified_hash);
    }
    
    #[test]
    fn test_genesis_block() {
        // Create a genesis block
        let metadata = BlockMetadata {
            postgres_version: "14.0".to_string(),
            protocol_version: "1.0".to_string(),
            operator_id: "operator1".to_string(),
            operator_signature: None,
            operator_public_key: None,
            additional_data: None,
        };
        
        let mut table_state_roots = HashMap::new();
        table_state_roots.insert("users".to_string(), [3; 32]);
        
        let genesis = BlockState::genesis(
            [2; 32],
            Utc::now(),
            metadata,
            table_state_roots,
        );
        
        // Verify the genesis block
        assert!(genesis.is_genesis());
        assert!(genesis.verify());
        assert_eq!(genesis.transaction_count, 0);
        assert_eq!(genesis.header.number, 0);
        assert_eq!(genesis.header.previous_hash, [0; 32]);
    }
    
    #[test]
    fn test_block_with_transactions() {
        // Create a transaction
        let now = Utc::now();
        let tx_id = Uuid::new_v4();
        
        let operation = Operation::new(
            OperationType::Insert,
            "INSERT INTO users (id, name) VALUES (1, 'Alice')".to_string(),
            None,
            vec!["users".to_string()],
            None,
            None,
            10,
        );
        
        let tx = TransactionRecord::new(
            tx_id,
            1,
            TransactionType::ReadWrite,
            now,
            now + Duration::milliseconds(100),
            vec![operation],
            [0; 32],
            [1; 32],
            HashMap::new(),
            1000,
            12345,
            None,
            None,
        );
        
        // Create a block with the transaction
        let metadata = BlockMetadata {
            postgres_version: "14.0".to_string(),
            protocol_version: "1.0".to_string(),
            operator_id: "operator1".to_string(),
            operator_signature: None,
            operator_public_key: None,
            additional_data: None,
        };
        
        let mut transactions = HashMap::new();
        transactions.insert(tx_id, tx);
        
        let mut table_state_roots = HashMap::new();
        table_state_roots.insert("users".to_string(), [3; 32]);
        
        // Calculate the transactions root
        let tx_hash = transactions.get(&tx_id).unwrap().hash.unwrap();
        let transactions_root = crypto::secure_hash_multiple(
            domains::BLOCK,
            &[&tx_hash]
        );
        
        let header = BlockHeader::new(
            1,
            [0; 32],
            transactions_root,
            [2; 32],
            now + Duration::milliseconds(200),
            metadata,
        );
        
        let block = BlockState::new(
            header,
            transactions,
            table_state_roots,
        );
        
        // Verify the block
        assert!(!block.is_genesis());
        assert!(block.verify());
        assert_eq!(block.transaction_count, 1);
        
        // Verify we can retrieve the transaction
        let retrieved_tx = block.get_transaction(&tx_id);
        assert!(retrieved_tx.is_some());
        
        // Verify we can get the table state root
        let table_root = block.get_table_state_root("users");
        assert!(table_root.is_some());
        assert_eq!(table_root.unwrap(), [3; 32]);
    }
    
    #[test]
    fn test_transactions_root_verification() {
        // Create two transactions
        let now = Utc::now();
        let tx_id1 = Uuid::new_v4();
        let tx_id2 = Uuid::new_v4();
        
        let operation1 = Operation::new(
            OperationType::Insert,
            "INSERT INTO users (id, name) VALUES (1, 'Alice')".to_string(),
            None,
            vec!["users".to_string()],
            None,
            None,
            10,
        );
        
        let operation2 = Operation::new(
            OperationType::Insert,
            "INSERT INTO users (id, name) VALUES (2, 'Bob')".to_string(),
            None,
            vec!["users".to_string()],
            None,
            None,
            10,
        );
        
        let tx1 = TransactionRecord::new(
            tx_id1,
            1,
            TransactionType::ReadWrite,
            now,
            now + Duration::milliseconds(100),
            vec![operation1],
            [0; 32],
            [1; 32],
            HashMap::new(),
            1000,
            12345,
            None,
            None,
        );
        
        let tx2 = TransactionRecord::new(
            tx_id2,
            1,
            TransactionType::ReadWrite,
            now + Duration::milliseconds(100),
            now + Duration::milliseconds(200),
            vec![operation2],
            [1; 32],
            [2; 32],
            HashMap::new(),
            1000,
            12346,
            None,
            None,
        );
        
        // Create a block with the transactions
        let metadata = BlockMetadata {
            postgres_version: "14.0".to_string(),
            protocol_version: "1.0".to_string(),
            operator_id: "operator1".to_string(),
            operator_signature: None,
            operator_public_key: None,
            additional_data: None,
        };
        
        let mut transactions = HashMap::new();
        transactions.insert(tx_id1, tx1);
        transactions.insert(tx_id2, tx2);
        
        let mut table_state_roots = HashMap::new();
        table_state_roots.insert("users".to_string(), [3; 32]);
        
        let block = BlockState {
            header: BlockHeader {
                number: 1,
                previous_hash: [0; 32],
                transactions_root: [0; 32], // Incorrect root (will fail verification)
                state_root: [2; 32],
                timestamp: now + Duration::milliseconds(200),
                metadata,
                hash: None,
            },
            transactions,
            table_state_roots,
            transaction_count: 2,
        };
        
        // The block should fail verification due to incorrect transactions root
        assert!(!block.verify_transactions_root());
        assert!(!block.verify());
        
        // Calculate the correct transactions root
        let correct_root = block.calculate_transactions_root();
        
        // Create a new block with the correct root
        let correct_metadata = BlockMetadata {
            postgres_version: "14.0".to_string(),
            protocol_version: "1.0".to_string(),
            operator_id: "operator1".to_string(),
            operator_signature: None,
            operator_public_key: None,
            additional_data: None,
        };
        
        let correct_header = BlockHeader::new(
            1,
            [0; 32],
            correct_root,
            [2; 32],
            now + Duration::milliseconds(200),
            correct_metadata,
        );
        
        let correct_block = BlockState {
            header: correct_header,
            transactions: block.transactions.clone(),
            table_state_roots: block.table_state_roots.clone(),
            transaction_count: 2,
        };
        
        // The corrected block should pass verification
        assert!(correct_block.verify_transactions_root());
        assert!(correct_block.verify());
    }
} 