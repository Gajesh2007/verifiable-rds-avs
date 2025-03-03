//! Data models for the Verifiable Database
//!
//! This module provides data structures for representing database state,
//! including tables, rows, transactions, and blocks.

mod table;
mod row;
mod transaction;
mod block;
mod challenge;

pub use table::{TableState, ColumnType, ColumnDefinition, TableSchema};
pub use row::{Row, ValueType, Value};
pub use transaction::{TransactionRecord, TransactionType, Operation, OperationType};
pub use block::{BlockState, BlockHeader, BlockMetadata};
pub use challenge::{Challenge, ChallengeType, ChallengeStatus, ChallengeEvidence};

/// Domain constants for data models
pub mod domains {
    /// Domain for table state
    pub const TABLE_STATE: &str = "VERIFIABLEDB_TABLE";
    
    /// Domain for row data
    pub const ROW: &str = "VERIFIABLEDB_ROW";
    
    /// Domain for transaction record
    pub const TRANSACTION: &str = "VERIFIABLEDB_TX";
    
    /// Domain for operation
    pub const OPERATION: &str = "VERIFIABLEDB_OP";
    
    /// Domain for block state
    pub const BLOCK: &str = "VERIFIABLEDB_BLOCK";
    
    /// Domain for challenge
    pub const CHALLENGE: &str = "VERIFIABLEDB_CHALLENGE";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    
    #[test]
    fn test_domain_separation() {
        // Test that different domains produce different hashes for the same data
        let data = b"test data";
        
        let table_hash = crypto::secure_hash(domains::TABLE_STATE, data);
        let row_hash = crypto::secure_hash(domains::ROW, data);
        let tx_hash = crypto::secure_hash(domains::TRANSACTION, data);
        let op_hash = crypto::secure_hash(domains::OPERATION, data);
        let block_hash = crypto::secure_hash(domains::BLOCK, data);
        let challenge_hash = crypto::secure_hash(domains::CHALLENGE, data);
        
        // All hashes should be different
        assert_ne!(table_hash, row_hash);
        assert_ne!(table_hash, tx_hash);
        assert_ne!(table_hash, op_hash);
        assert_ne!(table_hash, block_hash);
        assert_ne!(table_hash, challenge_hash);
        assert_ne!(row_hash, tx_hash);
        assert_ne!(row_hash, op_hash);
        assert_ne!(row_hash, block_hash);
        assert_ne!(row_hash, challenge_hash);
        assert_ne!(tx_hash, op_hash);
        assert_ne!(tx_hash, block_hash);
        assert_ne!(tx_hash, challenge_hash);
        assert_ne!(op_hash, block_hash);
        assert_ne!(op_hash, challenge_hash);
        assert_ne!(block_hash, challenge_hash);
    }
} 