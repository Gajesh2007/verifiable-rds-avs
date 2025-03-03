//! Database transaction representation
//!
//! This module provides data structures for representing database transactions
//! and operations.

use std::collections::HashMap;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::crypto;
use crate::crypto::SecureHasher;
use super::domains;
use super::row::Row;

/// Type of database transaction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionType {
    /// Read-only transaction
    ReadOnly,
    
    /// Read-write transaction
    ReadWrite,
    
    /// Schema change transaction (DDL)
    SchemaChange,
    
    /// System transaction (internal)
    System,
}

/// Type of database operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationType {
    /// Query (SELECT)
    Query,
    
    /// Insert (INSERT)
    Insert,
    
    /// Update (UPDATE)
    Update,
    
    /// Delete (DELETE)
    Delete,
    
    /// Create table (CREATE TABLE)
    CreateTable,
    
    /// Alter table (ALTER TABLE)
    AlterTable,
    
    /// Drop table (DROP TABLE)
    DropTable,
    
    /// Create index (CREATE INDEX)
    CreateIndex,
    
    /// Drop index (DROP INDEX)
    DropIndex,
    
    /// Begin transaction (BEGIN)
    Begin,
    
    /// Commit transaction (COMMIT)
    Commit,
    
    /// Rollback transaction (ROLLBACK)
    Rollback,
    
    /// Save point (SAVEPOINT)
    Savepoint,
    
    /// Other operation
    Other,
}

/// An operation within a transaction
#[derive(Clone, Serialize, Deserialize)]
pub struct Operation {
    /// Type of operation
    pub operation_type: OperationType,
    
    /// SQL statement
    pub sql: String,
    
    /// Parameters for prepared statements (JSON serialized)
    pub parameters: Option<String>,
    
    /// Affected tables
    pub affected_tables: Vec<String>,
    
    /// Affected rows before the operation
    pub rows_before: Option<Vec<Row>>,
    
    /// Affected rows after the operation
    pub rows_after: Option<Vec<Row>>,
    
    /// Execution time (milliseconds)
    pub execution_time_ms: u64,
    
    /// Hash of the operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<[u8; 32]>,
}

impl Debug for Operation {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Operation")
            .field("type", &self.operation_type)
            .field("sql", &self.sql)
            .field("affected_tables", &self.affected_tables)
            .field("execution_time_ms", &self.execution_time_ms)
            .finish()
    }
}

impl Operation {
    /// Create a new operation
    pub fn new(
        operation_type: OperationType,
        sql: String,
        parameters: Option<String>,
        affected_tables: Vec<String>,
        rows_before: Option<Vec<Row>>,
        rows_after: Option<Vec<Row>>,
        execution_time_ms: u64,
    ) -> Self {
        let mut operation = Operation {
            operation_type,
            sql,
            parameters,
            affected_tables,
            rows_before,
            rows_after,
            execution_time_ms,
            hash: None,
        };
        
        // Calculate the hash
        operation.hash = Some(operation.calculate_hash());
        
        operation
    }
    
    /// Calculate the hash of the operation with domain separation
    pub fn calculate_hash(&self) -> [u8; 32] {
        // Collect operation type, SQL, and parameters
        let operation_type_bytes = [self.operation_type as u8];
        let sql_bytes = self.sql.as_bytes();
        let parameters_bytes = match &self.parameters {
            Some(params) => params.as_bytes(),
            None => &[],
        };
        
        // Create a joined string of affected tables and store it
        let tables_joined = self.affected_tables.join(",");
        let tables_bytes = tables_joined.as_bytes();
        
        // Collect row hashes
        let rows_before_hash = match &self.rows_before {
            Some(rows) => {
                if rows.is_empty() {
                    [0; 32]
                } else {
                    // Convert each row hash to a byte slice and collect into a vector
                    let mut hash_slices = Vec::with_capacity(rows.len());
                    let hashes: Vec<[u8; 32]> = rows.iter().map(|row| row.hash()).collect();
                    for hash in &hashes {
                        hash_slices.push(&hash[..]);
                    }
                    crypto::secure_hash_multiple("ROWS_BEFORE", &hash_slices)
                }
            }
            None => [0; 32],
        };
        
        let rows_after_hash = match &self.rows_after {
            Some(rows) => {
                if rows.is_empty() {
                    [0; 32]
                } else {
                    // Convert each row hash to a byte slice and collect into a vector
                    let mut hash_slices = Vec::with_capacity(rows.len());
                    let hashes: Vec<[u8; 32]> = rows.iter().map(|row| row.hash()).collect();
                    for hash in &hashes {
                        hash_slices.push(&hash[..]);
                    }
                    crypto::secure_hash_multiple("ROWS_AFTER", &hash_slices)
                }
            }
            None => [0; 32],
        };
        
        let execution_time_bytes = self.execution_time_ms.to_be_bytes();
        
        // Hash with domain separation
        crypto::secure_hash_multiple(
            domains::OPERATION,
            &[
                &operation_type_bytes,
                sql_bytes,
                parameters_bytes,
                tables_bytes,
                &rows_before_hash,
                &rows_after_hash,
                &execution_time_bytes,
            ]
        )
    }
    
    /// Verify the hash of the operation
    pub fn verify_hash(&self) -> bool {
        match self.hash {
            Some(hash) => hash == self.calculate_hash(),
            None => true, // No hash to verify
        }
    }
}

/// A transaction record
#[derive(Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    /// Transaction ID
    pub id: Uuid,
    
    /// Block number this transaction belongs to
    pub block_number: u64,
    
    /// Transaction type
    pub transaction_type: TransactionType,
    
    /// Start timestamp
    pub start_time: DateTime<Utc>,
    
    /// End timestamp
    pub end_time: DateTime<Utc>,
    
    /// Operations in the transaction
    pub operations: Vec<Operation>,
    
    /// State root before the transaction
    pub pre_state_root: [u8; 32],
    
    /// State root after the transaction
    pub post_state_root: [u8; 32],
    
    /// Savepoint tracking (nested transactions)
    pub savepoints: HashMap<String, Vec<usize>>, // Savepoint name -> Operation indices
    
    /// PostgreSQL process ID
    pub postgres_pid: i32,
    
    /// PostgreSQL transaction ID
    pub postgres_xid: u32,
    
    /// Client information
    pub client_info: Option<String>,
    
    /// Transaction metadata (JSON serialized)
    pub metadata: Option<String>,
    
    /// Transaction hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<[u8; 32]>,
}

impl Debug for TransactionRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("TransactionRecord")
            .field("id", &self.id)
            .field("block", &self.block_number)
            .field("type", &self.transaction_type)
            .field("operations", &self.operations.len())
            .field("start_time", &self.start_time)
            .field("end_time", &self.end_time)
            .finish()
    }
}

impl TransactionRecord {
    /// Create a new transaction record
    pub fn new(
        id: Uuid,
        block_number: u64,
        transaction_type: TransactionType,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        operations: Vec<Operation>,
        pre_state_root: [u8; 32],
        post_state_root: [u8; 32],
        savepoints: HashMap<String, Vec<usize>>,
        postgres_pid: i32,
        postgres_xid: u32,
        client_info: Option<String>,
        metadata: Option<String>,
    ) -> Self {
        let mut tx = TransactionRecord {
            id,
            block_number,
            transaction_type,
            start_time,
            end_time,
            operations,
            pre_state_root,
            post_state_root,
            savepoints,
            postgres_pid,
            postgres_xid,
            client_info,
            metadata,
            hash: None,
        };
        
        // Calculate the hash
        tx.hash = Some(tx.calculate_hash());
        
        tx
    }
    
    /// Calculate the hash of the transaction with domain separation
    pub fn calculate_hash(&self) -> [u8; 32] {
        // Collect data for hashing
        let id_bytes = self.id.as_bytes();
        let block_bytes = self.block_number.to_be_bytes();
        let transaction_type_bytes = [self.transaction_type as u8];
        let start_time_bytes = self.start_time.timestamp_millis().to_be_bytes();
        let end_time_bytes = self.end_time.timestamp_millis().to_be_bytes();
        
        // Hash all operations
        let operations_hash = if self.operations.is_empty() {
            [0; 32]
        } else {
            // Convert each operation hash to a byte slice and collect into a vector
            let mut hash_slices = Vec::with_capacity(self.operations.len());
            let op_hashes: Vec<[u8; 32]> = self.operations.iter().map(|op| op.calculate_hash()).collect();
            for hash in &op_hashes {
                hash_slices.push(&hash[..]);
            }
            crypto::secure_hash_multiple("OPERATIONS", &hash_slices)
        };
        
        // Collect savepoint data
        let savepoint_bytes = if self.savepoints.is_empty() {
            Vec::new()
        } else {
            // Serialize savepoints in a deterministic way
            let mut savepoint_data = Vec::new();
            let mut savepoint_names: Vec<&String> = self.savepoints.keys().collect();
            savepoint_names.sort();
            
            for name in savepoint_names {
                savepoint_data.extend_from_slice(name.as_bytes());
                let indices = self.savepoints.get(name).unwrap();
                for &idx in indices {
                    savepoint_data.extend_from_slice(&idx.to_be_bytes());
                }
            }
            
            savepoint_data
        };
        
        let postgres_pid_bytes = self.postgres_pid.to_be_bytes();
        let postgres_xid_bytes = self.postgres_xid.to_be_bytes();
        
        let client_info_bytes = self.client_info.as_deref().unwrap_or("").as_bytes();
        let metadata_bytes = self.metadata.as_deref().unwrap_or("").as_bytes();
        
        // Hash with domain separation
        crypto::secure_hash_multiple(
            domains::TRANSACTION,
            &[
                id_bytes,
                &block_bytes,
                &transaction_type_bytes,
                &start_time_bytes,
                &end_time_bytes,
                &operations_hash,
                &self.pre_state_root,
                &self.post_state_root,
                &savepoint_bytes,
                &postgres_pid_bytes,
                &postgres_xid_bytes,
                client_info_bytes,
                metadata_bytes,
            ]
        )
    }
    
    /// Get an operation by index
    pub fn get_operation(&self, index: usize) -> Option<&Operation> {
        self.operations.get(index)
    }
    
    /// Get all operations for a savepoint
    pub fn get_savepoint_operations(&self, savepoint: &str) -> Vec<&Operation> {
        match self.savepoints.get(savepoint) {
            Some(indices) => {
                indices.iter()
                    .filter_map(|&idx| self.operations.get(idx))
                    .collect()
            }
            None => Vec::new(),
        }
    }
    
    /// Get affected tables in this transaction
    pub fn get_affected_tables(&self) -> Vec<String> {
        let mut tables = Vec::new();
        
        for op in &self.operations {
            for table in &op.affected_tables {
                if !tables.contains(table) {
                    tables.push(table.clone());
                }
            }
        }
        
        tables
    }
    
    /// Verify the hash of the transaction
    pub fn verify_hash(&self) -> bool {
        match self.hash {
            Some(hash) => hash == self.calculate_hash(),
            None => true, // No hash to verify
        }
    }
    
    /// Verify all operations in the transaction
    pub fn verify_operations(&self) -> bool {
        self.operations.iter().all(|op| op.verify_hash())
    }
    
    /// Get duration of the transaction in milliseconds
    pub fn duration_ms(&self) -> i64 {
        (self.end_time - self.start_time).num_milliseconds()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::collections::HashMap;
    use crate::models::row::{Row, Value};
    
    #[test]
    fn test_operation_hash() {
        // Create an operation
        let operation = Operation::new(
            OperationType::Insert,
            "INSERT INTO users (id, name) VALUES (1, 'Alice')".to_string(),
            None,
            vec!["users".to_string()],
            None,
            None,
            10,
        );
        
        // Verify the hash
        assert!(operation.verify_hash());
        
        // Create a modified operation
        let mut modified_op = operation.clone();
        modified_op.sql = "INSERT INTO users (id, name) VALUES (2, 'Bob')".to_string();
        
        // Calculate the hash for the modified operation
        let modified_hash = modified_op.calculate_hash();
        
        // The hashes should be different
        assert_ne!(operation.hash.unwrap(), modified_hash);
    }
    
    #[test]
    fn test_transaction_record() {
        // Create a transaction
        let now = Utc::now();
        let operation = Operation::new(
            OperationType::Insert,
            "INSERT INTO users (id, name) VALUES (1, 'Alice')".to_string(),
            None,
            vec!["users".to_string()],
            None,
            None,
            10,
        );
        
        let mut savepoints = HashMap::new();
        savepoints.insert("sp1".to_string(), vec![0]);
        
        let tx = TransactionRecord::new(
            Uuid::new_v4(),
            1,
            TransactionType::ReadWrite,
            now,
            now + Duration::milliseconds(100),
            vec![operation],
            [0; 32],
            [1; 32],
            savepoints,
            1000,
            12345,
            Some("client".to_string()),
            None,
        );
        
        // Verify the hash
        assert!(tx.verify_hash());
        
        // Verify operations
        assert!(tx.verify_operations());
        
        // Test getting operations
        let op = tx.get_operation(0);
        assert!(op.is_some());
        assert_eq!(op.unwrap().operation_type, OperationType::Insert);
        
        // Test getting savepoint operations
        let sp_ops = tx.get_savepoint_operations("sp1");
        assert_eq!(sp_ops.len(), 1);
        assert_eq!(sp_ops[0].operation_type, OperationType::Insert);
        
        // Test getting affected tables
        let tables = tx.get_affected_tables();
        assert_eq!(tables, vec!["users".to_string()]);
        
        // Test duration
        assert_eq!(tx.duration_ms(), 100);
    }
    
    #[test]
    fn test_transaction_with_rows() {
        // Create some rows for before/after
        let mut values1 = HashMap::new();
        values1.insert("id".to_string(), Value::Integer(1));
        values1.insert("name".to_string(), Value::Text("Alice".to_string()));
        
        let mut values2 = HashMap::new();
        values2.insert("id".to_string(), Value::Integer(1));
        values2.insert("name".to_string(), Value::Text("AliceUpdated".to_string()));
        
        let row_before = Row::new("1".to_string(), "users".to_string(), values1);
        let row_after = Row::new("1".to_string(), "users".to_string(), values2);
        
        // Create an operation with rows
        let operation = Operation::new(
            OperationType::Update,
            "UPDATE users SET name = 'AliceUpdated' WHERE id = 1".to_string(),
            None,
            vec!["users".to_string()],
            Some(vec![row_before]),
            Some(vec![row_after]),
            10,
        );
        
        // Verify the hash
        assert!(operation.verify_hash());
        
        // Create a transaction
        let now = Utc::now();
        let tx = TransactionRecord::new(
            Uuid::new_v4(),
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
        
        // Verify the hash
        assert!(tx.verify_hash());
    }
} 