//! State management for the core crate
//!
//! This module provides a state manager for tracking database state,
//! including blocks, transactions, and table states.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;
use chrono::Utc;

use crate::error::{CoreError, Result};
use crate::models::block::{BlockState, BlockHeader, BlockMetadata};
use crate::models::table::TableState;
use crate::models::transaction::TransactionRecord;
use crate::merkle::SecureMerkleTree;
use crate::config::CoreConfig;

/// State manager for tracking database state
#[derive(Debug)]
pub struct StateManager {
    /// Current block state
    current_block: RwLock<BlockState>,
    
    /// Table states
    table_states: RwLock<HashMap<String, TableState>>,
    
    /// Block history (block number -> block state)
    block_history: RwLock<HashMap<u64, BlockState>>,
    
    /// Transaction history (transaction ID -> transaction record)
    transaction_history: RwLock<HashMap<Uuid, TransactionRecord>>,
    
    /// Configuration
    config: CoreConfig,
    
    /// State root Merkle tree
    state_root_tree: RwLock<SecureMerkleTree>,
}

impl StateManager {
    /// Create a new state manager
    pub fn new(config: CoreConfig) -> Result<Self> {
        // Create an empty Merkle tree for the state root
        let state_root_tree = SecureMerkleTree::new(100);
        
        // Create a genesis block
        let metadata = BlockMetadata {
            postgres_version: config.database.postgres_version.clone(),
            protocol_version: "1.0".to_string(),
            operator_id: "genesis".to_string(),
            operator_signature: None,
            operator_public_key: None,
            additional_data: None,
        };
        
        let genesis_block = BlockState::genesis(
            [0; 32], // Empty state root
            Utc::now(),
            metadata,
            HashMap::new(),
        );
        
        Ok(StateManager {
            current_block: RwLock::new(genesis_block.clone()),
            table_states: RwLock::new(HashMap::new()),
            block_history: RwLock::new(HashMap::from([(0, genesis_block)])),
            transaction_history: RwLock::new(HashMap::new()),
            config,
            state_root_tree: RwLock::new(state_root_tree),
        })
    }
    
    /// Get the current block state
    pub fn current_block(&self) -> Result<BlockState> {
        let block = self.current_block.read()
            .map_err(|e| CoreError::StateError(format!("Failed to read current block: {}", e)))?;
        
        Ok(block.clone())
    }
    
    /// Get the current block number
    pub fn current_block_number(&self) -> Result<u64> {
        let block = self.current_block.read()
            .map_err(|e| CoreError::StateError(format!("Failed to read current block: {}", e)))?;
        
        Ok(block.header.number)
    }
    
    /// Get the current state root
    pub fn current_state_root(&self) -> Result<[u8; 32]> {
        let block = self.current_block.read()
            .map_err(|e| CoreError::StateError(format!("Failed to read current block: {}", e)))?;
        
        Ok(block.header.state_root)
    }
    
    /// Get a block by number
    pub fn get_block(&self, block_number: u64) -> Result<Option<BlockState>> {
        let blocks = self.block_history.read()
            .map_err(|e| CoreError::StateError(format!("Failed to read block history: {}", e)))?;
        
        Ok(blocks.get(&block_number).cloned())
    }
    
    /// Get a transaction by ID
    pub fn get_transaction(&self, transaction_id: &Uuid) -> Result<Option<TransactionRecord>> {
        let transactions = self.transaction_history.read()
            .map_err(|e| CoreError::StateError(format!("Failed to read transaction history: {}", e)))?;
        
        Ok(transactions.get(transaction_id).cloned())
    }
    
    /// Get a table state
    pub fn get_table_state(&self, table_name: &str) -> Result<Option<TableState>> {
        let tables = self.table_states.read()
            .map_err(|e| CoreError::StateError(format!("Failed to read table states: {}", e)))?;
        
        Ok(tables.get(table_name).cloned())
    }
    
    /// Add a transaction to the current block
    pub fn add_transaction(&self, transaction: TransactionRecord) -> Result<()> {
        // Add to transaction history
        let mut transactions = self.transaction_history.write()
            .map_err(|e| CoreError::StateError(format!("Failed to write transaction history: {}", e)))?;
        
        transactions.insert(transaction.id, transaction.clone());
        
        // Add to current block
        let mut block = self.current_block.write()
            .map_err(|e| CoreError::StateError(format!("Failed to write current block: {}", e)))?;
        
        block.transactions.insert(transaction.id, transaction);
        block.transaction_count = block.transactions.len();
        
        // Update the transactions root
        let transactions_root = block.calculate_transactions_root();
        block.header.transactions_root = transactions_root;
        
        Ok(())
    }
    
    /// Update a table state
    pub fn update_table_state(&self, table_state: TableState) -> Result<()> {
        let mut tables = self.table_states.write()
            .map_err(|e| CoreError::StateError(format!("Failed to write table states: {}", e)))?;
        
        let table_name = table_state.schema.name.clone();
        tables.insert(table_name.clone(), table_state.clone());
        
        // Update the table state root in the current block
        let mut block = self.current_block.write()
            .map_err(|e| CoreError::StateError(format!("Failed to write current block: {}", e)))?;
        
        if let Some(root_hash) = table_state.root_hash {
            block.table_state_roots.insert(table_name, root_hash);
        }
        
        // Recalculate the state root
        self.recalculate_state_root()?;
        
        Ok(())
    }
    
    /// Recalculate the state root
    pub fn recalculate_state_root(&self) -> Result<[u8; 32]> {
        let tables = self.table_states.read()
            .map_err(|e| CoreError::StateError(format!("Failed to read table states: {}", e)))?;
        
        let mut table_roots = Vec::new();
        
        // Collect all table root hashes
        for (table_name, table_state) in tables.iter() {
            if let Some(root_hash) = table_state.root_hash {
                table_roots.push((table_name.clone(), root_hash));
            }
        }
        
        // Sort by table name for determinism
        table_roots.sort_by(|(a, _), (b, _)| a.cmp(b));
        
        // Create a new Merkle tree with the table root hashes
        let mut tree = SecureMerkleTree::new(table_roots.len());
        
        for (i, (_, root_hash)) in table_roots.iter().enumerate() {
            tree.update_leaf(i, root_hash);
        }
        
        // Get the new state root
        let state_root = tree.root_hash();
        
        // Update the current block's state root
        let mut block = self.current_block.write()
            .map_err(|e| CoreError::StateError(format!("Failed to write current block: {}", e)))?;
        
        block.header.state_root = state_root;
        
        // Update the state root tree
        let mut state_root_tree = self.state_root_tree.write()
            .map_err(|e| CoreError::StateError(format!("Failed to write state root tree: {}", e)))?;
        
        *state_root_tree = tree;
        
        Ok(state_root)
    }
    
    /// Create a new block
    pub fn create_new_block(&self, operator_id: &str) -> Result<BlockState> {
        let current_block = self.current_block.read()
            .map_err(|e| CoreError::StateError(format!("Failed to read current block: {}", e)))?;
        
        let new_block_number = current_block.header.number + 1;
        
        // Create metadata for the new block
        let metadata = BlockMetadata {
            postgres_version: self.config.database.postgres_version.clone(),
            protocol_version: "1.0".to_string(),
            operator_id: operator_id.to_string(),
            operator_signature: None,
            operator_public_key: None,
            additional_data: None,
        };
        
        // Create the new block header
        let header = BlockHeader::new(
            new_block_number,
            current_block.header.hash.unwrap_or([0; 32]),
            [0; 32], // Will be updated when transactions are added
            current_block.header.state_root,
            Utc::now(),
            metadata,
        );
        
        // Create the new block
        let new_block = BlockState::new(
            header,
            HashMap::new(),
            current_block.table_state_roots.clone(),
        );
        
        // Update the current block
        let mut current = self.current_block.write()
            .map_err(|e| CoreError::StateError(format!("Failed to write current block: {}", e)))?;
        
        *current = new_block.clone();
        
        // Add to block history
        let mut blocks = self.block_history.write()
            .map_err(|e| CoreError::StateError(format!("Failed to write block history: {}", e)))?;
        
        blocks.insert(new_block_number, new_block.clone());
        
        Ok(new_block)
    }
    
    /// Finalize the current block
    pub fn finalize_current_block(&self) -> Result<BlockState> {
        let mut block = self.current_block.write()
            .map_err(|e| CoreError::StateError(format!("Failed to write current block: {}", e)))?;
        
        // Recalculate the transactions root
        let transactions_root = block.calculate_transactions_root();
        block.header.transactions_root = transactions_root;
        
        // Recalculate the state root
        let state_root = self.recalculate_state_root()?;
        block.header.state_root = state_root;
        
        // Update the block in history
        let mut blocks = self.block_history.write()
            .map_err(|e| CoreError::StateError(format!("Failed to write block history: {}", e)))?;
        
        blocks.insert(block.header.number, block.clone());
        
        Ok(block.clone())
    }
    
    /// Generate a proof for a table state
    pub fn generate_table_proof(&self, table_name: &str) -> Result<Vec<u8>> {
        let tables = self.table_states.read()
            .map_err(|e| CoreError::StateError(format!("Failed to read table states: {}", e)))?;
        
        let table_state = tables.get(table_name)
            .ok_or_else(|| CoreError::StateError(format!("Table not found: {}", table_name)))?;
        
        let state_root_tree = self.state_root_tree.read()
            .map_err(|e| CoreError::StateError(format!("Failed to read state root tree: {}", e)))?;
        
        // Find the position of the table in the state root tree
        let tables_vec: Vec<_> = tables.keys().collect();
        let position = tables_vec.iter().position(|&t| t == table_name)
            .ok_or_else(|| CoreError::StateError(format!("Table not found in state root tree: {}", table_name)))?;
        
        // Generate the proof
        let proof = state_root_tree.generate_proof(position);
        
        // Serialize the proof
        let proof_bytes = bincode::serialize(&proof)
            .map_err(|e| CoreError::SerializationError(format!("Failed to serialize proof: {}", e)))?;
        
        Ok(proof_bytes)
    }
    
    /// Verify a table state proof
    pub fn verify_table_proof(&self, table_name: &str, proof_bytes: &[u8]) -> Result<bool> {
        let state_root_tree = self.state_root_tree.read()
            .map_err(|e| CoreError::StateError(format!("Failed to read state root tree: {}", e)))?;
        
        // Deserialize the proof
        let proof = bincode::deserialize(proof_bytes)
            .map_err(|e| CoreError::SerializationError(format!("Failed to deserialize proof: {}", e)))?;
        
        // Verify the proof
        let result = state_root_tree.verify_proof(&proof);
        
        Ok(result)
    }
    
    /// Reset the state manager (for testing)
    #[cfg(test)]
    pub fn reset(&self) -> Result<()> {
        // Create a genesis block
        let metadata = BlockMetadata {
            postgres_version: self.config.database.postgres_version.clone(),
            protocol_version: "1.0".to_string(),
            operator_id: "genesis".to_string(),
            operator_signature: None,
            operator_public_key: None,
            additional_data: None,
        };
        
        let genesis_block = BlockState::genesis(
            [0; 32], // Empty state root
            Utc::now(),
            metadata,
            HashMap::new(),
        );
        
        // Reset all state
        let mut current_block = self.current_block.write()
            .map_err(|e| CoreError::StateError(format!("Failed to write current block: {}", e)))?;
        
        *current_block = genesis_block.clone();
        
        let mut table_states = self.table_states.write()
            .map_err(|e| CoreError::StateError(format!("Failed to write table states: {}", e)))?;
        
        table_states.clear();
        
        let mut block_history = self.block_history.write()
            .map_err(|e| CoreError::StateError(format!("Failed to write block history: {}", e)))?;
        
        block_history.clear();
        block_history.insert(0, genesis_block);
        
        let mut transaction_history = self.transaction_history.write()
            .map_err(|e| CoreError::StateError(format!("Failed to write transaction history: {}", e)))?;
        
        transaction_history.clear();
        
        let mut state_root_tree = self.state_root_tree.write()
            .map_err(|e| CoreError::StateError(format!("Failed to write state root tree: {}", e)))?;
        
        *state_root_tree = SecureMerkleTree::new(100);
        
        Ok(())
    }
}

/// Thread-safe state manager
pub type SharedStateManager = Arc<StateManager>;

/// Create a new shared state manager
pub fn create_state_manager(config: CoreConfig) -> Result<SharedStateManager> {
    let manager = StateManager::new(config)?;
    Ok(Arc::new(manager))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::table::{TableSchema, ColumnDefinition, ColumnType};
    use crate::models::row::{Row, Value};
    use crate::models::transaction::{TransactionType, Operation, OperationType};
    use std::collections::HashMap;
    
    // Helper to create a test table schema
    fn create_test_table_schema() -> TableSchema {
        let columns = vec![
            ColumnDefinition {
                name: "id".to_string(),
                column_type: ColumnType::Integer,
                nullable: false,
                primary_key: true,
                unique: true,
                default_value: None,
            },
            ColumnDefinition {
                name: "name".to_string(),
                column_type: ColumnType::VarChar(100),
                nullable: false,
                primary_key: false,
                unique: false,
                default_value: None,
            },
        ];
        
        TableSchema::new(
            "users".to_string(),
            columns,
            vec!["id".to_string()],
            Vec::new(),
            Vec::new(),
        )
    }
    
    // Helper to create a test row
    fn create_test_row(id: i32, name: &str) -> Row {
        let mut values = HashMap::new();
        values.insert("id".to_string(), Value::Integer(id));
        values.insert("name".to_string(), Value::Text(name.to_string()));
        
        Row::new(id.to_string(), "users".to_string(), values)
    }
    
    // Helper to create a test table state
    fn create_test_table_state() -> TableState {
        let schema = create_test_table_schema();
        let mut table_state = TableState::new(schema);
        
        // Add some rows
        table_state.insert_row(create_test_row(1, "Alice"));
        table_state.insert_row(create_test_row(2, "Bob"));
        table_state.insert_row(create_test_row(3, "Charlie"));
        
        table_state
    }
    
    // Helper to create a test transaction
    fn create_test_transaction(block_number: u64) -> TransactionRecord {
        let operation = Operation::new(
            OperationType::Insert,
            "INSERT INTO users (id, name) VALUES (4, 'Dave')".to_string(),
            None,
            vec!["users".to_string()],
            None,
            None,
            10,
        );
        
        TransactionRecord::new(
            Uuid::new_v4(),
            block_number,
            TransactionType::ReadWrite,
            Utc::now(),
            Utc::now(),
            vec![operation],
            [0; 32],
            [1; 32],
            HashMap::new(),
            1000,
            12345,
            None,
            None,
        )
    }
    
    #[test]
    fn test_state_manager_creation() {
        let config = CoreConfig::default();
        let manager = StateManager::new(config).unwrap();
        
        // Check that the genesis block was created
        let block = manager.current_block().unwrap();
        assert_eq!(block.header.number, 0);
        assert_eq!(block.transaction_count, 0);
    }
    
    #[test]
    fn test_add_transaction() {
        let config = CoreConfig::default();
        let manager = StateManager::new(config).unwrap();
        
        // Add a transaction
        let transaction = create_test_transaction(0);
        let tx_id = transaction.id;
        manager.add_transaction(transaction).unwrap();
        
        // Check that the transaction was added
        let block = manager.current_block().unwrap();
        assert_eq!(block.transaction_count, 1);
        
        // Check that we can retrieve the transaction
        let tx = manager.get_transaction(&tx_id).unwrap().unwrap();
        assert_eq!(tx.id, tx_id);
    }
    
    #[test]
    fn test_update_table_state() {
        let config = CoreConfig::default();
        let manager = StateManager::new(config).unwrap();
        
        // Update a table state
        let table_state = create_test_table_state();
        manager.update_table_state(table_state).unwrap();
        
        // Check that the table state was added
        let retrieved = manager.get_table_state("users").unwrap().unwrap();
        assert_eq!(retrieved.schema.name, "users");
        assert_eq!(retrieved.row_count, 3);
    }
    
    #[test]
    fn test_create_new_block() {
        let config = CoreConfig::default();
        let manager = StateManager::new(config).unwrap();
        
        // Create a new block
        let block = manager.create_new_block("test_operator").unwrap();
        assert_eq!(block.header.number, 1);
        
        // Check that the current block was updated
        let current = manager.current_block().unwrap();
        assert_eq!(current.header.number, 1);
        
        // Check that we can retrieve the block
        let retrieved = manager.get_block(1).unwrap().unwrap();
        assert_eq!(retrieved.header.number, 1);
    }
    
    #[test]
    fn test_finalize_block() {
        let config = CoreConfig::default();
        let manager = StateManager::new(config).unwrap();
        
        // Add a transaction
        let transaction = create_test_transaction(0);
        manager.add_transaction(transaction).unwrap();
        
        // Update a table state
        let table_state = create_test_table_state();
        manager.update_table_state(table_state).unwrap();
        
        // Finalize the block
        let block = manager.finalize_current_block().unwrap();
        
        // Check that the state root was updated
        assert_ne!(block.header.state_root, [0; 32]);
        
        // Check that the transactions root was updated
        assert_ne!(block.header.transactions_root, [0; 32]);
    }
    
    #[test]
    fn test_table_proof() {
        let config = CoreConfig::default();
        let manager = StateManager::new(config).unwrap();
        
        // Update a table state
        let table_state = create_test_table_state();
        manager.update_table_state(table_state).unwrap();
        
        // Finalize the block
        manager.finalize_current_block().unwrap();
        
        // Generate a proof for the table
        let proof = manager.generate_table_proof("users").unwrap();
        
        // Verify the proof
        let result = manager.verify_table_proof("users", &proof).unwrap();
        assert!(result);
    }
    
    #[test]
    fn test_reset() {
        let config = CoreConfig::default();
        let manager = StateManager::new(config).unwrap();
        
        // Add a transaction
        let transaction = create_test_transaction(0);
        manager.add_transaction(transaction).unwrap();
        
        // Update a table state
        let table_state = create_test_table_state();
        manager.update_table_state(table_state).unwrap();
        
        // Reset the state manager
        manager.reset().unwrap();
        
        // Check that the state was reset
        let block = manager.current_block().unwrap();
        assert_eq!(block.header.number, 0);
        assert_eq!(block.transaction_count, 0);
        
        let table = manager.get_table_state("users").unwrap();
        assert!(table.is_none());
    }
} 