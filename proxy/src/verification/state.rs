//! State capture mechanism for database verification
//!
//! This module provides functionality to efficiently capture database state
//! for verification purposes, including table snapshots and incremental updates.

use crate::error::{ProxyError, Result};
use verifiable_db_core::models::{self as core_models, TableSchema, TableState, Row, BlockState as CoreDatabaseState, BlockHeader, BlockMetadata, Value, ColumnType};
use verifiable_db_core::merkle::{self, SecureMerkleTree}; // Import SecureMerkleTree
use chrono::Utc;
use log::{debug, warn, info, error};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use hex;

// Helper struct to track changes within a single table for an in-progress transaction
#[derive(Debug, Default, Clone)]
struct TableChanges {
    inserts: Vec<Row>,
    updates: Vec<(String, Row)>, // Assuming String ID
    deletes: Vec<String>, // Assuming String ID
}

// Helper struct to manage the state of a transaction being built from WAL events
#[derive(Debug, Clone)]
struct InProgressTransactionState {
    transaction_id: Option<u32>,
    changes: HashMap<String, TableChanges>,
}

/// State capture manager using core::BlockState and WAL integration
#[derive(Debug)]
pub struct StateCaptureManager {
    /// History of committed database states (headers and roots), indexed by block number
    state_history: RwLock<HashMap<u64, CoreDatabaseState>>,
    /// The actual live TableState objects corresponding to the latest committed block
    live_table_states: RwLock<HashMap<String, TableState>>,
    /// The block number of the latest committed state in history
    latest_committed_block_number: RwLock<u64>,
    /// State changes accumulated from WAL for the current transaction (if any)
    in_progress_state: RwLock<Option<InProgressTransactionState>>,
    /// Schema cache
    schema_cache: Arc<Mutex<HashMap<String, TableSchema>>>, 
    /// Legacy transaction counter
    transaction_counter: Mutex<u64>,
}

impl StateCaptureManager {
    /// Create a new state capture manager
    pub fn new() -> Self {
        Self {
            state_history: RwLock::new(HashMap::new()),
            live_table_states: RwLock::new(HashMap::new()), // Initialize live states
            latest_committed_block_number: RwLock::new(0),
            in_progress_state: RwLock::new(None),
            schema_cache: Arc::new(Mutex::new(HashMap::new())), 
            transaction_counter: Mutex::new(0),
        }
    }

    /// Initializes the state manager with a genesis block.
    /// `genesis_state` contains the header and roots.
    /// `initial_table_states` contains the actual TableState objects for the genesis block.
    /// Assumes `initial_table_states` have their `root_hash` field correctly populated.
    pub fn initialize_with_genesis_state(&self, genesis_state: CoreDatabaseState, initial_table_states: HashMap<String, TableState>) -> Result<()> {
        let genesis_block_number = genesis_state.header.number;
        if genesis_block_number != 0 {
            return Err(ProxyError::Verification("Genesis block number must be 0".to_string()));
        }
        let mut history_lock = self.state_history.write().map_err(poison_err)?;
        let mut live_states_lock = self.live_table_states.write().map_err(poison_err)?;
        let mut latest_block_lock = self.latest_committed_block_number.write().map_err(poison_err)?;

        if *latest_block_lock != 0 || !history_lock.is_empty() || !live_states_lock.is_empty() {
            // State already initialized
            return Err(ProxyError::Verification("Attempted to initialize already initialized state".to_string()));
        }

        // Verify consistency between roots in genesis_state and provided initial_table_states
        for (table_name, root_in_block) in &genesis_state.table_state_roots {
            match initial_table_states.get(table_name) {
                Some(ts) => {
                    // Ensure TableState has its root calculated and matches the block's root
                    let calculated_root = ts.root_hash.ok_or_else(|| ProxyError::Verification(format!("Genesis TableState for '{}' missing its root_hash field", table_name)))?;
                    if calculated_root != *root_in_block {
                        return Err(ProxyError::Verification(format!(
                            "Genesis root mismatch for table '{}'. Block root: {:?}, TableState root: {:?}", 
                            table_name, hex::encode(root_in_block), hex::encode(calculated_root)
                        )));
                    }
                }
                None => return Err(ProxyError::Verification(format!("Genesis state has root for table '{}' but no corresponding TableState object was provided", table_name)))
            }
        }
        // Verify the number of roots matches the number of provided states
        if genesis_state.table_state_roots.len() != initial_table_states.len() {
             return Err(ProxyError::Verification(format!(
                 "Mismatch between number of roots in genesis BlockState ({}) and number of provided TableStates ({})", 
                 genesis_state.table_state_roots.len(), initial_table_states.len()
            )));
        }

        // Store genesis block (roots only) in history
        history_lock.insert(genesis_block_number, genesis_state);
        // Store full initial table states in live state map
        *live_states_lock = initial_table_states;
        // Set the current block number to the genesis block number
        *latest_block_lock = genesis_block_number;

        info!("StateCaptureManager initialized with genesis block {}", genesis_block_number);
        Ok(())
    }

    /// Begins tracking changes for a new transaction received from WAL.
    pub fn begin_wal_transaction(&self, transaction_id: Option<u32>) -> Result<()> {
        let mut in_progress_lock = self.in_progress_state.write().map_err(poison_err)?;
        if in_progress_lock.is_some() {
            // This might happen if COMMIT/ROLLBACK was missed. Log error and overwrite.
            error!("begin_wal_transaction called while another transaction was in progress. Overwriting.");
        }
        *in_progress_lock = Some(InProgressTransactionState {
            transaction_id,
            changes: HashMap::new(),
        });
        debug!("Began tracking WAL transaction {:?}", transaction_id);
        Ok(())
    }

    /// Applies an insert operation from WAL to the in-progress transaction state.
    pub fn apply_wal_insert(&self, table_name: String, new_row: Row) -> Result<()> {
        let mut in_progress_lock = self.in_progress_state.write().map_err(poison_err)?;
        if let Some(state) = in_progress_lock.as_mut() {
            state.changes.entry(table_name).or_default().inserts.push(new_row);
            debug!("Applied WAL insert to table '{}' for txn {:?}", state.changes.keys().last().unwrap_or(&"<unknown>".to_string()), state.transaction_id); // Improved debug log
            Ok(())
        } else {
            Err(ProxyError::Verification("Attempted to apply WAL insert outside of a transaction".to_string()))
        }
    }
    
    /// Applies an update operation from WAL.
    /// `row_id` is the string representation of the primary key.
    pub fn apply_wal_update(&self, table_name: String, row_id: String, new_row: Row) -> Result<()> {
        let mut in_progress_lock = self.in_progress_state.write().map_err(poison_err)?;
        if let Some(state) = in_progress_lock.as_mut() {
            state.changes.entry(table_name).or_default().updates.push((row_id.clone(), new_row)); // Clone row_id for logging
            debug!("Applied WAL update for row '{}' in table '{}' for txn {:?}", row_id, state.changes.keys().last().unwrap_or(&"<unknown>".to_string()), state.transaction_id); // Improved debug log
            Ok(())
        } else {
            Err(ProxyError::Verification("Attempted to apply WAL update outside of a transaction".to_string()))
        }
    }

    /// Applies a delete operation from WAL.
    /// `row_id` is the string representation of the primary key.
    pub fn apply_wal_delete(&self, table_name: String, row_id: String) -> Result<()> {
        let mut in_progress_lock = self.in_progress_state.write().map_err(poison_err)?;
        if let Some(state) = in_progress_lock.as_mut() {
            state.changes.entry(table_name).or_default().deletes.push(row_id.clone()); // Clone row_id for logging
            debug!("Applied WAL delete for row '{}' in table '{}' for txn {:?}", row_id, state.changes.keys().last().unwrap_or(&"<unknown>".to_string()), state.transaction_id); // Improved debug log
            Ok(())
        } else {
            Err(ProxyError::Verification("Attempted to apply WAL delete outside of a transaction".to_string()))
        }
    }

    /// Commits the accumulated WAL changes, creating a new block state.
    pub fn commit_wal_transaction(&self, commit_lsn: u64) -> Result<u64> {
        // 1. Take the in-progress state, error if none exists.
        let in_progress_state = self.in_progress_state.write().map_err(poison_err)?.take()
            .ok_or_else(|| ProxyError::Verification("Attempted to commit WAL transaction with no transaction in progress".to_string()))?;

        // 2. Lock necessary state components.
        let mut live_states_lock = self.live_table_states.write().map_err(poison_err)?;
        let mut history_lock = self.state_history.write().map_err(poison_err)?;
        let mut latest_block_lock = self.latest_committed_block_number.write().map_err(poison_err)?;

        // 3. Get the previous block state.
        let previous_block_number = *latest_block_lock;
        let previous_block_state = history_lock.get(&previous_block_number)
            .ok_or_else(|| ProxyError::Verification(format!("Failed to find previous block state for block {}", previous_block_number)))?;
        // Clone the previous hash for the new header later
        let previous_block_hash = previous_block_state.header.hash.unwrap_or([0u8; 32]);

        // --- 4. Apply changes to live TableState objects --- 
        let mut modified_tables = HashMap::new();

        for (table_name, changes) in in_progress_state.changes {
            // Get the live TableState or create if new (requires schema)
            let mut table_state = live_states_lock.remove(&table_name).unwrap_or_else(|| {
                // Attempt to fetch schema from cache
                let schema = self.get_schema(&table_name).unwrap_or_else(|| {
                    warn!("Schema not found in cache for new table '{}' during commit, creating empty TableState. Verification might fail later if schema differs.", table_name);
                    // Create a minimal schema. This might be insufficient.
                    // Consider fetching schema from DB if cache miss is critical.
                    let minimal_schema = TableSchema::new(table_name.clone(), vec![], vec![], vec![], vec![]);
                    self.cache_schema(minimal_schema.clone()); // Cache the minimal one to avoid repeated warnings
                    minimal_schema
                });
                TableState::new(schema)
            });

            // Apply deletes (using row_id string)
            for row_id_to_delete in changes.deletes {
                // `delete_row` returns Option<Row>, result ignored for now
                table_state.delete_row(&row_id_to_delete);
                debug!("Applied delete for row_id '{}' in table '{}'", row_id_to_delete, table_name);
            }
            // Apply updates (using row_id string - assumed delete+insert)
            for (row_id_to_update, updated_row) in changes.updates {
                // Assumes update_row implies deleting the old row first if it exists.
                // If TableState doesn't have a direct update, we do delete + insert.
                table_state.delete_row(&row_id_to_update); // Ignore result, might not exist
                table_state.insert_row(updated_row); // Insert new version
                debug!("Applied update for row_id '{}' in table '{}'", row_id_to_update, table_name);
            }
            // Apply inserts
            for inserted_row in changes.inserts {
                // `insert_row` might return an error if PK exists, handle if needed
                table_state.insert_row(inserted_row); 
                debug!("Applied insert in table '{}'", table_name); // Log less verbosely for inserts
            }

            // Recalculate Merkle root for the modified table state
            // This is crucial. Assumes TableState has this method.
            table_state.rebuild_merkle_tree(); 
            info!("Updated live state for table '{}', new row count: {}, new root: {:?}", 
                  table_name, table_state.row_count, table_state.root_hash.map(hex::encode));
            
            // Store modified state temporarily
            modified_tables.insert(table_name.clone(), table_state);
        }

        // Update the live_table_states with the modified ones (and add back unmodified ones removed earlier)
        live_states_lock.extend(modified_tables);

        // --- 5. Calculate Merkle Roots using SecureMerkleTree --- 

        // 5.1 Aggregate Table Root
        let final_table_state_roots: HashMap<String, [u8; 32]> = live_states_lock.iter()
            .filter_map(|(name, state_lock)| {
                let state = state_lock.read().unwrap(); // Handle potential poison error
                state.root_hash.map(|root| (name.clone(), root))
            })
            .collect();

        let mut sorted_table_roots: Vec<_> = final_table_state_roots.iter().collect();
        sorted_table_roots.sort_by_key(|(name, _)| *name); // Sort by table name for determinism
        let table_root_vecs: Vec<Vec<u8>> = sorted_table_roots.iter().map(|(_, hash)| hash.to_vec()).collect();
        let table_tree = SecureMerkleTree::from_leaves(&table_root_vecs);
        let new_overall_state_root = table_tree.root_hash();

        // 5.2 Empty Transaction Root
        let empty_tx_tree = SecureMerkleTree::from_leaves(&Vec::<Vec<u8>>::new());
        let transactions_root = empty_tx_tree.root_hash();

        // --- 6. Create Metadata (Example) --- 
        // TODO: Populate metadata fields properly
        let metadata = BlockMetadata {
            postgres_version: "unknown".to_string(),
            protocol_version: env!("CARGO_PKG_VERSION").to_string(),
            operator_id: "proxy-node-1".to_string(),
            operator_signature: None,
            operator_public_key: None,
            additional_data: Some(serde_json::to_string(&HashMap::from([("commit_lsn", commit_lsn)])).unwrap_or_default()),
        };

        // --- 7. Create the new block header using the calculated roots --- 
        let new_block_number = previous_block_number + 1;
        let new_block_header = BlockHeader::new(
            new_block_number,
            previous_block_hash, // Hash of the previous block's header
            transactions_root,   // Root calculated using SecureMerkleTree
            new_overall_state_root, // Root calculated using SecureMerkleTree
            Utc::now(),          // Timestamp of block creation
            metadata,            // Block metadata
        );

        // --- 8. Create new CoreDatabaseState --- 
        let new_block_state = CoreDatabaseState::new(
            new_block_header, // Pass the created header
            HashMap::new(),   // Empty transactions map for WAL commit
            final_table_state_roots, // Pass the final, complete map of table roots
        );

        // --- 9. Update History and Block Number --- 
        history_lock.insert(new_block_number, new_block_state);
        *latest_block_lock = new_block_number;

        // --- 9. Return New Block Number --- 
        info!("Committed WAL transaction. New block: {}, State root: {:?}", new_block_number, hex::encode(new_overall_state_root));
        Ok(new_block_number)
    }

    /// Gets the state root hash of the latest committed block.
    pub fn get_current_root_hash(&self) -> Result<Option<[u8; 32]>> {
        let latest_block_num = *self.latest_committed_block_number.read().map_err(poison_err)?;
        let history_lock = self.state_history.read().map_err(poison_err)?;
        // Check if history contains the latest block number (handles uninitialized case)
        match history_lock.get(&latest_block_num) {
            Some(state) => Ok(Some(state.header.state_root)),
            None => {
                // If latest_block_num is 0 but history is empty, it's uninitialized
                if latest_block_num == 0 {
                    Ok(None)
                } else {
                    // This indicates an inconsistency: latest_block_num points to a non-existent history entry
                    error!("Inconsistency: latest_committed_block_number is {}, but no corresponding state found in history.", latest_block_num);
                    Err(ProxyError::Verification(format!("State history inconsistent: block {} not found", latest_block_num)))
                }
            }
        }
    }

    /// Gets the block number of the latest committed block.
    pub fn get_current_block_number(&self) -> Result<u64> {
        Ok(*self.latest_committed_block_number.read().map_err(poison_err)?)
    }

    /// Gets the historical BlockState (header and roots) for a specific block number.
    pub fn get_historical_block_state(&self, block_number: u64) -> Result<Option<CoreDatabaseState>> {
        let history_guard = self.state_history.read().map_err(poison_err)?;
        let maybe_state_ref: Option<&CoreDatabaseState> = history_guard.get(&block_number);
        // Use explicit match instead of .map() or .cloned()
        let result: Option<CoreDatabaseState> = match maybe_state_ref {
            Some(state_ref) => Some(state_ref.clone()),
            None => None,
        };
        Ok(result)
    }

    /// Gets a clone of the latest committed BlockState (header and roots).
    pub fn get_latest_committed_block_state(&self) -> Result<Option<CoreDatabaseState>> {
        let latest_block_num = self.get_current_block_number()?;
        // Revert to simpler version calling the function above
        self.get_historical_block_state(latest_block_num)
    }

    /// Gets a clone of the latest committed *live* TableState (full state with rows) for a specific table.
    pub fn get_latest_committed_table_state(&self, table_name: &str) -> Result<Option<TableState>> {
        let live_states_guard = self.live_table_states.read().map_err(poison_err)?;
        let maybe_state_ref: Option<&TableState> = live_states_guard.get(table_name);
        // Use explicit match instead of .map() or .cloned()
        let result: Option<TableState> = match maybe_state_ref {
            Some(state_ref) => Some(state_ref.clone()),
            None => None,
        };
        Ok(result)
    }

    /// Gets a clone of a specific historical *live* TableState (full state with rows).
    /// **NOTE:** This is generally inefficient and only possible if the requested `block_number` 
    /// is the *latest* committed block, as only the latest live states are stored.
    /// For verifying past states, use `get_historical_block_state` to get roots and 
    /// generate proofs against the latest live state if needed.
    pub fn get_historical_table_state(&self, table_name: &str, block_number: u64) -> Result<Option<TableState>> {
        let latest_block_num = self.get_current_block_number()?;
        if block_number == latest_block_num {
             // If requesting the latest block, return the current live state
             self.get_latest_committed_table_state(table_name)
        } else {
            // Accessing full historical TableState objects is not directly supported by this structure.
            warn!("Attempted to access full historical TableState for table '{}' at block {}. This requires state snapshots or replay, which is not implemented. Only the root is available via get_historical_block_state.", table_name, block_number);
            Ok(None) 
        }
    }

    /// Retain schema cache and legacy ID methods for now
    pub fn cache_schema(&self, schema: TableSchema) {
        let mut cache = self.schema_cache.lock().unwrap();
        cache.insert(schema.name.clone(), schema);
    }

    pub fn get_schema(&self, table_name: &str) -> Option<TableSchema> {
        let cache_lock = self.schema_cache.lock().unwrap(); // TODO handle poison
        // Use explicit match instead of .cloned()
        match cache_lock.get(table_name) {
            Some(schema_ref) => Some(schema_ref.clone()),
            None => None,
        }
    }

    pub fn get_next_transaction_id(&self) -> u64 {
        let mut counter = self.transaction_counter.lock().unwrap();
        *counter += 1;
        *counter
    }
}

// Helper for lock poisoning errors (Keep)
fn poison_err<T>(e: PoisonError<T>) -> ProxyError {
    ProxyError::Verification(format!("State lock poisoned: {}", e))
}

// Replace old tests with new ones
#[cfg(test)]
mod tests {
    use super::*;
    use verifiable_db_core::models::{BlockHeader, ColumnDefinition, ColumnType, Row, Value, TableSchema};
    use std::collections::HashMap;
    use chrono::Utc;

    // --- Test Helper Functions --- 

    fn create_test_schema(name: &str) -> TableSchema {
        let columns = vec![
            ColumnDefinition {
                name: "id".to_string(),
                column_type: ColumnType::Integer, // Changed from data_type string
                nullable: false,
                primary_key: true,
                unique: true,
                default_value: None,
            },
            ColumnDefinition {
                name: "data".to_string(),
                column_type: ColumnType::Text, // Changed from data_type string
                nullable: true,
                primary_key: false,
                unique: false,
                default_value: None,
            },
        ];
        // Updated primary_keys field name
        let primary_keys = vec!["id".to_string()];
        // Add other fields if needed by TableSchema::new
        TableSchema::new(name.to_string(), columns, primary_keys, vec![], vec![])
    }

    fn create_test_row(id: i32, data: &str, table_name: &str) -> Row {
        let mut values = HashMap::new();
        values.insert("id".to_string(), Value::Integer(id));
        values.insert("data".to_string(), Value::Text(data.to_string()));
        let row_id_str = id.to_string(); // Calculate ID string
        Row::new(row_id_str, table_name.to_string(), values) // Pass id, table_name, and values
    }

    // Helper to get row ID string (assuming single integer PK "id" for simplicity)
    fn get_row_id_str(row: &Row) -> String {
        match row.values.get("id").unwrap() {
            Value::Integer(i) => i.to_string(),
            _ => panic!("Test row ID is not integer"),
        }
    }
    
    // Helper to create default BlockMetadata
    fn default_metadata() -> BlockMetadata {
        BlockMetadata {
            postgres_version: "test_version".to_string(),
            protocol_version: "test_proto".to_string(),
            operator_id: "test_op".to_string(),
            operator_signature: None,
            operator_public_key: None,
            additional_data: None,
        }
    }

    // Helper to setup genesis state for tests
    fn setup_genesis_state(manager: &StateCaptureManager, table_schemas: HashMap<String, TableSchema>, initial_data: HashMap<String, Vec<Row>>) -> Result<CoreDatabaseState> {
        let mut initial_table_states = HashMap::new();
        let mut genesis_table_roots = HashMap::new();

        for (table_name, schema) in table_schemas {
            let mut table_state = TableState::new(schema);
            if let Some(rows) = initial_data.get(&table_name) {
                for row in rows {
                    table_state.insert_row(row.clone());
                }
            }
            table_state.rebuild_merkle_tree(); // Calculate root for this table
            let root = table_state.root_hash.ok_or_else(|| ProxyError::Verification(format!("Failed to calculate root for genesis table '{}'", table_name)))?;
            genesis_table_roots.insert(table_name.clone(), root);
            initial_table_states.insert(table_name, table_state);
        }

        // Calculate Genesis Roots using SecureMerkleTree
        let mut sorted_genesis_roots: Vec<_> = genesis_table_roots.iter().collect();
        sorted_genesis_roots.sort_by_key(|(name, _)| *name);
        let genesis_root_vecs: Vec<Vec<u8>> = sorted_genesis_roots.iter().map(|(_, hash)| hash.to_vec()).collect();
        
        let genesis_table_tree = SecureMerkleTree::from_leaves(&genesis_root_vecs);
        let genesis_aggregate_root = genesis_table_tree.root_hash();

        let empty_tx_tree = SecureMerkleTree::from_leaves(&Vec::<Vec<u8>>::new());
        let genesis_tx_root = empty_tx_tree.root_hash();

        // Create Genesis Header
        let genesis_header = BlockHeader::new(
            0, // Genesis block number is 0
            [0u8; 32], // Previous hash for genesis
            genesis_tx_root, // Calculated genesis transaction root
            genesis_aggregate_root, // Calculated genesis state root
            Utc::now(),          // Timestamp of block creation
            Default::default() // Default metadata for genesis
        );

        // Create Genesis State
        let genesis_state = CoreDatabaseState::new(
            genesis_header, // Pass the created header
            HashMap::new(),   // No transactions in genesis state itself
            genesis_table_roots, // Pass the map of table names to their roots
        );

        // Set the initial state in the manager
        manager.initialize_with_genesis_state(genesis_state.clone(), initial_table_states)?;
        Ok(genesis_state)
    }

    // --- Test Cases --- 

    #[test]
    fn test_initialization_and_genesis() {
        let manager = StateCaptureManager::new();
        assert_eq!(manager.get_current_block_number().unwrap(), 0);
        // Before init, root hash should be None
        assert!(manager.get_current_root_hash().unwrap().is_none()); 
        assert!(manager.get_latest_committed_block_state().unwrap().is_none());

        // Setup genesis
        let schema = create_test_schema("test_table");
        let schemas = vec![("test_table".to_string(), schema)].into_iter().collect();
        let data = vec![("test_table".to_string(), vec![create_test_row(1, "genesis", "test_table")])].into_iter().collect();
        let genesis_state = setup_genesis_state(&manager, schemas, data).unwrap();
        let expected_genesis_root = genesis_state.header.state_root;

        // Verify post-init state
        assert_eq!(manager.get_current_block_number().unwrap(), 0);
        assert_eq!(manager.get_current_root_hash().unwrap(), Some(expected_genesis_root));
        
        let retrieved_block_state = manager.get_historical_block_state(0).unwrap().unwrap();
        assert_eq!(retrieved_block_state.header.number, 0);
        assert_eq!(retrieved_block_state.header.state_root, expected_genesis_root);
        assert_eq!(retrieved_block_state.table_state_roots.len(), 1);
        assert!(retrieved_block_state.table_state_roots.contains_key("test_table"));

        assert!(manager.get_historical_block_state(1).unwrap().is_none());
        
        let live_table_state = manager.get_latest_committed_table_state("test_table").unwrap().unwrap();
        assert_eq!(live_table_state.row_count, 1);
        assert!(live_table_state.get_row(&live_table_state.rows[0].id).is_some());
        assert_eq!(live_table_state.root_hash, Some(*retrieved_block_state.table_state_roots.get("test_table").unwrap()));

        // Try initializing again - should fail
        let empty_schemas = HashMap::new();
        let empty_data = HashMap::new();
        assert!(setup_genesis_state(&manager, empty_schemas, empty_data).is_err());
    }

    #[test]
    fn test_wal_transaction_flow() {
        let manager = StateCaptureManager::new();
        
        // Initialize with empty genesis
        let schema = create_test_schema("users");
        let schemas = vec![("users".to_string(), schema.clone())].into_iter().collect();
        let empty_data = HashMap::new();
        let genesis_state = setup_genesis_state(&manager, schemas, empty_data).unwrap();
        let root0 = genesis_state.header.state_root;

        // Cache schema needed for commit
        manager.cache_schema(schema);

        // === Transaction 1: Insert user 1, Insert user 2 ===
        manager.begin_wal_transaction(Some(100)).unwrap();
        let row1 = create_test_row(1, "alice", "users");
        let row2 = create_test_row(2, "bob", "users");
        manager.apply_wal_insert("users".to_string(), row1.clone()).unwrap();
        manager.apply_wal_insert("users".to_string(), row2.clone()).unwrap();
        let block1_num = manager.commit_wal_transaction(20).unwrap(); // Use LSN 20
        
        assert_eq!(block1_num, 1);
        assert!(manager.in_progress_state.read().unwrap().is_none()); // State cleared after commit
        assert_eq!(manager.get_current_block_number().unwrap(), 1);
        let root1 = manager.get_current_root_hash().unwrap().unwrap();
        assert_ne!(root0, root1); // Root should change

        // Verify state of block 1 (history and live)
        let state1_hist = manager.get_historical_block_state(1).unwrap().unwrap();
        assert_eq!(state1_hist.header.number, 1);
        assert_eq!(state1_hist.header.previous_hash, genesis_state.header.hash.unwrap());
        assert_eq!(state1_hist.header.state_root, root1);
        assert!(state1_hist.header.additional_data.unwrap().contains("\"commit_lsn\":20"));
        let state1_live_table = manager.get_latest_committed_table_state("users").unwrap().unwrap();
        assert_eq!(state1_live_table.row_count, 2);
        assert!(state1_live_table.get_row(&row1.id).is_some());
        assert!(state1_live_table.get_row(&row2.id).is_some());
        assert_eq!(state1_live_table.root_hash.unwrap(), *state1_hist.table_state_roots.get("users").unwrap());

        // === Transaction 2: Update user 1, Delete user 2, Insert user 3 ===
        manager.begin_wal_transaction(Some(101)).unwrap();
        let row1_updated = create_test_row(1, "alice_updated", "users");
        let row3 = create_test_row(3, "charlie", "users");
        manager.apply_wal_update("users".to_string(), row1.id.clone(), row1_updated.clone()).unwrap();
        manager.apply_wal_delete("users".to_string(), row2.id.clone()).unwrap();
        manager.apply_wal_insert("users".to_string(), row3.clone()).unwrap();
        let block2_num = manager.commit_wal_transaction(30).unwrap(); // Use LSN 30

        assert_eq!(block2_num, 2);
        assert_eq!(manager.get_current_block_number().unwrap(), 2);
        let root2 = manager.get_current_root_hash().unwrap().unwrap();
        assert_ne!(root1, root2);

        // Verify state of block 2 (history and live)
        let state2_hist = manager.get_historical_block_state(2).unwrap().unwrap();
        assert_eq!(state2_hist.header.number, 2);
        assert_eq!(state2_hist.header.previous_hash, state1_hist.header.hash.unwrap());
        assert_eq!(state2_hist.header.state_root, root2);
        assert!(state2_hist.header.additional_data.unwrap().contains("\"commit_lsn\":30"));
        let state2_live_table = manager.get_latest_committed_table_state("users").unwrap().unwrap();
        assert_eq!(state2_live_table.row_count, 2);
        assert!(state2_live_table.get_row(&row1_updated.id).is_some());
        assert_eq!(state2_live_table.get_row(&row1_updated.id).unwrap().values.get("data").unwrap(), &Value::Text("alice_updated".to_string()));
        assert!(state2_live_table.get_row(&row2.id).is_none()); // Bob deleted
        assert!(state2_live_table.get_row(&row3.id).is_some());
        assert_eq!(state2_live_table.root_hash.unwrap(), *state2_hist.table_state_roots.get("users").unwrap());

        // Verify history access
        assert!(manager.get_historical_block_state(0).unwrap().is_some());
        assert!(manager.get_historical_block_state(1).unwrap().is_some());
        assert!(manager.get_historical_block_state(2).unwrap().is_some());
        assert!(manager.get_historical_block_state(3).unwrap().is_none());

        // Verify historical table state access (only latest works)
        assert!(manager.get_historical_table_state("users", 2).unwrap().is_some());
        assert!(manager.get_historical_table_state("users", 1).unwrap().is_none());
        assert!(manager.get_historical_table_state("users", 0).unwrap().is_none());
    }
    
    // TODO: Add test_wal_errors
    // TODO: Add test_schema_handling_on_commit
}