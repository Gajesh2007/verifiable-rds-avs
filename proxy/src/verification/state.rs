//! State capture mechanism for database verification
//!
//! This module provides functionality to efficiently capture database state
//! for verification purposes, including table snapshots and incremental updates.

use crate::error::{ProxyError, Result};
use crate::verification::merkle::{MerkleTree, MerkleLeaf};
use log::{debug, warn, info};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use std::hash::{Hash, Hasher};

/// Table schema information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableSchema {
    /// Table name
    pub name: String,
    
    /// Schema name
    pub schema: String,
    
    /// Column definitions
    pub columns: Vec<ColumnDefinition>,
    
    /// Primary key columns
    pub primary_key: Vec<String>,
    
    /// Version of the schema
    pub version: u64,
    
    /// Creation timestamp
    pub created_at: u64,
    
    /// Last modified timestamp
    pub modified_at: u64,
}

/// Column definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnDefinition {
    /// Column name
    pub name: String,
    
    /// Column type
    pub data_type: String,
    
    /// Whether the column can be null
    pub nullable: bool,
    
    /// Default value
    pub default_value: Option<String>,
    
    /// Position in the table
    pub position: i32,
}

/// Row identifier
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowId {
    /// Primary key values
    pub values: HashMap<String, String>,
}

// Implement Hash manually for RowId since HashMap doesn't implement Hash
impl Hash for RowId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Sort the keys to ensure consistent hashing
        let mut keys: Vec<&String> = self.values.keys().collect();
        keys.sort();
        
        // Hash each key-value pair in sorted order
        for key in keys {
            key.hash(state);
            if let Some(value) = self.values.get(key) {
                value.hash(state);
            }
        }
    }
}

/// Table row
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    /// Row identifier
    pub id: RowId,
    
    /// Column values
    pub values: HashMap<String, Value>,
    
    /// Last modified timestamp
    pub modified_at: u64,
}

/// Value types for database state 
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    /// Null value
    Null,
    
    /// Boolean value
    Boolean(bool),
    
    /// Integer value
    Integer(i64),
    
    /// Float value
    Float(f64),
    
    /// String value
    String(String),
    
    /// Bytes value
    Bytes(Vec<u8>),
    
    /// Array value
    Array(Vec<Value>),
    
    /// Object value
    Object(HashMap<String, Value>),
}

/// State of a table
#[derive(Debug, Clone)]
pub struct TableState {
    /// Table name
    pub name: String,
    
    /// Schema name
    pub schema: String,
    
    /// Table schema
    pub table_schema: TableSchema,
    
    /// Rows in the table
    pub rows: HashMap<RowId, Row>,
    
    /// Merkle tree of the table data
    pub merkle_tree: Option<MerkleTree>,
    
    /// Table state root hash
    pub root_hash: Option<[u8; 32]>,
    
    /// Table state version
    pub version: u64,
    
    /// Last modified timestamp
    pub modified_at: u64,
}

/// State diff for a table
#[derive(Debug, Clone)]
pub struct TableStateDiff {
    /// Table name
    pub name: String,
    
    /// Schema name
    pub schema: String,
    
    /// Inserted rows
    pub inserted: Vec<Row>,
    
    /// Updated rows
    pub updated: Vec<(Row, Row)>, // (old, new)
    
    /// Deleted rows
    pub deleted: Vec<Row>,
    
    /// Schema changes
    pub schema_changes: Option<TableSchema>,
}

/// Database state
#[derive(Debug, Clone)]
pub struct DatabaseState {
    /// Tables in the database
    tables: HashMap<String, TableState>,
    
    /// Merkle tree mapping table names to root hashes
    table_roots: HashMap<String, [u8; 32]>,
    
    /// Database state root hash
    root_hash: Option<[u8; 32]>,
    
    /// Database state version
    version: u64,
    
    /// Last modified timestamp
    modified_at: u64,
}

/// State capture manager for database state
#[derive(Debug)]
pub struct StateCaptureManager {
    /// Current database state
    state: RwLock<DatabaseState>,
    
    /// Schema cache
    schema_cache: Arc<Mutex<HashMap<String, TableSchema>>>,
    
    // In a real implementation, this would be a connection pool to the database
    // For now, we'll simulate it
    // pool: Arc<Pool<PostgresConnectionManager<NoTls>>>,
}

impl DatabaseState {
    /// Create a new empty database state
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
            table_roots: HashMap::new(),
            root_hash: None,
            version: 0,
            modified_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
    
    /// Get the current database root hash
    pub fn root_hash(&self) -> Option<[u8; 32]> {
        self.root_hash
    }
    
    /// Get a table state
    pub fn get_table(&self, name: &str) -> Option<&TableState> {
        self.tables.get(name)
    }
    
    /// Get a table root hash
    pub fn get_table_root(&self, name: &str) -> Option<[u8; 32]> {
        self.table_roots.get(name).copied()
    }
    
    /// Update the database state with a new table state
    pub fn update_table(&mut self, table_state: TableState) -> Result<()> {
        // Update the table state
        let table_name = format!("{}.{}", table_state.schema, table_state.name);
        
        // Update table roots if there's a root hash
        if let Some(root_hash) = table_state.root_hash {
            self.table_roots.insert(table_name.clone(), root_hash);
        }
        
        // Update tables
        self.tables.insert(table_name, table_state);
        
        // Update database version
        self.version += 1;
        
        // Update modified timestamp
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Calculate new root hash
        self.calculate_root_hash()?;
        
        Ok(())
    }
    
    /// Calculate the database root hash
    pub fn calculate_root_hash(&mut self) -> Result<[u8; 32]> {
        // Create a Merkle tree of table root hashes
        let mut merkle_tree = MerkleTree::new();
        
        // Sort table names for deterministic ordering
        let mut table_names: Vec<String> = self.table_roots.keys().cloned().collect();
        table_names.sort();
        
        // Add table root hashes to the Merkle tree
        for table_name in table_names {
            if let Some(root_hash) = self.table_roots.get(&table_name) {
                // Create leaf data: table_name + root_hash
                let mut leaf_data = Vec::new();
                leaf_data.extend_from_slice(table_name.as_bytes());
                leaf_data.extend_from_slice(root_hash);
                
                merkle_tree.add_leaf(leaf_data);
            }
        }
        
        // Build the Merkle tree
        merkle_tree.build()?;
        
        // Get the root hash
        let root_hash = merkle_tree.root_hash()
            .ok_or_else(|| ProxyError::Verification("Failed to calculate database root hash".to_string()))?;
        
        self.root_hash = Some(root_hash);
        
        Ok(root_hash)
    }
    
    /// Get a reference to the tables map
    pub fn tables(&self) -> &HashMap<String, TableState> {
        &self.tables
    }
    
    /// Check if a table exists in the database state
    pub fn has_table(&self, name: &str) -> bool {
        self.tables.contains_key(name)
    }
}

impl TableState {
    /// Create a new table state
    pub fn new(name: &str, schema: &str, table_schema: TableSchema) -> Self {
        Self {
            name: name.to_string(),
            schema: schema.to_string(),
            table_schema,
            rows: HashMap::new(),
            merkle_tree: None,
            root_hash: None,
            version: 0,
            modified_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
    
    /// Add or update a row
    pub fn upsert_row(&mut self, row: Row) {
        self.rows.insert(row.id.clone(), row);
        self.version += 1;
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
    
    /// Delete a row
    pub fn delete_row(&mut self, row_id: &RowId) -> Option<Row> {
        let row = self.rows.remove(row_id);
        
        if row.is_some() {
            self.version += 1;
            self.modified_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
        
        row
    }
    
    /// Build the Merkle tree and calculate the root hash
    pub fn build_merkle_tree(&mut self) -> Result<[u8; 32]> {
        let mut merkle_tree = MerkleTree::new();
        
        // Sort row IDs for deterministic ordering
        let mut row_ids: Vec<&RowId> = self.rows.keys().collect();
        row_ids.sort_by_key(|id| format!("{:?}", id.values));
        
        // Add rows to the Merkle tree
        for row_id in row_ids {
            if let Some(row) = self.rows.get(row_id) {
                // Serialize the row to JSON
                let row_json = serde_json::to_string(row)
                    .map_err(|e| ProxyError::Verification(format!("Failed to serialize row: {}", e)))?;
                
                merkle_tree.add_leaf(row_json.as_bytes().to_vec());
            }
        }
        
        // Build the Merkle tree
        merkle_tree.build()?;
        
        // Get the root hash
        let root_hash = merkle_tree.root_hash()
            .ok_or_else(|| ProxyError::Verification("Failed to calculate table root hash".to_string()))?;
        
        self.merkle_tree = Some(merkle_tree);
        self.root_hash = Some(root_hash);
        
        Ok(root_hash)
    }
    
    /// Generate a Merkle proof for a row
    pub fn generate_proof(&self, row_id: &RowId) -> Result<Vec<u8>> {
        let merkle_tree = self.merkle_tree.as_ref()
            .ok_or_else(|| ProxyError::Verification("Merkle tree not built".to_string()))?;
        
        // Find the row index in the Merkle tree
        if let Some(row) = self.rows.get(row_id) {
            // Serialize the row to JSON
            let row_json = serde_json::to_string(row)
                .map_err(|e| ProxyError::Verification(format!("Failed to serialize row: {}", e)))?;
            
            // Hash the row data
            let row_hash = merkle_tree.hash_leaf(row_json.as_bytes());
            
            // Find the leaf index with this hash
            let mut leaf_index = None;
            for i in 0..merkle_tree.leaf_count() as u64 {
                if let Some(leaf) = merkle_tree.get_leaf(i) {
                    if leaf.hash == row_hash {
                        leaf_index = Some(i);
                        break;
                    }
                }
            }
            
            if let Some(index) = leaf_index {
                // Generate the proof
                let proof = merkle_tree.generate_proof(index)?;
                
                // Serialize the proof
                let proof_bytes = serde_json::to_vec(&proof)
                    .map_err(|e| ProxyError::Verification(format!("Failed to serialize proof: {}", e)))?;
                
                return Ok(proof_bytes);
            }
        }
        
        Err(ProxyError::Verification(format!("Row not found: {:?}", row_id)))
    }
}

impl StateCaptureManager {
    /// Create a new state capture manager
    pub fn new() -> Self {
        Self {
            state: RwLock::new(DatabaseState::new()),
            schema_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Get the current database state root hash
    pub fn get_current_root_hash(&self) -> Option<[u8; 32]> {
        let state = self.state.read().unwrap();
        state.root_hash()
    }
    
    /// Update the state with a table snapshot
    pub fn update_table_state(&self, table_state: TableState) -> Result<[u8; 32]> {
        // Build the Merkle tree for the table
        let mut table_state = table_state;
        let table_root = table_state.build_merkle_tree()?;
        
        // Update the database state
        let mut state = self.state.write().unwrap();
        state.update_table(table_state)?;
        
        // Return the new database root hash
        Ok(state.root_hash().unwrap_or([0; 32]))
    }
    
    /// Capture the state of a table
    pub async fn capture_table_state(&self, table_name: &str, schema_name: &str) -> Result<TableState> {
        // In a real implementation, this would query the database to get the table schema and rows
        // For now, we'll simulate it with a placeholder
        
        // Get table schema from cache or create a new one
        let table_schema = {
            let mut schema_cache = self.schema_cache.lock().unwrap();
            let key = format!("{}.{}", schema_name, table_name);
            
            if !schema_cache.contains_key(&key) {
                // Create a placeholder schema
                let schema = TableSchema {
                    name: table_name.to_string(),
                    schema: schema_name.to_string(),
                    columns: vec![
                        ColumnDefinition {
                            name: "id".to_string(),
                            data_type: "INTEGER".to_string(),
                            nullable: false,
                            default_value: None,
                            position: 1,
                        },
                        ColumnDefinition {
                            name: "name".to_string(),
                            data_type: "TEXT".to_string(),
                            nullable: true,
                            default_value: None,
                            position: 2,
                        },
                    ],
                    primary_key: vec!["id".to_string()],
                    version: 1,
                    created_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    modified_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };
                
                schema_cache.insert(key.clone(), schema.clone());
                schema
            } else {
                schema_cache.get(&key).unwrap().clone()
            }
        };
        
        // Create a new table state
        let mut table_state = TableState::new(table_name, schema_name, table_schema);
        
        // Simulate adding some rows
        let row1 = Row {
            id: RowId {
                values: {
                    let mut map = HashMap::new();
                    map.insert("id".to_string(), "1".to_string());
                    map
                },
            },
            values: {
                let mut map = HashMap::new();
                map.insert("id".to_string(), Value::Integer(1));
                map.insert("name".to_string(), Value::String("Alice".to_string()));
                map
            },
            modified_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        
        let row2 = Row {
            id: RowId {
                values: {
                    let mut map = HashMap::new();
                    map.insert("id".to_string(), "2".to_string());
                    map
                },
            },
            values: {
                let mut map = HashMap::new();
                map.insert("id".to_string(), Value::Integer(2));
                map.insert("name".to_string(), Value::String("Bob".to_string()));
                map
            },
            modified_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        
        table_state.upsert_row(row1);
        table_state.upsert_row(row2);
        
        Ok(table_state)
    }
    
    /// Calculate the difference between two table states
    pub fn calculate_table_diff(&self, old_state: &TableState, new_state: &TableState) -> TableStateDiff {
        let mut inserted = Vec::new();
        let mut updated = Vec::new();
        let mut deleted = Vec::new();
        
        // Check for inserted and updated rows
        for (row_id, new_row) in &new_state.rows {
            if let Some(old_row) = old_state.rows.get(row_id) {
                // Row exists in both states, check if it was updated
                if old_row.modified_at != new_row.modified_at {
                    updated.push((old_row.clone(), new_row.clone()));
                }
            } else {
                // Row only exists in new state, it was inserted
                inserted.push(new_row.clone());
            }
        }
        
        // Check for deleted rows
        for (row_id, old_row) in &old_state.rows {
            if !new_state.rows.contains_key(row_id) {
                // Row only exists in old state, it was deleted
                deleted.push(old_row.clone());
            }
        }
        
        // Check for schema changes
        let schema_changes = if old_state.table_schema.version != new_state.table_schema.version {
            Some(new_state.table_schema.clone())
        } else {
            None
        };
        
        TableStateDiff {
            name: new_state.name.clone(),
            schema: new_state.schema.clone(),
            inserted,
            updated,
            deleted,
            schema_changes,
        }
    }
    
    /// Generate a proof for a row
    pub fn generate_row_proof(&self, table_name: &str, schema_name: &str, row_id: &RowId) -> Result<Vec<u8>> {
        let state = self.state.read().unwrap();
        
        let key = format!("{}.{}", schema_name, table_name);
        if let Some(table_state) = state.get_table(&key) {
            table_state.generate_proof(row_id)
        } else {
            Err(ProxyError::Verification(format!("Table not found: {}", key)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_table_state() {
        // Create a table schema
        let schema = TableSchema {
            name: "users".to_string(),
            schema: "public".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    data_type: "INTEGER".to_string(),
                    nullable: false,
                    default_value: None,
                    position: 1,
                },
                ColumnDefinition {
                    name: "name".to_string(),
                    data_type: "TEXT".to_string(),
                    nullable: true,
                    default_value: None,
                    position: 2,
                },
            ],
            primary_key: vec!["id".to_string()],
            version: 1,
            created_at: 0,
            modified_at: 0,
        };
        
        // Create a table state
        let mut table_state = TableState::new("users", "public", schema);
        
        // Add some rows
        let row1 = Row {
            id: RowId {
                values: {
                    let mut map = HashMap::new();
                    map.insert("id".to_string(), "1".to_string());
                    map
                },
            },
            values: {
                let mut map = HashMap::new();
                map.insert("id".to_string(), Value::Integer(1));
                map.insert("name".to_string(), Value::String("Alice".to_string()));
                map
            },
            modified_at: 0,
        };
        
        let row2 = Row {
            id: RowId {
                values: {
                    let mut map = HashMap::new();
                    map.insert("id".to_string(), "2".to_string());
                    map
                },
            },
            values: {
                let mut map = HashMap::new();
                map.insert("id".to_string(), Value::Integer(2));
                map.insert("name".to_string(), Value::String("Bob".to_string()));
                map
            },
            modified_at: 0,
        };
        
        table_state.upsert_row(row1.clone());
        table_state.upsert_row(row2.clone());
        
        // Build the Merkle tree
        let root_hash = table_state.build_merkle_tree().unwrap();
        
        // Check the root hash
        assert!(root_hash != [0; 32]);
        
        // Check the number of rows
        assert_eq!(table_state.rows.len(), 2);
        
        // Delete a row
        let deleted_row = table_state.delete_row(&row1.id).unwrap();
        assert_eq!(deleted_row.id, row1.id);
        
        // Check the number of rows after deletion
        assert_eq!(table_state.rows.len(), 1);
        
        // Rebuild the Merkle tree
        let new_root_hash = table_state.build_merkle_tree().unwrap();
        
        // Root hash should have changed
        assert_ne!(root_hash, new_root_hash);
    }
    
    #[test]
    fn test_database_state() {
        // Create a database state
        let mut db_state = DatabaseState::new();
        
        // Create a table schema
        let schema = TableSchema {
            name: "users".to_string(),
            schema: "public".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    data_type: "INTEGER".to_string(),
                    nullable: false,
                    default_value: None,
                    position: 1,
                },
                ColumnDefinition {
                    name: "name".to_string(),
                    data_type: "TEXT".to_string(),
                    nullable: true,
                    default_value: None,
                    position: 2,
                },
            ],
            primary_key: vec!["id".to_string()],
            version: 1,
            created_at: 0,
            modified_at: 0,
        };
        
        // Create a table state
        let mut table_state = TableState::new("users", "public", schema);
        
        // Add some rows
        let row1 = Row {
            id: RowId {
                values: {
                    let mut map = HashMap::new();
                    map.insert("id".to_string(), "1".to_string());
                    map
                },
            },
            values: {
                let mut map = HashMap::new();
                map.insert("id".to_string(), Value::Integer(1));
                map.insert("name".to_string(), Value::String("Alice".to_string()));
                map
            },
            modified_at: 0,
        };
        
        let row2 = Row {
            id: RowId {
                values: {
                    let mut map = HashMap::new();
                    map.insert("id".to_string(), "2".to_string());
                    map
                },
            },
            values: {
                let mut map = HashMap::new();
                map.insert("id".to_string(), Value::Integer(2));
                map.insert("name".to_string(), Value::String("Bob".to_string()));
                map
            },
            modified_at: 0,
        };
        
        table_state.upsert_row(row1);
        table_state.upsert_row(row2);
        
        // Build the Merkle tree
        table_state.build_merkle_tree().unwrap();
        
        // Update the database state
        db_state.update_table(table_state).unwrap();
        
        // Check the root hash
        assert!(db_state.root_hash().is_some());
        
        // Create another table
        let schema2 = TableSchema {
            name: "orders".to_string(),
            schema: "public".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    data_type: "INTEGER".to_string(),
                    nullable: false,
                    default_value: None,
                    position: 1,
                },
                ColumnDefinition {
                    name: "user_id".to_string(),
                    data_type: "INTEGER".to_string(),
                    nullable: false,
                    default_value: None,
                    position: 2,
                },
                ColumnDefinition {
                    name: "amount".to_string(),
                    data_type: "DECIMAL".to_string(),
                    nullable: false,
                    default_value: None,
                    position: 3,
                },
            ],
            primary_key: vec!["id".to_string()],
            version: 1,
            created_at: 0,
            modified_at: 0,
        };
        
        let mut table_state2 = TableState::new("orders", "public", schema2);
        
        // Add some rows
        let order1 = Row {
            id: RowId {
                values: {
                    let mut map = HashMap::new();
                    map.insert("id".to_string(), "1".to_string());
                    map
                },
            },
            values: {
                let mut map = HashMap::new();
                map.insert("id".to_string(), Value::Integer(1));
                map.insert("user_id".to_string(), Value::Integer(1));
                map.insert("amount".to_string(), Value::Float(100.0));
                map
            },
            modified_at: 0,
        };
        
        table_state2.upsert_row(order1);
        
        // Build the Merkle tree
        table_state2.build_merkle_tree().unwrap();
        
        // Get the initial root hash
        let initial_root = db_state.root_hash().unwrap();
        
        // Update the database state
        db_state.update_table(table_state2).unwrap();
        
        // Root hash should have changed
        assert_ne!(initial_root, db_state.root_hash().unwrap());
    }
    
    #[test]
    fn test_table_diff() {
        // Create a state capture manager
        let manager = StateCaptureManager::new();
        
        // Create a table schema
        let schema = TableSchema {
            name: "users".to_string(),
            schema: "public".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    data_type: "INTEGER".to_string(),
                    nullable: false,
                    default_value: None,
                    position: 1,
                },
                ColumnDefinition {
                    name: "name".to_string(),
                    data_type: "TEXT".to_string(),
                    nullable: true,
                    default_value: None,
                    position: 2,
                },
            ],
            primary_key: vec!["id".to_string()],
            version: 1,
            created_at: 0,
            modified_at: 0,
        };
        
        // Create old table state
        let mut old_state = TableState::new("users", "public", schema.clone());
        
        // Add some rows
        let row1 = Row {
            id: RowId {
                values: {
                    let mut map = HashMap::new();
                    map.insert("id".to_string(), "1".to_string());
                    map
                },
            },
            values: {
                let mut map = HashMap::new();
                map.insert("id".to_string(), Value::Integer(1));
                map.insert("name".to_string(), Value::String("Alice".to_string()));
                map
            },
            modified_at: 0,
        };
        
        let row2 = Row {
            id: RowId {
                values: {
                    let mut map = HashMap::new();
                    map.insert("id".to_string(), "2".to_string());
                    map
                },
            },
            values: {
                let mut map = HashMap::new();
                map.insert("id".to_string(), Value::Integer(2));
                map.insert("name".to_string(), Value::String("Bob".to_string()));
                map
            },
            modified_at: 0,
        };
        
        old_state.upsert_row(row1.clone());
        old_state.upsert_row(row2.clone());
        
        // Create new table state with changes
        let mut new_state = TableState::new("users", "public", schema.clone());
        
        // Update a row
        let mut row2_updated = row2.clone();
        row2_updated.values.insert("name".to_string(), Value::String("Robert".to_string()));
        row2_updated.modified_at = 1; // Update the modified timestamp
        
        // Add a new row
        let row3 = Row {
            id: RowId {
                values: {
                    let mut map = HashMap::new();
                    map.insert("id".to_string(), "3".to_string());
                    map
                },
            },
            values: {
                let mut map = HashMap::new();
                map.insert("id".to_string(), Value::Integer(3));
                map.insert("name".to_string(), Value::String("Charlie".to_string()));
                map
            },
            modified_at: 1,
        };
        
        // Add rows to new state, but skip row1 (to simulate deletion)
        new_state.upsert_row(row2_updated.clone());
        new_state.upsert_row(row3.clone());
        
        // Calculate the diff
        let diff = manager.calculate_table_diff(&old_state, &new_state);
        
        // Check the diff
        assert_eq!(diff.inserted.len(), 1);
        assert_eq!(diff.inserted[0].id, row3.id);
        
        assert_eq!(diff.updated.len(), 1);
        assert_eq!(diff.updated[0].0.id, row2.id);
        assert_eq!(diff.updated[0].1.id, row2_updated.id);
        
        assert_eq!(diff.deleted.len(), 1);
        assert_eq!(diff.deleted[0].id, row1.id);
        
        assert!(diff.schema_changes.is_none());
    }
} 