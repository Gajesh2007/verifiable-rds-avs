//! Database table representation
//!
//! This module provides data structures for representing database tables
//! including schema and state tracking.

use std::collections::HashMap;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use serde::{Serialize, Deserialize};

use crate::crypto;
use crate::merkle::SecureMerkleTree;
use super::domains;
use super::row::Row;

/// Type of column in a table schema
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColumnType {
    /// Integer (32-bit)
    Integer,
    
    /// Big integer (64-bit)
    BigInt,
    
    /// Floating point (64-bit)
    Float,
    
    /// Variable-length text string
    VarChar(usize),
    
    /// Fixed-length text string
    Char(usize),
    
    /// Text (unlimited length)
    Text,
    
    /// Binary data
    Binary,
    
    /// Boolean
    Boolean,
    
    /// UUID
    Uuid,
    
    /// Timestamp
    Timestamp,
    
    /// JSON data
    Json,
}

/// Definition of a column in a table schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnDefinition {
    /// Name of the column
    pub name: String,
    
    /// Type of the column
    pub column_type: ColumnType,
    
    /// Whether the column can be null
    pub nullable: bool,
    
    /// Whether the column is a primary key
    pub primary_key: bool,
    
    /// Whether the column is unique
    pub unique: bool,
    
    /// Default value for the column (as serialized JSON)
    pub default_value: Option<String>,
}

/// Schema of a database table
#[derive(Clone, Serialize, Deserialize)]
pub struct TableSchema {
    /// Name of the table
    pub name: String,
    
    /// Columns in the table
    pub columns: Vec<ColumnDefinition>,
    
    /// Primary key column names
    pub primary_keys: Vec<String>,
    
    /// Unique constraints
    pub unique_constraints: Vec<Vec<String>>,
    
    /// Foreign key constraints
    pub foreign_keys: Vec<(Vec<String>, String, Vec<String>)>,
    
    /// Hash of the schema
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<[u8; 32]>,
}

impl Debug for TableSchema {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("TableSchema")
            .field("name", &self.name)
            .field("columns", &self.columns)
            .field("primary_keys", &self.primary_keys)
            .field("unique_constraints", &self.unique_constraints)
            .field("foreign_keys", &self.foreign_keys)
            .finish()
    }
}

impl TableSchema {
    /// Create a new table schema
    pub fn new(
        name: String,
        columns: Vec<ColumnDefinition>,
        primary_keys: Vec<String>,
        unique_constraints: Vec<Vec<String>>,
        foreign_keys: Vec<(Vec<String>, String, Vec<String>)>,
    ) -> Self {
        let mut schema = TableSchema {
            name,
            columns,
            primary_keys,
            unique_constraints,
            foreign_keys,
            hash: None,
        };
        
        // Calculate the hash
        schema.hash = Some(schema.calculate_hash());
        
        schema
    }
    
    /// Calculate the hash of the schema with domain separation
    pub fn calculate_hash(&self) -> [u8; 32] {
        // Serialize the schema to JSON for hashing
        let schema_json = serde_json::to_string(self).unwrap_or_default();
        
        // Hash with domain separation
        crypto::secure_hash(domains::TABLE_STATE, schema_json.as_bytes())
    }
    
    /// Get a column by name
    pub fn get_column(&self, name: &str) -> Option<&ColumnDefinition> {
        self.columns.iter().find(|col| col.name == name)
    }
    
    /// Check if the schema has a column
    pub fn has_column(&self, name: &str) -> bool {
        self.columns.iter().any(|col| col.name == name)
    }
    
    /// Get the primary key columns
    pub fn primary_key_columns(&self) -> Vec<&ColumnDefinition> {
        self.columns
            .iter()
            .filter(|col| col.primary_key)
            .collect()
    }
    
    /// Verify the hash of the schema
    pub fn verify_hash(&self) -> bool {
        match self.hash {
            Some(hash) => hash == self.calculate_hash(),
            None => true, // No hash to verify
        }
    }
}

/// State of a database table
#[derive(Clone, Serialize, Deserialize)]
pub struct TableState {
    /// Schema of the table
    pub schema: TableSchema,
    
    /// Rows in the table, keyed by primary key/ID
    pub rows: HashMap<String, Row>,
    
    /// Merkle tree of the rows for verification
    #[serde(skip)]
    pub merkle_tree: Option<SecureMerkleTree>,
    
    /// Root hash of the Merkle tree
    pub root_hash: Option<[u8; 32]>,
    
    /// Number of rows in the table
    pub row_count: usize,
}

impl Debug for TableState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("TableState")
            .field("schema", &self.schema)
            .field("row_count", &self.row_count)
            .field("root_hash", &self.root_hash.map(|h| hex::encode(&h[0..4])))
            .finish()
    }
}

impl TableState {
    /// Create a new empty table state
    pub fn new(schema: TableSchema) -> Self {
        TableState {
            schema,
            rows: HashMap::new(),
            merkle_tree: None,
            root_hash: None,
            row_count: 0,
        }
    }
    
    /// Get a row by ID
    pub fn get_row(&self, id: &str) -> Option<&Row> {
        self.rows.get(id)
    }
    
    /// Insert a row
    pub fn insert_row(&mut self, row: Row) {
        let id = row.id.clone();
        self.rows.insert(id, row);
        self.row_count = self.rows.len();
        
        // Rebuild the Merkle tree (or we could optimize this to just update)
        self.rebuild_merkle_tree();
    }
    
    /// Update a row
    pub fn update_row(&mut self, row: Row) {
        let id = row.id.clone();
        self.rows.insert(id, row);
        
        // Rebuild the Merkle tree
        self.rebuild_merkle_tree();
    }
    
    /// Delete a row
    pub fn delete_row(&mut self, id: &str) -> Option<Row> {
        let row = self.rows.remove(id);
        if row.is_some() {
            self.row_count = self.rows.len();
            
            // Rebuild the Merkle tree
            self.rebuild_merkle_tree();
        }
        row
    }
    
    /// Rebuild the Merkle tree for the table
    pub fn rebuild_merkle_tree(&mut self) {
        // Collect row hashes in a deterministic order (by ID)
        let mut row_ids: Vec<String> = self.rows.keys().cloned().collect();
        row_ids.sort();
        
        // First collect all the hashes into a vector
        let hashes: Vec<[u8; 32]> = row_ids
            .iter()
            .map(|id| {
                let row = self.rows.get(id).unwrap();
                row.hash()
            })
            .collect();
        
        // Convert to Vec<Vec<u8>> for the Merkle tree
        let row_hashes: Vec<Vec<u8>> = hashes.iter().map(|h| h.to_vec()).collect();
        
        // Check if there are any rows
        if row_hashes.is_empty() {
            self.merkle_tree = None;
            self.root_hash = None;
            return;
        }
        
        // Create a Merkle tree from the row hashes
        let tree = SecureMerkleTree::from_leaves(&row_hashes);
        
        // Save the root hash
        let root_hash = tree.root_hash();
        
        self.merkle_tree = Some(tree);
        self.root_hash = Some(root_hash);
    }
    
    /// Generate a Merkle proof for a row
    pub fn generate_proof(&self, id: &str) -> Option<(Row, Vec<u8>)> {
        // Get the row
        let row = self.get_row(id)?;
        
        // Get the Merkle tree
        let tree = self.merkle_tree.as_ref()?;
        
        // Find the index of the row in the tree
        let mut row_ids: Vec<String> = self.rows.keys().cloned().collect();
        row_ids.sort();
        
        let position = row_ids.iter().position(|rid| rid == id)?;
        
        // Generate the proof
        let proof = tree.generate_proof(position);
        
        // Serialize the proof for external use
        let proof_bytes = bincode::serialize(&proof).ok()?;
        
        Some((row.clone(), proof_bytes))
    }
    
    /// Calculate the hash of the table state
    pub fn calculate_hash(&self) -> [u8; 32] {
        // Hash the schema
        let schema_hash = self.schema.calculate_hash();
        
        // Use the root hash if available, otherwise hash the rows directly
        let data_hash = match self.root_hash {
            Some(hash) => hash,
            None => {
                // If no Merkle tree, create a hash of all rows
                let mut row_ids: Vec<String> = self.rows.keys().cloned().collect();
                row_ids.sort();
                
                // First collect all the hashes into a vector
                let hashes: Vec<[u8; 32]> = row_ids
                    .iter()
                    .map(|id| {
                        let row = self.rows.get(id).unwrap();
                        row.hash()
                    })
                    .collect();
                
                // Convert to Vec<Vec<u8>> for the Merkle tree
                let row_hashes: Vec<Vec<u8>> = hashes.iter().map(|h| h.to_vec()).collect();
                
                if row_hashes.is_empty() {
                    [0; 32] // Empty data hash
                } else {
                    // Convert Vec<Vec<u8>> to Vec<&[u8]> for secure_hash_multiple
                    let row_hash_refs: Vec<&[u8]> = row_hashes.iter().map(|h| h.as_slice()).collect();
                    crypto::secure_hash_multiple(
                        domains::TABLE_STATE,
                        &row_hash_refs
                    )
                }
            }
        };
        
        // Combine schema hash and data hash
        crypto::secure_hash_multiple(
            domains::TABLE_STATE,
            &[&schema_hash, &data_hash, &self.row_count.to_be_bytes()]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::row::{Value, ValueType};
    use std::collections::HashMap;
    
    // Helper to create a test schema
    fn create_test_schema() -> TableSchema {
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
            ColumnDefinition {
                name: "email".to_string(),
                column_type: ColumnType::VarChar(100),
                nullable: false,
                primary_key: false,
                unique: true,
                default_value: None,
            },
        ];
        
        TableSchema::new(
            "users".to_string(),
            columns,
            vec!["id".to_string()],
            vec![vec!["email".to_string()]],
            vec![],
        )
    }
    
    // Helper to create a test row
    fn create_test_row(id: i32, name: &str, email: &str) -> Row {
        let mut values = HashMap::new();
        values.insert("id".to_string(), Value::Integer(id));
        values.insert("name".to_string(), Value::Text(name.to_string()));
        values.insert("email".to_string(), Value::Text(email.to_string()));
        
        Row::new(id.to_string(), "users".to_string(), values)
    }
    
    #[test]
    fn test_table_schema_hash() {
        let schema = create_test_schema();
        
        // Verify the hash
        assert!(schema.verify_hash());
        
        // Create a modified schema
        let mut modified_schema = schema.clone();
        modified_schema.columns.push(ColumnDefinition {
            name: "active".to_string(),
            column_type: ColumnType::Boolean,
            nullable: false,
            primary_key: false,
            unique: false,
            default_value: Some("true".to_string()),
        });
        
        // Calculate the hash for the modified schema
        let modified_hash = modified_schema.calculate_hash();
        
        // The hashes should be different
        assert_ne!(schema.hash.unwrap(), modified_hash);
    }
    
    #[test]
    fn test_table_state_operations() {
        let schema = create_test_schema();
        let mut table_state = TableState::new(schema);
        
        // Initially empty
        assert_eq!(table_state.row_count, 0);
        assert!(table_state.root_hash.is_none());
        
        // Insert some rows
        let row1 = create_test_row(1, "Alice", "alice@example.com");
        let row2 = create_test_row(2, "Bob", "bob@example.com");
        let row3 = create_test_row(3, "Charlie", "charlie@example.com");
        
        table_state.insert_row(row1.clone());
        assert_eq!(table_state.row_count, 1);
        assert!(table_state.root_hash.is_some());
        
        table_state.insert_row(row2.clone());
        assert_eq!(table_state.row_count, 2);
        
        table_state.insert_row(row3.clone());
        assert_eq!(table_state.row_count, 3);
        
        // Get a row
        let fetched_row = table_state.get_row("2");
        assert!(fetched_row.is_some());
        assert_eq!(fetched_row.unwrap().id, "2");
        
        // Update a row
        let mut updated_row = row2.clone();
        if let Some(Value::Text(name)) = updated_row.values.get_mut("name") {
            *name = "Robert".to_string();
        }
        table_state.update_row(updated_row);
        
        // Check the updated row
        let fetched_updated = table_state.get_row("2");
        assert!(fetched_updated.is_some());
        let name_value = fetched_updated.unwrap().get("name");
        assert!(name_value.is_some());
        if let Value::Text(name) = name_value.unwrap() {
            assert_eq!(name, "Robert");
        }
        
        // Delete a row
        let deleted = table_state.delete_row("3");
        assert!(deleted.is_some());
        assert_eq!(deleted.unwrap().id, "3");
        assert_eq!(table_state.row_count, 2);
        
        // Generate proof
        let proof = table_state.generate_proof("1");
        assert!(proof.is_some());
    }
    
    #[test]
    fn test_table_state_hash() {
        let schema = create_test_schema();
        let mut table_state = TableState::new(schema);
        
        // Initial hash
        let initial_hash = table_state.calculate_hash();
        
        // Add a row and check hash changes
        let row = create_test_row(1, "Alice", "alice@example.com");
        table_state.insert_row(row);
        
        let hash_with_row = table_state.calculate_hash();
        assert_ne!(initial_hash, hash_with_row);
    }
} 