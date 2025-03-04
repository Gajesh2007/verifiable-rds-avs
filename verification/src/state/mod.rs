use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::merkle::SecureMerkleTree;

/// A representation of a database table's state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableState {
    /// Table name
    pub name: String,
    
    /// Schema name
    pub schema: String,
    
    /// Column metadata
    pub columns: Vec<ColumnInfo>,
    
    /// Row data
    pub rows: Vec<Row>,
    
    /// Merkle root of the table data
    pub merkle_root: [u8; 32],
    
    /// State version number
    pub version: u64,
    
    /// Independent checksum for cross-validation
    pub checksum: [u8; 32],
}

/// Information about a column in a table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnInfo {
    /// Column name
    pub name: String,
    
    /// PostgreSQL data type
    pub data_type: String,
    
    /// Whether this column is part of the primary key
    pub is_primary_key: bool,
    
    /// Position in the table definition
    pub ordinal_position: i32,
}

/// A unique identifier for a row, typically using primary key values
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RowId(String);

/// A row in a table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    /// Unique row identifier
    pub id: RowId,
    
    /// Column name to value mapping
    pub values: HashMap<String, serde_json::Value>,
    
    /// Hash of the row for verification
    pub row_hash: [u8; 32],
}

/// A service for capturing and tracking database state
pub struct StateCaptureService {
    /// Pool for database connections
    db_pool: tokio_postgres::Client,
}

impl StateCaptureService {
    /// Create a new state capture service
    pub async fn new(db_config: &str) -> Result<Self, tokio_postgres::Error> {
        // In a real implementation, this would establish a connection pool
        // For this simplified version, we'll just create a placeholder client
        let (client, connection) = tokio_postgres::connect(db_config, tokio_postgres::NoTls).await?;
        
        // Spawn the connection handler to process connection events
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Connection error: {}", e);
            }
        });
        
        Ok(Self {
            db_pool: client,
        })
    }
    
    /// Capture the state of a specific table
    pub async fn capture_table_state(&self, table_name: &str) -> Result<TableState, tokio_postgres::Error> {
        // Get table schema information
        let columns = self.get_table_columns(table_name).await?;
        
        // Get primary key columns
        let primary_key_columns: Vec<String> = columns.iter()
            .filter(|col| col.is_primary_key)
            .map(|col| col.name.clone())
            .collect();
        
        // Build a query to fetch all rows from the table
        let mut query = format!("SELECT * FROM {}", table_name);
        
        // Add ORDER BY for primary key columns
        if !primary_key_columns.is_empty() {
            query.push_str(" ORDER BY ");
            query.push_str(&primary_key_columns.join(", "));
        }
        
        // Execute the query
        let rows = self.db_pool.query(&query, &[]).await?;
        
        // Convert to our Row type
        let mut table_rows = Vec::new();
        for row in rows {
            let mut values = HashMap::new();
            let mut row_id_parts = Vec::new();
            
            for (i, column) in columns.iter().enumerate() {
                let value: Option<serde_json::Value> = match row.try_get::<_, Option<String>>(i) {
                    Ok(Some(val)) => Some(serde_json::Value::String(val)),
                    Ok(None) => None,
                    Err(_) => None, // Handle errors by treating as null
                };
                
                values.insert(column.name.clone(), value.clone().unwrap_or(serde_json::Value::Null));
                
                if column.is_primary_key {
                    if let Some(serde_json::Value::String(val)) = &value {
                        row_id_parts.push(val.clone());
                    } else {
                        row_id_parts.push("null".to_string());
                    }
                }
            }
            
            // Create a row ID from primary key values
            let row_id = RowId(row_id_parts.join(":"));
            
            // Hash the row values for integrity checking
            let row_hash = self.hash_row(&values);
            
            table_rows.push(Row {
                id: row_id,
                values,
                row_hash,
            });
        }
        
        // Build the Merkle tree for the table
        let merkle_tree = self.build_merkle_tree(&table_rows);
        
        // Calculate checksum before moving table_rows
        let checksum = self.calculate_checksum(table_name, &table_rows);
        
        // Create the table state
        let table_state = TableState {
            name: table_name.to_string(),
            schema: "public".to_string(), // Default schema
            columns,
            rows: table_rows,
            merkle_root: merkle_tree.get_root(),
            version: 1, // Version would be incremented for each state change
            checksum,
        };
        
        Ok(table_state)
    }
    
    /// Get column information for a table
    async fn get_table_columns(&self, table_name: &str) -> Result<Vec<ColumnInfo>, tokio_postgres::Error> {
        // Query to get column information
        let query = r#"
            SELECT
                c.column_name,
                c.data_type,
                c.ordinal_position,
                (CASE WHEN pk.column_name IS NOT NULL THEN true ELSE false END) as is_primary_key
            FROM
                information_schema.columns c
            LEFT JOIN (
                SELECT
                    kcu.column_name
                FROM
                    information_schema.table_constraints tc
                JOIN
                    information_schema.key_column_usage kcu
                    ON kcu.constraint_name = tc.constraint_name
                    AND kcu.table_schema = tc.table_schema
                    AND kcu.table_name = tc.table_name
                WHERE
                    tc.constraint_type = 'PRIMARY KEY'
                    AND tc.table_name = $1
            ) pk ON pk.column_name = c.column_name
            WHERE
                c.table_name = $1
            ORDER BY
                c.ordinal_position
        "#;
        
        let rows = self.db_pool.query(query, &[&table_name]).await?;
        
        let columns = rows.iter().map(|row| {
            ColumnInfo {
                name: row.get("column_name"),
                data_type: row.get("data_type"),
                is_primary_key: row.get("is_primary_key"),
                ordinal_position: row.get("ordinal_position"),
            }
        }).collect();
        
        Ok(columns)
    }
    
    /// Hash a row's values for integrity checking
    fn hash_row(&self, values: &HashMap<String, serde_json::Value>) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        
        // Sort keys for deterministic hashing
        let mut sorted_keys: Vec<&String> = values.keys().collect();
        sorted_keys.sort();
        
        let mut hasher = Sha256::new();
        
        // Domain separation
        hasher.update(b"ROW");
        
        // Hash each value in sorted order
        for key in sorted_keys {
            hasher.update(key.as_bytes());
            hasher.update(b":");
            hasher.update(values[key].to_string().as_bytes());
            hasher.update(b"|");
        }
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Build a Merkle tree from table rows
    fn build_merkle_tree(&self, rows: &[Row]) -> SecureMerkleTree {
        let mut merkle_tree = SecureMerkleTree::new();
        
        // Add each row as a leaf
        for row in rows {
            // In a real implementation, we would serialize the row in a standardized format
            // For simplicity, we'll just use the JSON representation of the values
            let row_data = serde_json::to_vec(&row.values).unwrap_or_default();
            merkle_tree.add_leaf(&row_data);
        }
        
        merkle_tree
    }
    
    /// Calculate an independent checksum for the table
    fn calculate_checksum(&self, table_name: &str, rows: &[Row]) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        
        // Include table name in the checksum
        hasher.update(table_name.as_bytes());
        
        // Include each row hash
        for row in rows {
            hasher.update(&row.row_hash);
        }
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Capture the state of the entire database
    pub async fn capture_database_state(&self) -> Result<DatabaseState, tokio_postgres::Error> {
        // Get all tables in the database
        let query = r#"
            SELECT
                table_name
            FROM
                information_schema.tables
            WHERE
                table_schema = 'public'
                AND table_type = 'BASE TABLE'
        "#;
        
        let rows = self.db_pool.query(query, &[]).await?;
        
        let mut tables = HashMap::new();
        
        // Capture state for each table
        for row in rows {
            let table_name: String = row.get("table_name");
            let table_state = self.capture_table_state(&table_name).await?;
            tables.insert(table_name, table_state);
        }
        
        // Build a Merkle tree for the database state
        let mut db_merkle_tree = SecureMerkleTree::new();
        
        // Add each table's Merkle root as a leaf
        for (table_name, table_state) in &tables {
            let mut data = Vec::new();
            data.extend_from_slice(table_name.as_bytes());
            data.extend_from_slice(&table_state.merkle_root);
            db_merkle_tree.add_leaf(&data);
        }
        
        // Create the database state
        let database_state = DatabaseState {
            tables,
            merkle_root: db_merkle_tree.get_root(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            version: 1,
        };
        
        Ok(database_state)
    }
}

/// The state of the entire database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseState {
    /// Table states by name
    pub tables: HashMap<String, TableState>,
    
    /// Merkle root of all table states
    pub merkle_root: [u8; 32],
    
    /// Timestamp when the state was captured
    pub timestamp: u64,
    
    /// State version
    pub version: u64,
} 