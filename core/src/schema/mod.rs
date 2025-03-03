//! Database schema validation
//!
//! This module provides utilities for validating database schemas
//! and tracking schema migrations.

mod validator;
mod migration;
mod ddl;

pub use validator::{SchemaValidator, ValidationResult, ValidationError};
pub use migration::{SchemaMigration, MigrationDirection, MigrationOperation};
pub use ddl::{DdlStatement, DdlOperation, ColumnDefinitionDdl};

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use thiserror::Error;
use log::{debug, warn, info};

use crate::crypto;
use crate::models::{TableSchema, ColumnType};

/// Schema version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaVersion {
    /// Version identifier
    pub id: Uuid,
    
    /// Version number
    pub version: u32,
    
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    
    /// Creator identifier
    pub created_by: String,
    
    /// Description of this schema version
    pub description: String,
    
    /// Tables in this schema version
    pub tables: HashMap<String, TableSchema>,
    
    /// Migration from previous version (if not initial schema)
    pub migration: Option<SchemaMigration>,
    
    /// Checksum of the schema
    pub checksum: [u8; 32],
}

impl SchemaVersion {
    /// Create a new schema version
    pub fn new(
        version: u32,
        created_by: String,
        description: String,
        tables: HashMap<String, TableSchema>,
        migration: Option<SchemaMigration>,
    ) -> Self {
        let mut schema_version = SchemaVersion {
            id: Uuid::new_v4(),
            version,
            created_at: Utc::now(),
            created_by,
            description,
            tables,
            migration,
            checksum: [0; 32],
        };
        
        // Calculate checksum
        schema_version.checksum = schema_version.calculate_checksum();
        
        schema_version
    }
    
    /// Calculate checksum of the schema
    pub fn calculate_checksum(&self) -> [u8; 32] {
        // Serialize schema to JSON for hashing
        let schema_json = serde_json::to_string(&self).unwrap_or_default();
        
        // Hash with domain separation
        crypto::secure_hash("VERIFIABLEDB_SCHEMA", schema_json.as_bytes())
    }
    
    /// Verify the checksum of the schema
    pub fn verify_checksum(&self) -> bool {
        let calculated = self.calculate_checksum();
        calculated == self.checksum
    }
    
    /// Get a table by name
    pub fn get_table(&self, name: &str) -> Option<&TableSchema> {
        self.tables.get(name)
    }
    
    /// Check if the schema has a table
    pub fn has_table(&self, name: &str) -> bool {
        self.tables.contains_key(name)
    }
    
    /// Get the number of tables in the schema
    pub fn table_count(&self) -> usize {
        self.tables.len()
    }
    
    /// Create initial schema
    pub fn create_initial(
        created_by: String,
        description: String,
        tables: HashMap<String, TableSchema>,
    ) -> Self {
        Self::new(1, created_by, description, tables, None)
    }
    
    /// Create new version from migration
    pub fn create_from_migration(
        previous: &SchemaVersion,
        migration: SchemaMigration,
        created_by: String,
        description: String,
    ) -> Self {
        // Apply migration to previous tables
        let mut new_tables = previous.tables.clone();
        
        // Process each operation in the migration
        for operation in &migration.operations {
            match &operation.statement.ddl {
                DdlOperation::CreateTable(table_def) => {
                    // Create a new table
                    if !new_tables.contains_key(&table_def.name) {
                        let columns = table_def.columns.clone();
                        let primary_keys = table_def.primary_keys.clone();
                        let unique_constraints = table_def.unique_constraints.clone();
                        let foreign_keys = table_def.foreign_keys.clone();
                        
                        let schema = TableSchema::new(
                            table_def.name.clone(),
                            columns,
                            primary_keys,
                            unique_constraints,
                            foreign_keys,
                        );
                        
                        new_tables.insert(table_def.name.clone(), schema);
                    }
                }
                DdlOperation::DropTable(table_name) => {
                    // Remove the table
                    new_tables.remove(table_name);
                }
                DdlOperation::AlterTable(table_name, column_operations) => {
                    // Modify the table if it exists
                    if let Some(table) = new_tables.get_mut(table_name) {
                        let mut new_columns = table.columns.clone();
                        
                        for col_op in column_operations {
                            match col_op {
                                ColumnDefinitionDdl::AddColumn(column_def) => {
                                    // Add the column
                                    new_columns.push(column_def.clone());
                                }
                                ColumnDefinitionDdl::DropColumn(column_name) => {
                                    // Remove the column
                                    new_columns.retain(|col| col.name != *column_name);
                                }
                                ColumnDefinitionDdl::ModifyColumn(column_def) => {
                                    // Update the column
                                    if let Some(index) = new_columns.iter().position(|col| col.name == column_def.name) {
                                        new_columns[index] = column_def.clone();
                                    }
                                }
                                ColumnDefinitionDdl::RenameColumn(old_name, new_name) => {
                                    // Rename the column
                                    if let Some(index) = new_columns.iter().position(|col| col.name == *old_name) {
                                        let mut column = new_columns[index].clone();
                                        column.name = new_name.clone();
                                        new_columns[index] = column;
                                    }
                                }
                            }
                        }
                        
                        // Update the table schema with new columns
                        let mut updated_table = table.clone();
                        updated_table.columns = new_columns;
                        *table = updated_table;
                    }
                }
                DdlOperation::RenameTable(old_name, new_name) => {
                    // Rename the table
                    if let Some(table) = new_tables.remove(old_name) {
                        let mut new_table = table.clone();
                        // Create a new table schema with the new name
                        let mut new_table_schema = TableSchema::new(
                            new_name.clone(),
                            new_table.columns.clone(),
                            new_table.primary_keys.clone(),
                            new_table.unique_constraints.clone(),
                            new_table.foreign_keys.clone(),
                        );
                        new_tables.insert(new_name.clone(), new_table_schema);
                    }
                }
            }
        }
        
        Self::new(
            previous.version + 1,
            created_by,
            description,
            new_tables,
            Some(migration),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::table::{ColumnDefinition, ColumnType};
    
    // Helper to create a test table schema
    fn create_test_table() -> TableSchema {
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
    
    #[test]
    fn test_schema_version_checksum() {
        // Create a schema with one table
        let mut tables = HashMap::new();
        tables.insert("users".to_string(), create_test_table());
        
        let schema = SchemaVersion::create_initial(
            "test_user".to_string(),
            "Initial schema".to_string(),
            tables,
        );
        
        // Verify the checksum
        assert!(schema.verify_checksum());
        
        // Test table access methods
        assert!(schema.has_table("users"));
        assert!(!schema.has_table("non_existent"));
        assert_eq!(schema.table_count(), 1);
        
        let users_table = schema.get_table("users");
        assert!(users_table.is_some());
        assert_eq!(users_table.unwrap().name, "users");
    }
    
    #[test]
    fn test_schema_migration() {
        // Create initial schema with one table
        let mut tables = HashMap::new();
        tables.insert("users".to_string(), create_test_table());
        
        let initial_schema = SchemaVersion::create_initial(
            "test_user".to_string(),
            "Initial schema".to_string(),
            tables,
        );
        
        // Create a migration to add a table
        let posts_columns = vec![
            ColumnDefinition {
                name: "id".to_string(),
                column_type: ColumnType::Integer,
                nullable: false,
                primary_key: true,
                unique: true,
                default_value: None,
            },
            ColumnDefinition {
                name: "title".to_string(),
                column_type: ColumnType::VarChar(200),
                nullable: false,
                primary_key: false,
                unique: false,
                default_value: None,
            },
            ColumnDefinition {
                name: "user_id".to_string(),
                column_type: ColumnType::Integer,
                nullable: false,
                primary_key: false,
                unique: false,
                default_value: None,
            },
        ];
        
        let create_posts_table = DdlStatement {
            ddl: DdlOperation::CreateTable(ddl::TableDefinition {
                name: "posts".to_string(),
                columns: posts_columns,
                primary_keys: vec!["id".to_string()],
                unique_constraints: Vec::new(),
                foreign_keys: vec![(
                    vec!["user_id".to_string()],
                    "users".to_string(),
                    vec!["id".to_string()],
                )],
            }),
            sql: "CREATE TABLE posts (id INT PRIMARY KEY, title VARCHAR(200) NOT NULL, user_id INT NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id))".to_string(),
        };
        
        // Add a column to users table
        let alter_users_table = DdlStatement {
            ddl: DdlOperation::AlterTable(
                "users".to_string(),
                vec![ColumnDefinitionDdl::AddColumn(
                    ColumnDefinition {
                        name: "email".to_string(),
                        column_type: ColumnType::VarChar(100),
                        nullable: true,
                        primary_key: false,
                        unique: true,
                        default_value: None,
                    }
                )],
            ),
            sql: "ALTER TABLE users ADD COLUMN email VARCHAR(100) UNIQUE".to_string(),
        };
        
        let migration = SchemaMigration {
            id: Uuid::new_v4(),
            name: "add_posts_table".to_string(),
            created_at: Utc::now(),
            direction: MigrationDirection::Up,
            operations: vec![
                MigrationOperation {
                    order: 1,
                    statement: create_posts_table,
                },
                MigrationOperation {
                    order: 2,
                    statement: alter_users_table,
                },
            ],
        };
        
        // Apply migration to create new schema version
        let new_schema = SchemaVersion::create_from_migration(
            &initial_schema,
            migration,
            "test_user".to_string(),
            "Add posts table and email to users".to_string(),
        );
        
        // Verify the new schema
        assert!(new_schema.verify_checksum());
        assert_eq!(new_schema.version, 2);
        assert_eq!(new_schema.table_count(), 2);
        assert!(new_schema.has_table("users"));
        assert!(new_schema.has_table("posts"));
        
        // Verify users table has email column
        let users_table = new_schema.get_table("users").unwrap();
        assert_eq!(users_table.columns.len(), 3);
        assert!(users_table.columns.iter().any(|col| col.name == "email"));
        
        // Verify posts table has correct structure
        let posts_table = new_schema.get_table("posts").unwrap();
        assert_eq!(posts_table.columns.len(), 3);
        assert_eq!(posts_table.primary_keys, vec!["id".to_string()]);
        assert_eq!(posts_table.foreign_keys.len(), 1);
    }
} 