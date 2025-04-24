//! Schema validation
//!
//! This module provides utilities for validating database schemas and migrations.

use std::collections::{HashMap, HashSet};
use thiserror::Error;

use crate::models::{TableSchema, ColumnType}; // Removed unused ColumnDefinition
use super::{SchemaMigration, DdlOperation, ColumnDefinitionDdl};

/// Schema validation error
#[derive(Debug, Clone, Error)]
pub enum ValidationError {
    /// Table already exists
    #[error("Table {0} already exists")]
    TableAlreadyExists(String),
    
    /// Table does not exist
    #[error("Table {0} does not exist")]
    TableNotFound(String),
    
    /// Column already exists
    #[error("Column {0} already exists in table {1}")]
    ColumnAlreadyExists(String, String),
    
    /// Column does not exist
    #[error("Column {0} does not exist in table {1}")]
    ColumnNotFound(String, String),
    
    /// Primary key columns not found
    #[error("Primary key column(s) not found in table {0}: {1}")]
    PrimaryKeyColumnNotFound(String, String),
    
    /// Referenced table not found
    #[error("Referenced table {0} not found for foreign key in table {1}")]
    ReferencedTableNotFound(String, String),
    
    /// Referenced column not found
    #[error("Referenced column(s) {0} not found in table {1} for foreign key")]
    ReferencedColumnNotFound(String, String),
    
    /// Invalid column type
    #[error("Invalid column type for column {0} in table {1}")]
    InvalidColumnType(String, String),
    
    /// Column type mismatch
    #[error("Column type mismatch for column {0} in table {1}")]
    ColumnTypeMismatch(String, String),
    
    /// Nullable column in primary key
    #[error("Primary key column {0} in table {1} cannot be nullable")]
    NullablePrimaryKey(String, String),
    
    /// Invalid migration operation
    #[error("Invalid migration operation: {0}")]
    InvalidMigrationOperation(String),
    
    /// Schema version mismatch
    #[error("Schema version mismatch: expected {0}, got {1}")]
    SchemaVersionMismatch(u32, u32),
    
    /// General validation error
    #[error("Schema validation error: {0}")]
    GeneralError(String),
}

/// Schema validation result
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Schema validator
#[derive(Debug, Clone)]
pub struct SchemaValidator;

impl SchemaValidator {
    /// Validate a table schema
    pub fn validate_table(table: &TableSchema) -> ValidationResult<()> {
        // Check for primary key columns
        if table.primary_keys.is_empty() {
            return Err(ValidationError::GeneralError(
                format!("Table {} has no primary key", table.name)
            ));
        }
        
        // Ensure primary key columns exist in the table
        for pk_column in &table.primary_keys {
            if !table.columns.iter().any(|col| &col.name == pk_column) {
                return Err(ValidationError::PrimaryKeyColumnNotFound(
                    table.name.clone(),
                    pk_column.clone()
                ));
            }
        }
        
        // Check primary key columns are not nullable
        for pk_column in &table.primary_keys {
            if let Some(col) = table.columns.iter().find(|col| &col.name == pk_column) {
                if col.nullable {
                    return Err(ValidationError::NullablePrimaryKey(
                        col.name.clone(),
                        table.name.clone()
                    ));
                }
            }
        }
        
        // Check for duplicate column names
        let mut column_names = HashSet::new();
        for column in &table.columns {
            if !column_names.insert(&column.name) {
                return Err(ValidationError::ColumnAlreadyExists(
                    column.name.clone(),
                    table.name.clone()
                ));
            }
        }
        
        // Foreign key validation needs schema-level context, so it's done elsewhere
        
        Ok(())
    }
    
    /// Validate the schema-level integrity
    pub fn validate_schema_integrity(tables: &HashMap<String, TableSchema>) -> ValidationResult<()> {
        // Check for foreign key validity
        for (table_name, table) in tables {
            for (fk_columns, ref_table_name, ref_columns) in &table.foreign_keys {
                // Check referenced table exists
                if !tables.contains_key(ref_table_name) {
                    return Err(ValidationError::ReferencedTableNotFound(
                        ref_table_name.clone(),
                        table_name.clone()
                    ));
                }
                
                let referenced_table = &tables[ref_table_name];
                
                // Check foreign key columns exist in the current table
                for fk_column in fk_columns {
                    if !table.columns.iter().any(|col| &col.name == fk_column) {
                        return Err(ValidationError::ColumnNotFound(
                            fk_column.clone(),
                            table_name.clone()
                        ));
                    }
                }
                
                // Check referenced columns exist in the referenced table
                for ref_column in ref_columns {
                    if !referenced_table.columns.iter().any(|col| &col.name == ref_column) {
                        return Err(ValidationError::ReferencedColumnNotFound(
                            ref_column.clone(),
                            ref_table_name.clone()
                        ));
                    }
                }
                
                // Check column counts match
                if fk_columns.len() != ref_columns.len() {
                    return Err(ValidationError::GeneralError(
                        format!("Foreign key column count mismatch in table {}: {} vs {}",
                            table_name, fk_columns.len(), ref_columns.len()
                        )
                    ));
                }
                
                // Check column types match
                for (i, fk_column) in fk_columns.iter().enumerate() {
                    let ref_column = &ref_columns[i];
                    
                    let fk_column_def = table.columns.iter()
                        .find(|col| &col.name == fk_column)
                        .unwrap();
                    
                    let ref_column_def = referenced_table.columns.iter()
                        .find(|col| &col.name == ref_column)
                        .unwrap();
                    
                    if !Self::are_compatible_types(&fk_column_def.column_type, &ref_column_def.column_type) {
                        return Err(ValidationError::ColumnTypeMismatch(
                            fk_column.clone(),
                            table_name.clone()
                        ));
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Validate a migration against a schema
    pub fn validate_migration(
        migration: &SchemaMigration,
        current_schema: &HashMap<String, TableSchema>
    ) -> ValidationResult<()> {
        let mut schema_clone = current_schema.clone();
        
        for operation in &migration.operations {
            match &operation.statement.ddl {
                DdlOperation::CreateTable(table_def) => {
                    // Check table doesn't exist
                    if schema_clone.contains_key(&table_def.name) {
                        return Err(ValidationError::TableAlreadyExists(table_def.name.clone()));
                    }
                    
                    // Create a TableSchema to validate
                    let table = TableSchema::new(
                        table_def.name.clone(),
                        table_def.columns.clone(),
                        table_def.primary_keys.clone(),
                        table_def.unique_constraints.clone(),
                        table_def.foreign_keys.clone(),
                    );
                    
                    // Validate the table structure
                    Self::validate_table(&table)?;
                    
                    // Add to schema for subsequent operations
                    schema_clone.insert(table_def.name.clone(), table);
                }
                DdlOperation::DropTable(table_name) => {
                    // Check table exists
                    if !schema_clone.contains_key(table_name) {
                        return Err(ValidationError::TableNotFound(table_name.clone()));
                    }
                    
                    // Check for foreign key references to this table
                    for (t_name, table) in &schema_clone {
                        if t_name == table_name {
                            continue;
                        }
                        
                        for (_, ref_table, _) in &table.foreign_keys {
                            if ref_table == table_name {
                                return Err(ValidationError::InvalidMigrationOperation(
                                    format!("Cannot drop table {} because it is referenced by table {}", 
                                            table_name, t_name)
                                ));
                            }
                        }
                    }
                    
                    // Remove table for subsequent operations
                    schema_clone.remove(table_name);
                }
                DdlOperation::AlterTable(table_name, column_operations) => {
                    // Check table exists
                    if !schema_clone.contains_key(table_name) {
                        return Err(ValidationError::TableNotFound(table_name.clone()));
                    }
                    
                    let mut table = schema_clone.get(table_name).unwrap().clone();
                    
                    for op in column_operations {
                        match op {
                            ColumnDefinitionDdl::AddColumn(column) => {
                                // Check column doesn't exist
                                if table.columns.iter().any(|col| col.name == column.name) {
                                    return Err(ValidationError::ColumnAlreadyExists(
                                        column.name.clone(),
                                        table_name.clone()
                                    ));
                                }
                                
                                // Check if adding a primary key column that is nullable
                                if column.primary_key && column.nullable {
                                    return Err(ValidationError::NullablePrimaryKey(
                                        column.name.clone(),
                                        table_name.clone()
                                    ));
                                }
                                
                                // Add column
                                table.columns.push(column.clone());
                                
                                // If it's a primary key, add to primary keys
                                if column.primary_key && !table.primary_keys.contains(&column.name) {
                                    table.primary_keys.push(column.name.clone());
                                }
                            }
                            ColumnDefinitionDdl::DropColumn(column_name) => {
                                // Check column exists
                                if !table.columns.iter().any(|col| col.name == *column_name) {
                                    return Err(ValidationError::ColumnNotFound(
                                        column_name.clone(),
                                        table_name.clone()
                                    ));
                                }
                                
                                // Check column is not part of primary key
                                if table.primary_keys.contains(column_name) {
                                    return Err(ValidationError::InvalidMigrationOperation(
                                        format!("Cannot drop column {} because it is part of the primary key", 
                                                column_name)
                                    ));
                                }
                                
                                // Check column is not part of foreign key
                                for (fk_columns, _, _) in &table.foreign_keys {
                                    if fk_columns.contains(column_name) {
                                        return Err(ValidationError::InvalidMigrationOperation(
                                            format!("Cannot drop column {} because it is part of a foreign key", 
                                                    column_name)
                                        ));
                                    }
                                }
                                
                                // Remove column for subsequent operations
                                table.columns.retain(|col| col.name != *column_name);
                            }
                            ColumnDefinitionDdl::ModifyColumn(column_def) => {
                                // Check column exists
                                if !table.columns.iter().any(|col| col.name == column_def.name) {
                                    return Err(ValidationError::ColumnNotFound(
                                        column_def.name.clone(),
                                        table_name.clone()
                                    ));
                                }
                                
                                // Check modifications are valid
                                let old_column = table.columns.iter()
                                    .find(|col| col.name == column_def.name)
                                    .unwrap();
                                
                                // Check type changes are compatible
                                if !Self::are_compatible_types(&old_column.column_type, &column_def.column_type) {
                                    return Err(ValidationError::ColumnTypeMismatch(
                                        column_def.name.clone(),
                                        table_name.clone()
                                    ));
                                }
                                
                                // Check primary key nullability
                                if table.primary_keys.contains(&column_def.name) && column_def.nullable {
                                    return Err(ValidationError::NullablePrimaryKey(
                                        column_def.name.clone(),
                                        table_name.clone()
                                    ));
                                }
                                
                                // Update column for subsequent operations
                                let index = table.columns.iter().position(|col| col.name == column_def.name).unwrap();
                                table.columns[index] = column_def.clone();
                            }
                            ColumnDefinitionDdl::RenameColumn(old_name, new_name) => {
                                // Check old column exists
                                if !table.columns.iter().any(|col| col.name == *old_name) {
                                    return Err(ValidationError::ColumnNotFound(
                                        old_name.clone(),
                                        table_name.clone()
                                    ));
                                }
                                
                                // Check new name doesn't exist
                                if table.columns.iter().any(|col| col.name == *new_name) {
                                    return Err(ValidationError::ColumnAlreadyExists(
                                        new_name.clone(),
                                        table_name.clone()
                                    ));
                                }
                                
                                // Rename column for subsequent operations
                                let index = table.columns.iter().position(|col| col.name == *old_name).unwrap();
                                let mut column = table.columns[index].clone();
                                column.name = new_name.clone();
                                table.columns[index] = column;
                                
                                // Update primary key if necessary
                                if let Some(index) = table.primary_keys.iter().position(|col| col == old_name) {
                                    table.primary_keys[index] = new_name.clone();
                                }
                                
                                // Update foreign keys if necessary
                                for (fk_columns, _, _) in &mut table.foreign_keys {
                                    for col in fk_columns {
                                        if col == old_name {
                                            *col = new_name.clone();
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    // Update table
                    schema_clone.insert(table_name.clone(), table);
                }
                DdlOperation::RenameTable(old_name, new_name) => {
                    // Check old table exists
                    if !schema_clone.contains_key(old_name) {
                        return Err(ValidationError::TableNotFound(old_name.clone()));
                    }
                    
                    // Check new name doesn't exist
                    if schema_clone.contains_key(new_name) {
                        return Err(ValidationError::TableAlreadyExists(new_name.clone()));
                    }
                    
                    // Rename table for subsequent operations
                    let table = schema_clone.remove(old_name).unwrap();
                    let mut new_table = table.clone();
                    new_table = TableSchema::new(
                        new_name.clone(),
                        new_table.columns.clone(),
                        new_table.primary_keys.clone(),
                        new_table.unique_constraints.clone(),
                        new_table.foreign_keys.clone(),
                    );
                    schema_clone.insert(new_name.clone(), new_table);
                    
                    // Update foreign keys in other tables
                    for (_, table) in &mut schema_clone {
                        for (_, ref_table, _) in &mut table.foreign_keys {
                            if ref_table == old_name {
                                *ref_table = new_name.clone();
                            }
                        }
                    }
                }
            }
        }
        
        // Validate overall schema integrity after all operations
        Self::validate_schema_integrity(&schema_clone)?;
        
        Ok(())
    }
    
    /// Check if two column types are compatible
    fn are_compatible_types(old_type: &ColumnType, new_type: &ColumnType) -> bool {
        match (old_type, new_type) {
            // Exact same types are compatible
            (a, b) if a == b => true,
            
            // Numeric type compatibility
            (ColumnType::Integer, ColumnType::BigInt) => true, // Integer can be upgraded to BigInt
            
            // Text type compatibility
            (ColumnType::Char(old_len), ColumnType::Char(new_len)) => new_len >= old_len,
            (ColumnType::VarChar(old_len), ColumnType::VarChar(new_len)) => new_len >= old_len,
            (ColumnType::Char(_), ColumnType::VarChar(_)) => true, // Char can be converted to VarChar
            (ColumnType::Char(_), ColumnType::Text) => true, // Char can be converted to Text
            (ColumnType::VarChar(_), ColumnType::Text) => true, // VarChar can be converted to Text
            
            // Other combinations are not compatible
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ColumnDefinition, ColumnType, TableSchema};
    use crate::schema::{SchemaMigration, DdlOperation, ColumnDefinitionDdl, MigrationDirection};
    use crate::schema::ddl::{DdlStatement, TableDefinition};
    use chrono::Utc;
    use uuid::Uuid;
    use std::collections::HashMap;
    
    #[test]
    fn test_validate_table() {
        // Valid table
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
        
        let table = TableSchema::new(
            "users".to_string(),
            columns,
            vec!["id".to_string()],
            Vec::new(),
            Vec::new(),
        );
        
        assert!(SchemaValidator::validate_table(&table).is_ok());
        
        // Invalid table - no primary key
        let columns_no_pk = vec![
            ColumnDefinition {
                name: "id".to_string(),
                column_type: ColumnType::Integer,
                nullable: false,
                primary_key: false, // Not a primary key
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
        
        let table_no_pk = TableSchema::new(
            "users".to_string(),
            columns_no_pk,
            vec![],
            vec![],
            vec![]
        );
        
        assert!(SchemaValidator::validate_table(&table_no_pk).is_err());
        
        // Invalid table - non-existent primary key column
        let table_bad_pk = TableSchema::new(
            "users".to_string(),
            columns_no_pk,
            vec!["non_existent".to_string()], // Non-existent column
            vec![],
            vec![]
        );
        
        assert!(SchemaValidator::validate_table(&table_bad_pk).is_err());
        
        // Invalid table - nullable primary key
        let columns_nullable_pk = vec![
            ColumnDefinition {
                name: "id".to_string(),
                column_type: ColumnType::Integer,
                nullable: true, // Nullable
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
        
        let table_nullable_pk = TableSchema::new(
            "users".to_string(),
            columns_nullable_pk,
            vec!["id".to_string()],
            vec![],
            vec![]
        );
        
        assert!(SchemaValidator::validate_table(&table_nullable_pk).is_err());
    }
    
    #[test]
    fn test_validate_schema_integrity() {
        // Create a schema with two tables and a foreign key
        let users_columns = vec![
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
        
        let users_table = TableSchema::new(
            "users".to_string(),
            users_columns,
            vec!["id".to_string()],
            vec![],
            vec![]
        );
        
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
        
        let posts_table = TableSchema::new(
            "posts".to_string(),
            posts_columns,
            vec!["id".to_string()],
            vec![],
            vec![(
                vec!["user_id".to_string()],
                "users".to_string(),
                vec!["id".to_string()],
            )],
        );
        
        let mut schema = HashMap::new();
        schema.insert("users".to_string(), users_table);
        schema.insert("posts".to_string(), posts_table);
        
        // Valid schema
        assert!(SchemaValidator::validate_schema_integrity(&schema).is_ok());
        
        // Invalid schema - referenced table doesn't exist
        let mut schema_bad_ref = schema.clone();
        let mut posts_bad_ref = schema_bad_ref.get("posts").unwrap().clone();
        posts_bad_ref.foreign_keys = vec![(
            vec!["user_id".to_string()],
            "non_existent".to_string(), // Non-existent table
            vec!["id".to_string()],
        )];
        schema_bad_ref.insert("posts".to_string(), posts_bad_ref);
        
        assert!(SchemaValidator::validate_schema_integrity(&schema_bad_ref).is_err());
        
        // Invalid schema - referenced column doesn't exist
        let mut schema_bad_col = schema.clone();
        let mut posts_bad_col = schema_bad_col.get("posts").unwrap().clone();
        posts_bad_col.foreign_keys = vec![(
            vec!["user_id".to_string()],
            "users".to_string(),
            vec!["non_existent".to_string()], // Non-existent column
        )];
        schema_bad_col.insert("posts".to_string(), posts_bad_col);
        
        assert!(SchemaValidator::validate_schema_integrity(&schema_bad_col).is_err());
        
        // Invalid schema - column type mismatch
        let mut schema_type_mismatch = schema.clone();
        let mut posts_type_mismatch = schema_type_mismatch.get("posts").unwrap().clone();
        
        // Change user_id to VarChar, which is incompatible with Integer
        let col_index = posts_type_mismatch.columns
            .iter()
            .position(|col| col.name == "user_id")
            .unwrap();
        posts_type_mismatch.columns[col_index].column_type = ColumnType::VarChar(10);
        
        schema_type_mismatch.insert("posts".to_string(), posts_type_mismatch);
        
        assert!(SchemaValidator::validate_schema_integrity(&schema_type_mismatch).is_err());
    }
    
    #[test]
    fn test_validate_migration() {
        // Create initial schema with one table
        let users_columns = vec![
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
        
        let users_table = TableSchema::new(
            "users".to_string(),
            users_columns,
            vec!["id".to_string()],
            vec![],
            vec![]
        );
        
        let mut schema = HashMap::new();
        schema.insert("users".to_string(), users_table);
        
        // Valid migration - add a table
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
            ddl: DdlOperation::CreateTable(TableDefinition {
                name: "posts".to_string(),
                columns: posts_columns,
                primary_keys: vec!["id".to_string()],
                unique_constraints: vec![],
                foreign_keys: vec![(
                    vec!["user_id".to_string()],
                    "users".to_string(),
                    vec!["id".to_string()],
                )],
            }),
            sql: "CREATE TABLE posts (...)".to_string(),
        };
        
        let valid_migration = SchemaMigration {
            id: Uuid::new_v4(),
            name: "add_posts_table".to_string(),
            created_at: Utc::now(),
            direction: MigrationDirection::Up,
            operations: vec![
                super::super::MigrationOperation {
                    order: 1,
                    statement: create_posts_table,
                },
            ],
        };
        
        assert!(SchemaValidator::validate_migration(&valid_migration, &schema).is_ok());
        
        // Invalid migration - create existing table
        let create_users_table = DdlStatement {
            ddl: DdlOperation::CreateTable(TableDefinition {
                name: "users".to_string(), // Already exists
                columns: users_columns,
                primary_keys: vec!["id".to_string()],
                unique_constraints: vec![],
                foreign_keys: vec![],
            }),
            sql: "CREATE TABLE users (...)".to_string(),
        };
        
        let invalid_migration1 = SchemaMigration {
            id: Uuid::new_v4(),
            name: "create_users_again".to_string(),
            created_at: Utc::now(),
            direction: MigrationDirection::Up,
            operations: vec![
                super::super::MigrationOperation {
                    order: 1,
                    statement: create_users_table,
                },
            ],
        };
        
        assert!(SchemaValidator::validate_migration(&invalid_migration1, &schema).is_err());
        
        // Invalid migration - drop non-existent table
        let drop_nonexistent_table = DdlStatement {
            ddl: DdlOperation::DropTable("non_existent".to_string()),
            sql: "DROP TABLE non_existent".to_string(),
        };
        
        let invalid_migration2 = SchemaMigration {
            id: Uuid::new_v4(),
            name: "drop_nonexistent".to_string(),
            created_at: Utc::now(),
            direction: MigrationDirection::Up,
            operations: vec![
                super::super::MigrationOperation {
                    order: 1,
                    statement: drop_nonexistent_table,
                },
            ],
        };
        
        assert!(SchemaValidator::validate_migration(&invalid_migration2, &schema).is_err());
        
        // Invalid migration - add column with primary key nullable
        let add_nullable_pk_column = DdlStatement {
            ddl: DdlOperation::AlterTable(
                "users".to_string(),
                vec![ColumnDefinitionDdl::AddColumn(
                    ColumnDefinition {
                        name: "new_pk".to_string(),
                        column_type: ColumnType::Integer,
                        nullable: true, // Nullable
                        primary_key: true, // Primary key
                        unique: true,
                        default_value: None,
                    }
                )],
            ),
            sql: "ALTER TABLE users ADD COLUMN new_pk INT PRIMARY KEY NULL".to_string(),
        };
        
        let invalid_migration3 = SchemaMigration {
            id: Uuid::new_v4(),
            name: "add_nullable_pk".to_string(),
            created_at: Utc::now(),
            direction: MigrationDirection::Up,
            operations: vec![
                super::super::MigrationOperation {
                    order: 1,
                    statement: add_nullable_pk_column,
                },
            ],
        };
        
        // This should pass the initial check but fail the final schema integrity validation
        assert!(SchemaValidator::validate_migration(&invalid_migration3, &schema).is_err());
    }
    
    #[test]
    fn test_compatible_types() {
        // Direct compatibility
        assert!(SchemaValidator::are_compatible_types(&ColumnType::Integer, &ColumnType::Integer));
        assert!(SchemaValidator::are_compatible_types(&ColumnType::Text, &ColumnType::Text));
        
        // Numeric compatibility
        assert!(SchemaValidator::are_compatible_types(&ColumnType::Integer, &ColumnType::BigInt));
        assert!(!SchemaValidator::are_compatible_types(&ColumnType::BigInt, &ColumnType::Integer));
        
        // Text compatibility
        assert!(SchemaValidator::are_compatible_types(&ColumnType::Char(10), &ColumnType::Char(20)));
        assert!(!SchemaValidator::are_compatible_types(&ColumnType::Char(20), &ColumnType::Char(10)));
        assert!(SchemaValidator::are_compatible_types(&ColumnType::VarChar(10), &ColumnType::VarChar(20)));
        assert!(!SchemaValidator::are_compatible_types(&ColumnType::VarChar(20), &ColumnType::VarChar(10)));
        assert!(SchemaValidator::are_compatible_types(&ColumnType::Char(10), &ColumnType::VarChar(20)));
        assert!(SchemaValidator::are_compatible_types(&ColumnType::Char(10), &ColumnType::Text));
        assert!(SchemaValidator::are_compatible_types(&ColumnType::VarChar(10), &ColumnType::Text));
        
        // Incompatible types
        assert!(!SchemaValidator::are_compatible_types(&ColumnType::Integer, &ColumnType::Text));
        assert!(!SchemaValidator::are_compatible_types(&ColumnType::Text, &ColumnType::VarChar(10)));
        assert!(!SchemaValidator::are_compatible_types(&ColumnType::Boolean, &ColumnType::Integer));
    }
} 