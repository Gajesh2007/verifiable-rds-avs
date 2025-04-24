//! Schema migration handling
//!
//! This module provides data structures for representing and 
//! handling database schema migrations.

use std::fmt::{Debug, Display};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use super::ddl::DdlStatement;

/// Direction of a schema migration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationDirection {
    /// Migration upwards (applying changes)
    Up,
    
    /// Migration downwards (reverting changes)
    Down,
}

impl Display for MigrationDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationDirection::Up => write!(f, "up"),
            MigrationDirection::Down => write!(f, "down"),
        }
    }
}

/// A database migration operation with an DDL statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationOperation {
    /// Execution order of the operation
    pub order: usize,
    
    /// The DDL statement to execute
    pub statement: DdlStatement,
}

/// A database schema migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaMigration {
    /// Migration identifier
    pub id: Uuid,
    
    /// Migration name
    pub name: String,
    
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    
    /// Migration direction
    pub direction: MigrationDirection,
    
    /// Migration operations
    pub operations: Vec<MigrationOperation>,
}

impl SchemaMigration {
    /// Create a new schema migration
    pub fn new(
        name: String,
        direction: MigrationDirection,
        operations: Vec<MigrationOperation>,
    ) -> Self {
        SchemaMigration {
            id: Uuid::new_v4(),
            name,
            created_at: Utc::now(),
            direction,
            operations,
        }
    }
    
    /// Create a reversed migration (up → down or down → up)
    pub fn reversed(&self) -> Option<Self> {
        // For a proper reverse migration, we need reverse DDL statements
        // and they need to be executed in reverse order
        
        let reversed_direction = match self.direction {
            MigrationDirection::Up => MigrationDirection::Down,
            MigrationDirection::Down => MigrationDirection::Up,
        };
        
        // Create reversed operations
        let mut reversed_operations = Vec::new();
        
        // Process operations in reverse order
        for op in self.operations.iter().rev() {
            if let Some(reversed_stmt) = op.statement.reverse() {
                reversed_operations.push(MigrationOperation {
                    order: reversed_operations.len() + 1,
                    statement: reversed_stmt,
                });
            } else {
                // If any operation can't be reversed, the entire migration can't be reversed
                return None;
            }
        }
        
        if reversed_operations.is_empty() {
            return None;
        }
        
        Some(SchemaMigration {
            id: Uuid::new_v4(),
            name: format!("reverse_{}", self.name),
            created_at: Utc::now(),
            direction: reversed_direction,
            operations: reversed_operations,
        })
    }
    
    /// Get SQL statements for the migration
    pub fn get_sql(&self) -> Vec<String> {
        self.operations
            .iter()
            .map(|op| op.statement.sql.clone())
            .collect()
    }
    
    /// Sort the operations by order
    pub fn sort_operations(&mut self) {
        self.operations.sort_by_key(|op| op.order);
    }
    
    /// Check if the migration is reversible
    pub fn is_reversible(&self) -> bool {
        self.operations.iter().all(|op| op.statement.is_reversible())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ddl::{DdlOperation, ColumnDefinitionDdl, TableDefinition};
    
    #[test]
    fn test_migration_creation() {
        // Create columns for a table
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
        
        // Create a table definition
        let table_def = TableDefinition {
            name: "users".to_string(),
            columns: columns.clone(),
            primary_keys: vec!["id".to_string()],
            unique_constraints: Vec::new(),
            foreign_keys: Vec::new(),
        };
        
        // Create a DDL statement
        let create_table = DdlStatement {
            ddl: DdlOperation::CreateTable(table_def),
            sql: "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100) NOT NULL)".to_string(),
        };
        
        // Create a migration operation
        let operation = MigrationOperation {
            order: 1,
            statement: create_table,
        };
        
        // Create a migration
        let migration = SchemaMigration::new(
            "create_users_table".to_string(),
            MigrationDirection::Up,
            vec![operation],
        );
        
        assert_eq!(migration.name, "create_users_table");
        assert_eq!(migration.direction, MigrationDirection::Up);
        assert_eq!(migration.operations.len(), 1);
        assert!(migration.is_reversible());
        
        // Test SQL extraction
        let sql = migration.get_sql();
        assert_eq!(sql.len(), 1);
        assert_eq!(sql[0], "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100) NOT NULL)");
    }
    
    #[test]
    fn test_migration_reverse() {
        // Create a table creation migration
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
        
        let table_def = TableDefinition {
            name: "users".to_string(),
            columns,
            primary_keys: vec!["id".to_string()],
            unique_constraints: Vec::new(),
            foreign_keys: Vec::new(),
        };
        
        let create_table = DdlStatement {
            ddl: DdlOperation::CreateTable(table_def),
            sql: "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100) NOT NULL)".to_string(),
        };
        
        let operation = MigrationOperation {
            order: 1,
            statement: create_table,
        };
        
        let migration = SchemaMigration::new(
            "create_users_table".to_string(),
            MigrationDirection::Up,
            vec![operation],
        );
        
        // Reverse the migration
        let reversed = migration.reversed().unwrap();
        
        assert_eq!(reversed.direction, MigrationDirection::Down);
        assert_eq!(reversed.operations.len(), 1);
        
        // Check the reversed operation is a DROP TABLE
        match &reversed.operations[0].statement.ddl {
            DdlOperation::DropTable(table_name) => {
                assert_eq!(table_name, "users");
            }
            _ => panic!("Expected DropTable operation"),
        }
    }
    
    #[test]
    fn test_multiple_operations() {
        // Create a migration with multiple operations
        let create_table = DdlStatement {
            ddl: DdlOperation::CreateTable(TableDefinition {
                name: "users".to_string(),
                columns: vec![
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
                ],
                primary_keys: vec!["id".to_string()],
                unique_constraints: Vec::new(),
                foreign_keys: Vec::new(),
            }),
            sql: "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100) NOT NULL)".to_string(),
        };
        
        let alter_table = DdlStatement {
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
            sql: "ALTER TABLE users ADD COLUMN email VARCHAR(100) NULL UNIQUE".to_string(),
        };
        
        let operations = vec![
            MigrationOperation {
                order: 1,
                statement: create_table,
            },
            MigrationOperation {
                order: 2,
                statement: alter_table,
            },
        ];
        
        let migration = SchemaMigration::new(
            "create_users_table_with_email".to_string(),
            MigrationDirection::Up,
            operations,
        );
        
        // Test sort operations
        let mut unsorted_migration = migration.clone();
        unsorted_migration.operations.reverse(); // Swap the order
        unsorted_migration.sort_operations();
        
        // Should be back in the original order
        assert_eq!(
            unsorted_migration.operations[0].order,
            migration.operations[0].order
        );
        
        // Test reversibility
        assert!(migration.is_reversible());
        let reversed = migration.reversed().unwrap();
        
        // Reversed should have operations in opposite order
        assert_eq!(reversed.operations.len(), 2);
        
        // First operation should be dropping the email column
        match &reversed.operations[0].statement.ddl {
            DdlOperation::AlterTable(table_name, col_ops) => {
                assert_eq!(table_name, "users");
                assert_eq!(col_ops.len(), 1);
                match &col_ops[0] {
                    ColumnDefinitionDdl::DropColumn(col_name) => {
                        assert_eq!(col_name, "email");
                    }
                    _ => panic!("Expected DropColumn operation"),
                }
            }
            _ => panic!("Expected AlterTable operation"),
        }
        
        // Second operation should be dropping the table
        match &reversed.operations[1].statement.ddl {
            DdlOperation::DropTable(table_name) => {
                assert_eq!(table_name, "users");
            }
            _ => panic!("Expected DropTable operation"),
        }
    }
    
    #[test]
    fn test_irreversible_migration() {
        // Create a migration with irreversible operations (e.g., dropping a column)
        let drop_column = DdlStatement {
            ddl: DdlOperation::AlterTable(
                "users".to_string(),
                vec![ColumnDefinitionDdl::DropColumn("name".to_string())],
            ),
            sql: "ALTER TABLE users DROP COLUMN name".to_string(),
            // This is irreversible because we don't know the original column definition
        };
        
        let migration = SchemaMigration::new(
            "drop_name_column".to_string(),
            MigrationDirection::Up,
            vec![MigrationOperation {
                order: 1,
                statement: drop_column,
            }],
        );
        
        // Migration should not be reversible
        assert!(!migration.is_reversible());
        assert!(migration.reversed().is_none());
    }
} 