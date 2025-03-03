//! Data Definition Language (DDL) representation
//!
//! This module provides data structures for representing database DDL statements
//! such as CREATE TABLE, ALTER TABLE, etc.

use serde::{Serialize, Deserialize};

use crate::models::{ColumnDefinition, ColumnType};

/// Definition of a database table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableDefinition {
    /// Name of the table
    pub name: String,
    
    /// Columns in the table
    pub columns: Vec<ColumnDefinition>,
    
    /// Primary key column names
    pub primary_keys: Vec<String>,
    
    /// Unique constraints
    pub unique_constraints: Vec<Vec<String>>,
    
    /// Foreign key constraints (column names, referenced table, referenced columns)
    pub foreign_keys: Vec<(Vec<String>, String, Vec<String>)>,
}

/// Column definition DDL operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ColumnDefinitionDdl {
    /// Add a column
    AddColumn(ColumnDefinition),
    
    /// Drop a column
    DropColumn(String),
    
    /// Modify a column
    ModifyColumn(ColumnDefinition),
    
    /// Rename a column
    RenameColumn(String, String),
}

/// DDL operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DdlOperation {
    /// Create a table
    CreateTable(TableDefinition),
    
    /// Drop a table
    DropTable(String),
    
    /// Alter a table
    AlterTable(String, Vec<ColumnDefinitionDdl>),
    
    /// Rename a table
    RenameTable(String, String),
}

/// DDL statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdlStatement {
    /// DDL operation
    pub ddl: DdlOperation,
    
    /// SQL statement
    pub sql: String,
}

impl DdlStatement {
    /// Create a new DDL statement
    pub fn new(ddl: DdlOperation, sql: String) -> Self {
        DdlStatement { ddl, sql }
    }
    
    /// Create a DDL statement for creating a table
    pub fn create_table(table: TableDefinition, sql: String) -> Self {
        DdlStatement {
            ddl: DdlOperation::CreateTable(table),
            sql,
        }
    }
    
    /// Create a DDL statement for dropping a table
    pub fn drop_table(table_name: String, sql: String) -> Self {
        DdlStatement {
            ddl: DdlOperation::DropTable(table_name),
            sql,
        }
    }
    
    /// Create a DDL statement for altering a table
    pub fn alter_table(table_name: String, operations: Vec<ColumnDefinitionDdl>, sql: String) -> Self {
        DdlStatement {
            ddl: DdlOperation::AlterTable(table_name, operations),
            sql,
        }
    }
    
    /// Create a DDL statement for renaming a table
    pub fn rename_table(old_name: String, new_name: String, sql: String) -> Self {
        DdlStatement {
            ddl: DdlOperation::RenameTable(old_name, new_name),
            sql,
        }
    }
    
    /// Check if a DDL statement is reversible
    pub fn is_reversible(&self) -> bool {
        match &self.ddl {
            DdlOperation::CreateTable(_) => true, // Can be reversed with DROP TABLE
            DdlOperation::DropTable(_) => false, // Can't be reversed without knowing the table definition
            DdlOperation::AlterTable(_, column_operations) => {
                // Check each column operation
                column_operations.iter().all(|op| match op {
                    ColumnDefinitionDdl::AddColumn(_) => true, // Can be reversed with DROP COLUMN
                    ColumnDefinitionDdl::DropColumn(_) => false, // Can't be reversed without knowing the column definition
                    ColumnDefinitionDdl::ModifyColumn(_) => false, // Can't be reversed without knowing the original column definition
                    ColumnDefinitionDdl::RenameColumn(_, _) => true, // Can be reversed by swapping the names
                })
            }
            DdlOperation::RenameTable(_, _) => true, // Can be reversed by swapping the names
        }
    }
    
    /// Create a reversed DDL statement
    pub fn reverse(&self) -> Option<Self> {
        match &self.ddl {
            DdlOperation::CreateTable(table_def) => {
                // Reverse is DROP TABLE
                Some(DdlStatement {
                    ddl: DdlOperation::DropTable(table_def.name.clone()),
                    sql: format!("DROP TABLE {}", table_def.name),
                })
            }
            DdlOperation::DropTable(_) => {
                // Can't reverse without knowing the table definition
                None
            }
            DdlOperation::AlterTable(table_name, column_operations) => {
                // Collect reversed operations
                let mut reversed_operations = Vec::new();
                
                for op in column_operations {
                    match op {
                        ColumnDefinitionDdl::AddColumn(column_def) => {
                            // Reverse is DROP COLUMN
                            reversed_operations.push(ColumnDefinitionDdl::DropColumn(
                                column_def.name.clone()
                            ));
                        }
                        ColumnDefinitionDdl::DropColumn(_) => {
                            // Can't reverse without knowing the column definition
                            return None;
                        }
                        ColumnDefinitionDdl::ModifyColumn(_) => {
                            // Can't reverse without knowing the original column definition
                            return None;
                        }
                        ColumnDefinitionDdl::RenameColumn(old_name, new_name) => {
                            // Reverse is RENAME COLUMN with swapped names
                            reversed_operations.push(ColumnDefinitionDdl::RenameColumn(
                                new_name.clone(),
                                old_name.clone()
                            ));
                        }
                    }
                }
                
                if reversed_operations.is_empty() {
                    return None;
                }
                
                // Create reversed SQL (simplified)
                let reversed_sql = format!("ALTER TABLE {} /* Reversed */", table_name);
                
                Some(DdlStatement {
                    ddl: DdlOperation::AlterTable(table_name.clone(), reversed_operations),
                    sql: reversed_sql,
                })
            }
            DdlOperation::RenameTable(old_name, new_name) => {
                // Reverse is RENAME TABLE with swapped names
                Some(DdlStatement {
                    ddl: DdlOperation::RenameTable(new_name.clone(), old_name.clone()),
                    sql: format!("RENAME TABLE {} TO {}", new_name, old_name),
                })
            }
        }
    }
    
    /// Parse a DDL statement from SQL (not fully implemented)
    pub fn parse_sql(_sql: &str) -> Option<Self> {
        // For a full implementation, we would need a SQL parser to convert
        // SQL statements into DdlOperation structures
        // This would be complex and likely require a separate crate
        
        // Example skeleton for a simple CREATE TABLE statement:
        /*
        if sql.trim().to_uppercase().starts_with("CREATE TABLE") {
            // Extract table name
            let table_name = extract_table_name(sql)?;
            
            // Extract columns
            let columns = extract_columns(sql)?;
            
            // Extract primary keys
            let primary_keys = extract_primary_keys(sql)?;
            
            // Build table definition
            let table_def = TableDefinition {
                name: table_name,
                columns,
                primary_keys,
                unique_constraints: Vec::new(),
                foreign_keys: Vec::new(),
            };
            
            return Some(DdlStatement {
                ddl: DdlOperation::CreateTable(table_def),
                sql: sql.to_string(),
            });
        }
        */
        
        // For now, just return None to indicate parsing is not implemented
        None
    }
}

/// Helper to create a column definition
pub fn column(
    name: &str,
    column_type: ColumnType,
    nullable: bool,
    primary_key: bool,
    unique: bool,
) -> ColumnDefinition {
    ColumnDefinition {
        name: name.to_string(),
        column_type,
        nullable,
        primary_key,
        unique,
        default_value: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Helper function to create a simple table definition
    fn create_users_table() -> TableDefinition {
        TableDefinition {
            name: "users".to_string(),
            columns: vec![
                column("id", ColumnType::Integer, false, true, true),
                column("name", ColumnType::VarChar(100), false, false, false),
                column("email", ColumnType::VarChar(100), true, false, true),
            ],
            primary_keys: vec!["id".to_string()],
            unique_constraints: vec![vec!["email".to_string()]],
            foreign_keys: Vec::new(),
        }
    }
    
    #[test]
    fn test_create_table() {
        let table = create_users_table();
        let sql = "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(100) UNIQUE)".to_string();
        
        let stmt = DdlStatement::create_table(table.clone(), sql.clone());
        
        // Check the statement
        assert!(matches!(stmt.ddl, DdlOperation::CreateTable(_)));
        assert_eq!(stmt.sql, sql);
        
        if let DdlOperation::CreateTable(ref table_def) = stmt.ddl {
            assert_eq!(table_def.name, "users");
            assert_eq!(table_def.columns.len(), 3);
            assert_eq!(table_def.primary_keys, vec!["id".to_string()]);
        } else {
            panic!("Expected CreateTable operation");
        }
        
        // Check reversibility
        assert!(stmt.is_reversible());
        
        // Check reversal
        let reversed = stmt.reverse().unwrap();
        assert!(matches!(reversed.ddl, DdlOperation::DropTable(_)));
        
        if let DdlOperation::DropTable(table_name) = reversed.ddl {
            assert_eq!(table_name, "users");
        } else {
            panic!("Expected DropTable operation");
        }
    }
    
    #[test]
    fn test_alter_table() {
        // Test adding a column
        let add_column = DdlStatement::alter_table(
            "users".to_string(),
            vec![ColumnDefinitionDdl::AddColumn(
                column("active", ColumnType::Boolean, false, false, false)
            )],
            "ALTER TABLE users ADD COLUMN active BOOLEAN NOT NULL".to_string(),
        );
        
        // Check the statement
        assert!(matches!(add_column.ddl, DdlOperation::AlterTable(_, _)));
        assert!(add_column.is_reversible());
        
        // Check reversal
        let reversed = add_column.reverse().unwrap();
        assert!(matches!(reversed.ddl, DdlOperation::AlterTable(_, _)));
        
        if let DdlOperation::AlterTable(table_name, operations) = reversed.ddl {
            assert_eq!(table_name, "users");
            assert_eq!(operations.len(), 1);
            
            if let ColumnDefinitionDdl::DropColumn(column_name) = &operations[0] {
                assert_eq!(column_name, "active");
            } else {
                panic!("Expected DropColumn operation");
            }
        } else {
            panic!("Expected AlterTable operation");
        }
        
        // Test dropping a column
        let drop_column = DdlStatement::alter_table(
            "users".to_string(),
            vec![ColumnDefinitionDdl::DropColumn("email".to_string())],
            "ALTER TABLE users DROP COLUMN email".to_string(),
        );
        
        // Should not be reversible
        assert!(!drop_column.is_reversible());
        assert!(drop_column.reverse().is_none());
    }
    
    #[test]
    fn test_rename_table() {
        let rename_table = DdlStatement::rename_table(
            "users".to_string(),
            "accounts".to_string(),
            "RENAME TABLE users TO accounts".to_string(),
        );
        
        // Check the statement
        assert!(matches!(rename_table.ddl, DdlOperation::RenameTable(_, _)));
        assert!(rename_table.is_reversible());
        
        // Check reversal
        let reversed = rename_table.reverse().unwrap();
        assert!(matches!(reversed.ddl, DdlOperation::RenameTable(_, _)));
        
        if let DdlOperation::RenameTable(old_name, new_name) = reversed.ddl {
            assert_eq!(old_name, "accounts");
            assert_eq!(new_name, "users");
        } else {
            panic!("Expected RenameTable operation");
        }
    }
    
    #[test]
    fn test_column_helper() {
        let col = column("id", ColumnType::Integer, false, true, true);
        
        assert_eq!(col.name, "id");
        assert_eq!(col.column_type, ColumnType::Integer);
        assert!(!col.nullable);
        assert!(col.primary_key);
        assert!(col.unique);
        assert!(col.default_value.is_none());
    }
} 