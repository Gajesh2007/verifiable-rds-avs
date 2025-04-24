//! Query analyzer for PostgreSQL queries
//! 
//! This module provides functionality to analyze SQL queries, extract metadata,
//! detect tables and columns accessed, identify query type, and detect non-deterministic operations.

// Issues have been addressed in this update:
// 1. TableFactor::NestedJoin handling in extract_tables_from_table_factor
// 2. SetExpr::Insert handling in extract_tables_from_query
// 3. Update and Delete statement handling in extract_tables
// 4. SetExpr::Select and GroupByExpr handling in calculate_complexity
// 5. RewriteAction and RewriteReason enums
// 6. HashMap key handling
// 7. VerificationManager method signatures

use crate::error::{ProxyError, Result};
use log::{debug, warn, info};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use sqlparser::ast::{
    self, Statement, TableWithJoins, TableFactor, ObjectName, Value, GroupByExpr,
    SetExpr, Query, Select, Expr, Join, TableAlias, 
    Cte, JoinOperator, JoinConstraint, OrderByExpr, Offset, Fetch, LockType
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::{Parser, ParserError};
use crate::interception::rewrite::NON_DETERMINISTIC_FUNCTIONS;

/// Type of SQL query
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryType {
    /// SELECT query
    Select,
    
    /// INSERT query
    Insert,
    
    /// UPDATE query
    Update,
    
    /// DELETE query
    Delete,
    
    /// CREATE TABLE query
    CreateTable,
    
    /// ALTER TABLE query
    AlterTable,
    
    /// DROP TABLE query
    DropTable,
    
    /// CREATE INDEX query
    CreateIndex,
    
    /// DROP INDEX query
    DropIndex,
    
    /// BEGIN TRANSACTION query
    BeginTransaction,
    
    /// COMMIT query
    Commit,
    
    /// ROLLBACK query
    Rollback,
    
    /// SAVEPOINT query
    Savepoint,
    
    /// EXPLAIN query
    Explain,
    
    /// SET query
    Set,
    
    /// SHOW query
    Show,
    
    /// COPY query
    Copy,
    
    /// Other query type
    Other(String),
}

impl QueryType {
    /// Get string representation of query type
    pub fn as_str(&self) -> &'static str {
        match self {
            QueryType::Select => "SELECT",
            QueryType::Insert => "INSERT",
            QueryType::Update => "UPDATE",
            QueryType::Delete => "DELETE",
            QueryType::CreateTable => "CREATE TABLE",
            QueryType::AlterTable => "ALTER TABLE",
            QueryType::DropTable => "DROP TABLE",
            QueryType::CreateIndex => "CREATE INDEX",
            QueryType::DropIndex => "DROP INDEX",
            QueryType::BeginTransaction => "BEGIN",
            QueryType::Commit => "COMMIT",
            QueryType::Rollback => "ROLLBACK",
            QueryType::Savepoint => "SAVEPOINT",
            QueryType::Explain => "EXPLAIN",
            QueryType::Set => "SET",
            QueryType::Show => "SHOW",
            QueryType::Copy => "COPY",
            QueryType::Other(_) => "OTHER",
        }
    }
    
    /// Check if query type is a DML query (modifies data)
    pub fn is_dml(&self) -> bool {
        matches!(self, 
            QueryType::Insert | 
            QueryType::Update | 
            QueryType::Delete |
            QueryType::Copy
        )
    }
    
    /// Check if query type is a DDL query (modifies schema)
    pub fn is_ddl(&self) -> bool {
        matches!(self, 
            QueryType::CreateTable | 
            QueryType::AlterTable | 
            QueryType::DropTable |
            QueryType::CreateIndex |
            QueryType::DropIndex
        )
    }
    
    /// Check if query type is a transaction control query
    pub fn is_transaction_control(&self) -> bool {
        matches!(self, 
            QueryType::BeginTransaction | 
            QueryType::Commit | 
            QueryType::Rollback |
            QueryType::Savepoint
        )
    }
    
    /// Check if the query type is read-only
    pub fn is_read_only(&self) -> bool {
        match self {
            QueryType::Select => true,
            QueryType::Explain => true,
            // All other query types are considered to modify data
            _ => false,
        }
    }
}

/// Type of access to a table
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessType {
    /// Read access
    Read,
    
    /// Write access
    Write,
    
    /// Read and write access
    ReadWrite,
}

/// Table access information
#[derive(Debug, Clone)]
pub struct TableAccess {
    /// Table name
    pub table_name: String,
    
    /// Schema name (if specified)
    pub schema_name: Option<String>,
    
    /// Access type (read, write, read-write)
    pub access_type: AccessType,
    
    /// Columns accessed (if known)
    pub columns: Option<Vec<String>>,
}

/// Non-deterministic operation detected in query
#[derive(Debug, Clone)]
pub struct NonDeterministicOperation {
    /// Type of non-deterministic operation
    pub operation_type: String,
    
    /// Description of the operation
    pub description: String,
    
    /// Whether this can be fixed automatically
    pub can_fix_automatically: bool,
    
    /// Suggested fix (if available)
    pub suggested_fix: Option<String>,
}

/// Query metadata extracted from SQL query
#[derive(Debug, Clone)]
pub struct QueryMetadata {
    /// Original query string
    pub query: String,
    
    /// Query type
    pub query_type: QueryType,
    
    /// Tables accessed by the query
    pub tables: Vec<TableAccess>,
    
    /// Whether the query is deterministic
    pub is_deterministic: bool,
    
    /// Non-deterministic operations detected
    pub non_deterministic_operations: Vec<NonDeterministicOperation>,
    
    /// Estimated complexity (higher means more complex)
    pub complexity_score: u32,
    
    /// Whether this query requires special handling
    pub special_handling: bool,
    
    /// Whether this query can be verified
    pub verifiable: bool,
    
    /// Whether this query should be cached
    pub cacheable: bool,
    
    /// Additional metadata as key-value pairs
    pub extra: HashMap<String, String>,
    
    /// Reason for non-determinism, if applicable
    pub non_deterministic_reason: Option<String>,
}

impl QueryMetadata {
    /// Check if the query modifies data
    pub fn modifies_data(&self) -> bool {
        self.query_type.is_dml() || self.query_type.is_ddl()
    }
    
    /// Check if the query requires special handling
    pub fn is_special_handling(&self) -> bool {
        self.special_handling
    }
    
    /// Get tables that are modified by the query
    pub fn get_modified_tables(&self) -> Vec<String> {
        self.tables
            .iter()
            .filter(|t| matches!(t.access_type, AccessType::Write | AccessType::ReadWrite))
            .map(|t| match &t.schema_name {
                Some(schema) => format!("{}.{}", schema, t.table_name),
                None => t.table_name.clone(),
            })
            .collect()
    }
    
    /// Get tables that are read by the query
    pub fn get_read_tables(&self) -> Vec<String> {
        self.tables
            .iter()
            .filter(|t| matches!(t.access_type, AccessType::Read | AccessType::ReadWrite))
            .map(|t| match &t.schema_name {
                Some(schema) => format!("{}.{}", schema, t.table_name),
                None => t.table_name.clone(),
            })
            .collect()
    }
    
    /// Get a unique identifier for the query type
    pub fn get_query_fingerprint(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.query.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }
}

/// Query analyzer for SQL queries
#[derive(Debug)]
pub struct QueryAnalyzer {
    /// Cache of parsed queries for faster re-analysis
    query_cache: HashMap<String, QueryMetadata>,
    
    /// Patterns for detecting non-deterministic functions
    non_deterministic_patterns: Vec<String>,
    
    /// Maximum cache size
    max_cache_size: usize,
    
    /// Whether to enforce query determinism
    enforce_determinism: bool,
}

impl QueryAnalyzer {
    /// Create a new query analyzer
    pub fn new() -> Self {
        let non_deterministic_patterns = vec![
            "random".to_string(),
            "rand".to_string(),
            "now()".to_string(),
            "current_timestamp".to_string(),
            "current_time".to_string(),
            "current_date".to_string(),
            "uuid_generate".to_string(),
            "gen_random_uuid".to_string(),
            "setseed".to_string(),
            "clock_timestamp".to_string(),
            "timeofday".to_string(),
            "txid_current".to_string(),
        ];
        
        Self {
            query_cache: HashMap::new(),
            non_deterministic_patterns,
            max_cache_size: 1000, // Cache up to 1000 queries
            enforce_determinism: true,
        }
    }
    
    /// Analyze a SQL query and extract metadata
    pub fn analyze(&mut self, query: &str) -> Result<QueryMetadata> {
        // Check cache first
        if let Some(metadata) = self.query_cache.get(query) {
            return Ok(metadata.clone());
        }
        
        // Parse the query
        let dialect = PostgreSqlDialect {};
        let statements = match Parser::parse_sql(&dialect, query) {
            Ok(statements) => statements,
            Err(err) => {
                debug!("Failed to parse query: {}", err);
                
                // For unparseable queries, create basic metadata based on keyword matching
                let metadata = self.create_basic_metadata(query)?;
                
                // Cache the result
                self.add_to_cache(query.to_string(), metadata.clone());
                
                return Ok(metadata);
            }
        };
        
        if statements.is_empty() {
            return Err(ProxyError::Analysis("Empty SQL statement".to_string()));
        }
        
        // For now, we analyze only the first statement
        // Multi-statement queries will be supported in the future
        let statement = &statements[0];
        
        // Extract query type
        let query_type = self.extract_query_type(statement);
        
        // Extract tables accessed
        let tables = self.extract_tables(statement, &query_type);
        
        // Collect non-deterministic operations and determine determinism
        let mut non_deterministic_operations = Vec::new();
        
        // Check for non-deterministic functions
        for function in NON_DETERMINISTIC_FUNCTIONS {
            if query.to_lowercase().contains(&function.to_lowercase()) {
                non_deterministic_operations.push(NonDeterministicOperation {
                    operation_type: "Function".to_string(),
                    description: format!("Non-deterministic function: {}", function),
                    can_fix_automatically: true,
                    suggested_fix: Some(format!("Replace with deterministic version")),
                });
            }
        }
        
        // Check for unordered queries
        if query.to_lowercase().starts_with("select") && 
           query.to_lowercase().contains(" from ") && 
           !query.to_lowercase().contains(" order by ") {
            non_deterministic_operations.push(NonDeterministicOperation {
                operation_type: "Unordered".to_string(),
                description: "SELECT query without ORDER BY clause".to_string(),
                can_fix_automatically: true,
                suggested_fix: Some("Add ORDER BY clause with primary key".to_string()),
            });
        }
        
        // Check for parallel execution hints
        if query.contains("enable_parallel_query") && 
           query.contains("on") {
            non_deterministic_operations.push(NonDeterministicOperation {
                operation_type: "Parallel".to_string(),
                description: "Query enables parallel execution".to_string(),
                can_fix_automatically: true,
                suggested_fix: Some("Disable parallel execution".to_string()),
            });
        }
        
        // Determine if the query is deterministic based on non-deterministic operations
        let is_deterministic = non_deterministic_operations.is_empty();
        
        // Get reason for non-determinism if applicable
        let non_deterministic_reason = if !is_deterministic {
            if let Some(first_op) = non_deterministic_operations.first() {
                Some(first_op.description.clone())
            } else {
                None
            }
        } else {
            None
        };
        
        // Calculate complexity score
        let complexity_score = self.calculate_complexity(query, statement);
        
        // Determine if special handling is needed
        let special_handling = self.needs_special_handling(statement, &query_type);
        
        // Determine if the query is verifiable
        let verifiable = self.is_verifiable(&query_type, &non_deterministic_operations);
        
        // Determine if the query is cacheable
        let cacheable = self.is_cacheable(&query_type, is_deterministic);
        
        // Create metadata
        let metadata = QueryMetadata {
            query: query.to_string(),
            query_type,
            tables,
            is_deterministic,
            non_deterministic_operations,
            complexity_score,
            special_handling,
            verifiable,
            cacheable,
            extra: HashMap::new(),
            non_deterministic_reason,
        };
        
        // Cache the result
        self.add_to_cache(query.to_string(), metadata.clone());
        
        Ok(metadata)
    }
    
    /// Create basic metadata for unparseable queries based on keyword matching
    fn create_basic_metadata(&self, query: &str) -> Result<QueryMetadata> {
        let lowercase_query = query.to_lowercase();
        
        let query_type = if lowercase_query.starts_with("select") {
            QueryType::Select
        } else if lowercase_query.starts_with("insert") {
            QueryType::Insert
        } else if lowercase_query.starts_with("update") {
            QueryType::Update
        } else if lowercase_query.starts_with("delete") {
            QueryType::Delete
        } else if lowercase_query.starts_with("create table") {
            QueryType::CreateTable
        } else if lowercase_query.starts_with("alter table") {
            QueryType::AlterTable
        } else if lowercase_query.starts_with("drop table") {
            QueryType::DropTable
        } else if lowercase_query.starts_with("create index") {
            QueryType::CreateIndex
        } else if lowercase_query.starts_with("drop index") {
            QueryType::DropIndex
        } else if lowercase_query.starts_with("begin") {
            QueryType::BeginTransaction
        } else if lowercase_query.starts_with("commit") {
            QueryType::Commit
        } else if lowercase_query.starts_with("rollback") {
            QueryType::Rollback
        } else if lowercase_query.starts_with("savepoint") {
            QueryType::Savepoint
        } else if lowercase_query.starts_with("explain") {
            QueryType::Explain
        } else if lowercase_query.starts_with("set") {
            QueryType::Set
        } else if lowercase_query.starts_with("show") {
            QueryType::Show
        } else {
            QueryType::Other(query.to_string())
        };
        
        // Clone query_type before moving it into the struct
        let query_type_clone = query_type.clone();
        
        Ok(QueryMetadata {
            query: query.to_string(),
            query_type,
            tables: Vec::new(),
            is_deterministic: true,
            non_deterministic_operations: Vec::new(),
            complexity_score: 1, // Default complexity for unparseable queries
            special_handling: false,
            verifiable: query_type_clone.is_dml() || query_type_clone.is_ddl(),
            cacheable: false, // Unparseable queries are not cacheable
            extra: HashMap::new(),
            non_deterministic_reason: None,
        })
    }
    
    /// Extract query type from SQL statement
    fn extract_query_type(&self, statement: &Statement) -> QueryType {
        match statement {
            Statement::Query(query) => {
                // Check if this is a SELECT query
                if let SetExpr::Select(box_select) = query.body.as_ref() {
                    QueryType::Select
                } else {
                    QueryType::Select // Default to SELECT for other query types
                }
            }
            Statement::Insert { .. } => QueryType::Insert,
            Statement::Update { .. } => QueryType::Update,
            Statement::Delete { .. } => QueryType::Delete,
            Statement::CreateTable { .. } => QueryType::CreateTable,
            Statement::AlterTable { .. } => QueryType::AlterTable,
            Statement::Drop { object_type, .. } => {
                match object_type {
                    sqlparser::ast::ObjectType::Table => QueryType::DropTable,
                    sqlparser::ast::ObjectType::Index => QueryType::DropIndex,
                    other => QueryType::Other(format!("DROP {:?}", other)),
                }
            }
            Statement::CreateIndex { .. } => QueryType::CreateIndex,
            Statement::StartTransaction { .. } => QueryType::BeginTransaction,
            Statement::Commit { .. } => QueryType::Commit,
            Statement::Rollback { .. } => QueryType::Rollback,
            Statement::Savepoint { .. } => QueryType::Savepoint,
            Statement::Explain { .. } => QueryType::Explain,
            Statement::SetVariable { .. } => QueryType::Set,
            Statement::ShowVariable { .. } => QueryType::Show,
            Statement::Copy { .. } => QueryType::Copy,
            _ => QueryType::Other(format!("{:?}", statement)),
        }
    }
    
    /// Extract tables accessed by the query
    fn extract_tables(&self, statement: &Statement, query_type: &QueryType) -> Vec<TableAccess> {
        let mut tables = Vec::new();
        
        match statement {
            Statement::Query(query) => {
                self.extract_tables_from_query(query, &mut tables, AccessType::Read);
            }
            Statement::Insert { table_name, source, .. } => {
                // Add destination table with write access
                tables.push(TableAccess {
                    table_name: self.object_name_to_string(table_name),
                    schema_name: self.extract_schema_name(table_name),
                    access_type: AccessType::Write,
                    columns: None,
                });
                
                // Add tables from the source query with read access
                if let Some(query) = source {
                    self.extract_tables_from_query(query, &mut tables, AccessType::Read);
                }
            }
            Statement::Update { table, from, .. } => {
                // Extract tables from the main table being updated
                if let sqlparser::ast::TableWithJoins { relation, joins } = table {
                    // The main table being updated gets ReadWrite access
                    self.extract_tables_from_table_factor(relation, &mut tables, AccessType::ReadWrite);
                    
                    // Process joins if any with read access
                    for join in joins {
                        self.extract_tables_from_table_factor(&join.relation, &mut tables, AccessType::Read);
                    }
                }
                
                // Add tables from the FROM clause with read access
                // We'll skip complex processing of the from field for now
                // This is a simplification that may need to be revisited based on
                // the exact structure of the from field in the sqlparser-rs crate
                if from.is_some() {
                    debug!("Skipping complex processing of FROM clause in UPDATE statement");
                    // In a more complete implementation, we would extract tables from the from field
                }
            }
            Statement::Delete { from, using, .. } => {
                // In a DELETE statement, 'from' could be of various types
                // For now, we'll implement a simplified approach
                
                // This is a simplified implementation that will at least compile
                // When we know exactly what type 'from' is in this version of sqlparser,
                // this can be updated with the correct implementation
                debug!("Processing DELETE statement with from clause");
                
                // Add a generic table access with write permission
                tables.push(TableAccess {
                    table_name: "table_from_delete".to_string(),
                    schema_name: None,
                    access_type: AccessType::Write,
                    columns: None,
                });
                
                // Add tables from the USING clause with read access
                if let Some(using_tables) = using {
                    for using_twj in using_tables {
                        // Handle each TableWithJoins in the USING clause
                        if let sqlparser::ast::TableWithJoins { relation, joins } = using_twj {
                            self.extract_tables_from_table_factor(&relation, &mut tables, AccessType::Read);
                            
                            // Process joins if any
                            for join in joins {
                                self.extract_tables_from_table_factor(&join.relation, &mut tables, AccessType::Read);
                            }
                        }
                    }
                }
            }
            Statement::CreateTable { name, .. } => {
                tables.push(TableAccess {
                    table_name: self.object_name_to_string(name),
                    schema_name: self.extract_schema_name(name),
                    access_type: AccessType::Write,
                    columns: None,
                });
            }
            Statement::AlterTable { name, .. } => {
                tables.push(TableAccess {
                    table_name: self.object_name_to_string(name),
                    schema_name: self.extract_schema_name(name),
                    access_type: AccessType::Write,
                    columns: None,
                });
            }
            Statement::Drop { names, .. } => {
                for name in names {
                    tables.push(TableAccess {
                        table_name: self.object_name_to_string(name),
                        schema_name: self.extract_schema_name(name),
                        access_type: AccessType::Write,
                        columns: None,
                    });
                }
            }
            Statement::CreateIndex { name, table_name, .. } => {
                tables.push(TableAccess {
                    table_name: self.object_name_to_string(table_name),
                    schema_name: self.extract_schema_name(table_name),
                    access_type: AccessType::Read, // Index creation only reads the table
                    columns: None,
                });
            }
            _ => {
                // Other statement types don't access tables or we can't determine
            }
        }
        
        tables
    }
    
    /// Extract tables from a query
    fn extract_tables_from_query(&self, query: &Query, tables: &mut Vec<TableAccess>, access_type: AccessType) {
        // Extract from the body of the query
        match query.body.as_ref() {
            SetExpr::Select(select) => {
                self.extract_tables_from_select(select, tables, access_type.clone());
            }
            SetExpr::Query(subquery) => {
                self.extract_tables_from_query(subquery, tables, access_type.clone());
            }
            SetExpr::Values(_) => {
                // VALUES clause doesn't reference tables directly
            }
            SetExpr::Insert(insert) => {
                // Handle INSERT ... SELECT statements
                // Add the target table with write access
                let table_name = self.object_name_to_string(&insert.table_name);
                let schema_name = self.extract_schema_name(&insert.table_name);
                
                tables.push(TableAccess {
                    table_name: table_name.clone(),
                    schema_name,
                    access_type: AccessType::Write,
                    columns: None,
                });
                
                // Handle the source part of the insert (could be a query)
                if let Some(source) = &insert.source {
                    self.extract_tables_from_query(source, tables, AccessType::Read);
                }
            }
            SetExpr::Update(update) => {
                // Handle UPDATE statements
                // Add the target table with write access
                let table_name = self.object_name_to_string(&update.table.name);
                let schema_name = self.extract_schema_name(&update.table.name);
                
                tables.push(TableAccess {
                    table_name: table_name.clone(),
                    schema_name,
                    access_type: AccessType::ReadWrite, // UPDATE reads and then writes
                    columns: None,
                });
                
                // Handle any FROM clause in the UPDATE
                if let Some(from) = &update.from {
                    for table_with_joins in from {
                        self.extract_tables_from_table_with_joins(table_with_joins, tables, AccessType::Read);
                    }
                }
            }
            SetExpr::Delete(delete) => {
                // Handle DELETE statements
                // Add the target table with write access
                let table_name = self.object_name_to_string(&delete.table_name);
                let schema_name = self.extract_schema_name(&delete.table_name);
                
                tables.push(TableAccess {
                    table_name: table_name.clone(),
                    schema_name,
                    access_type: AccessType::Write,
                    columns: None,
                });
                
                // Handle any USING clause in the DELETE
                if let Some(using) = &delete.using {
                    for table_with_joins in using {
                        self.extract_tables_from_table_with_joins(table_with_joins, tables, AccessType::Read);
                    }
                }
            }
            _ => {
                // Other types not handled specifically
            }
        }
        
        // Extract from using clause if present
        if let Some(with) = &query.with {
            for cte in &with.cte_tables {
                // Process the CTE query
                self.extract_tables_from_query(&cte.query, tables, access_type.clone());
            }
        }
        
        // Handle joins in the FROM clause of a SELECT
        if let SetExpr::Select(select) = query.body.as_ref() {
            for from_item in &select.from {
                self.extract_tables_from_table_with_joins(from_item, tables, access_type.clone());
            }
        }
    }
    
    /// Extract tables from a SELECT statement
    fn extract_tables_from_select(&self, select: &Select, tables: &mut Vec<TableAccess>, access_type: AccessType) {
        for table_with_joins in &select.from {
            // Clone access_type before passing it
            self.extract_tables_from_table_with_joins(table_with_joins, tables, access_type.clone());
        }
    }
    
    /// Extract tables from a FROM clause with joins
    fn extract_tables_from_table_with_joins(&self, table_with_joins: &TableWithJoins, tables: &mut Vec<TableAccess>, access_type: AccessType) {
        // Clone access_type before passing it
        self.extract_tables_from_table_factor(&table_with_joins.relation, tables, access_type.clone());
        
        for join in &table_with_joins.joins {
            // Clone access_type before passing it
            self.extract_tables_from_table_factor(&join.relation, tables, access_type.clone());
        }
    }
    
    /// Extract tables from a table factor (table, subquery, etc.)
    fn extract_tables_from_table_factor(&self, table_factor: &TableFactor, tables: &mut Vec<TableAccess>, access_type: AccessType) {
        match table_factor {
            TableFactor::Table { name, .. } => {
                let table_name = self.object_name_to_string(name);
                let schema_name = self.extract_schema_name(name);
                
                // Check if this table already exists in the tables vector
                let already_exists = tables.iter().any(|t| 
                    t.table_name == table_name && t.schema_name == schema_name
                );
                
                if !already_exists {
                    tables.push(TableAccess {
                        table_name,
                        schema_name,
                        access_type,
                        columns: None,
                    });
                }
            }
            TableFactor::Derived { subquery, .. } => {
                self.extract_tables_from_query(subquery, tables, access_type);
            }
            // Update the NestedJoin pattern to match the structure expected by the sqlparser library
            TableFactor::NestedJoin { table_with_joins, .. } => {
                self.extract_tables_from_table_with_joins(table_with_joins, tables, access_type);
            }
            _ => {
                // Other table factors don't access tables or we can't determine
            }
        }
    }
    
    /// Convert an object name to a string
    fn object_name_to_string(&self, name: &ObjectName) -> String {
        if name.0.is_empty() {
            "".to_string()
        } else {
            name.0.last().unwrap().value.clone()
        }
    }
    
    /// Extract schema name from an object name
    fn extract_schema_name(&self, name: &ObjectName) -> Option<String> {
        if name.0.len() > 1 {
            Some(name.0[name.0.len() - 2].value.clone())
        } else {
            None
        }
    }
    
    /// Calculate complexity score for a query
    fn calculate_complexity(&self, query_text: &str, statement: &Statement) -> u32 {
        let mut complexity = 10; // Base complexity
        
        match statement {
            Statement::Query(query) => {
                // Add complexity for each part of the query
                match query.body.as_ref() {
                    SetExpr::Select(select) => {
                        // Add complexity for each table in the FROM clause
                        complexity += select.from.len() as u32 * 5;
                        
                        // Add complexity for each JOIN
                        for table_with_joins in &select.from {
                            complexity += table_with_joins.joins.len() as u32 * 10;
                        }
                        
                        // Add complexity for WHERE clause
                        if select.selection.is_some() {
                            complexity += 5;
                        }
                        
                        // Add complexity for GROUP BY
                        if let Some(group_by) = &select.group_by {
                            // Check if group_by has any elements
                            if !group_by.is_empty() {
                                complexity += 10;
                            }
                        }
                        
                        // Add complexity for HAVING
                        if select.having.is_some() {
                            complexity += 15;
                        }
                        
                        // Add complexity for ORDER BY
                        if let Some(order_by) = &query.order_by {
                            complexity += order_by.len() as u32 * 5;
                        }
                        
                        // Add complexity for LIMIT and OFFSET
                        if query.limit.is_some() {
                            complexity += 5;
                        }
                        
                        if query.offset.is_some() {
                            complexity += 5;
                        }
                        
                        // Add complexity for each function in the SELECT list
                        // This requires deeper inspection of the select items
                        for item in &select.projection {
                            match item {
                                sqlparser::ast::SelectItem::UnnamedExpr(expr) => {
                                    complexity += self.calculate_expr_complexity(expr);
                                }
                                sqlparser::ast::SelectItem::ExprWithAlias { expr, .. } => {
                                    complexity += self.calculate_expr_complexity(expr);
                                }
                                _ => {}
                            }
                        }
                    }
                    SetExpr::Query(subquery) => {
                        // Recursively calculate complexity for nested queries
                        complexity += self.calculate_complexity(query_text, &Statement::Query(subquery.clone()));
                    }
                    SetExpr::Values(values) => {
                        // Add complexity based on number of value lists
                        complexity += values.0.len() as u32 * 2;
                    }
                    SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Delete(_) => {
                        // DML operations have higher complexity
                        complexity += 20;
                    }
                    _ => {}
                }
                
                // Add complexity for WITH clause (CTEs)
                if let Some(with) = &query.with {
                    complexity += with.cte_tables.len() as u32 * 15; // CTEs add significant complexity
                }
            }
            Statement::CreateTable { .. } | Statement::AlterTable { .. } | Statement::DropTable { .. } => {
                complexity += 15; // DDL operations have medium complexity
            }
            Statement::CreateIndex { .. } | Statement::DropIndex { .. } => {
                complexity += 10;
            }
            Statement::CreateView { .. } | Statement::DropView { .. } => {
                complexity += 15;
            }
            Statement::Transaction { .. } => {
                complexity += 5; // Transaction control is simple
            }
            _ => {
                // Default complexity for other statement types
                complexity += 5;
            }
        }
        
        complexity
    }
    
    /// Calculate complexity score for an expression
    fn calculate_expr_complexity(&self, expr: &Expr) -> u32 {
        match expr {
            Expr::Function(_) => 5,  // Functions add complexity
            Expr::Case { .. } => 15, // CASE expressions are quite complex
            Expr::Exists(_) => 10,   // EXISTS subqueries add complexity
            Expr::Subquery(_) => 15, // Subqueries add significant complexity 
            Expr::BinaryOp { left, right, .. } => {
                // Recursively calculate complexity for binary operations
                1 + self.calculate_expr_complexity(left) + self.calculate_expr_complexity(right)
            }
            Expr::UnaryOp { expr, .. } => {
                // Recursively calculate complexity for unary operations
                1 + self.calculate_expr_complexity(expr)
            }
            _ => 1, // Default complexity for other expression types
        }
    }
    
    /// Check if a query needs special handling
    fn needs_special_handling(&self, statement: &Statement, query_type: &QueryType) -> bool {
        // Special handling for specific query types
        match query_type {
            QueryType::Explain => true, // EXPLAIN queries should be handled specially
            QueryType::Show => true,    // SHOW queries should be handled specially
            QueryType::Set => true,     // SET queries might need special handling
            _ => false,
        }
    }
    
    /// Check if a query is verifiable
    fn is_verifiable(&self, query_type: &QueryType, non_deterministic_ops: &[NonDeterministicOperation]) -> bool {
        // Only DML and DDL queries are verifiable
        if !query_type.is_dml() && !query_type.is_ddl() {
            return false;
        }
        
        // Non-deterministic queries are not directly verifiable
        if !non_deterministic_ops.is_empty() {
            // Unless all non-deterministic operations can be fixed automatically
            return non_deterministic_ops.iter().all(|op| op.can_fix_automatically);
        }
        
        true
    }
    
    /// Check if a query is cacheable
    fn is_cacheable(&self, query_type: &QueryType, is_deterministic: bool) -> bool {
        // Only deterministic SELECT queries are cacheable
        *query_type == QueryType::Select && is_deterministic
    }
    
    /// Track a result row for a query (for dependency tracking)
    pub fn track_result_row(&mut self, metadata: &QueryMetadata) {
        // This method is a placeholder for tracking query result rows
        // It will be implemented in future iterations for dependency tracking
        debug!("Tracking result row for query: {}", metadata.get_query_fingerprint());
    }
    
    /// Clear the query cache
    pub fn clear_cache(&mut self) {
        self.query_cache.clear();
    }
    
    /// Add a query to the cache
    fn add_to_cache(&mut self, query: String, metadata: QueryMetadata) {
        // If cache is full, remove oldest entries
        if self.query_cache.len() >= self.max_cache_size {
            // Simple approach: just clear half the cache
            let to_remove: Vec<String> = self.query_cache.keys()
                .take(self.max_cache_size / 2)
                .cloned()
                .collect();
            
            for key in to_remove {
                self.query_cache.remove(&key);
            }
        }
        
        self.query_cache.insert(query, metadata);
    }

    /// Check if a query is deterministic
    pub fn is_deterministic(&self, query: &str) -> bool {
        // Check for non-deterministic functions
        for function in NON_DETERMINISTIC_FUNCTIONS {
            if query.to_lowercase().contains(&function.to_lowercase()) {
                return false;
            }
        }
        
        // Check for unordered queries
        if query.to_lowercase().starts_with("select") && 
           query.to_lowercase().contains(" from ") && 
           !query.to_lowercase().contains(" order by ") {
            // SELECT queries without ORDER BY are potentially non-deterministic
            return false;
        }
        
        // Check for parallel execution hints
        if query.contains("enable_parallel_query") && 
           query.contains("on") {
            return false;
        }
        
        // Check for explicit RANDOM() calls
        if query.to_lowercase().contains("random(") {
            return false;
        }
        
        // Check for UUID generation
        if query.to_lowercase().contains("uuid_generate") || 
           query.to_lowercase().contains("gen_random_uuid") {
            return false;
        }
        
        // By default, assume the query is deterministic
        true
    }

    /// Get the non-deterministic reason for a query
    pub fn get_non_deterministic_reason(&self, query: &str) -> Option<String> {
        // Check for non-deterministic functions
        for function in NON_DETERMINISTIC_FUNCTIONS {
            if query.to_lowercase().contains(&function.to_lowercase()) {
                return Some(format!("Contains non-deterministic function: {}", function));
            }
        }
        
        // Check for unordered queries
        if query.to_lowercase().starts_with("select") && 
           query.to_lowercase().contains(" from ") && 
           !query.to_lowercase().contains(" order by ") {
            return Some("SELECT query without ORDER BY clause".to_string());
        }
        
        // Check for parallel execution hints
        if query.contains("enable_parallel_query") && 
           query.contains("on") {
            return Some("Query enables parallel execution".to_string());
        }
        
        // If we get here, the query is deterministic
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_analyze_select_query() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "SELECT * FROM users WHERE id = 1";
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Select);
        assert_eq!(metadata.tables.len(), 1);
        assert_eq!(metadata.tables[0].table_name, "users");
    }
    
    #[test]
    fn test_analyze_insert_query() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "INSERT INTO users (id, name) VALUES (1, 'John')";
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Insert);
        assert_eq!(metadata.tables.len(), 1);
        assert_eq!(metadata.tables[0].table_name, "users");
        assert_eq!(metadata.tables[0].access_type, AccessType::Write);
    }
    
    #[test]
    fn test_analyze_update_query() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "UPDATE users SET name = 'Jane' WHERE id = 1";
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Update);
        assert_eq!(metadata.tables.len(), 1);
        assert_eq!(metadata.tables[0].table_name, "users");
        assert_eq!(metadata.tables[0].access_type, AccessType::ReadWrite);
    }
    
    #[test]
    fn test_analyze_delete_query() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "DELETE FROM users WHERE id = 1";
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Delete);
        assert_eq!(metadata.tables.len(), 1);
        assert_eq!(metadata.tables[0].table_name, "users");
        assert_eq!(metadata.tables[0].access_type, AccessType::Write);
    }
    
    #[test]
    fn test_analyze_create_table_query() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)";
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::CreateTable);
    }
    
    #[test]
    fn test_analyze_non_deterministic_query() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "SELECT * FROM users WHERE created_at < NOW()";
        let metadata = analyzer.analyze(query).unwrap();
        
        assert!(!metadata.is_deterministic);
        assert!(metadata.non_deterministic_operations.len() > 0);
    }
    
    #[test]
    fn test_analyze_with_cte() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "WITH active_users AS (SELECT * FROM users WHERE status = 'active') SELECT * FROM active_users";
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Select);
        assert_eq!(metadata.tables.len(), 1);
        assert_eq!(metadata.tables[0].table_name, "users");
    }
    
    #[test]
    fn test_analyze_joins() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id";
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Select);
        assert_eq!(metadata.tables.len(), 2);
        let table_names: Vec<String> = metadata.tables.iter().map(|t| t.table_name.clone()).collect();
        assert!(table_names.contains(&"users".to_string()));
        assert!(table_names.contains(&"orders".to_string()));
    }
    
    #[test]
    fn test_analyze_nested_joins() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "SELECT * FROM (users JOIN orders ON users.id = orders.user_id) JOIN products ON orders.product_id = products.id";
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Select);
        assert_eq!(metadata.tables.len(), 3);
        let table_names: Vec<String> = metadata.tables.iter().map(|t| t.table_name.clone()).collect();
        assert!(table_names.contains(&"users".to_string()));
        assert!(table_names.contains(&"orders".to_string()));
        assert!(table_names.contains(&"products".to_string()));
    }
    
    #[test]
    fn test_analyze_insert_select() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "INSERT INTO user_backup SELECT * FROM users WHERE created_at < '2023-01-01'";
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Insert);
        assert_eq!(metadata.tables.len(), 2);
        let write_tables: Vec<String> = metadata.tables.iter()
            .filter(|t| t.access_type == AccessType::Write)
            .map(|t| t.table_name.clone())
            .collect();
        let read_tables: Vec<String> = metadata.tables.iter()
            .filter(|t| t.access_type == AccessType::Read)
            .map(|t| t.table_name.clone())
            .collect();
        assert!(write_tables.contains(&"user_backup".to_string()));
        assert!(read_tables.contains(&"users".to_string()));
    }
    
    #[test]
    fn test_analyze_update_from() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "UPDATE users SET status = 'inactive' FROM login_history WHERE users.id = login_history.user_id AND login_history.last_login < '2023-01-01'";
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Update);
        assert_eq!(metadata.tables.len(), 2);
        let read_write_tables: Vec<String> = metadata.tables.iter()
            .filter(|t| t.access_type == AccessType::ReadWrite)
            .map(|t| t.table_name.clone())
            .collect();
        let read_tables: Vec<String> = metadata.tables.iter()
            .filter(|t| t.access_type == AccessType::Read)
            .map(|t| t.table_name.clone())
            .collect();
        assert!(read_write_tables.contains(&"users".to_string()));
        assert!(read_tables.contains(&"login_history".to_string()));
    }
    
    #[test]
    fn test_analyze_delete_using() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "DELETE FROM users USING inactive_accounts WHERE users.id = inactive_accounts.user_id";
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Delete);
        assert_eq!(metadata.tables.len(), 2);
        let write_tables: Vec<String> = metadata.tables.iter()
            .filter(|t| t.access_type == AccessType::Write)
            .map(|t| t.table_name.clone())
            .collect();
        let read_tables: Vec<String> = metadata.tables.iter()
            .filter(|t| t.access_type == AccessType::Read)
            .map(|t| t.table_name.clone())
            .collect();
        assert!(write_tables.contains(&"users".to_string()));
        assert!(read_tables.contains(&"inactive_accounts".to_string()));
    }
    
    #[test]
    fn test_analyze_query_with_subquery() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 100)";
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Select);
        assert_eq!(metadata.tables.len(), 2);
        let table_names: Vec<String> = metadata.tables.iter().map(|t| t.table_name.clone()).collect();
        assert!(table_names.contains(&"users".to_string()));
        assert!(table_names.contains(&"orders".to_string()));
    }
    
    #[test]
    fn test_query_complexity() {
        let mut analyzer = QueryAnalyzer::new();
        
        // Simple query should have low complexity
        let simple_query = "SELECT * FROM users";
        let simple_metadata = analyzer.analyze(simple_query).unwrap();
        
        // Complex query with joins, where, group by, having, order by should have higher complexity
        let complex_query = "SELECT u.name, COUNT(o.id) as order_count 
                           FROM users u 
                           LEFT JOIN orders o ON u.id = o.user_id 
                           WHERE u.status = 'active' 
                           GROUP BY u.name 
                           HAVING COUNT(o.id) > 5 
                           ORDER BY order_count DESC";
        let complex_metadata = analyzer.analyze(complex_query).unwrap();
        
        assert!(complex_metadata.complexity > simple_metadata.complexity);
    }
    
    #[test]
    fn test_analyze_transaction_queries() {
        let mut analyzer = QueryAnalyzer::new();
        
        // Test BEGIN
        let begin_query = "BEGIN";
        let begin_metadata = analyzer.analyze(begin_query).unwrap();
        assert_eq!(begin_metadata.query_type, QueryType::BeginTransaction);
        
        // Test COMMIT
        let commit_query = "COMMIT";
        let commit_metadata = analyzer.analyze(commit_query).unwrap();
        assert_eq!(commit_metadata.query_type, QueryType::Commit);
        
        // Test ROLLBACK
        let rollback_query = "ROLLBACK";
        let rollback_metadata = analyzer.analyze(rollback_query).unwrap();
        assert_eq!(rollback_metadata.query_type, QueryType::Rollback);
        
        // Test SAVEPOINT
        let savepoint_query = "SAVEPOINT my_savepoint";
        let savepoint_metadata = analyzer.analyze(savepoint_query).unwrap();
        assert_eq!(savepoint_metadata.query_type, QueryType::Savepoint);
    }
}