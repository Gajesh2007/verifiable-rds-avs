//! Query analyzer for PostgreSQL queries
//! 
//! This module provides functionality to analyze SQL queries, extract metadata,
//! detect tables and columns accessed, identify query type, and detect non-deterministic operations.

use crate::error::{ProxyError, Result};
use log::{debug, warn, info};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use sqlparser::ast::{Statement, Query, SetExpr, Select, TableWithJoins, TableFactor, ObjectName, Value};
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
}

/// Table access type
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
        
        // Try to determine query type from keywords
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
        } else if lowercase_query.starts_with("begin") || lowercase_query.starts_with("start transaction") {
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
            QueryType::Other("Unknown".to_string())
        };
        
        // Try to extract table names using a simple regex-like approach
        let mut tables = Vec::new();
        
        // For unparseable queries, we can't reliably extract tables
        // but we can make a best effort for common patterns
        
        // Check for determinism using pattern matching
        let mut is_deterministic = true;
        let mut non_deterministic_operations = Vec::new();
        
        for pattern in &self.non_deterministic_patterns {
            if lowercase_query.contains(pattern) {
                is_deterministic = false;
                non_deterministic_operations.push(NonDeterministicOperation {
                    operation_type: "Function".to_string(),
                    description: format!("Non-deterministic function: {}", pattern),
                    can_fix_automatically: false,
                    suggested_fix: None,
                });
            }
        }
        
        Ok(QueryMetadata {
            query: query.to_string(),
            query_type,
            tables,
            is_deterministic,
            non_deterministic_operations,
            complexity_score: 1, // Default complexity for unparseable queries
            special_handling: false,
            verifiable: query_type.is_dml() || query_type.is_ddl(),
            cacheable: false, // Unparseable queries are not cacheable
            extra: HashMap::new(),
            non_deterministic_reason: None,
        })
    }
    
    /// Extract query type from SQL statement
    fn extract_query_type(&self, statement: &Statement) -> QueryType {
        match statement {
            Statement::Query(query) => {
                // Check if it's a SELECT query
                match &query.body {
                    SetExpr::Select(_) => QueryType::Select,
                    SetExpr::Insert { .. } => QueryType::Insert,
                    _ => QueryType::Select, // Default to SELECT for other query types
                }
            }
            Statement::Insert { .. } => QueryType::Insert,
            Statement::Update { .. } => QueryType::Update,
            Statement::Delete { .. } => QueryType::Delete,
            Statement::CreateTable { .. } => QueryType::CreateTable,
            Statement::AlterTable { .. } => QueryType::AlterTable,
            Statement::Drop { object_type, .. } => {
                if let Some(obj_type) = object_type {
                    match obj_type.to_string().as_str() {
                        "TABLE" => QueryType::DropTable,
                        "INDEX" => QueryType::DropIndex,
                        _ => QueryType::Other(format!("DROP {}", obj_type)),
                    }
                } else {
                    QueryType::Other("DROP".to_string())
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
            Statement::Insert { table_name, .. } => {
                tables.push(TableAccess {
                    table_name: self.object_name_to_string(table_name),
                    schema_name: self.extract_schema_name(table_name),
                    access_type: AccessType::Write,
                    columns: None,
                });
            }
            Statement::Update { table_name, .. } => {
                tables.push(TableAccess {
                    table_name: self.object_name_to_string(table_name),
                    schema_name: self.extract_schema_name(table_name),
                    access_type: AccessType::ReadWrite,
                    columns: None,
                });
            }
            Statement::Delete { table_name, .. } => {
                tables.push(TableAccess {
                    table_name: self.object_name_to_string(table_name),
                    schema_name: self.extract_schema_name(table_name),
                    access_type: AccessType::Write,
                    columns: None,
                });
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
        match &query.body {
            SetExpr::Select(select) => {
                self.extract_tables_from_select(select, tables, access_type);
            }
            SetExpr::Insert { table_name, .. } => {
                tables.push(TableAccess {
                    table_name: self.object_name_to_string(table_name),
                    schema_name: self.extract_schema_name(table_name),
                    access_type: AccessType::Write,
                    columns: None,
                });
            }
            SetExpr::Query(subquery) => {
                self.extract_tables_from_query(subquery, tables, access_type);
            }
            _ => {
                // Other query types don't access tables or we can't determine
            }
        }
    }
    
    /// Extract tables from a SELECT statement
    fn extract_tables_from_select(&self, select: &Select, tables: &mut Vec<TableAccess>, access_type: AccessType) {
        for table_with_joins in &select.from {
            self.extract_tables_from_table_with_joins(table_with_joins, tables, access_type);
        }
    }
    
    /// Extract tables from a FROM clause with joins
    fn extract_tables_from_table_with_joins(&self, table_with_joins: &TableWithJoins, tables: &mut Vec<TableAccess>, access_type: AccessType) {
        self.extract_tables_from_table_factor(&table_with_joins.relation, tables, access_type);
        
        for join in &table_with_joins.joins {
            self.extract_tables_from_table_factor(&join.relation, tables, access_type);
        }
    }
    
    /// Extract tables from a table factor (table, subquery, etc.)
    fn extract_tables_from_table_factor(&self, table_factor: &TableFactor, tables: &mut Vec<TableAccess>, access_type: AccessType) {
        match table_factor {
            TableFactor::Table { name, .. } => {
                tables.push(TableAccess {
                    table_name: self.object_name_to_string(name),
                    schema_name: self.extract_schema_name(name),
                    access_type,
                    columns: None,
                });
            }
            TableFactor::Derived { subquery, .. } => {
                self.extract_tables_from_query(subquery, tables, access_type);
            }
            TableFactor::NestedJoin { join, .. } => {
                self.extract_tables_from_table_with_joins(join, tables, access_type);
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
        let mut score = 1; // Base score
        
        // Length-based complexity
        score += (query_text.len() as u32) / 100;
        
        // Check for joins
        if let Statement::Query(query) = statement {
            if let SetExpr::Select(select) = &query.body {
                // Count tables in FROM clause
                for table_with_joins in &select.from {
                    score += 1; // Base score for each table
                    score += table_with_joins.joins.len() as u32; // Additional score for joins
                }
                
                // Check for subqueries
                let has_subquery = query_text.to_lowercase().contains("select") && 
                                  query_text.matches("select").count() > 1;
                if has_subquery {
                    score += 3; // Subqueries add complexity
                }
                
                // Check for GROUP BY
                if select.group_by.len() > 0 {
                    score += 2;
                }
                
                // Check for aggregates
                let has_aggregates = query_text.to_lowercase().contains("count(") || 
                                    query_text.to_lowercase().contains("sum(") ||
                                    query_text.to_lowercase().contains("avg(") ||
                                    query_text.to_lowercase().contains("min(") ||
                                    query_text.to_lowercase().contains("max(");
                if has_aggregates {
                    score += 2;
                }
                
                // Check for window functions
                if query_text.to_lowercase().contains("over(") || 
                   query_text.to_lowercase().contains("over (") {
                    score += 3;
                }
            }
        }
        
        score
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
        let query = "SELECT id, name FROM users WHERE age > 18 ORDER BY name";
        
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Select);
        assert_eq!(metadata.tables.len(), 1);
        assert_eq!(metadata.tables[0].table_name, "users");
        assert_eq!(metadata.tables[0].access_type, AccessType::Read);
        assert!(metadata.is_deterministic);
        assert!(metadata.cacheable);
        assert!(!metadata.modifies_data());
    }
    
    #[test]
    fn test_analyze_insert_query() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "INSERT INTO users (name, age) VALUES ('John', 25)";
        
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Insert);
        assert_eq!(metadata.tables.len(), 1);
        assert_eq!(metadata.tables[0].table_name, "users");
        assert_eq!(metadata.tables[0].access_type, AccessType::Write);
        assert!(metadata.is_deterministic);
        assert!(!metadata.cacheable);
        assert!(metadata.modifies_data());
    }
    
    #[test]
    fn test_analyze_update_query() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "UPDATE users SET age = 26 WHERE name = 'John'";
        
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Update);
        assert_eq!(metadata.tables.len(), 1);
        assert_eq!(metadata.tables[0].table_name, "users");
        assert_eq!(metadata.tables[0].access_type, AccessType::ReadWrite);
        assert!(metadata.is_deterministic);
        assert!(!metadata.cacheable);
        assert!(metadata.modifies_data());
    }
    
    #[test]
    fn test_analyze_create_table_query() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "CREATE TABLE products (id SERIAL PRIMARY KEY, name TEXT, price DECIMAL)";
        
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::CreateTable);
        assert_eq!(metadata.tables.len(), 1);
        assert_eq!(metadata.tables[0].table_name, "products");
        assert_eq!(metadata.tables[0].access_type, AccessType::Write);
        assert!(metadata.is_deterministic);
        assert!(!metadata.cacheable);
        assert!(metadata.modifies_data());
    }
    
    #[test]
    fn test_analyze_non_deterministic_query() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "SELECT id, name, NOW() FROM users ORDER BY RANDOM()";
        
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Select);
        assert!(!metadata.is_deterministic);
        assert!(metadata.non_deterministic_operations.len() >= 2); // Should detect NOW() and RANDOM()
        assert!(!metadata.cacheable);
    }
    
    #[test]
    fn test_analyze_query_with_subquery() {
        let mut analyzer = QueryAnalyzer::new();
        let query = "SELECT u.name FROM users u WHERE u.id IN (SELECT user_id FROM orders)";
        
        let metadata = analyzer.analyze(query).unwrap();
        
        assert_eq!(metadata.query_type, QueryType::Select);
        assert!(metadata.tables.len() >= 2); // Should detect both users and orders tables
        assert!(metadata.complexity_score > 1); // Should have higher complexity due to subquery
    }
    
    #[test]
    fn test_query_complexity() {
        let mut analyzer = QueryAnalyzer::new();
        
        let simple_query = "SELECT id FROM users";
        let complex_query = "SELECT u.name, COUNT(o.id) FROM users u 
                            JOIN orders o ON u.id = o.user_id 
                            JOIN order_items oi ON o.id = oi.order_id
                            WHERE o.status = 'completed' 
                            GROUP BY u.name 
                            HAVING COUNT(o.id) > 5";
        
        let simple_metadata = analyzer.analyze(simple_query).unwrap();
        let complex_metadata = analyzer.analyze(complex_query).unwrap();
        
        assert!(complex_metadata.complexity_score > simple_metadata.complexity_score);
    }
    
    #[test]
    fn test_analyze_transaction_queries() {
        let mut analyzer = QueryAnalyzer::new();
        
        let begin = "BEGIN TRANSACTION";
        let commit = "COMMIT";
        let rollback = "ROLLBACK";
        
        let begin_metadata = analyzer.analyze(begin).unwrap();
        let commit_metadata = analyzer.analyze(commit).unwrap();
        let rollback_metadata = analyzer.analyze(rollback).unwrap();
        
        assert_eq!(begin_metadata.query_type, QueryType::BeginTransaction);
        assert_eq!(commit_metadata.query_type, QueryType::Commit);
        assert_eq!(rollback_metadata.query_type, QueryType::Rollback);
        
        assert!(begin_metadata.query_type.is_transaction_control());
        assert!(commit_metadata.query_type.is_transaction_control());
        assert!(rollback_metadata.query_type.is_transaction_control());
        
        assert!(!begin_metadata.modifies_data());
        assert!(!commit_metadata.modifies_data());
        assert!(!rollback_metadata.modifies_data());
    }
} 