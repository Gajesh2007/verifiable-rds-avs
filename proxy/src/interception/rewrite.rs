//! Query rewriter for PostgreSQL queries
//! 
//! This module provides functionality to rewrite SQL queries to ensure deterministic
//! execution, replace non-deterministic functions, and enforce query plans when needed.

use crate::error::{ProxyError, Result};
use crate::interception::analyzer::{NonDeterministicOperation, QueryMetadata, QueryType};
use log::{debug, warn, info};
use std::collections::HashMap;
use sqlparser::ast::{Statement, Query, SetExpr, Select, Expr, Function, FunctionArg, ObjectName, Ident};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

/// Reason for rewriting a query
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteReason {
    /// Non-deterministic function replacement
    NonDeterministicFunction,
    
    /// Add explicit ORDER BY for deterministic results
    AddExplicitOrdering,
    
    /// Enforce specific query plan
    EnforceQueryPlan,
    
    /// Add query parameter for tracking
    AddTrackingParameter,
    
    /// Security restriction
    SecurityRestriction,
    
    /// Other reason
    Other(String),
}

/// Action taken when rewriting a query
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteAction {
    /// No rewrite needed
    None,
    
    /// Query was rewritten
    Rewritten(RewriteReason),
    
    /// Query was rejected
    Rejected(String),
    
    /// Query was replaced with another query
    Replaced(RewriteReason),
}

/// Function replacement definition
#[derive(Debug, Clone)]
struct FunctionReplacement {
    /// Original function name
    original: String,
    
    /// Replacement function name
    replacement: String,
    
    /// Whether to add special arguments
    add_special_args: bool,
    
    /// Special arguments to add
    special_args: Vec<String>,
}

/// Query rewriter for SQL queries
#[derive(Debug)]
pub struct QueryRewriter {
    /// Function replacements
    function_replacements: HashMap<String, FunctionReplacement>,
    
    /// Configuration for the rewriter
    config: RewriterConfig,
}

/// Configuration for the query rewriter
#[derive(Debug, Clone)]
pub struct RewriterConfig {
    /// Whether rewriting is enabled
    pub enabled: bool,
    
    /// Whether to enforce query plans
    pub enforce_query_plans: bool,
    
    /// Whether to add tracking parameters
    pub add_tracking: bool,
    
    /// Maximum query length to rewrite
    pub max_query_length: usize,
    
    /// Whether to reject non-deterministic queries that can't be fixed
    pub reject_unfixable_queries: bool,
}

impl Default for RewriterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            enforce_query_plans: false,
            add_tracking: false,
            max_query_length: 100000,
            reject_unfixable_queries: false,
        }
    }
}

/// Functions that are non-deterministic and need to be replaced
pub const NON_DETERMINISTIC_FUNCTIONS: &[&str] = &[
    "now()",
    "current_timestamp",
    "random()",
    "uuid_generate_v4()",
    "txid_current()",
    "gen_random_uuid()",
    "timeofday()",
    "clock_timestamp()",
    "statement_timestamp()",
    "transaction_timestamp()",
];

/// Map of non-deterministic functions to their deterministic replacements
pub fn get_deterministic_replacement(function: &str, tx_id: u64, seed: u64) -> Option<String> {
    match function.to_lowercase().as_str() {
        "now()" | "current_timestamp" => {
            Some("verification_timestamp()".to_string())
        },
        "random()" => {
            Some(format!("verification_random({}, {})", tx_id, seed))
        },
        "uuid_generate_v4()" | "gen_random_uuid()" => {
            Some(format!("verification_uuid({}, {})", tx_id, seed))
        },
        "txid_current()" => {
            Some(format!("{}", tx_id))
        },
        "timeofday()" | "clock_timestamp()" | "statement_timestamp()" | "transaction_timestamp()" => {
            Some("verification_timestamp()".to_string())
        },
        _ => None,
    }
}

impl QueryRewriter {
    /// Create a new query rewriter
    pub fn new(config: RewriterConfig) -> Self {
        let mut function_replacements = HashMap::new();
        
        // Add standard function replacements
        function_replacements.insert(
            "now".to_string(),
            FunctionReplacement {
                original: "now".to_string(),
                replacement: "verification_timestamp".to_string(),
                add_special_args: false,
                special_args: vec![],
            },
        );
        
        function_replacements.insert(
            "current_timestamp".to_string(),
            FunctionReplacement {
                original: "current_timestamp".to_string(),
                replacement: "verification_timestamp".to_string(),
                add_special_args: false,
                special_args: vec![],
            },
        );
        
        function_replacements.insert(
            "current_time".to_string(),
            FunctionReplacement {
                original: "current_time".to_string(),
                replacement: "verification_time".to_string(),
                add_special_args: false,
                special_args: vec![],
            },
        );
        
        function_replacements.insert(
            "current_date".to_string(),
            FunctionReplacement {
                original: "current_date".to_string(),
                replacement: "verification_date".to_string(),
                add_special_args: false,
                special_args: vec![],
            },
        );
        
        function_replacements.insert(
            "random".to_string(),
            FunctionReplacement {
                original: "random".to_string(),
                replacement: "verification_random".to_string(),
                add_special_args: false,
                special_args: vec![],
            },
        );
        
        function_replacements.insert(
            "gen_random_uuid".to_string(),
            FunctionReplacement {
                original: "gen_random_uuid".to_string(),
                replacement: "verification_uuid".to_string(),
                add_special_args: false,
                special_args: vec![],
            },
        );
        
        function_replacements.insert(
            "uuid_generate_v4".to_string(),
            FunctionReplacement {
                original: "uuid_generate_v4".to_string(),
                replacement: "verification_uuid".to_string(),
                add_special_args: false,
                special_args: vec![],
            },
        );
        
        Self {
            function_replacements,
            config,
        }
    }
    
    /// Rewrite a query based on its metadata
    pub fn rewrite(&self, query: &str, metadata: &QueryMetadata) -> Result<(String, RewriteAction)> {
        if !self.config.enabled {
            return Ok((query.to_string(), RewriteAction::None));
        }
        
        if query.len() > self.config.max_query_length {
            debug!("Query too long to rewrite: {} bytes", query.len());
            return Ok((query.to_string(), RewriteAction::None));
        }
        
        // Check if query needs rewriting
        if metadata.is_deterministic && !self.config.add_tracking && !self.config.enforce_query_plans {
            // No rewriting needed
            return Ok((query.to_string(), RewriteAction::None));
        }
        
        // Check if query has non-deterministic operations that can't be fixed
        if !metadata.is_deterministic && 
           self.config.reject_unfixable_queries && 
           !metadata.non_deterministic_operations.iter().all(|op| op.can_fix_automatically) {
            
            // Create a descriptive error message
            let unfixable_ops: Vec<String> = metadata.non_deterministic_operations
                .iter()
                .filter(|op| !op.can_fix_automatically)
                .map(|op| op.description.clone())
                .collect();
            
            let error_msg = format!(
                "Query contains non-deterministic operations that cannot be fixed automatically: {}",
                unfixable_ops.join(", ")
            );
            
            return Ok((query.to_string(), RewriteAction::Rejected(error_msg)));
        }
        
        // Parse the query
        let dialect = PostgreSqlDialect {};
        let statements = match Parser::parse_sql(&dialect, query) {
            Ok(statements) => statements,
            Err(err) => {
                debug!("Failed to parse query for rewriting: {}", err);
                return Ok((query.to_string(), RewriteAction::None));
            }
        };
        
        if statements.is_empty() {
            return Ok((query.to_string(), RewriteAction::None));
        }
        
        // For now, we only rewrite the first statement
        // Multi-statement rewriting will be supported in the future
        let mut statement = statements[0].clone();
        let mut rewrite_action = RewriteAction::None;
        
        // Apply function replacements for non-deterministic functions
        if !metadata.is_deterministic {
            let (new_statement, action) = self.replace_non_deterministic_functions(&statement, metadata)?;
            statement = new_statement;
            rewrite_action = action;
        }
        
        // Add explicit ORDER BY if needed
        if !metadata.is_deterministic && 
           metadata.query_type == QueryType::Select && 
           metadata.non_deterministic_operations.iter().any(|op| op.operation_type == "OrderBy") {
            
            let (new_statement, action) = self.add_explicit_ordering(&statement, metadata)?;
            statement = new_statement;
            
            if action != RewriteAction::None {
                rewrite_action = action;
            }
        }
        
        // Add query plan enforcement if configured
        if self.config.enforce_query_plans && 
           (metadata.query_type == QueryType::Select || 
            metadata.query_type == QueryType::Update || 
            metadata.query_type == QueryType::Delete) {
            
            let (new_statement, action) = self.enforce_query_plan(&statement)?;
            statement = new_statement;
            
            if action != RewriteAction::None {
                rewrite_action = action;
            }
        }
        
        // Convert rewritten statement back to SQL
        let rewritten_query = self.statement_to_string(&statement);
        
        if rewritten_query == query {
            // No changes were made
            return Ok((query.to_string(), RewriteAction::None));
        }
        
        Ok((rewritten_query, rewrite_action))
    }
    
    /// Replace non-deterministic functions in a statement
    fn replace_non_deterministic_functions(&self, statement: &Statement, metadata: &QueryMetadata) 
        -> Result<(Statement, RewriteAction)> {
        
        let mut new_statement = statement.clone();
        let mut has_replacements = false;
        
        // Currently, this is a placeholder for actual implementation
        // In a real implementation, we would walk the AST and replace function calls
        
        // For now, we'll use a simple text-based replacement as a demonstration
        if metadata.non_deterministic_operations.iter().any(|op| op.can_fix_automatically) {
            let statement_str = self.statement_to_string(statement);
            let mut rewritten_str = statement_str.clone();
            
            for replacement in self.function_replacements.values() {
                let original_pattern = format!("{}(", replacement.original);
                let replacement_pattern = format!("{}(", replacement.replacement);
                
                if rewritten_str.to_lowercase().contains(&original_pattern.to_lowercase()) {
                    rewritten_str = rewritten_str.replace(&original_pattern, &replacement_pattern);
                    rewritten_str = rewritten_str.replace(&original_pattern.to_uppercase(), &replacement_pattern);
                    has_replacements = true;
                }
                
                // Also check for function calls without parentheses (e.g., CURRENT_TIMESTAMP)
                let original_word = format!("{} ", replacement.original);
                let replacement_word = format!("{}() ", replacement.replacement);
                
                if rewritten_str.to_lowercase().contains(&original_word.to_lowercase()) {
                    rewritten_str = rewritten_str.replace(&original_word, &replacement_word);
                    rewritten_str = rewritten_str.replace(&original_word.to_uppercase(), &replacement_word);
                    has_replacements = true;
                }
            }
            
            if has_replacements {
                // Parse the rewritten query back into a statement
                let dialect = PostgreSqlDialect {};
                match Parser::parse_sql(&dialect, &rewritten_str) {
                    Ok(statements) => {
                        if !statements.is_empty() {
                            new_statement = statements[0].clone();
                        }
                    }
                    Err(err) => {
                        debug!("Failed to parse rewritten query: {}", err);
                        // Fall back to the original statement
                        new_statement = statement.clone();
                        has_replacements = false;
                    }
                }
            }
        }
        
        if has_replacements {
            Ok((new_statement, RewriteAction::Rewritten(RewriteReason::NonDeterministicFunction)))
        } else {
            Ok((new_statement, RewriteAction::None))
        }
    }
    
    /// Add explicit ordering to a query
    fn add_explicit_ordering(&self, statement: &Statement, metadata: &QueryMetadata) 
        -> Result<(Statement, RewriteAction)> {
        
        // This is a placeholder for actual implementation
        // In a real implementation, we would analyze the query and add appropriate ORDER BY clauses
        
        if let Statement::Query(query) = statement {
            let mut new_query = query.clone();
            
            if let SetExpr::Select(select) = &query.body {
                // For demonstration purposes, we'll add a simple ORDER BY primary key
                // In a real implementation, we would analyze the tables and add appropriate columns
                
                if metadata.tables.len() == 1 {
                    let table_name = &metadata.tables[0].table_name;
                    
                    // In a real implementation, we would look up the primary key columns
                    // For now, we'll assume "id" is the primary key
                    let column_name = "id";
                    
                    // Only add ORDER BY if it doesn't already have one
                    if query.order_by.is_empty() {
                        // Build a simple ORDER BY clause
                        let dialect = PostgreSqlDialect {};
                        let orderby_clause = format!("SELECT 1 ORDER BY {}.{}", table_name, column_name);
                        
                        match Parser::parse_sql(&dialect, &orderby_clause) {
                            Ok(statements) => {
                                if let Some(Statement::Query(orderby_query)) = statements.first() {
                                    new_query.order_by = orderby_query.order_by.clone();
                                }
                            }
                            Err(err) => {
                                debug!("Failed to parse ORDER BY clause: {}", err);
                            }
                        }
                    }
                }
            }
            
            if &new_query != query {
                let mut new_statement = statement.clone();
                if let Statement::Query(ref mut q) = new_statement {
                    *q = new_query;
                }
                
                return Ok((new_statement, RewriteAction::Rewritten(RewriteReason::AddExplicitOrdering)));
            }
        }
        
        Ok((statement.clone(), RewriteAction::None))
    }
    
    /// Enforce a specific query plan
    fn enforce_query_plan(&self, statement: &Statement) -> Result<(Statement, RewriteAction)> {
        if !self.config.enforce_query_plans {
            return Ok((statement.clone(), RewriteAction::None));
        }
        
        // This is a placeholder for actual implementation
        // In a real implementation, we would add query hints to enforce specific plans
        
        // For PostgreSQL, we could add comments with hints or modify query parameters
        // For this simple example, we'll just pretend we're enforcing a plan
        
        Ok((statement.clone(), RewriteAction::None))
    }
    
    /// Add tracking comment to a query
    fn add_tracking_comment(&self, query: &str) -> String {
        if !self.config.add_tracking {
            return query.to_string();
        }
        
        // Add a tracking comment with a unique identifier
        let tracking_id = uuid::Uuid::new_v4().to_string();
        format!("/* tracking_id:{} */ {}", tracking_id, query)
    }
    
    /// Convert a statement back to a string
    fn statement_to_string(&self, statement: &Statement) -> String {
        // In a real implementation, we would use a proper SQL formatter
        // For now, we'll use a simple debug representation
        format!("{:?}", statement)
    }
    
    /// Check if a query can be fixed automatically
    pub fn can_fix_automatically(&self, metadata: &QueryMetadata) -> bool {
        if !metadata.is_deterministic {
            return metadata.non_deterministic_operations.iter().all(|op| op.can_fix_automatically);
        }
        
        true
    }
    
    /// Add a custom function replacement
    pub fn add_function_replacement(&mut self, original: &str, replacement: &str) {
        self.function_replacements.insert(
            original.to_string(),
            FunctionReplacement {
                original: original.to_string(),
                replacement: replacement.to_string(),
                add_special_args: false,
                special_args: vec![],
            },
        );
    }

    /// Transform a query to be deterministic
    pub fn make_query_deterministic(&self, query: &str, tx_id: u64) -> Result<(String, RewriteAction)> {
        // Start with the original query
        let mut rewritten_query = query.to_string();
        let mut action = RewriteAction::None;
        let seed = tx_id; // Use transaction ID as seed for deterministic functions

        // Replace non-deterministic functions
        for function in NON_DETERMINISTIC_FUNCTIONS {
            if query.to_lowercase().contains(&function.to_lowercase()) {
                if let Some(replacement) = get_deterministic_replacement(function, tx_id, seed) {
                    rewritten_query = rewritten_query.replace(function, &replacement);
                    action = RewriteAction::Rewritten(RewriteReason::NonDeterministicFunction);
                }
            }
        }
        
        // Parse the query to determine if it's a SELECT without an ORDER BY
        if query.to_lowercase().starts_with("select") && !query.to_lowercase().contains("order by") {
            // If the query has a FROM clause, add an ORDER BY primary key
            if query.to_lowercase().contains(" from ") {
                // Extract table names
                let tables = self.extract_tables_from_query(query)?;
                
                // If we have tables, add an ORDER BY clause with primary keys
                if !tables.is_empty() {
                    // Get primary keys for the tables
                    let mut primary_keys = Vec::new();
                    for table in &tables {
                        if let Some(pks) = self.get_primary_keys(table) {
                            for pk in pks {
                                primary_keys.push(format!("{}.{}", table, pk));
                            }
                        }
                    }
                    
                    // If we have primary keys, add an ORDER BY clause
                    if !primary_keys.is_empty() {
                        // Check if the query already has an ORDER BY clause
                        if !rewritten_query.to_lowercase().contains("order by") {
                            rewritten_query = format!("{} ORDER BY {}", rewritten_query, primary_keys.join(", "));
                            action = RewriteAction::Rewritten(RewriteReason::MissingOrderBy);
                        }
                    }
                }
            }
        }
        
        // Force deterministic query plans by adding query hints
        if self.config.enforce_deterministic_plans && 
            (query.to_lowercase().starts_with("select") || 
             query.to_lowercase().starts_with("with")) {
            // Add a leading comment with query hints
            rewritten_query = format!("/*+ SET_CONFIG('enable_hashjoin', 'off', true) SET_CONFIG('enable_parallel_query', 'off', true) */ {}", rewritten_query);
            action = RewriteAction::Rewritten(RewriteReason::NonDeterministicPlan);
        }
        
        Ok((rewritten_query, action))
    }

    /// Extract table names from a query
    fn extract_tables_from_query(&self, query: &str) -> Result<Vec<String>> {
        // This is a simplified implementation
        // In a real system, you would use a SQL parser like sqlparser-rs
        let mut tables = Vec::new();
        
        // Extract tables from FROM clause
        if let Some(from_pos) = query.to_lowercase().find(" from ") {
            let after_from = &query[from_pos + 6..];
            
            // Extract until the next clause (WHERE, GROUP BY, etc.)
            let end_pos = [
                after_from.to_lowercase().find(" where ").unwrap_or(usize::MAX),
                after_from.to_lowercase().find(" group by ").unwrap_or(usize::MAX),
                after_from.to_lowercase().find(" having ").unwrap_or(usize::MAX),
                after_from.to_lowercase().find(" order by ").unwrap_or(usize::MAX),
                after_from.to_lowercase().find(" limit ").unwrap_or(usize::MAX),
                after_from.to_lowercase().find(" offset ").unwrap_or(usize::MAX),
                after_from.len(),
            ].into_iter().min().unwrap();
            
            let from_clause = &after_from[..end_pos].trim();
            
            // Split by commas
            for table_expr in from_clause.split(',') {
                // Handle table aliases
                let table_parts: Vec<&str> = table_expr.trim().split_whitespace().collect();
                if !table_parts.is_empty() {
                    // Extract just the table name (before AS or alias)
                    tables.push(table_parts[0].trim().to_string());
                }
            }
        }
        
        Ok(tables)
    }

    /// Get primary keys for a table
    fn get_primary_keys(&self, table: &str) -> Option<Vec<String>> {
        // In a real implementation, you would query the database schema
        // For now, we'll return a simple default
        Some(vec!["id".to_string()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interception::analyzer::{QueryAnalyzer, AccessType, TableAccess};
    
    fn create_test_metadata(query: &str, is_deterministic: bool) -> QueryMetadata {
        let mut non_deterministic_operations = Vec::new();
        
        if !is_deterministic {
            non_deterministic_operations.push(NonDeterministicOperation {
                operation_type: "Function".to_string(),
                description: "Non-deterministic function: now()".to_string(),
                can_fix_automatically: true,
                suggested_fix: Some("Replace with verification_timestamp()".to_string()),
            });
        }
        
        QueryMetadata {
            query: query.to_string(),
            query_type: QueryType::Select,
            tables: vec![
                TableAccess {
                    table_name: "users".to_string(),
                    schema_name: None,
                    access_type: AccessType::Read,
                    columns: None,
                },
            ],
            is_deterministic,
            non_deterministic_operations,
            complexity_score: 1,
            special_handling: false,
            verifiable: true,
            cacheable: is_deterministic,
            extra: HashMap::new(),
        }
    }
    
    #[test]
    fn test_rewrite_deterministic_query() {
        let config = RewriterConfig::default();
        let rewriter = QueryRewriter::new(config);
        
        let query = "SELECT id, name FROM users WHERE age > 18";
        let metadata = create_test_metadata(query, true);
        
        let (rewritten_query, action) = rewriter.rewrite(query, &metadata).unwrap();
        
        assert_eq!(action, RewriteAction::None);
        assert_eq!(rewritten_query, query);
    }
    
    #[test]
    fn test_rewrite_non_deterministic_query() {
        let config = RewriterConfig::default();
        let rewriter = QueryRewriter::new(config);
        
        let query = "SELECT id, name, NOW() FROM users";
        let metadata = create_test_metadata(query, false);
        
        let (rewritten_query, action) = rewriter.rewrite(query, &metadata).unwrap();
        
        // The exact string might vary depending on the implementation, but 
        // we should get a RewriteAction::Rewritten with NonDeterministicFunction reason
        if let RewriteAction::Rewritten(reason) = action {
            assert_eq!(reason, RewriteReason::NonDeterministicFunction);
            assert!(rewritten_query.contains("verification_timestamp"));
        } else {
            panic!("Expected RewriteAction::Rewritten, got {:?}", action);
        }
    }
    
    #[test]
    fn test_reject_unfixable_query() {
        let mut config = RewriterConfig::default();
        config.reject_unfixable_queries = true;
        let rewriter = QueryRewriter::new(config);
        
        let query = "SELECT id, name, NOW() FROM users ORDER BY RANDOM()";
        
        // Create metadata with unfixable operations
        let mut metadata = create_test_metadata(query, false);
        metadata.non_deterministic_operations.push(NonDeterministicOperation {
            operation_type: "Function".to_string(),
            description: "Non-deterministic function: random()".to_string(),
            can_fix_automatically: false, // This one can't be fixed
            suggested_fix: None,
        });
        
        let (_, action) = rewriter.rewrite(query, &metadata).unwrap();
        
        if let RewriteAction::Rejected(reason) = action {
            assert!(reason.contains("cannot be fixed automatically"));
        } else {
            panic!("Expected RewriteAction::Rejected, got {:?}", action);
        }
    }
    
    #[test]
    fn test_integration_with_analyzer() {
        // This test demonstrates how the analyzer and rewriter work together
        
        let mut analyzer = QueryAnalyzer::new();
        let config = RewriterConfig::default();
        let rewriter = QueryRewriter::new(config);
        
        // A query with non-deterministic functions
        let query = "SELECT id, name, NOW(), RANDOM() FROM users";
        
        // First, analyze the query
        let metadata = analyzer.analyze(query).unwrap();
        
        // The query should be identified as non-deterministic
        assert!(!metadata.is_deterministic);
        assert!(!metadata.non_deterministic_operations.is_empty());
        
        // Then, try to rewrite it
        let (rewritten_query, action) = rewriter.rewrite(query, &metadata).unwrap();
        
        // Verify that the query was rewritten
        if let RewriteAction::Rewritten(reason) = action {
            assert_eq!(reason, RewriteReason::NonDeterministicFunction);
            
            // The rewritten query should contain the replacement functions
            assert!(rewritten_query.contains("verification_timestamp") ||
                   rewritten_query.contains("verification_random"));
        } else {
            panic!("Expected RewriteAction::Rewritten, got {:?}", action);
        }
    }
} 