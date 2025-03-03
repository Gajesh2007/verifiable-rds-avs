//! Query execution component for handling special queries
//! 
//! This module provides functionality to execute special queries directly,
//! without sending them to the backend database. This includes system
//! queries, verification-related queries, and other special cases.

use crate::error::{ProxyError, Result};
use crate::interception::analyzer::{QueryMetadata, QueryType};
use crate::protocol::message::{BackendMessage, DataRow, CommandComplete, RowDescription, FieldDescription};
use log::{debug, warn, info};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use bytes::Bytes;

/// Type of execution plan
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionPlanType {
    /// Execute query normally on the backend
    Normal,
    
    /// Execute query directly without sending to backend
    Direct,
    
    /// Modify query before sending to backend
    Modified,
    
    /// Reject query
    Reject,
}

/// Execution plan for a query
#[derive(Debug, Clone)]
pub struct ExecutionPlan {
    /// Type of execution
    pub plan_type: ExecutionPlanType,
    
    /// Modified query (if applicable)
    pub modified_query: Option<String>,
    
    /// Result messages (if direct execution)
    pub result_messages: Option<Vec<BackendMessage>>,
    
    /// Error message (if rejected)
    pub error_message: Option<String>,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Result of query execution
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Query metadata
    pub metadata: QueryMetadata,
    
    /// Result messages
    pub messages: Vec<BackendMessage>,
    
    /// Rows affected (if applicable)
    pub rows_affected: Option<u64>,
    
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    
    /// Error message (if execution failed)
    pub error: Option<String>,
}

/// Handler for a special query
type QueryHandler = Box<dyn Fn(&str, &QueryMetadata) -> Result<Vec<BackendMessage>> + Send + Sync>;

/// Query executor for special queries
#[derive(Clone)]
pub struct QueryExecutor {
    /// Handlers for special queries
    handlers: Arc<Mutex<HashMap<String, QueryHandler>>>,
    
    /// Configuration for the executor
    config: ExecutorConfig,
    
    /// System metadata cache
    system_metadata: Arc<Mutex<HashMap<String, String>>>,
    
    /// Transaction session variables
    session_vars: Arc<Mutex<HashMap<String, String>>>,
}

/// Configuration for the query executor
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Whether to handle SET commands internally
    pub handle_set_internally: bool,
    
    /// Whether to handle SHOW commands internally
    pub handle_show_internally: bool,
    
    /// Whether to handle EXPLAIN commands internally
    pub handle_explain_internally: bool,
    
    /// Whether direct execution is enabled
    pub direct_execution_enabled: bool,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            handle_set_internally: true,
            handle_show_internally: true,
            handle_explain_internally: false,
            direct_execution_enabled: true,
        }
    }
}

impl QueryExecutor {
    /// Create a new query executor
    pub fn new(config: ExecutorConfig) -> Self {
        let handlers = Arc::new(Mutex::new(HashMap::new()));
        let system_metadata = Arc::new(Mutex::new(HashMap::new()));
        let session_vars = Arc::new(Mutex::new(HashMap::new()));
        
        let mut executor = Self {
            handlers,
            config,
            system_metadata,
            session_vars,
        };
        
        // Register default handlers
        executor.register_default_handlers();
        
        executor
    }
    
    /// Register default handlers for special queries
    fn register_default_handlers(&mut self) {
        // Handler for verification_version()
        self.register_handler("verification_version()", Box::new(|query, metadata| {
            let mut messages = Vec::new();
            
            // Column description
            let fields = vec![
                FieldDescription {
                    name: "version".to_string(),
                    table_oid: 0,
                    column_oid: 0,
                    data_type_oid: 25, // TEXT
                    data_type_size: -1,
                    type_modifier: -1,
                    format_code: 0,
                }
            ];
            
            messages.push(BackendMessage::RowDescription(fields));
            
            // Data row
            let values = vec![Some("1.0.0".as_bytes().to_vec())];
            messages.push(BackendMessage::DataRow(values));
            
            // Command complete
            messages.push(BackendMessage::CommandComplete("SELECT 1".to_string()));
            
            Ok(messages)
        }));
        
        // Handler for SET commands
        if self.config.handle_set_internally {
            self.register_handler("SET ", Box::new(move |query, metadata| {
                let session_vars = Arc::new(Mutex::new(HashMap::new()));
                
                // Parse the SET command
                // Format: SET [SESSION|LOCAL] name = value
                let parts: Vec<&str> = query.trim().splitn(2, ' ').collect();
                if parts.len() < 2 {
                    return Err(ProxyError::Execution("Invalid SET command".to_string()));
                }
                
                let command_parts: Vec<&str> = parts[1].splitn(2, '=').collect();
                if command_parts.len() < 2 {
                    return Err(ProxyError::Execution("Invalid SET command format".to_string()));
                }
                
                let var_name = command_parts[0].trim();
                let var_value = command_parts[1].trim().trim_matches('\'').trim_matches('"');
                
                // Store the variable in session vars
                if let Ok(mut vars) = session_vars.lock() {
                    vars.insert(var_name.to_string(), var_value.to_string());
                }
                
                // Return a simple command complete message
                let mut messages = Vec::new();
                messages.push(BackendMessage::CommandComplete("SET".to_string()));
                
                Ok(messages)
            }));
        }
        
        // Handler for SHOW commands
        if self.config.handle_show_internally {
            self.register_handler("SHOW ", Box::new(move |query, metadata| {
                let session_vars = Arc::new(Mutex::new(HashMap::new()));
                
                // Parse the SHOW command
                // Format: SHOW name
                let parts: Vec<&str> = query.trim().splitn(2, ' ').collect();
                if parts.len() < 2 {
                    return Err(ProxyError::Execution("Invalid SHOW command".to_string()));
                }
                
                let var_name = parts[1].trim();
                
                // Get the variable value from session vars
                let var_value = if let Ok(vars) = session_vars.lock() {
                    vars.get(var_name).cloned().unwrap_or_else(|| "".to_string())
                } else {
                    "".to_string()
                };
                
                let mut messages = Vec::new();
                
                // Column description
                let fields = vec![
                    FieldDescription {
                        name: var_name.to_string(),
                        table_oid: 0,
                        column_oid: 0,
                        data_type_oid: 25, // TEXT
                        data_type_size: -1,
                        type_modifier: -1,
                        format_code: 0,
                    }
                ];
                
                messages.push(BackendMessage::RowDescription(fields));
                
                // Data row
                let values = vec![Some(var_value.as_bytes().to_vec())];
                messages.push(BackendMessage::DataRow(values));
                
                // Command complete
                messages.push(BackendMessage::CommandComplete("SHOW".to_string()));
                
                Ok(messages)
            }));
        }
        
        // Handler for verification_state_root()
        self.register_handler("verification_state_root()", Box::new(|query, metadata| {
            let mut messages = Vec::new();
            
            // Column description
            let fields = vec![
                FieldDescription {
                    name: "state_root".to_string(),
                    table_oid: 0,
                    column_oid: 0,
                    data_type_oid: 25, // TEXT
                    data_type_size: -1,
                    type_modifier: -1,
                    format_code: 0,
                }
            ];
            
            messages.push(BackendMessage::RowDescription(fields));
            
            // Data row - this would be the actual state root in a real implementation
            let state_root = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
            let values = vec![Some(state_root.as_bytes().to_vec())];
            messages.push(BackendMessage::DataRow(values));
            
            // Command complete
            messages.push(BackendMessage::CommandComplete("SELECT 1".to_string()));
            
            Ok(messages)
        }));
    }
    
    /// Register a handler for a special query
    pub fn register_handler(&mut self, query_pattern: &str, handler: QueryHandler) {
        if let Ok(mut handlers) = self.handlers.lock() {
            handlers.insert(query_pattern.to_string(), handler);
        }
    }
    
    /// Create an execution plan for a query
    pub fn create_execution_plan(&self, query: &str, metadata: &QueryMetadata) -> Result<ExecutionPlan> {
        // Check for special queries that should be directly executed
        if self.config.direct_execution_enabled {
            if let Some(result_messages) = self.check_for_special_query(query, metadata)? {
                return Ok(ExecutionPlan {
                    plan_type: ExecutionPlanType::Direct,
                    modified_query: None,
                    result_messages: Some(result_messages),
                    error_message: None,
                    metadata: HashMap::new(),
                });
            }
        }
        
        // Check for internal handling of SET commands
        if self.config.handle_set_internally && query.trim().to_uppercase().starts_with("SET ") {
            if let Some(result_messages) = self.handle_set_command(query, metadata)? {
                return Ok(ExecutionPlan {
                    plan_type: ExecutionPlanType::Direct,
                    modified_query: None,
                    result_messages: Some(result_messages),
                    error_message: None,
                    metadata: HashMap::new(),
                });
            }
        }
        
        // Check for internal handling of SHOW commands
        if self.config.handle_show_internally && query.trim().to_uppercase().starts_with("SHOW ") {
            if let Some(result_messages) = self.handle_show_command(query, metadata)? {
                return Ok(ExecutionPlan {
                    plan_type: ExecutionPlanType::Direct,
                    modified_query: None,
                    result_messages: Some(result_messages),
                    error_message: None,
                    metadata: HashMap::new(),
                });
            }
        }
        
        // Default to normal execution
        Ok(ExecutionPlan {
            plan_type: ExecutionPlanType::Normal,
            modified_query: None,
            result_messages: None,
            error_message: None,
            metadata: HashMap::new(),
        })
    }
    
    /// Execute a query directly
    pub fn execute_query(&self, query: &str, metadata: &QueryMetadata) -> Result<ExecutionResult> {
        let start_time = std::time::Instant::now();
        
        let result_messages = match self.check_for_special_query(query, metadata)? {
            Some(messages) => messages,
            None => {
                return Err(ProxyError::Execution(format!(
                    "No handler found for query: {}", query
                )));
            }
        };
        
        let execution_time = start_time.elapsed();
        
        let rows_affected = self.extract_affected_rows(&result_messages);
        
        Ok(ExecutionResult {
            metadata: metadata.clone(),
            messages: result_messages,
            rows_affected,
            execution_time_ms: execution_time.as_millis() as u64,
            error: None,
        })
    }
    
    /// Check if a query is a special query that should be directly executed
    fn check_for_special_query(&self, query: &str, metadata: &QueryMetadata) -> Result<Option<Vec<BackendMessage>>> {
        let normalized_query = normalize_query(query);
        
        if let Ok(handlers) = self.handlers.lock() {
            for (pattern, handler) in handlers.iter() {
                if normalized_query.contains(pattern) {
                    match handler(query, metadata) {
                        Ok(messages) => return Ok(Some(messages)),
                        Err(err) => {
                            warn!("Handler for pattern '{}' failed: {}", pattern, err);
                            // Continue trying other handlers
                        }
                    }
                }
            }
        }
        
        // No handler found
        Ok(None)
    }
    
    /// Handle SET command internally
    fn handle_set_command(&self, query: &str, metadata: &QueryMetadata) -> Result<Option<Vec<BackendMessage>>> {
        // Parse the SET command
        // Format: SET [SESSION|LOCAL] name = value
        let query = query.trim();
        
        // Skip "SET " prefix
        let command_parts = if query.to_lowercase().starts_with("set session ") {
            &query[12..]
        } else if query.to_lowercase().starts_with("set local ") {
            &query[10..]
        } else {
            &query[4..]
        };
        
        let parts: Vec<&str> = command_parts.splitn(2, '=').collect();
        if parts.len() < 2 {
            return Err(ProxyError::Execution("Invalid SET command format".to_string()));
        }
        
        let var_name = parts[0].trim();
        let var_value = parts[1].trim().trim_matches('\'').trim_matches('"');
        
        // Store the variable in session vars
        if let Ok(mut vars) = self.session_vars.lock() {
            vars.insert(var_name.to_string(), var_value.to_string());
        }
        
        // Return a simple command complete message
        let mut messages = Vec::new();
        messages.push(BackendMessage::CommandComplete("SET".to_string()));
        
        Ok(Some(messages))
    }
    
    /// Handle SHOW command internally
    fn handle_show_command(&self, query: &str, metadata: &QueryMetadata) -> Result<Option<Vec<BackendMessage>>> {
        // Parse the SHOW command
        // Format: SHOW name
        let query = query.trim();
        
        // Skip "SHOW " prefix
        let var_name = &query[5..].trim();
        
        // Get the variable value from session vars
        let var_value = if let Ok(vars) = self.session_vars.lock() {
            vars.get(var_name).cloned().unwrap_or_else(|| "".to_string())
        } else {
            "".to_string()
        };
        
        let mut messages = Vec::new();
        
        // Column description
        let fields = vec![
            FieldDescription {
                name: var_name.to_string(),
                table_oid: 0,
                column_oid: 0,
                data_type_oid: 25, // TEXT
                data_type_size: -1,
                type_modifier: -1,
                format_code: 0,
            }
        ];
        
        messages.push(BackendMessage::RowDescription(fields));
        
        // Data row
        let values = vec![Some(var_value.as_bytes().to_vec())];
        messages.push(BackendMessage::DataRow(values));
        
        // Command complete
        messages.push(BackendMessage::CommandComplete("SHOW".to_string()));
        
        Ok(Some(messages))
    }
    
    /// Extract the number of rows affected from command completion messages
    fn extract_affected_rows(&self, messages: &[BackendMessage]) -> Option<u64> {
        for message in messages {
            if let BackendMessage::CommandComplete(tag) = message {
                // Parse the command completion tag to extract row count
                // Format: command count (e.g., "INSERT 0 1", "DELETE 5")
                let parts: Vec<&str> = tag.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(count) = parts.last().unwrap_or(&"0").parse::<u64>() {
                        return Some(count);
                    }
                }
            }
        }
        
        None
    }
    
    /// Set a system metadata value
    pub fn set_system_metadata(&self, key: &str, value: &str) {
        if let Ok(mut metadata) = self.system_metadata.lock() {
            metadata.insert(key.to_string(), value.to_string());
        }
    }
    
    /// Get a system metadata value
    pub fn get_system_metadata(&self, key: &str) -> Option<String> {
        if let Ok(metadata) = self.system_metadata.lock() {
            metadata.get(key).cloned()
        } else {
            None
        }
    }
    
    /// Set a session variable
    pub fn set_session_var(&self, key: &str, value: &str) {
        if let Ok(mut vars) = self.session_vars.lock() {
            vars.insert(key.to_string(), value.to_string());
        }
    }
    
    /// Get a session variable
    pub fn get_session_var(&self, key: &str) -> Option<String> {
        if let Ok(vars) = self.session_vars.lock() {
            vars.get(key).cloned()
        } else {
            None
        }
    }
    
    /// Clear all session variables
    pub fn clear_session_vars(&self) {
        if let Ok(mut vars) = self.session_vars.lock() {
            vars.clear();
        }
    }
}

/// Normalize a query for pattern matching
fn normalize_query(query: &str) -> String {
    // Remove extra whitespace
    let query = query.trim();
    
    // Convert to lowercase
    let query = query.to_lowercase();
    
    // Remove comments
    // (This is a simplified version - a real implementation would handle nested comments, etc.)
    let query = query.lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<&str>>()
        .join(" ");
    
    query
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interception::analyzer::{QueryType, AccessType, TableAccess};
    
    fn create_test_metadata(query: &str, query_type: QueryType) -> QueryMetadata {
        QueryMetadata {
            query: query.to_string(),
            query_type,
            tables: vec![
                TableAccess {
                    table_name: "users".to_string(),
                    schema_name: None,
                    access_type: AccessType::Read,
                    columns: None,
                },
            ],
            is_deterministic: true,
            non_deterministic_operations: Vec::new(),
            complexity_score: 1,
            special_handling: false,
            verifiable: true,
            cacheable: true,
            extra: HashMap::new(),
        }
    }
    
    #[test]
    fn test_create_execution_plan_normal() {
        let config = ExecutorConfig::default();
        let executor = QueryExecutor::new(config);
        
        let query = "SELECT id, name FROM users";
        let metadata = create_test_metadata(query, QueryType::Select);
        
        let plan = executor.create_execution_plan(query, &metadata).unwrap();
        
        assert_eq!(plan.plan_type, ExecutionPlanType::Normal);
        assert!(plan.modified_query.is_none());
        assert!(plan.result_messages.is_none());
    }
    
    #[test]
    fn test_handle_special_query() {
        let config = ExecutorConfig::default();
        let executor = QueryExecutor::new(config);
        
        let query = "SELECT verification_version()";
        let metadata = create_test_metadata(query, QueryType::Select);
        
        let plan = executor.create_execution_plan(query, &metadata).unwrap();
        
        assert_eq!(plan.plan_type, ExecutionPlanType::Direct);
        assert!(plan.modified_query.is_none());
        assert!(plan.result_messages.is_some());
        
        let messages = plan.result_messages.unwrap();
        assert_eq!(messages.len(), 3); // RowDescription, DataRow, CommandComplete
        
        if let BackendMessage::DataRow(values) = &messages[1] {
            assert_eq!(values.len(), 1);
            assert_eq!(std::str::from_utf8(&values[0].as_ref().unwrap()).unwrap(), "1.0.0");
        } else {
            panic!("Expected DataRow, got {:?}", messages[1]);
        }
    }
    
    #[test]
    fn test_handle_set_command() {
        let config = ExecutorConfig::default();
        let executor = QueryExecutor::new(config);
        
        let query = "SET search_path = public";
        let metadata = create_test_metadata(query, QueryType::Set);
        
        let plan = executor.create_execution_plan(query, &metadata).unwrap();
        
        assert_eq!(plan.plan_type, ExecutionPlanType::Direct);
        assert!(plan.modified_query.is_none());
        assert!(plan.result_messages.is_some());
        
        let messages = plan.result_messages.unwrap();
        assert_eq!(messages.len(), 1); // CommandComplete
        
        // Check that the variable was set
        assert_eq!(executor.get_session_var("search_path").unwrap_or_default(), "public");
    }
    
    #[test]
    fn test_handle_show_command() {
        let config = ExecutorConfig::default();
        let executor = QueryExecutor::new(config);
        
        // First, set a variable
        executor.set_session_var("search_path", "public");
        
        let query = "SHOW search_path";
        let metadata = create_test_metadata(query, QueryType::Show);
        
        let plan = executor.create_execution_plan(query, &metadata).unwrap();
        
        assert_eq!(plan.plan_type, ExecutionPlanType::Direct);
        assert!(plan.modified_query.is_none());
        assert!(plan.result_messages.is_some());
        
        let messages = plan.result_messages.unwrap();
        assert_eq!(messages.len(), 3); // RowDescription, DataRow, CommandComplete
        
        if let BackendMessage::DataRow(values) = &messages[1] {
            assert_eq!(values.len(), 1);
            assert_eq!(std::str::from_utf8(&values[0].as_ref().unwrap()).unwrap(), "public");
        } else {
            panic!("Expected DataRow, got {:?}", messages[1]);
        }
    }
    
    #[test]
    fn test_custom_handler() {
        let config = ExecutorConfig::default();
        let mut executor = QueryExecutor::new(config);
        
        // Register a custom handler
        executor.register_handler("custom_function()", Box::new(|query, metadata| {
            let mut messages = Vec::new();
            
            // Column description
            let fields = vec![
                FieldDescription {
                    name: "result".to_string(),
                    table_oid: 0,
                    column_oid: 0,
                    data_type_oid: 25, // TEXT
                    data_type_size: -1,
                    type_modifier: -1,
                    format_code: 0,
                }
            ];
            
            messages.push(BackendMessage::RowDescription(fields));
            
            // Data row
            let values = vec![Some("custom result".as_bytes().to_vec())];
            messages.push(BackendMessage::DataRow(values));
            
            // Command complete
            messages.push(BackendMessage::CommandComplete("SELECT 1".to_string()));
            
            Ok(messages)
        }));
        
        let query = "SELECT custom_function()";
        let metadata = create_test_metadata(query, QueryType::Select);
        
        let plan = executor.create_execution_plan(query, &metadata).unwrap();
        
        assert_eq!(plan.plan_type, ExecutionPlanType::Direct);
        assert!(plan.modified_query.is_none());
        assert!(plan.result_messages.is_some());
        
        let messages = plan.result_messages.unwrap();
        assert_eq!(messages.len(), 3); // RowDescription, DataRow, CommandComplete
        
        if let BackendMessage::DataRow(values) = &messages[1] {
            assert_eq!(values.len(), 1);
            assert_eq!(std::str::from_utf8(&values[0].as_ref().unwrap()).unwrap(), "custom result");
        } else {
            panic!("Expected DataRow, got {:?}", messages[1]);
        }
    }
    
    #[test]
    fn test_extract_affected_rows() {
        let config = ExecutorConfig::default();
        let executor = QueryExecutor::new(config);
        
        let messages = vec![
            BackendMessage::CommandComplete("INSERT 0 5".to_string()),
        ];
        
        let rows_affected = executor.extract_affected_rows(&messages);
        assert_eq!(rows_affected, Some(5));
        
        let messages = vec![
            BackendMessage::CommandComplete("DELETE 10".to_string()),
        ];
        
        let rows_affected = executor.extract_affected_rows(&messages);
        assert_eq!(rows_affected, Some(10));
        
        let messages = vec![
            BackendMessage::CommandComplete("SELECT 15".to_string()),
        ];
        
        let rows_affected = executor.extract_affected_rows(&messages);
        assert_eq!(rows_affected, Some(15));
    }
} 