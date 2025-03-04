//! Transaction tracker for PostgreSQL wire protocol
//! 
//! This module tracks transaction states, savepoints, and ensures
//! clean transaction boundaries for security.

use crate::error::{ProxyError, Result};
use crate::protocol::message::{FrontendMessage, BackendMessage};
use std::collections::{HashMap, HashSet};
use log::{debug, error, info, warn};

/// Transaction isolation level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    /// Read committed isolation level
    ReadCommitted,
    
    /// Repeatable read isolation level
    RepeatableRead,
    
    /// Serializable isolation level
    Serializable,
}

impl Default for IsolationLevel {
    fn default() -> Self {
        // PostgreSQL default is READ COMMITTED
        IsolationLevel::ReadCommitted
    }
}

/// Transaction access mode
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum AccessMode {
    /// Read-write transactions (default)
    ReadWrite,
    
    /// Read-only transactions
    ReadOnly,
}

impl Default for AccessMode {
    fn default() -> Self {
        // PostgreSQL default is READ WRITE
        AccessMode::ReadWrite
    }
}

/// Transaction state
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TransactionState {
    /// Not in a transaction
    Idle,
    
    /// In an active transaction
    InTransaction,
    
    /// In a failed transaction that must be rolled back
    Failed,
    
    /// In an implicit transaction (for example, from a simple query)
    Implicit,
}

impl Default for TransactionState {
    fn default() -> Self {
        TransactionState::Idle
    }
}

/// Transaction information
#[derive(Debug, Default)]
pub struct TransactionInfo {
    /// Current transaction state
    pub state: TransactionState,
    
    /// Isolation level of the current transaction
    pub isolation_level: IsolationLevel,
    
    /// Access mode of the current transaction
    pub access_mode: AccessMode,
    
    /// Whether the transaction is deferrable (only applies to serializable read-only transactions)
    pub deferrable: bool,
    
    /// Active savepoints in the transaction
    pub savepoints: HashSet<String>,
    
    /// Transaction nesting level
    pub nesting_level: u32,
    
    /// Query count within this transaction
    pub query_count: u64,
    
    /// Error encountered in the transaction, if any
    pub error: Option<String>,
}

/// Transaction tracker
#[derive(Debug, Default)]
pub struct TransactionTracker {
    /// Current transaction information
    transaction: TransactionInfo,
    
    /// Session variables
    session_vars: HashMap<String, String>,
}

impl TransactionTracker {
    /// Create a new transaction tracker
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Get the current transaction state
    pub fn get_state(&self) -> TransactionState {
        self.transaction.state
    }
    
    /// Get the current transaction info
    pub fn get_transaction_info(&self) -> &TransactionInfo {
        &self.transaction
    }
    
    /// Is the connection in a transaction?
    pub fn in_transaction(&self) -> bool {
        matches!(
            self.transaction.state,
            TransactionState::InTransaction | 
            TransactionState::Failed | 
            TransactionState::Implicit
        )
    }
    
    /// Is the transaction in a failed state?
    pub fn is_failed(&self) -> bool {
        self.transaction.state == TransactionState::Failed
    }
    
    /// Reset the transaction state to idle
    pub fn reset(&mut self) {
        self.transaction = TransactionInfo::default();
    }
    
    /// Update transaction state based on incoming query
    pub fn update_from_query(&mut self, query: &str) -> Result<()> {
        let normalized_query = query.trim().to_lowercase();
        
        // Check for BEGIN/START TRANSACTION
        if normalized_query.starts_with("begin") || normalized_query.starts_with("start transaction") {
            return self.handle_begin_transaction(query);
        }
        
        // Check for COMMIT
        if normalized_query.starts_with("commit") {
            return self.handle_commit();
        }
        
        // Check for ROLLBACK
        if normalized_query.starts_with("rollback") && !normalized_query.contains("to savepoint") {
            return self.handle_rollback();
        }
        
        // Check for SAVEPOINT
        if normalized_query.starts_with("savepoint") {
            return self.handle_savepoint(query);
        }
        
        // Check for ROLLBACK TO SAVEPOINT
        if normalized_query.starts_with("rollback to") || normalized_query.starts_with("rollback work to") {
            return self.handle_rollback_to_savepoint(query);
        }
        
        // Check for RELEASE SAVEPOINT
        if normalized_query.starts_with("release savepoint") || normalized_query.starts_with("release") {
            return self.handle_release_savepoint(query);
        }
        
        // For SET commands, track session variables
        if normalized_query.starts_with("set ") {
            return self.handle_set_command(query);
        }
        
        // For all other queries within a transaction, increment query count
        if self.in_transaction() {
            self.transaction.query_count += 1;
        } else {
            // Auto-start an implicit transaction for non-transaction control statements
            // that are not in the following categories:
            
            // Don't start implicit transaction for SET/SHOW/RESET commands
            if !normalized_query.starts_with("set ") &&
               !normalized_query.starts_with("show ") &&
               !normalized_query.starts_with("reset ") {
                
                // Don't start implicit transaction for DISCARD commands
                if !normalized_query.starts_with("discard ") {
                    
                    // Don't start for transaction for various utility commands
                    if !normalized_query.starts_with("explain ") &&
                       !normalized_query.starts_with("vacuum ") &&
                       !normalized_query.starts_with("analyze ") &&
                       !normalized_query.starts_with("cluster ") {
                        
                        debug!("Starting implicit transaction for query");
                        self.transaction.state = TransactionState::Implicit;
                        self.transaction.query_count = 1;
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Update transaction state based on command completion
    pub fn update_from_command_complete(&mut self, complete: &String) -> Result<()> {
        // Extract command tag which is the first word
        let tag_parts: Vec<&str> = complete.split_whitespace().collect();
        if tag_parts.is_empty() {
            return Ok(());
        }
        
        match tag_parts[0] {
            "BEGIN" => {
                // If we see a BEGIN complete, we're in a transaction
                self.transaction.state = TransactionState::InTransaction;
                self.transaction.query_count = 0;
                Ok(())
            },
            "COMMIT" => {
                // End transaction on commit
                self.reset();
                Ok(())
            },
            "ROLLBACK" => {
                // End transaction on rollback
                self.reset();
                Ok(())
            },
            _ => {
                // If we're in an implicit transaction, auto-commit after command completion
                if self.transaction.state == TransactionState::Implicit {
                    debug!("Auto-committing implicit transaction after command completion");
                    self.reset();
                }
                Ok(())
            }
        }
    }
    
    /// Update transaction state based on an error response
    pub fn update_from_error(&mut self, error_message: &str) {
        // If in a transaction, mark it as failed
        if self.in_transaction() {
            debug!("Transaction failed due to error: {}", error_message);
            self.transaction.state = TransactionState::Failed;
            self.transaction.error = Some(error_message.to_string());
        }
    }
    
    /// Handle BEGIN TRANSACTION command
    fn handle_begin_transaction(&mut self, query: &str) -> Result<()> {
        // Check if already in transaction
        if self.in_transaction() {
            if self.is_failed() {
                return Err(ProxyError::Transaction(
                    "Cannot begin a new transaction within a failed transaction".to_string(),
                ));
            }
            
            // In PostgreSQL, BEGIN while already in a transaction is a no-op
            debug!("BEGIN ignored - already in a transaction");
            return Ok(());
        }
        
        // Parse transaction attributes from the BEGIN command
        let lowercase_query = query.to_lowercase();
        
        // Check isolation level
        if lowercase_query.contains("isolation level read committed") {
            self.transaction.isolation_level = IsolationLevel::ReadCommitted;
        } else if lowercase_query.contains("isolation level repeatable read") {
            self.transaction.isolation_level = IsolationLevel::RepeatableRead;
        } else if lowercase_query.contains("isolation level serializable") {
            self.transaction.isolation_level = IsolationLevel::Serializable;
        } else {
            // Default isolation level
            self.transaction.isolation_level = IsolationLevel::ReadCommitted;
        }
        
        // Check access mode
        if lowercase_query.contains("read only") {
            self.transaction.access_mode = AccessMode::ReadOnly;
        } else if lowercase_query.contains("read write") {
            self.transaction.access_mode = AccessMode::ReadWrite;
        } else {
            // Default access mode
            self.transaction.access_mode = AccessMode::ReadWrite;
        }
        
        // Check deferrable (only applicable for serializable read-only transactions)
        if lowercase_query.contains("deferrable") {
            self.transaction.deferrable = true;
        } else if lowercase_query.contains("not deferrable") {
            self.transaction.deferrable = false;
        } else {
            // Default is not deferrable
            self.transaction.deferrable = false;
        }
        
        // Update transaction state
        self.transaction.state = TransactionState::InTransaction;
        self.transaction.nesting_level = 1;
        self.transaction.query_count = 0;
        self.transaction.savepoints.clear();
        self.transaction.error = None;
        
        debug!(
            "Started transaction: isolation={:?}, mode={:?}, deferrable={}",
            self.transaction.isolation_level,
            self.transaction.access_mode,
            self.transaction.deferrable
        );
        
        Ok(())
    }
    
    /// Handle COMMIT command
    fn handle_commit(&mut self) -> Result<()> {
        if !self.in_transaction() {
            // In PostgreSQL, this is a warning but not an error
            warn!("COMMIT issued but not in a transaction");
            return Ok(());
        }
        
        if self.is_failed() {
            return Err(ProxyError::Transaction(
                "Cannot commit a failed transaction. ROLLBACK required".to_string(),
            ));
        }
        
        // Will be reset when we receive the command completion
        debug!("Committing transaction");
        Ok(())
    }
    
    /// Handle ROLLBACK command
    fn handle_rollback(&mut self) -> Result<()> {
        if !self.in_transaction() {
            // In PostgreSQL, this is a warning but not an error
            warn!("ROLLBACK issued but not in a transaction");
            return Ok(());
        }
        
        // Will be reset when we receive the command completion
        debug!("Rolling back transaction");
        Ok(())
    }
    
    /// Handle SAVEPOINT command
    fn handle_savepoint(&mut self, query: &str) -> Result<()> {
        if !self.in_transaction() {
            return Err(ProxyError::Transaction(
                "Cannot create savepoint - not in a transaction".to_string(),
            ));
        }
        
        if self.is_failed() {
            return Err(ProxyError::Transaction(
                "Cannot create savepoint in a failed transaction".to_string(),
            ));
        }
        
        // Extract savepoint name
        let parts: Vec<&str> = query.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(ProxyError::Transaction(
                "Invalid SAVEPOINT command".to_string(),
            ));
        }
        
        let savepoint_name = parts[1].trim().to_string();
        self.transaction.savepoints.insert(savepoint_name.clone());
        debug!("Created savepoint: {}", savepoint_name);
        
        Ok(())
    }
    
    /// Handle ROLLBACK TO SAVEPOINT command
    fn handle_rollback_to_savepoint(&mut self, query: &str) -> Result<()> {
        if !self.in_transaction() {
            return Err(ProxyError::Transaction(
                "Cannot rollback to savepoint - not in a transaction".to_string(),
            ));
        }
        
        // Extract savepoint name
        // Format is "ROLLBACK TO [SAVEPOINT] name"
        let parts: Vec<&str> = query.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(ProxyError::Transaction(
                "Invalid ROLLBACK TO SAVEPOINT command".to_string(),
            ));
        }
        
        let savepoint_idx = if parts[2].to_lowercase() == "savepoint" { 3 } else { 2 };
        if parts.len() <= savepoint_idx {
            return Err(ProxyError::Transaction(
                "Savepoint name missing".to_string(),
            ));
        }
        
        let savepoint_name = parts[savepoint_idx].trim().to_string();
        
        // Check if savepoint exists
        if !self.transaction.savepoints.contains(&savepoint_name) {
            return Err(ProxyError::Transaction(
                format!("Savepoint {} does not exist", savepoint_name),
            ));
        }
        
        // When rolling back to a savepoint in a failed transaction, clear the error state
        if self.is_failed() {
            debug!("Rolling back to savepoint {} in failed transaction", savepoint_name);
            self.transaction.state = TransactionState::InTransaction;
            self.transaction.error = None;
        }
        
        debug!("Rolled back to savepoint: {}", savepoint_name);
        Ok(())
    }
    
    /// Handle RELEASE SAVEPOINT command
    fn handle_release_savepoint(&mut self, query: &str) -> Result<()> {
        if !self.in_transaction() {
            return Err(ProxyError::Transaction(
                "Cannot release savepoint - not in a transaction".to_string(),
            ));
        }
        
        if self.is_failed() {
            return Err(ProxyError::Transaction(
                "Cannot release savepoint in a failed transaction".to_string(),
            ));
        }
        
        // Extract savepoint name
        // Format is "RELEASE [SAVEPOINT] name"
        let parts: Vec<&str> = query.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(ProxyError::Transaction(
                "Invalid RELEASE SAVEPOINT command".to_string(),
            ));
        }
        
        let savepoint_idx = if parts[1].to_lowercase() == "savepoint" { 2 } else { 1 };
        if parts.len() <= savepoint_idx {
            return Err(ProxyError::Transaction(
                "Savepoint name missing".to_string(),
            ));
        }
        
        let savepoint_name = parts[savepoint_idx].trim().to_string();
        
        // Check if savepoint exists
        if !self.transaction.savepoints.contains(&savepoint_name) {
            return Err(ProxyError::Transaction(
                format!("Savepoint {} does not exist", savepoint_name),
            ));
        }
        
        // Remove the savepoint
        self.transaction.savepoints.remove(&savepoint_name);
        debug!("Released savepoint: {}", savepoint_name);
        
        Ok(())
    }
    
    /// Handle SET command
    fn handle_set_command(&mut self, query: &str) -> Result<()> {
        // Format is "SET [SESSION|LOCAL] name TO|= value"
        let parts: Vec<&str> = query.split_whitespace().collect();
        if parts.len() < 3 {
            return Ok(());  // Invalid SET command, but let the database handle it
        }
        
        let mut var_name_idx = 1;
        
        // Skip SESSION|LOCAL if present
        if parts[1].to_lowercase() == "session" || parts[1].to_lowercase() == "local" {
            var_name_idx = 2;
        }
        
        if parts.len() <= var_name_idx {
            return Ok(());  // Invalid SET command, but let the database handle it
        }
        
        let var_name = parts[var_name_idx].to_lowercase();
        
        // Find the "TO" or "=" part
        let mut value_idx = 0;
        for i in (var_name_idx + 1)..parts.len() {
            if parts[i].to_lowercase() == "to" || parts[i] == "=" {
                value_idx = i + 1;
                break;
            }
        }
        
        if value_idx == 0 || value_idx >= parts.len() {
            return Ok(());  // Invalid SET command, but let the database handle it
        }
        
        // Join the remaining parts as the value
        let value = parts[value_idx..].join(" ");
        
        // Clean up value (remove quotes if present)
        let clean_value = value
            .trim()
            .trim_matches('\'')
            .trim_matches('"')
            .to_string();
        
        debug!("Setting session variable: {} = {}", var_name, clean_value);
        self.session_vars.insert(var_name.clone(), clean_value);
        
        // Handle special transaction-related variables
        if var_name == "transaction_isolation" {
            match self.session_vars.get("transaction_isolation") {
                Some(value) if value == "read committed" => {
                    self.transaction.isolation_level = IsolationLevel::ReadCommitted;
                }
                Some(value) if value == "repeatable read" => {
                    self.transaction.isolation_level = IsolationLevel::RepeatableRead;
                }
                Some(value) if value == "serializable" => {
                    self.transaction.isolation_level = IsolationLevel::Serializable;
                }
                _ => {} // Ignore other values
            }
        } else if var_name == "transaction_read_only" {
            match self.session_vars.get("transaction_read_only").map(|s| s.as_str()) {
                Some("on") | Some("true") | Some("yes") => {
                    self.transaction.access_mode = AccessMode::ReadOnly;
                }
                Some("off") | Some("false") | Some("no") => {
                    self.transaction.access_mode = AccessMode::ReadWrite;
                }
                _ => {} // Ignore other values
            }
        }
        
        Ok(())
    }
    
    /// Get a session variable value
    pub fn get_session_var(&self, name: &str) -> Option<&String> {
        self.session_vars.get(&name.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_transaction_begin_commit() {
        let mut tracker = TransactionTracker::new();
        
        // Check initial state
        assert_eq!(tracker.get_state(), TransactionState::Idle);
        assert!(!tracker.in_transaction());
        
        // Begin transaction
        tracker.update_from_query("BEGIN TRANSACTION").unwrap();
        assert_eq!(tracker.get_state(), TransactionState::InTransaction);
        assert!(tracker.in_transaction());
        
        // Simulate command completion
        tracker.update_from_command_complete(&"BEGIN".to_string()).unwrap();
        
        // Run a query in the transaction
        tracker.update_from_query("SELECT * FROM users").unwrap();
        assert_eq!(tracker.get_transaction_info().query_count, 1);
        
        // Commit transaction
        tracker.update_from_query("COMMIT").unwrap();
        
        // Simulate command completion
        tracker.update_from_command_complete(&"COMMIT".to_string()).unwrap();
        
        // Check state after commit
        assert_eq!(tracker.get_state(), TransactionState::Idle);
        assert!(!tracker.in_transaction());
        assert_eq!(tracker.get_transaction_info().query_count, 0);
    }
    
    #[test]
    fn test_transaction_isolation_levels() {
        let mut tracker = TransactionTracker::new();
        
        // Begin with READ COMMITTED
        tracker.update_from_query("BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED").unwrap();
        assert_eq!(tracker.get_transaction_info().isolation_level, IsolationLevel::ReadCommitted);
        tracker.reset();
        
        // Begin with REPEATABLE READ
        tracker.update_from_query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ").unwrap();
        assert_eq!(tracker.get_transaction_info().isolation_level, IsolationLevel::RepeatableRead);
        tracker.reset();
        
        // Begin with SERIALIZABLE
        tracker.update_from_query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE").unwrap();
        assert_eq!(tracker.get_transaction_info().isolation_level, IsolationLevel::Serializable);
        tracker.reset();
    }
    
    #[test]
    fn test_transaction_access_modes() {
        let mut tracker = TransactionTracker::new();
        
        // Begin with READ ONLY
        tracker.update_from_query("BEGIN TRANSACTION READ ONLY").unwrap();
        assert_eq!(tracker.get_transaction_info().access_mode, AccessMode::ReadOnly);
        tracker.reset();
        
        // Begin with READ WRITE
        tracker.update_from_query("BEGIN TRANSACTION READ WRITE").unwrap();
        assert_eq!(tracker.get_transaction_info().access_mode, AccessMode::ReadWrite);
        tracker.reset();
    }
    
    #[test]
    fn test_transaction_savepoints() {
        let mut tracker = TransactionTracker::new();
        
        // Begin transaction
        tracker.update_from_query("BEGIN").unwrap();
        
        // Create savepoint
        tracker.update_from_query("SAVEPOINT my_savepoint").unwrap();
        assert!(tracker.get_transaction_info().savepoints.contains("my_savepoint"));
        
        // Rollback to savepoint
        tracker.update_from_query("ROLLBACK TO SAVEPOINT my_savepoint").unwrap();
        assert!(tracker.get_transaction_info().savepoints.contains("my_savepoint"));
        
        // Release savepoint
        tracker.update_from_query("RELEASE SAVEPOINT my_savepoint").unwrap();
        assert!(!tracker.get_transaction_info().savepoints.contains("my_savepoint"));
    }
    
    #[test]
    fn test_transaction_failure() {
        let mut tracker = TransactionTracker::new();
        
        // Begin transaction
        tracker.update_from_query("BEGIN").unwrap();
        
        // Simulate error
        tracker.update_from_error("ERROR: division by zero");
        assert_eq!(tracker.get_state(), TransactionState::Failed);
        
        // Try to commit failed transaction
        let result = tracker.update_from_query("COMMIT");
        assert!(result.is_err());
        
        // Rollback transaction
        tracker.update_from_query("ROLLBACK").unwrap();
        
        // Simulate command completion
        tracker.update_from_command_complete(&"ROLLBACK".to_string()).unwrap();
        
        // Check state after rollback
        assert_eq!(tracker.get_state(), TransactionState::Idle);
    }
    
    #[test]
    fn test_implicit_transactions() {
        let mut tracker = TransactionTracker::new();
        
        // Execute a query without explicit transaction
        tracker.update_from_query("SELECT * FROM users").unwrap();
        assert_eq!(tracker.get_state(), TransactionState::Implicit);
        
        // Simulate command completion which should auto-commit
        tracker.update_from_command_complete(&"SELECT 5".to_string()).unwrap();
        
        // Check state after auto-commit
        assert_eq!(tracker.get_state(), TransactionState::Idle);
    }
    
    #[test]
    fn test_session_variables() {
        let mut tracker = TransactionTracker::new();
        
        // Set a session variable
        tracker.update_from_query("SET search_path TO public, myschema").unwrap();
        assert_eq!(tracker.get_session_var("search_path"), Some(&"public, myschema".to_string()));
        
        // Set isolation level
        tracker.update_from_query("SET transaction_isolation TO 'serializable'").unwrap();
        assert_eq!(tracker.get_transaction_info().isolation_level, IsolationLevel::Serializable);
        
        // Set read-only mode
        tracker.update_from_query("SET transaction_read_only = on").unwrap();
        assert_eq!(tracker.get_transaction_info().access_mode, AccessMode::ReadOnly);
    }
} 