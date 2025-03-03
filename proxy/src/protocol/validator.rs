//! Protocol validator for PostgreSQL wire protocol
//! 
//! This module provides validation of PostgreSQL protocol state transitions
//! to ensure security and prevent protocol exploitation attacks.

use crate::error::{ProxyError, Result};
use crate::protocol::connection::ConnectionState;
use crate::protocol::message::{FrontendMessage, BackendMessage, TransactionStatus};
use std::collections::HashMap;
use log::{debug, warn};

/// Protocol validator for PostgreSQL wire protocol
#[derive(Debug, Default)]
pub struct ProtocolValidator {
    /// Permitted message types in each connection state
    permitted_messages: HashMap<ConnectionState, Vec<PermittedMessageType>>,
    
    /// Current sequence counter (for detecting duplicate messages)
    sequence_counter: u64,
    
    /// Last received message type
    last_message_type: Option<String>,
    
    /// Configuration for protocol validation
    config: ProtocolValidatorConfig,
}

/// Configuration for protocol validation
#[derive(Debug, Clone)]
pub struct ProtocolValidatorConfig {
    /// Whether to enforce strict protocol validation
    pub strict_mode: bool,
    
    /// Maximum allowed query length
    pub max_query_length: usize,
    
    /// Maximum allowed parameter size
    pub max_parameter_size: usize,
    
    /// Allowed authentication methods
    pub allowed_auth_methods: Vec<String>,
    
    /// Whether to allow unknown message types
    pub allow_unknown_messages: bool,
}

impl Default for ProtocolValidatorConfig {
    fn default() -> Self {
        Self {
            strict_mode: true,
            max_query_length: 1_000_000, // 1MB
            max_parameter_size: 100_000, // 100KB
            allowed_auth_methods: vec![
                "md5".to_string(),
                "scram-sha-256".to_string(),
            ],
            allow_unknown_messages: false,
        }
    }
}

/// Permitted message type
#[derive(Debug, Clone, PartialEq)]
enum PermittedMessageType {
    /// Message type for startup phase
    Startup(u8),
    
    /// Message type for specific tag
    Specific(u8),
    
    /// Message type for query related commands
    Query,
    
    /// Message type for extended protocol
    Extended,
    
    /// Any message type (permissive)
    Any,
}

impl ProtocolValidator {
    /// Create a new protocol validator
    pub fn new(config: ProtocolValidatorConfig) -> Self {
        let mut validator = Self {
            permitted_messages: HashMap::new(),
            sequence_counter: 0,
            last_message_type: None,
            config,
        };
        
        // Initialize permitted message types for each connection state
        validator.initialize_permitted_messages();
        
        validator
    }
    
    /// Initialize the permitted message types for each connection state
    fn initialize_permitted_messages(&mut self) {
        // Initial state permits startup message, cancel request, and SSL request
        self.permitted_messages.insert(
            ConnectionState::Initial,
            vec![
                PermittedMessageType::Startup(0),   // Startup
                PermittedMessageType::Specific(b'X'), // Terminate
            ],
        );
        
        // Authenticating state permits password, SASL responses, and terminate
        self.permitted_messages.insert(
            ConnectionState::Authenticating,
            vec![
                PermittedMessageType::Specific(b'p'), // Password
                PermittedMessageType::Specific(b'X'), // Terminate
            ],
        );
        
        // Ready state permits queries, extended protocol, and terminate
        self.permitted_messages.insert(
            ConnectionState::Ready,
            vec![
                PermittedMessageType::Specific(b'Q'), // Simple query
                PermittedMessageType::Specific(b'P'), // Parse
                PermittedMessageType::Specific(b'B'), // Bind
                PermittedMessageType::Specific(b'E'), // Execute
                PermittedMessageType::Specific(b'D'), // Describe
                PermittedMessageType::Specific(b'S'), // Sync
                PermittedMessageType::Specific(b'H'), // Flush
                PermittedMessageType::Specific(b'C'), // Close
                PermittedMessageType::Specific(b'X'), // Terminate
            ],
        );
        
        // InTransaction state permits the same messages as Ready
        self.permitted_messages.insert(
            ConnectionState::InTransaction,
            vec![
                PermittedMessageType::Specific(b'Q'), // Simple query
                PermittedMessageType::Specific(b'P'), // Parse
                PermittedMessageType::Specific(b'B'), // Bind
                PermittedMessageType::Specific(b'E'), // Execute
                PermittedMessageType::Specific(b'D'), // Describe
                PermittedMessageType::Specific(b'S'), // Sync
                PermittedMessageType::Specific(b'H'), // Flush
                PermittedMessageType::Specific(b'C'), // Close
                PermittedMessageType::Specific(b'X'), // Terminate
            ],
        );
        
        // InFailedTransaction state permits sync, rollback via query, and terminate
        self.permitted_messages.insert(
            ConnectionState::InFailedTransaction,
            vec![
                PermittedMessageType::Specific(b'Q'), // Simple query (for ROLLBACK)
                PermittedMessageType::Specific(b'S'), // Sync
                PermittedMessageType::Specific(b'X'), // Terminate
            ],
        );
        
        // Closing state only permits terminate
        self.permitted_messages.insert(
            ConnectionState::Closing,
            vec![
                PermittedMessageType::Specific(b'X'), // Terminate
            ],
        );
        
        // Closed state doesn't permit any messages
        self.permitted_messages.insert(
            ConnectionState::Closed,
            vec![],
        );
    }
    
    /// Validate a frontend message in the current connection state
    pub fn validate_frontend_message(
        &mut self,
        message: &FrontendMessage,
        state: &ConnectionState,
    ) -> Result<()> {
        // Increment sequence counter
        self.sequence_counter += 1;
        
        // Get permitted message types for the current state
        let permitted = self.permitted_messages.get(state).ok_or_else(|| {
            ProxyError::Protocol(format!("Unknown connection state: {:?}", state))
        })?;
        
        // Check message type against permitted types
        let is_permitted = match message {
            FrontendMessage::Startup { .. } => {
                permitted.contains(&PermittedMessageType::Startup(0))
            }
            FrontendMessage::SSLRequest => {
                permitted.contains(&PermittedMessageType::Startup(0))
            }
            FrontendMessage::CancelRequest { .. } => {
                permitted.contains(&PermittedMessageType::Startup(0))
            }
            FrontendMessage::Password(_) => {
                permitted.contains(&PermittedMessageType::Specific(b'p'))
            }
            FrontendMessage::Query(query) => {
                // Validate query length
                if query.len() > self.config.max_query_length {
                    return Err(ProxyError::Protocol(format!(
                        "Query exceeds maximum length: {} > {}",
                        query.len(),
                        self.config.max_query_length
                    )));
                }
                
                // If in failed transaction, only allow ROLLBACK
                if *state == ConnectionState::InFailedTransaction {
                    let query_upper = query.to_uppercase();
                    if !query_upper.contains("ROLLBACK") && !query_upper.contains("ABORT") {
                        return Err(ProxyError::Protocol(
                            "Only ROLLBACK is allowed in a failed transaction".to_string()
                        ));
                    }
                }
                
                permitted.contains(&PermittedMessageType::Specific(b'Q'))
            }
            FrontendMessage::Parse { query, .. } => {
                // Validate query length
                if query.len() > self.config.max_query_length {
                    return Err(ProxyError::Protocol(format!(
                        "Query exceeds maximum length: {} > {}",
                        query.len(),
                        self.config.max_query_length
                    )));
                }
                
                permitted.contains(&PermittedMessageType::Specific(b'P'))
            }
            FrontendMessage::Bind { param_values, .. } => {
                // Validate parameter sizes
                for param in param_values {
                    if let Some(value) = param {
                        if value.len() > self.config.max_parameter_size {
                            return Err(ProxyError::Protocol(format!(
                                "Parameter exceeds maximum size: {} > {}",
                                value.len(),
                                self.config.max_parameter_size
                            )));
                        }
                    }
                }
                
                permitted.contains(&PermittedMessageType::Specific(b'B'))
            }
            FrontendMessage::Execute { .. } => {
                permitted.contains(&PermittedMessageType::Specific(b'E'))
            }
            FrontendMessage::Describe { .. } => {
                permitted.contains(&PermittedMessageType::Specific(b'D'))
            }
            FrontendMessage::Sync => {
                permitted.contains(&PermittedMessageType::Specific(b'S'))
            }
            FrontendMessage::Flush => {
                permitted.contains(&PermittedMessageType::Specific(b'H'))
            }
            FrontendMessage::Close { .. } => {
                permitted.contains(&PermittedMessageType::Specific(b'C'))
            }
            FrontendMessage::Terminate => {
                permitted.contains(&PermittedMessageType::Specific(b'X'))
            }
            FrontendMessage::CopyData(_) => {
                // Copy operations have their own sub-protocol
                permitted.contains(&PermittedMessageType::Specific(b'd'))
            }
            FrontendMessage::CopyDone => {
                permitted.contains(&PermittedMessageType::Specific(b'c'))
            }
            FrontendMessage::CopyFail(_) => {
                permitted.contains(&PermittedMessageType::Specific(b'f'))
            }
            FrontendMessage::FunctionCall { .. } => {
                permitted.contains(&PermittedMessageType::Specific(b'F'))
            }
            FrontendMessage::Unknown { tag, .. } => {
                if !self.config.allow_unknown_messages {
                    return Err(ProxyError::Protocol(format!(
                        "Unknown message type: {:?}",
                        tag
                    )));
                }
                true
            }
        };
        
        // Update last message type
        self.last_message_type = Some(format!("{:?}", message));
        
        // If not permitted, return an error
        if !is_permitted {
            return Err(ProxyError::Protocol(format!(
                "Message {:?} not permitted in state {:?}",
                message, state
            )));
        }
        
        Ok(())
    }
    
    /// Validate a backend message in the current connection state
    pub fn validate_backend_message(
        &mut self,
        message: &BackendMessage,
        state: &ConnectionState,
    ) -> Result<()> {
        // Primary purpose here is to detect suspicious backend behavior
        // like returning authentication success without a password message
        
        // For now, just basic validation based on current state
        match (message, state) {
            (BackendMessage::Authentication(_), ConnectionState::Initial) => {
                // Valid: Initial -> Authentication
                Ok(())
            }
            (BackendMessage::Authentication(_), ConnectionState::Authenticating) => {
                // Valid: multiple auth messages during auth phase
                Ok(())
            }
            (BackendMessage::ErrorResponse(_), _) => {
                // Error responses can happen in any state
                Ok(())
            }
            (BackendMessage::ReadyForQuery(_), _) => {
                // ReadyForQuery can generally happen in any state except Initial
                if *state == ConnectionState::Initial {
                    return Err(ProxyError::Protocol(
                        "ReadyForQuery not expected in Initial state".to_string()
                    ));
                }
                Ok(())
            }
            _ => {
                // For backend messages, we're less strict to allow for implementation variations
                Ok(())
            }
        }
    }
    
    /// Update validator based on transaction status
    pub fn update_transaction_status(&mut self, status: TransactionStatus) {
        // This is mainly for tracking purposes
        debug!("Transaction status updated: {:?}", status);
    }
    
    /// Reset the validator state
    pub fn reset(&mut self) {
        self.sequence_counter = 0;
        self.last_message_type = None;
        debug!("Protocol validator reset");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::message::TransactionStatus;
    
    #[test]
    fn test_validate_startup_sequence() {
        let config = ProtocolValidatorConfig::default();
        let mut validator = ProtocolValidator::new(config);
        
        // Startup message in Initial state should be valid
        let startup_msg = FrontendMessage::Startup {
            version_major: 3,
            version_minor: 0,
            parameters: [
                ("user".to_string(), "postgres".to_string()),
                ("database".to_string(), "postgres".to_string()),
            ].iter().cloned().collect(),
        };
        
        assert!(validator.validate_frontend_message(&startup_msg, &ConnectionState::Initial).is_ok());
        
        // Password message in Authenticating state should be valid
        let password_msg = FrontendMessage::Password("password123".to_string());
        assert!(validator.validate_frontend_message(&password_msg, &ConnectionState::Authenticating).is_ok());
        
        // Query in Ready state should be valid
        let query_msg = FrontendMessage::Query("SELECT 1".to_string());
        assert!(validator.validate_frontend_message(&query_msg, &ConnectionState::Ready).is_ok());
        
        // Terminate in any state should be valid
        let terminate_msg = FrontendMessage::Terminate;
        assert!(validator.validate_frontend_message(&terminate_msg, &ConnectionState::Ready).is_ok());
        assert!(validator.validate_frontend_message(&terminate_msg, &ConnectionState::Authenticating).is_ok());
    }
    
    #[test]
    fn test_invalid_message_for_state() {
        let config = ProtocolValidatorConfig::default();
        let mut validator = ProtocolValidator::new(config);
        
        // Query in Initial state should be invalid
        let query_msg = FrontendMessage::Query("SELECT 1".to_string());
        assert!(validator.validate_frontend_message(&query_msg, &ConnectionState::Initial).is_err());
        
        // Parse in Authenticating state should be invalid
        let parse_msg = FrontendMessage::Parse {
            name: "".to_string(),
            query: "SELECT 1".to_string(),
            param_types: vec![],
        };
        assert!(validator.validate_frontend_message(&parse_msg, &ConnectionState::Authenticating).is_err());
        
        // Password in Ready state should be invalid
        let password_msg = FrontendMessage::Password("password123".to_string());
        assert!(validator.validate_frontend_message(&password_msg, &ConnectionState::Ready).is_err());
    }
    
    #[test]
    fn test_query_length_validation() {
        let mut config = ProtocolValidatorConfig::default();
        config.max_query_length = 10;
        let mut validator = ProtocolValidator::new(config);
        
        // Short query should be valid
        let short_query_msg = FrontendMessage::Query("SELECT 1".to_string());
        assert!(validator.validate_frontend_message(&short_query_msg, &ConnectionState::Ready).is_ok());
        
        // Long query should be invalid
        let long_query_msg = FrontendMessage::Query("SELECT * FROM really_long_table_name WHERE column_a > 100".to_string());
        assert!(validator.validate_frontend_message(&long_query_msg, &ConnectionState::Ready).is_err());
    }
    
    #[test]
    fn test_failed_transaction_restrictions() {
        let config = ProtocolValidatorConfig::default();
        let mut validator = ProtocolValidator::new(config);
        
        // ROLLBACK should be valid in failed transaction
        let rollback_msg = FrontendMessage::Query("ROLLBACK".to_string());
        assert!(validator.validate_frontend_message(&rollback_msg, &ConnectionState::InFailedTransaction).is_ok());
        
        // Other queries should be invalid in failed transaction
        let query_msg = FrontendMessage::Query("SELECT 1".to_string());
        assert!(validator.validate_frontend_message(&query_msg, &ConnectionState::InFailedTransaction).is_err());
    }
} 