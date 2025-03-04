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
#[derive(Debug, Default, Clone)]
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
    Specific(char),
    
    /// Message type for query related commands
    Query,
    
    /// Message type for extended protocol
    Extended,
    
    /// Any message type (permissive)
    Any,
}

impl ProtocolValidator {
    /// Create a new protocol validator with the given configuration
    pub fn new(config: ProtocolValidatorConfig) -> Self {
        Self {
            permitted_messages: ProtocolValidator::initialize_permitted_messages(),
            sequence_counter: 0,
            last_message_type: None,
            config,
        }
    }
    
    /// Validate a frontend message against the current connection state
    pub fn validate_message(&self, message: &FrontendMessage, state: ConnectionState) -> Result<()> {
        // Simple implementation for now
        debug!("Validating message: {:?} in state {:?}", message, state);
        
        // Check if the message type is permitted in the current state
        let message_type = self.get_message_type(message);
        
        let permitted = match self.permitted_messages.get(&state) {
            Some(permitted_types) => {
                permitted_types.iter().any(|permitted_type| match permitted_type {
                    PermittedMessageType::Any => true,
                    PermittedMessageType::Specific(c) => message_type.starts_with(&c.to_string()),
                    PermittedMessageType::Query => message_type == "Query",
                    PermittedMessageType::Extended => {
                        matches!(message_type, "Parse" | "Bind" | "Execute" | "Describe" | "Sync" | "Flush")
                    },
                    PermittedMessageType::Startup(_) => {
                        // Special case for startup message
                        matches!(message, FrontendMessage::Startup { .. })
                    },
                })
            },
            None => false,
        };
        
        if !permitted {
            return Err(ProxyError::Protocol(format!(
                "Message type {:?} not permitted in state {:?}",
                message_type, state
            )));
        }
        
        Ok(())
    }
    
    // Helper method to get the message type
    fn get_message_type(&self, message: &FrontendMessage) -> &'static str {
        match message {
            FrontendMessage::Startup { .. } => "Startup",
            FrontendMessage::Password(_) => "Password",
            FrontendMessage::Query(_) => "Query",
            FrontendMessage::Parse { .. } => "Parse",
            FrontendMessage::Bind { .. } => "Bind",
            FrontendMessage::Execute { .. } => "Execute",
            FrontendMessage::Describe { .. } => "Describe",
            FrontendMessage::Sync => "Sync",
            FrontendMessage::Flush => "Flush",
            FrontendMessage::Close { .. } => "Close",
            FrontendMessage::Terminate => "X",
            _ => "Unknown",
        }
    }
    
    // Initialize permitted messages for different states
    fn initialize_permitted_messages() -> HashMap<ConnectionState, Vec<PermittedMessageType>> {
        let mut permitted_messages = HashMap::new();
        
        // Initial state permits only startup
        permitted_messages.insert(
            ConnectionState::Initial,
            vec![
                PermittedMessageType::Specific('S'), // 'S' for Startup
                PermittedMessageType::Startup(0),    // 0 for Startup message (doesn't have a message type tag)
                PermittedMessageType::Specific('X'), // 'X' for Terminate - allowed in all states
            ],
        );
        
        // Authenticating state permits only password
        permitted_messages.insert(
            ConnectionState::Authenticating,
            vec![
                PermittedMessageType::Specific('P'), // 'P' for Password
                PermittedMessageType::Specific('p'), // 'p' for lowercase password (client can use either)
                PermittedMessageType::Specific('X'), // 'X' for Terminate - allowed in all states
            ],
        );
        
        // Ready state permits most messages
        permitted_messages.insert(
            ConnectionState::Ready,
            vec![
                PermittedMessageType::Query,
                PermittedMessageType::Extended,
                PermittedMessageType::Specific('X'), // 'X' for Terminate
            ],
        );
        
        // InTransaction state permits most messages
        permitted_messages.insert(
            ConnectionState::InTransaction,
            vec![
                PermittedMessageType::Query,
                PermittedMessageType::Extended,
                PermittedMessageType::Specific('X'), // 'X' for Terminate
            ],
        );
        
        // InFailedTransaction state permits most messages
        permitted_messages.insert(
            ConnectionState::InFailedTransaction,
            vec![
                PermittedMessageType::Query,
                PermittedMessageType::Extended,
                PermittedMessageType::Specific('X'), // 'X' for Terminate
            ],
        );
        
        // Closing state permits only terminate
        permitted_messages.insert(
            ConnectionState::Closing,
            vec![PermittedMessageType::Specific('X')], // 'X' for Terminate
        );
        
        permitted_messages
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
                permitted.contains(&PermittedMessageType::Specific('p'))
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
                
                permitted.contains(&PermittedMessageType::Query)
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
                
                permitted.contains(&PermittedMessageType::Extended)
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
                
                permitted.contains(&PermittedMessageType::Extended)
            }
            FrontendMessage::Execute { .. } => {
                permitted.contains(&PermittedMessageType::Extended)
            }
            FrontendMessage::Describe { .. } => {
                permitted.contains(&PermittedMessageType::Extended)
            }
            FrontendMessage::Sync => {
                permitted.contains(&PermittedMessageType::Extended)
            }
            FrontendMessage::Flush => {
                permitted.contains(&PermittedMessageType::Extended)
            }
            FrontendMessage::Close { .. } => {
                permitted.contains(&PermittedMessageType::Extended)
            }
            FrontendMessage::Terminate => {
                permitted.contains(&PermittedMessageType::Specific('X'))
            }
            FrontendMessage::CopyData(_) => {
                // Copy operations have their own sub-protocol
                permitted.contains(&PermittedMessageType::Extended)
            }
            FrontendMessage::CopyDone => {
                permitted.contains(&PermittedMessageType::Extended)
            }
            FrontendMessage::CopyFail(_) => {
                permitted.contains(&PermittedMessageType::Extended)
            }
            FrontendMessage::FunctionCall { .. } => {
                permitted.contains(&PermittedMessageType::Extended)
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