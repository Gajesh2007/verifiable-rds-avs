//! PostgreSQL wire protocol implementation
//!
//! This module provides functionality for parsing and formatting PostgreSQL 
//! wire protocol messages, as well as managing connections, transactions, and security.

/// Message types for the PostgreSQL wire protocol
pub mod message;

/// Authentication handler for PostgreSQL clients
pub mod auth;

/// Message parser for PostgreSQL wire protocol messages
pub mod parser;

/// Message formatter for PostgreSQL wire protocol responses
pub mod formatter;

/// Connection manager for client connections
pub mod connection;

/// Protocol validator for PostgreSQL protocol correctness
pub mod validator;

/// Transaction manager for PostgreSQL transactions
pub mod transaction;

// Re-export common types
pub use self::message::{FrontendMessage, BackendMessage, AuthenticationRequest};
pub use self::parser::MessageParser;
pub use self::formatter::MessageFormatter;
pub use self::connection::{ClientConnection, ConnectionState, ConnectionStats};
pub use self::auth::{AuthHandler, AuthState, AuthMethod, AuthConfig};
pub use self::transaction::{TransactionTracker, TransactionState, IsolationLevel, AccessMode};
pub use self::validator::{ProtocolValidator, ProtocolValidatorConfig}; 