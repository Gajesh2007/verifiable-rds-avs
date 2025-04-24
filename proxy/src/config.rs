//! Configuration for the proxy server
//!
//! This module provides configuration options for the PostgreSQL proxy server.

use crate::protocol::auth::AuthConfig;
use crate::protocol::validator::ProtocolValidatorConfig;
use crate::interception::analyzer::QueryAnalyzer;
use crate::interception::rewrite::RewriterConfig;
use crate::interception::execution::ExecutorConfig;
use crate::interception::verification::VerificationConfig;
use crate::security::RateLimiterConfig;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Proxy configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Listening address for the proxy
    pub listen_addr: SocketAddr,
    
    /// Backend server address
    pub backend_addr: SocketAddr,
    
    /// TLS configuration
    pub tls_config: Option<TlsConfig>,
    
    /// Authentication configuration
    pub auth_config: AuthConfig,
    
    /// Protocol validator configuration
    pub validator_config: ProtocolValidatorConfig,
    
    /// Query rewriter configuration
    pub rewriter_config: RewriterConfig,
    
    /// Query executor configuration
    pub executor_config: ExecutorConfig,
    
    /// Verification configuration
    pub verification_config: VerificationConfig,
    
    /// Rate limiter configuration
    pub rate_limiter_config: RateLimiterConfig,
    
    /// Maximum query length in bytes
    pub max_query_length: usize,
    
    /// Whether to enable transaction boundary protection
    pub transaction_boundary_protection: bool,
    
    /// Rate limit (requests per minute)
    pub rate_limit: u32,
    
    /// Connection timeout
    pub connection_timeout: u64,
    
    /// Maximum number of connections
    pub max_connections: usize,
    
    /// Whether to log queries
    pub log_queries: bool,
    
    /// Log level
    pub log_level: String,
    
    /// Log file
    pub log_file: Option<PathBuf>,
    
    /// Whether to enable metrics
    pub enable_metrics: bool,
    
    /// Metrics address
    pub metrics_addr: Option<SocketAddr>,
    
    /// Message timeout in seconds
    pub message_timeout: u64,
    
    /// Database user
    pub db_user: Option<String>,
    
    /// Database password
    pub db_password: Option<String>,
    
    /// Database name
    pub db_name: Option<String>,
    
    // WAL Listener Configuration
    /// Optional connection string for logical replication
    pub replication_connection_string: Option<String>,
    /// Optional logical replication slot name
    pub replication_slot_name: Option<String>,
}

/// TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_file: PathBuf,
    
    /// Path to key file
    pub key_file: PathBuf,
    
    /// Whether to require client certificates
    pub require_client_certs: bool,
    
    /// Path to CA certificate file
    pub ca_file: Option<PathBuf>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:5432".parse().unwrap(),
            backend_addr: "127.0.0.1:5433".parse().unwrap(),
            tls_config: None,
            auth_config: AuthConfig::default(),
            validator_config: ProtocolValidatorConfig::default(),
            rewriter_config: RewriterConfig::default(),
            executor_config: ExecutorConfig::default(),
            verification_config: VerificationConfig::default(),
            rate_limiter_config: RateLimiterConfig::default(),
            max_query_length: 8192,
            transaction_boundary_protection: true,
            rate_limit: 0,
            connection_timeout: 30,
            max_connections: 100,
            log_queries: true,
            log_level: "info".to_string(),
            log_file: None,
            enable_metrics: false,
            metrics_addr: None,
            message_timeout: 0,
            db_user: None,
            db_password: None,
            db_name: None,
            // Default WAL listener config to None
            replication_connection_string: None,
            replication_slot_name: None,
        }
    }
}

impl ProxyConfig {
    /// Create a new proxy configuration with default values
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Load configuration from a file
    pub fn from_file(path: &str) -> std::io::Result<Self> {
        // This would load from a file in a real implementation
        // For now, just return the default
        Ok(Self::default())
    }
    
    /// Create a configuration for local development
    pub fn for_development() -> Self {
        Self {
            listen_addr: "127.0.0.1:5432".parse().unwrap(),
            backend_addr: "127.0.0.1:5433".parse().unwrap(),
            // Enable all verification features in development
            verification_config: VerificationConfig {
                enabled: true,
                enforce: false, // Don't enforce in development
                ..Default::default()
            },
            // Enable query logging in development
            log_queries: true,
            log_level: "debug".to_string(),
            // Enable rate limiting in development
            rate_limiter_config: RateLimiterConfig {
                enabled: true,
                rate_limit: 1000, // 1000 requests per minute
                allow_list: vec!["127.0.0.1".parse().unwrap()], // Allow localhost
                block_list: vec![],
            },
            ..Default::default()
        }
    }
    
    /// Create a configuration for production
    pub fn for_production() -> Self {
        Self {
            // Listen on all interfaces in production
            listen_addr: "0.0.0.0:5432".parse().unwrap(),
            backend_addr: "127.0.0.1:5433".parse().unwrap(),
            // Enable all security features in production
            verification_config: VerificationConfig {
                enabled: true,
                enforce: true, // Enforce verification in production
                ..Default::default()
            },
            // Enable rate limiting in production
            rate_limiter_config: RateLimiterConfig {
                enabled: true,
                ..Default::default()
            },
            // Higher connection limits for production
            max_connections: 1000,
            // Info log level for production
            log_level: "info".to_string(),
            ..Default::default()
        }
    }
    
    /// Create a configuration for testing
    pub fn for_testing() -> Self {
        Self {
            listen_addr: "127.0.0.1:0".parse().unwrap(), // Random port
            backend_addr: "127.0.0.1:5433".parse().unwrap(),
            // Disable verification in testing
            verification_config: VerificationConfig {
                enabled: false,
                ..Default::default()
            },
            // Disable rate limiting in testing
            rate_limiter_config: RateLimiterConfig {
                enabled: false,
                ..Default::default()
            },
            // Smaller connection limits for testing
            max_connections: 10,
            // Debug log level for testing
            log_level: "debug".to_string(),
            ..Default::default()
        }
    }
} 