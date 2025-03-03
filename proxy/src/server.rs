//! Server implementation for the PostgreSQL proxy
//!
//! This module provides the main server implementation for the PostgreSQL proxy.

use crate::config::ProxyConfig;
use crate::error::{ProxyError, Result};
use crate::protocol::auth::AuthHandler;
use crate::protocol::connection::ClientConnection;
use crate::protocol::validator::ProtocolValidator;
use crate::interception::analyzer::QueryAnalyzer;
use crate::interception::rewrite::QueryRewriter;
use crate::interception::execution::QueryExecutor;
use crate::interception::verification::VerificationManager;
use crate::security::DosProtection;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use log::{info, error, debug, warn};

/// Main proxy server implementation
pub struct ProxyServer {
    /// Server configuration
    config: ProxyConfig,
    
    /// Authentication handler
    auth_handler: AuthHandler,
    
    /// Protocol validator
    protocol_validator: ProtocolValidator,
    
    /// Query analyzer
    query_analyzer: QueryAnalyzer,
    
    /// Query rewriter
    query_rewriter: QueryRewriter,
    
    /// Query executor
    query_executor: QueryExecutor,
    
    /// Verification manager
    verification_manager: VerificationManager,
    
    /// DoS protection
    dos_protection: DosProtection,
    
    /// Whether the server is running
    running: Arc<Mutex<bool>>,
}

impl ProxyServer {
    /// Create a new proxy server
    pub fn new(config: ProxyConfig) -> Self {
        // Create the authentication handler
        let auth_handler = AuthHandler::new(config.auth_config.clone());
        
        // Create the protocol validator
        let protocol_validator = ProtocolValidator::new(config.validator_config.clone());
        
        // Create the query analyzer
        let query_analyzer = QueryAnalyzer::new();
        
        // Create the query rewriter
        let query_rewriter = QueryRewriter::new(config.rewriter_config.clone());
        
        // Create the query executor
        let query_executor = QueryExecutor::new(config.executor_config.clone());
        
        // Create the verification manager
        let verification_manager = VerificationManager::new(config.verification_config.clone());
        
        // Create the DoS protection
        let dos_protection = DosProtection::new(config.rate_limiter_config.clone());
        
        Self {
            config,
            auth_handler,
            protocol_validator,
            query_analyzer,
            query_rewriter,
            query_executor,
            verification_manager,
            dos_protection,
            running: Arc::new(Mutex::new(false)),
        }
    }
    
    /// Start the proxy server
    pub fn start(&self) -> Result<()> {
        // Make sure we're not already running
        {
            let mut running = self.running.lock().unwrap();
            if *running {
                return Err(ProxyError::Server("Server is already running".to_string()));
            }
            *running = true;
        }
        
        // Create a TCP listener
        let listener = TcpListener::bind(self.config.listen_addr)
            .map_err(|e| ProxyError::Server(format!("Failed to bind to {}: {}", self.config.listen_addr, e)))?;
        
        info!("Proxy server listening on {}", self.config.listen_addr);
        
        // Create a thread-safe reference to self
        let server = Arc::new(self.clone());
        
        // Spawn a thread to handle incoming connections
        let running = self.running.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                // Check if we're still running
                if !*running.lock().unwrap() {
                    break;
                }
                
                match stream {
                    Ok(stream) => {
                        // Clone the server reference for this connection
                        let connection_server = server.clone();
                        
                        // Spawn a thread to handle this connection
                        thread::spawn(move || {
                            if let Err(e) = connection_server.handle_connection(stream) {
                                error!("Error handling connection: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Error accepting connection: {}", e);
                    }
                }
            }
            
            info!("Proxy server stopped");
        });
        
        Ok(())
    }
    
    /// Stop the proxy server
    pub fn stop(&self) {
        let mut running = self.running.lock().unwrap();
        *running = false;
        info!("Stopping proxy server...");
    }
    
    /// Handle a client connection
    fn handle_connection(&self, client_stream: TcpStream) -> Result<()> {
        // Get the client's IP address
        let client_addr = client_stream.peer_addr()
            .map_err(|e| ProxyError::Server(format!("Failed to get peer address: {}", e)))?;
        
        // Check if the client is allowed to connect
        if !self.dos_protection.allow_connection(client_addr.ip()) {
            debug!("Connection from {} rejected by DoS protection", client_addr);
            return Ok(());
        }
        
        info!("New connection from {}", client_addr);
        
        // Connect to the backend server
        let backend_stream = TcpStream::connect(self.config.backend_addr)
            .map_err(|e| ProxyError::Server(format!("Failed to connect to backend: {}", e)))?;
        
        // Create a client connection
        let mut client_connection = ClientConnection::new(
            client_stream,
            backend_stream,
            self.auth_handler.clone(),
            self.protocol_validator.clone(),
        );
        
        // Handle the connection
        match client_connection.handle() {
            Ok(stats) => {
                info!("Connection from {} closed. Stats: {} messages, {} bytes", 
                      client_addr, stats.messages_processed, stats.bytes_processed);
                Ok(())
            }
            Err(e) => {
                error!("Error handling connection from {}: {}", client_addr, e);
                Err(e)
            }
        }
    }
    
    /// Get server configuration
    pub fn config(&self) -> &ProxyConfig {
        &self.config
    }
    
    /// Check if the server is running
    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }
}

impl Clone for ProxyServer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            auth_handler: self.auth_handler.clone(),
            protocol_validator: self.protocol_validator.clone(),
            query_analyzer: QueryAnalyzer::new(), // Can't clone analyzer
            query_rewriter: self.query_rewriter.clone(),
            query_executor: self.query_executor.clone(),
            verification_manager: self.verification_manager.clone(),
            dos_protection: self.dos_protection.clone(),
            running: self.running.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_server_creation() {
        let config = ProxyConfig::default();
        let server = ProxyServer::new(config.clone()).unwrap();
        
        assert_eq!(server.config().proxy_port, config.proxy_port);
        assert_eq!(server.config().pg_host, config.pg_host);
        assert_eq!(server.config().pg_port, config.pg_port);
    }
} 