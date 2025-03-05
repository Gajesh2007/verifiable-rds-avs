//! Server implementation for the PostgreSQL proxy
//!
//! This module provides the main server implementation for the PostgreSQL proxy.

use crate::config::ProxyConfig;
use crate::error::{ProxyError, Result};
use crate::protocol::auth::AuthHandler;
use crate::protocol::connection::ClientConnection;
use crate::protocol::validator::ProtocolValidator;
use crate::transaction::TransactionManager;
use crate::security::{RateLimiter, RateLimiterConfig};
use tokio::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::net::SocketAddr;
use log::{info, error, debug, warn};

/// Main proxy server implementation
#[derive(Clone)]
pub struct ProxyServer {
    /// Server configuration
    config: ProxyConfig,
    
    /// Rate limiter for DoS protection
    rate_limiter: Arc<Mutex<RateLimiter>>,
    
    /// Whether the server is running
    running: Arc<Mutex<bool>>,
}

impl ProxyServer {
    /// Create a new proxy server
    pub fn new(config: ProxyConfig) -> Result<Self> {
        // Create rate limiter
        let rate_limiter_config = RateLimiterConfig {
            enabled: config.rate_limiter_config.enabled,
            rate_limit: config.rate_limiter_config.rate_limit,
            allow_list: vec!["127.0.0.1".parse().unwrap()],
            block_list: Vec::new(),
        };
        
        let rate_limiter = Arc::new(Mutex::new(RateLimiter::new(rate_limiter_config)?));
        
        Ok(Self {
            config,
            rate_limiter,
            running: Arc::new(Mutex::new(false)),
        })
    }
    
    /// Start the proxy server
    pub async fn start(&self) -> Result<()> {
        // Make sure we're not already running
        {
            let mut running = self.running.lock().unwrap();
            if *running {
                return Err(ProxyError::Other("Server is already running".to_string()));
            }
            *running = true;
        }
        
        // Create a TCP listener
        let listener = TcpListener::bind(&self.config.listen_addr).await
            .map_err(|e| ProxyError::Other(format!("Failed to bind to {}: {}", self.config.listen_addr, e)))?;
        
        info!("Proxy server listening on {}", self.config.listen_addr);
        
        // Create a thread-safe reference to self
        let server = Arc::new(self.clone());
        
        // Accept incoming connections
        let running = self.running.clone();
        
        tokio::spawn(async move {
            loop {
                // Check if we're still running
                if !*running.lock().unwrap() {
                    break;
                }
                
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        // Clone the server reference for this connection
                        let connection_server = server.clone();
                        
                        // Spawn a task to handle this connection
                        tokio::spawn(async move {
                            if let Err(e) = connection_server.handle_connection(stream, addr).await {
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
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.lock().unwrap();
        if !*running {
            return Ok(());  // Already stopped
        }
        
        *running = false;
        info!("Stopping proxy server...");
        
        // Give any active connections time to close gracefully
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        
        Ok(())
    }
    
    /// Handle a client connection
    async fn handle_connection(&self, client_stream: TcpStream, client_addr: SocketAddr) -> Result<()> {
        // Check if the client is allowed to connect
        if !self.rate_limiter.lock().unwrap().check_connection(client_addr.ip()) {
            debug!("Connection from {} rejected by rate limiter", client_addr);
            return Ok(());
        }
        
        info!("New connection from {}", client_addr);
        
        // Connect to the backend server
        let backend_stream = TcpStream::connect(&self.config.backend_addr).await
            .map_err(|e| ProxyError::Other(format!("Failed to connect to backend: {}", e)))?;
        
        // Create a transaction manager
        let transaction_manager = Arc::new(Mutex::new(TransactionManager::new()));
        
        // Create a client connection
        let mut client_connection = ClientConnection::new(
            client_stream,
            client_addr,
            self.config.clone(),
            transaction_manager,
        );
        
        // Handle the connection
        match client_connection.handle_connection().await {
            Ok(()) => {
                info!("Connection from {} closed", client_addr);
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;
    
    #[test]
    fn test_server_creation() {
        let config = ProxyConfig::default();
        let server = ProxyServer::new(config).unwrap();
        
        assert!(!server.is_running());
    }
    
    #[test]
    fn test_server_start_stop() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let config = ProxyConfig::default();
            let server = ProxyServer::new(config).unwrap();
            
            // Start the server
            server.start().await.unwrap();
            assert!(server.is_running());
            
            // Stop the server
            server.stop().await.unwrap();
            assert!(!server.is_running());
        });
    }
} 