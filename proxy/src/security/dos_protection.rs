//! DoS protection for the proxy
//!
//! This module provides protection against denial of service attacks.

use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

/// Configuration for DoS protection
#[derive(Debug, Clone)]
pub struct DoSProtectionConfig {
    /// Maximum number of connections per IP
    pub max_connections_per_ip: usize,
    
    /// Time window for tracking connections (in seconds)
    pub time_window_seconds: u64,
    
    /// Whether to enable DoS protection
    pub enabled: bool,
}

impl Default for DoSProtectionConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: 100,
            time_window_seconds: 60,
            enabled: true,
        }
    }
}

/// Protection against denial of service attacks
pub struct DoSProtection {
    /// Configuration
    config: DoSProtectionConfig,
    
    /// Connection tracking
    connections: Mutex<HashMap<SocketAddr, Vec<Instant>>>,
}

impl DoSProtection {
    /// Create a new DoS protection instance
    pub fn new(config: DoSProtectionConfig) -> Self {
        Self {
            config,
            connections: Mutex::new(HashMap::new()),
        }
    }
    
    /// Check if a connection is allowed
    pub fn allow_connection(&self, addr: SocketAddr) -> bool {
        if !self.config.enabled {
            return true;
        }
        
        let mut connections = self.connections.lock().unwrap();
        let now = Instant::now();
        let time_window = Duration::from_secs(self.config.time_window_seconds);
        
        // Clean up old connections
        if let Some(conn_times) = connections.get_mut(&addr) {
            conn_times.retain(|time| now.duration_since(*time) < time_window);
            
            // Check if allowed
            if conn_times.len() >= self.config.max_connections_per_ip {
                return false;
            }
            
            // Add new connection
            conn_times.push(now);
        } else {
            // First connection from this IP
            connections.insert(addr, vec![now]);
        }
        
        true
    }
} 