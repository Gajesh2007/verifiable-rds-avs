//! Traffic analyzer for client traffic patterns
//!
//! This module analyzes client traffic patterns to identify potential security issues.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Configuration for traffic analysis
#[derive(Debug, Clone)]
pub struct TrafficAnalyzerConfig {
    /// Whether to enable traffic analysis
    pub enabled: bool,
    
    /// Time window for analysis (in seconds)
    pub time_window_seconds: u64,
    
    /// Maximum requests per client in the time window
    pub max_requests_per_client: usize,
    
    /// Threshold for suspicious traffic patterns (ratio)
    pub suspicious_pattern_threshold: f64,
}

impl Default for TrafficAnalyzerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            time_window_seconds: 60,
            max_requests_per_client: 1000,
            suspicious_pattern_threshold: 0.9,
        }
    }
}

/// Client traffic statistics
#[derive(Debug)]
struct ClientStats {
    /// Request timestamps
    request_times: Vec<Instant>,
    
    /// Query types count
    query_types: HashMap<String, usize>,
    
    /// Total bytes sent
    bytes_sent: usize,
    
    /// Total bytes received
    bytes_received: usize,
}

impl ClientStats {
    fn new() -> Self {
        Self {
            request_times: Vec::new(),
            query_types: HashMap::new(),
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

/// Analyzer for client traffic patterns
pub struct TrafficAnalyzer {
    /// Configuration
    config: TrafficAnalyzerConfig,
    
    /// Client statistics
    client_stats: Mutex<HashMap<SocketAddr, ClientStats>>,
    
    /// Last cleanup time
    last_cleanup: Mutex<Instant>,
}

impl TrafficAnalyzer {
    /// Create a new traffic analyzer
    pub fn new(config: TrafficAnalyzerConfig) -> Self {
        Self {
            config,
            client_stats: Mutex::new(HashMap::new()),
            last_cleanup: Mutex::new(Instant::now()),
        }
    }
    
    /// Record client traffic
    pub fn record_traffic(&self, addr: SocketAddr, query_type: &str, bytes_sent: usize, bytes_received: usize) {
        if !self.config.enabled {
            return;
        }
        
        let now = Instant::now();
        let mut stats = self.client_stats.lock().unwrap();
        
        // Add or update client stats
        let client_stats = stats.entry(addr).or_insert_with(ClientStats::new);
        client_stats.request_times.push(now);
        *client_stats.query_types.entry(query_type.to_string()).or_insert(0) += 1;
        client_stats.bytes_sent += bytes_sent;
        client_stats.bytes_received += bytes_received;
        
        // Periodic cleanup
        self.cleanup_if_needed();
    }
    
    /// Check if client traffic is suspicious
    pub fn is_suspicious(&self, addr: SocketAddr) -> bool {
        if !self.config.enabled {
            return false;
        }
        
        let stats = self.client_stats.lock().unwrap();
        if let Some(client_stats) = stats.get(&addr) {
            // Check request frequency
            let now = Instant::now();
            let time_window = Duration::from_secs(self.config.time_window_seconds);
            
            let recent_requests = client_stats.request_times.iter()
                .filter(|time| now.duration_since(**time) < time_window)
                .count();
                
            if recent_requests > self.config.max_requests_per_client {
                return true;
            }
        }
        
        false
    }
    
    /// Cleanup old statistics
    fn cleanup_if_needed(&self) {
        let now = Instant::now();
        let mut last_cleanup = self.last_cleanup.lock().unwrap();
        
        // Cleanup every minute
        if now.duration_since(*last_cleanup) > Duration::from_secs(60) {
            let time_window = Duration::from_secs(self.config.time_window_seconds);
            let mut stats = self.client_stats.lock().unwrap();
            
            // Remove old request times
            for client_stats in stats.values_mut() {
                client_stats.request_times.retain(|time| now.duration_since(*time) < time_window);
            }
            
            // Remove clients with no recent activity
            stats.retain(|_, client_stats| !client_stats.request_times.is_empty());
            
            *last_cleanup = now;
        }
    }
} 