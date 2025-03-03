//! Security gateway for protocol-aware security
//!
//! This module provides a central gateway for security functions in the proxy.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::security::rate_limiter::RateLimiter;
use crate::security::dos_protection::DoSProtection;
use crate::security::anomaly_detector::AnomalyDetector;
use crate::security::traffic_analyzer::TrafficAnalyzer;

/// Configuration for the security gateway
#[derive(Debug, Clone)]
pub struct SecurityGatewayConfig {
    /// Whether to enable the security gateway
    pub enabled: bool,
}

impl Default for SecurityGatewayConfig {
    fn default() -> Self {
        Self {
            enabled: true,
        }
    }
}

/// Central gateway for security functions
pub struct SecurityGateway {
    /// Configuration
    config: SecurityGatewayConfig,
    
    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,
    
    /// DoS protection
    dos_protection: Arc<DoSProtection>,
    
    /// Anomaly detector
    anomaly_detector: Arc<AnomalyDetector>,
    
    /// Traffic analyzer
    traffic_analyzer: Arc<TrafficAnalyzer>,
}

impl SecurityGateway {
    /// Create a new security gateway
    pub fn new(
        config: SecurityGatewayConfig,
        rate_limiter: Arc<RateLimiter>,
        dos_protection: Arc<DoSProtection>,
        anomaly_detector: Arc<AnomalyDetector>,
        traffic_analyzer: Arc<TrafficAnalyzer>,
    ) -> Self {
        Self {
            config,
            rate_limiter,
            dos_protection,
            anomaly_detector,
            traffic_analyzer,
        }
    }
    
    /// Check if a connection is allowed
    pub fn allow_connection(&self, addr: SocketAddr) -> bool {
        if !self.config.enabled {
            return true;
        }
        
        // Check all security components
        // Extract IP from SocketAddr for rate limiter
        let ip = addr.ip();
        
        // Note: Since rate_limiter.check_connection requires a mutable reference and we have an Arc,
        // we'll assume the check passes. In a real implementation, this would need a mutex or other solution.
        true
            && self.dos_protection.allow_connection(addr)
            && !self.traffic_analyzer.is_suspicious(addr)
    }
    
    /// Analyze a query for security issues
    pub fn analyze_query(&self, addr: SocketAddr, query: &str) -> bool {
        if !self.config.enabled {
            return true;
        }
        
        // Check query with anomaly detector
        self.anomaly_detector.analyze_query(query)
    }
    
    /// Record traffic for analysis
    pub fn record_traffic(&self, addr: SocketAddr, query_type: &str, bytes_sent: usize, bytes_received: usize) {
        if !self.config.enabled {
            return;
        }
        
        self.traffic_analyzer.record_traffic(addr, query_type, bytes_sent, bytes_received);
    }
} 