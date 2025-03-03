//! Security features for the proxy
//!
//! This module contains security features like rate limiting,
//! DoS protection, anomaly detection, etc.

/// Rate limiter for client connections
pub mod rate_limiter;

/// DoS protection for the proxy
pub mod dos_protection;

/// Anomaly detection for query patterns
pub mod anomaly_detector;

/// Traffic analyzer for client traffic patterns
pub mod traffic_analyzer;

/// Security gateway for protocol-aware security
pub mod security_gateway;

// Re-export important types
pub use rate_limiter::{RateLimiter, RateLimiterConfig};
pub use dos_protection::DoSProtection;
pub use anomaly_detector::AnomalyDetector;
pub use traffic_analyzer::TrafficAnalyzer;
pub use security_gateway::SecurityGateway; 