//! Security features like rate limiting and DoS protection
//! 
//! This module provides security features to protect the proxy server from
//! various attacks, including rate limiting, DoS protection, and anomaly detection.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use log::{warn, info, debug};

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Maximum number of requests per second
    pub max_requests_per_second: u32,
    
    /// Maximum number of connections per client
    pub max_connections_per_client: u32,
    
    /// Duration to ban clients after exceeding limits
    pub ban_duration: Duration,
    
    /// Whether to enable rate limiting
    pub enabled: bool,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            max_requests_per_second: 100,
            max_connections_per_client: 10,
            ban_duration: Duration::from_secs(300), // 5 minutes
            enabled: true,
        }
    }
}

/// Client tracking information
#[derive(Debug, Clone)]
struct ClientInfo {
    /// IP address of the client
    ip: IpAddr,
    
    /// First seen timestamp
    first_seen: Instant,
    
    /// Last seen timestamp
    last_seen: Instant,
    
    /// Current connection count
    connection_count: u32,
    
    /// Request count in the current window
    request_count: u32,
    
    /// Start of the current window
    window_start: Instant,
    
    /// Banned until timestamp (if banned)
    banned_until: Option<Instant>,
}

/// Rate limiter for controlling client access
pub struct RateLimiter {
    /// Configuration
    config: RateLimiterConfig,
    
    /// Client information
    clients: Arc<Mutex<HashMap<IpAddr, ClientInfo>>>,
    
    /// Last cleanup time
    last_cleanup: Arc<Mutex<Instant>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            clients: Arc::new(Mutex::new(HashMap::new())),
            last_cleanup: Arc::new(Mutex::new(Instant::now())),
        }
    }
    
    /// Check if a client is allowed to connect
    pub fn check_connection(&self, ip: IpAddr) -> bool {
        if !self.config.enabled {
            return true;
        }
        
        self.cleanup_old_entries();
        
        let mut clients = self.clients.lock().unwrap();
        
        // Check if client is banned
        if let Some(client) = clients.get(&ip) {
            if let Some(banned_until) = client.banned_until {
                if Instant::now() < banned_until {
                    debug!("Client {} is banned until {:?}", ip, banned_until);
                    return false;
                }
            }
        }
        
        // Update or create client info
        let now = Instant::now();
        let client = clients.entry(ip).or_insert_with(|| {
            ClientInfo {
                ip,
                first_seen: now,
                last_seen: now,
                connection_count: 0,
                request_count: 0,
                window_start: now,
                banned_until: None,
            }
        });
        
        // Update client info
        client.last_seen = now;
        client.connection_count += 1;
        
        // Check if client has too many connections
        if client.connection_count > self.config.max_connections_per_client {
            warn!("Client {} has too many connections ({})", ip, client.connection_count);
            client.banned_until = Some(now + self.config.ban_duration);
            return false;
        }
        
        true
    }
    
    /// Record a request from a client
    pub fn record_request(&self, ip: IpAddr) -> bool {
        if !self.config.enabled {
            return true;
        }
        
        self.cleanup_old_entries();
        
        let mut clients = self.clients.lock().unwrap();
        
        // Get client info
        let now = Instant::now();
        let client = clients.entry(ip).or_insert_with(|| {
            ClientInfo {
                ip,
                first_seen: now,
                last_seen: now,
                connection_count: 1,
                request_count: 0,
                window_start: now,
                banned_until: None,
            }
        });
        
        // Update client info
        client.last_seen = now;
        
        // Check if client is banned
        if let Some(banned_until) = client.banned_until {
            if now < banned_until {
                debug!("Client {} is banned until {:?}", ip, banned_until);
                return false;
            } else {
                // Reset ban
                client.banned_until = None;
            }
        }
        
        // Reset window if it's been more than a second
        if now.duration_since(client.window_start).as_secs() >= 1 {
            client.window_start = now;
            client.request_count = 0;
        }
        
        // Increment request count
        client.request_count += 1;
        
        // Check if client has too many requests
        if client.request_count > self.config.max_requests_per_second {
            warn!("Client {} exceeded rate limit ({} requests/sec)", 
                  ip, client.request_count);
            client.banned_until = Some(now + self.config.ban_duration);
            return false;
        }
        
        true
    }
    
    /// Close a connection from a client
    pub fn close_connection(&self, ip: IpAddr) {
        if !self.config.enabled {
            return;
        }
        
        let mut clients = self.clients.lock().unwrap();
        
        if let Some(client) = clients.get_mut(&ip) {
            client.connection_count = client.connection_count.saturating_sub(1);
        }
    }
    
    /// Ban a client for the configured duration
    pub fn ban_client(&self, ip: IpAddr) {
        if !self.config.enabled {
            return;
        }
        
        let mut clients = self.clients.lock().unwrap();
        
        let now = Instant::now();
        let client = clients.entry(ip).or_insert_with(|| {
            ClientInfo {
                ip,
                first_seen: now,
                last_seen: now,
                connection_count: 0,
                request_count: 0,
                window_start: now,
                banned_until: None,
            }
        });
        
        client.banned_until = Some(now + self.config.ban_duration);
        warn!("Client {} has been banned for {} seconds", 
              ip, self.config.ban_duration.as_secs());
    }
    
    /// Check if a client is banned
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        if !self.config.enabled {
            return false;
        }
        
        let clients = self.clients.lock().unwrap();
        
        if let Some(client) = clients.get(&ip) {
            if let Some(banned_until) = client.banned_until {
                return Instant::now() < banned_until;
            }
        }
        
        false
    }
    
    /// Cleanup old entries
    fn cleanup_old_entries(&self) {
        let mut last_cleanup = self.last_cleanup.lock().unwrap();
        
        // Only clean up every minute
        if last_cleanup.elapsed() < Duration::from_secs(60) {
            return;
        }
        
        let now = Instant::now();
        *last_cleanup = now;
        
        let mut clients = self.clients.lock().unwrap();
        
        // Remove clients that haven't been seen in a while and aren't banned
        clients.retain(|_, client| {
            client.connection_count > 0 || 
            client.last_seen.elapsed() < Duration::from_secs(3600) || 
            client.banned_until.map_or(false, |t| t > now)
        });
        
        debug!("Cleaned up rate limiter, {} clients remaining", clients.len());
    }
}

/// DoS protection module
pub struct DosProtection {
    /// Rate limiter
    rate_limiter: RateLimiter,
    
    /// Known malicious IP addresses
    blacklist: Arc<Mutex<HashMap<IpAddr, String>>>,
}

impl DosProtection {
    /// Create a new DoS protection module
    pub fn new(rate_limiter_config: RateLimiterConfig) -> Self {
        Self {
            rate_limiter: RateLimiter::new(rate_limiter_config),
            blacklist: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Check if a connection is allowed
    pub fn allow_connection(&self, ip: IpAddr) -> bool {
        // Check blacklist first
        {
            let blacklist = self.blacklist.lock().unwrap();
            if blacklist.contains_key(&ip) {
                debug!("Connection from blacklisted IP {} rejected", ip);
                return false;
            }
        }
        
        // Then check rate limiter
        self.rate_limiter.check_connection(ip)
    }
    
    /// Record a request
    pub fn record_request(&self, ip: IpAddr) -> bool {
        // Check blacklist first
        {
            let blacklist = self.blacklist.lock().unwrap();
            if blacklist.contains_key(&ip) {
                debug!("Request from blacklisted IP {} rejected", ip);
                return false;
            }
        }
        
        // Then check rate limiter
        self.rate_limiter.record_request(ip)
    }
    
    /// Close a connection
    pub fn close_connection(&self, ip: IpAddr) {
        self.rate_limiter.close_connection(ip);
    }
    
    /// Add an IP to the blacklist
    pub fn blacklist_ip(&self, ip: IpAddr, reason: &str) {
        let mut blacklist = self.blacklist.lock().unwrap();
        blacklist.insert(ip, reason.to_string());
        warn!("IP {} added to blacklist: {}", ip, reason);
    }
    
    /// Remove an IP from the blacklist
    pub fn remove_from_blacklist(&self, ip: IpAddr) {
        let mut blacklist = self.blacklist.lock().unwrap();
        blacklist.remove(&ip);
        info!("IP {} removed from blacklist", ip);
    }
    
    /// Check if an IP is blacklisted
    pub fn is_blacklisted(&self, ip: IpAddr) -> bool {
        let blacklist = self.blacklist.lock().unwrap();
        blacklist.contains_key(&ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread::sleep;
    
    #[test]
    fn test_rate_limiter() {
        let config = RateLimiterConfig {
            max_requests_per_second: 5,
            max_connections_per_client: 3,
            ban_duration: Duration::from_secs(1),
            enabled: true,
        };
        
        let rate_limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        
        // Test connection limit
        assert!(rate_limiter.check_connection(ip));
        assert!(rate_limiter.check_connection(ip));
        assert!(rate_limiter.check_connection(ip));
        assert!(!rate_limiter.check_connection(ip));
        
        // Close connections and try again
        rate_limiter.close_connection(ip);
        rate_limiter.close_connection(ip);
        rate_limiter.close_connection(ip);
        assert!(rate_limiter.check_connection(ip));
        
        // Test request rate limit
        for _ in 0..5 {
            assert!(rate_limiter.record_request(ip));
        }
        assert!(!rate_limiter.record_request(ip));
        
        // Wait for ban to expire
        sleep(Duration::from_secs(2));
        assert!(rate_limiter.record_request(ip));
    }
    
    #[test]
    fn test_dos_protection() {
        let config = RateLimiterConfig {
            max_requests_per_second: 5,
            max_connections_per_client: 3,
            ban_duration: Duration::from_secs(1),
            enabled: true,
        };
        
        let dos_protection = DosProtection::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        
        // Test blacklisting
        assert!(dos_protection.allow_connection(ip));
        dos_protection.blacklist_ip(ip, "Test blacklisting");
        assert!(!dos_protection.allow_connection(ip));
        assert!(!dos_protection.record_request(ip));
        assert!(dos_protection.is_blacklisted(ip));
        
        // Remove from blacklist
        dos_protection.remove_from_blacklist(ip);
        assert!(!dos_protection.is_blacklisted(ip));
        assert!(dos_protection.allow_connection(ip));
        assert!(dos_protection.record_request(ip));
    }
} 