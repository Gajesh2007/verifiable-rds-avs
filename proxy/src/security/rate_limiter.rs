//! Rate limiter for client connections
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovernorRateLimiter,
};
use log::{debug, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::error::{ProxyError, Result};

/// Rate limiter for client connections
pub struct RateLimiter {
    /// Rate limiter implementation
    limiter: GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>,
    
    /// Client reputation tracking
    client_reputation: HashMap<IpAddr, ClientReputation>,
    
    /// Rate limit per minute
    rate_limit: u32,
    
    /// Allow list for IPs that are exempt from rate limiting
    allow_list: Vec<IpAddr>,
    
    /// Block list for IPs that are always blocked
    block_list: Vec<IpAddr>,
}

/// Client reputation for rate limiting
#[derive(Debug, Clone)]
struct ClientReputation {
    /// Current reputation score (0-100, higher is better)
    score: u8,
    
    /// Last access time
    last_access: Instant,
    
    /// Number of accesses in current window
    access_count: u32,
    
    /// Number of rate limit violations
    violations: u32,
}

impl RateLimiter {
    /// Create a new rate limiter with the given rate limit
    pub fn new(rate_limit: u32) -> Result<Self> {
        // Ensure rate limit is positive
        let rate_limit = std::cmp::max(1, rate_limit);
        
        // Create quota
        let quota = Quota::per_minute(
            NonZeroU32::new(rate_limit)
                .ok_or_else(|| ProxyError::Config("Rate limit must be positive".to_string()))?,
        );
        
        // Create governor rate limiter
        let limiter = GovernorRateLimiter::direct(quota);
        
        Ok(Self {
            limiter,
            client_reputation: HashMap::new(),
            rate_limit,
            allow_list: Vec::new(),
            block_list: Vec::new(),
        })
    }
    
    /// Add an IP to the allow list
    pub fn add_to_allow_list(&mut self, ip: IpAddr) {
        if !self.allow_list.contains(&ip) {
            self.allow_list.push(ip);
        }
    }
    
    /// Remove an IP from the allow list
    pub fn remove_from_allow_list(&mut self, ip: IpAddr) {
        self.allow_list.retain(|&x| x != ip);
    }
    
    /// Add an IP to the block list
    pub fn add_to_block_list(&mut self, ip: IpAddr) {
        if !self.block_list.contains(&ip) {
            self.block_list.push(ip);
        }
    }
    
    /// Remove an IP from the block list
    pub fn remove_from_block_list(&mut self, ip: IpAddr) {
        self.block_list.retain(|&x| x != ip);
    }
    
    /// Check if an IP is allowed to proceed
    pub fn check(&mut self, ip: IpAddr) -> bool {
        // Immediately allow if in allow list
        if self.allow_list.contains(&ip) {
            return true;
        }
        
        // Immediately block if in block list
        if self.block_list.contains(&ip) {
            warn!("IP {} is in block list, denying access", ip);
            return false;
        }
        
        // Update client reputation
        self.update_client_reputation(ip);
        
        // Get client reputation
        let reputation = self.client_reputation.get(&ip).unwrap();
        
        // If reputation is too low, block
        if reputation.score < 10 {
            warn!("IP {} has low reputation score {}, denying access", ip, reputation.score);
            return false;
        }
        
        // Check rate limiter
        let check_result = self.limiter.check();
        if check_result.is_err() {
            debug!("Rate limit exceeded for IP {}", ip);
            // Track violation
            if let Some(reputation) = self.client_reputation.get_mut(&ip) {
                reputation.violations += 1;
                // Reduce reputation score for violations
                if reputation.score > 5 {
                    reputation.score -= 5;
                }
            }
            return false;
        }
        
        true
    }
    
    /// Update client reputation
    fn update_client_reputation(&mut self, ip: IpAddr) {
        let now = Instant::now();
        
        // Create or update client reputation
        let reputation = self.client_reputation.entry(ip).or_insert_with(|| ClientReputation {
            score: 50, // Start with medium reputation
            last_access: now,
            access_count: 0,
            violations: 0,
        });
        
        // Update access count and last access time
        reputation.access_count += 1;
        reputation.last_access = now;
        
        // Adjust reputation based on behavior
        if reputation.access_count > self.rate_limit / 4 && reputation.access_count < self.rate_limit / 2 {
            // Client is using a reasonable amount of their quota, increase reputation
            if reputation.score < 100 {
                reputation.score += 1;
            }
        } else if reputation.access_count >= self.rate_limit / 2 {
            // Client is using a lot of their quota, decrease reputation
            if reputation.score > 0 {
                reputation.score -= 1;
            }
        }
    }
    
    /// Clean up old client reputation data
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.client_reputation.retain(|_, reputation| {
            now.duration_since(reputation.last_access) < Duration::from_secs(3600)
        });
    }
}

/// Rate limiter manager for distributed rate limiting
pub struct RateLimiterManager {
    /// Rate limiters by IP
    limiters: Arc<Mutex<HashMap<IpAddr, Arc<Mutex<RateLimiter>>>>>,
    
    /// Default rate limit
    default_rate_limit: u32,
}

impl RateLimiterManager {
    /// Create a new rate limiter manager
    pub fn new(default_rate_limit: u32) -> Self {
        Self {
            limiters: Arc::new(Mutex::new(HashMap::new())),
            default_rate_limit,
        }
    }
    
    /// Get a rate limiter for the given IP
    pub async fn get_limiter_for_ip(&self, ip: IpAddr) -> Arc<Mutex<RateLimiter>> {
        let mut limiters = self.limiters.lock().await;
        
        if !limiters.contains_key(&ip) {
            // Create a new rate limiter for this IP
            let limiter = RateLimiter::new(self.default_rate_limit).unwrap();
            limiters.insert(ip, Arc::new(Mutex::new(limiter)));
        }
        
        limiters.get(&ip).unwrap().clone()
    }
    
    /// Check if an IP is allowed to proceed
    pub async fn check(&self, ip: IpAddr) -> bool {
        let limiter = self.get_limiter_for_ip(ip).await;
        let mut limiter = limiter.lock().await;
        limiter.check(ip)
    }
    
    /// Clean up old rate limiters
    pub async fn cleanup(&self) {
        let mut limiters = self.limiters.lock().await;
        
        // Clean up each limiter
        for limiter in limiters.values() {
            let mut limiter = limiter.lock().await;
            limiter.cleanup();
        }
        
        // Remove empty limiters
        limiters.retain(|_, limiter| {
            let limiter = limiter.try_lock();
            if let Ok(limiter) = limiter {
                !limiter.client_reputation.is_empty()
            } else {
                true
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rate_limiter_creation() {
        let rate_limiter = RateLimiter::new(100).unwrap();
        assert_eq!(rate_limiter.rate_limit, 100);
    }
    
    #[test]
    fn test_rate_limiter_check() {
        let mut rate_limiter = RateLimiter::new(100).unwrap();
        let ip = "127.0.0.1".parse::<IpAddr>().unwrap();
        
        // Should allow the first request
        assert!(rate_limiter.check(ip));
        
        // Allow list should work
        rate_limiter.add_to_allow_list(ip);
        assert!(rate_limiter.check(ip));
        
        // Block list should work
        rate_limiter.add_to_block_list(ip);
        assert!(!rate_limiter.check(ip));
    }
} 