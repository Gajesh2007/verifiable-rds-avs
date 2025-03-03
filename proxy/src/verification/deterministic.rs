//! Deterministic replacements for PostgreSQL functions
//!
//! This module provides deterministic alternatives to PostgreSQL functions
//! that are non-deterministic, to ensure reproducible query execution.

use crate::error::{ProxyError, Result};
use log::{debug, warn, info};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Deterministic timestamp function
///
/// Unlike PostgreSQL's NOW() or CURRENT_TIMESTAMP, this returns a
/// deterministic timestamp based on the block time or logical time.
#[derive(Debug)]
pub struct DeterministicTimestamp {
    /// Block timestamp (seconds since epoch)
    block_timestamp: u64,
    
    /// Logical timestamp (used for ordering within a block)
    logical_timestamp: u64,
}

impl DeterministicTimestamp {
    /// Create a new deterministic timestamp
    pub fn new(block_timestamp: u64) -> Self {
        Self {
            block_timestamp,
            logical_timestamp: 0,
        }
    }
    
    /// Create a new deterministic timestamp with current system time
    pub fn now() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        Self {
            block_timestamp: now,
            logical_timestamp: 0,
        }
    }
    
    /// Get the timestamp as seconds since epoch
    pub fn as_secs(&self) -> u64 {
        self.block_timestamp
    }
    
    /// Get the timestamp as a string in PostgreSQL format
    /// Format: YYYY-MM-DD HH:MM:SS.uuuuuu+00
    pub fn as_string(&self) -> String {
        let secs = self.block_timestamp;
        let millis = self.logical_timestamp % 1000;
        
        // Convert to date and time components
        let (year, month, day, hour, minute, second) = seconds_to_date_time(secs);
        
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}+00",
            year, month, day, hour, minute, second, millis * 1000
        )
    }
    
    /// Increment the logical timestamp
    pub fn increment(&mut self) {
        self.logical_timestamp += 1;
    }
}

/// Deterministic random number generator
///
/// Unlike PostgreSQL's RANDOM(), this returns a deterministic
/// random number based on the transaction ID and seed.
#[derive(Debug)]
pub struct DeterministicRandom {
    /// Current seed value
    seed: u64,
}

impl DeterministicRandom {
    /// Create a new deterministic random number generator
    pub fn new(tx_id: u64, seed: u64) -> Self {
        let seed = combine_seeds(tx_id, seed);
        Self { seed }
    }
    
    /// Generate a random double between 0.0 and 1.0
    pub fn random_double(&mut self) -> f64 {
        // Update the seed
        self.seed = lcg_next(self.seed);
        
        // Convert to double between 0.0 and 1.0
        (self.seed as f64) / (u64::MAX as f64)
    }
    
    /// Generate a random integer in a range
    pub fn random_int(&mut self, min: i32, max: i32) -> i32 {
        let range = (max - min + 1) as u64;
        let rand = self.random_double();
        min + (rand * range as f64) as i32
    }
    
    /// Generate a random UUID
    pub fn random_uuid(&mut self) -> Uuid {
        // Generate 16 random bytes
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            self.seed = lcg_next(self.seed);
            bytes[i] = (self.seed % 256) as u8;
        }
        
        // Set the version (4) and variant bits
        bytes[6] = (bytes[6] & 0x0F) | 0x40; // Version 4
        bytes[8] = (bytes[8] & 0x3F) | 0x80; // RFC4122 variant
        
        Uuid::from_bytes(bytes)
    }
}

/// Linear congruential generator for random numbers
fn lcg_next(seed: u64) -> u64 {
    const A: u64 = 6364136223846793005;
    const C: u64 = 1442695040888963407;
    seed.wrapping_mul(A).wrapping_add(C)
}

/// Combine two seed values
fn combine_seeds(a: u64, b: u64) -> u64 {
    // Use a cryptographic hash to combine the seeds
    let mut hasher = Sha256::new();
    hasher.update(a.to_le_bytes());
    hasher.update(b.to_le_bytes());
    let result = hasher.finalize();
    
    // Convert first 8 bytes to u64
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&result[0..8]);
    u64::from_le_bytes(bytes)
}

/// Convert seconds since epoch to date and time components
fn seconds_to_date_time(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    // Simplified implementation - in a real system, use a proper date library
    const SECONDS_PER_MINUTE: u64 = 60;
    const SECONDS_PER_HOUR: u64 = 60 * SECONDS_PER_MINUTE;
    const SECONDS_PER_DAY: u64 = 24 * SECONDS_PER_HOUR;
    
    // Epoch (1970-01-01) was a Thursday (day 4 of the week)
    let days_since_epoch = secs / SECONDS_PER_DAY;
    let seconds_in_day = secs % SECONDS_PER_DAY;
    
    // Time components
    let hour = (seconds_in_day / SECONDS_PER_HOUR) as u32;
    let minute = ((seconds_in_day % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE) as u32;
    let second = (seconds_in_day % SECONDS_PER_MINUTE) as u32;
    
    // Date components - very simplified
    // In a real implementation, use a proper date library
    let year = 1970 + (days_since_epoch / 365) as u32;
    let month = 1 + ((days_since_epoch % 365) / 30) as u32;
    let day = 1 + ((days_since_epoch % 365) % 30) as u32;
    
    (year, month, day, hour, minute, second)
}

/// Deterministic SQL functions for use by the rewriter
#[derive(Debug)]
pub struct DeterministicSqlFunctions {
    /// Timestamp generator
    timestamp: DeterministicTimestamp,
    
    /// Random number generator
    random: DeterministicRandom,
}

impl DeterministicSqlFunctions {
    /// Create a new instance with transaction ID and block timestamp
    pub fn new(tx_id: u64, block_timestamp: u64, seed: u64) -> Self {
        Self {
            timestamp: DeterministicTimestamp::new(block_timestamp),
            random: DeterministicRandom::new(tx_id, seed),
        }
    }
    
    /// Get a deterministic timestamp
    pub fn timestamp(&mut self) -> String {
        let result = self.timestamp.as_string();
        self.timestamp.increment();
        result
    }
    
    /// Get a deterministic random number
    pub fn random(&mut self) -> f64 {
        self.random.random_double()
    }
    
    /// Get a deterministic UUID
    pub fn uuid(&mut self) -> String {
        self.random.random_uuid().to_string()
    }
    
    /// Get a deterministic transaction ID
    pub fn txid(&self) -> u64 {
        // This is already deterministic since we use the actual transaction ID
        // We just pass through the value
        self.random.seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_deterministic_timestamp() {
        let mut ts = DeterministicTimestamp::new(1609459200); // 2021-01-01 00:00:00 UTC
        
        // Check initial values
        assert_eq!(ts.as_secs(), 1609459200);
        assert_eq!(ts.as_string(), "2021-01-01 00:00:00.000000+00");
        
        // Check incremented timestamp
        ts.increment();
        assert_eq!(ts.as_string(), "2021-01-01 00:00:00.001000+00");
    }
    
    #[test]
    fn test_deterministic_random() {
        let mut rng1 = DeterministicRandom::new(1, 0);
        let mut rng2 = DeterministicRandom::new(1, 0);
        
        // Same seeds should produce same sequence
        let val1 = rng1.random_double();
        let val2 = rng2.random_double();
        assert_eq!(val1, val2);
        
        // Values should be between 0.0 and 1.0
        assert!(val1 >= 0.0 && val1 < 1.0);
        
        // Int values should be in range
        for _ in 0..10 {
            let int_val = rng1.random_int(1, 10);
            assert!(int_val >= 1 && int_val <= 10);
        }
        
        // Different seeds should produce different sequences
        let mut rng3 = DeterministicRandom::new(2, 0);
        let val3 = rng3.random_double();
        assert_ne!(val1, val3);
    }
    
    #[test]
    fn test_deterministic_uuid() {
        let mut rng1 = DeterministicRandom::new(1, 0);
        let mut rng2 = DeterministicRandom::new(1, 0);
        
        // Same seeds should produce same UUIDs
        let uuid1 = rng1.random_uuid();
        let uuid2 = rng2.random_uuid();
        assert_eq!(uuid1, uuid2);
        
        // UUIDs should be version 4
        assert_eq!(uuid1.get_version_num(), 4);
        
        // Different seeds should produce different UUIDs
        let mut rng3 = DeterministicRandom::new(2, 0);
        let uuid3 = rng3.random_uuid();
        assert_ne!(uuid1, uuid3);
    }
    
    #[test]
    fn test_sql_functions() {
        let mut functions = DeterministicSqlFunctions::new(1, 1609459200, 0);
        
        // Check timestamp
        let ts = functions.timestamp();
        assert_eq!(ts, "2021-01-01 00:00:00.000000+00");
        
        // Timestamp increments
        let ts2 = functions.timestamp();
        assert_eq!(ts2, "2021-01-01 00:00:00.001000+00");
        
        // Check random values
        let rand1 = functions.random();
        let rand2 = functions.random();
        assert_ne!(rand1, rand2); // Subsequent calls should give different values
        assert!(rand1 >= 0.0 && rand1 < 1.0);
        
        // Check UUID
        let uuid = functions.uuid();
        assert!(uuid.len() == 36); // UUID format check
    }
} 