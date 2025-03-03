//! Utility functions and helpers
//!
//! This module provides various utility functions and helpers used throughout the codebase.

pub mod resource;
pub mod string;
pub mod timer;

pub use resource::ResourceLimiter;
pub use string::StringUtils;
pub use timer::Timer;

use std::time::{Duration, Instant};
use uuid::Uuid;
use log::info;

/// Generate a UUID v4
pub fn generate_uuid() -> Uuid {
    Uuid::new_v4()
}

/// Generate a timestamp in milliseconds since UNIX epoch
pub fn current_timestamp_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as i64
}

/// Measure execution time of a closure
pub fn measure_time<F, T>(name: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    let elapsed = start.elapsed();
    info!("{} took {}ms", name, elapsed.as_millis());
    result
}

/// Retry a fallible operation with exponential backoff
pub async fn retry_with_backoff<F, Fut, T, E>(
    mut operation: F,
    max_retries: usize,
    initial_backoff: Duration,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut retries = 0;
    let mut backoff = initial_backoff;
    
    loop {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if retries >= max_retries {
                    return Err(err);
                }
                
                retries += 1;
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }
        }
    }
}

/// Convert a byte array to a hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Convert a hex string to a byte array
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_uuid() {
        let uuid1 = generate_uuid();
        let uuid2 = generate_uuid();
        
        // UUIDs should be different
        assert_ne!(uuid1, uuid2);
    }
    
    #[test]
    fn test_current_timestamp_millis() {
        let timestamp = current_timestamp_millis();
        
        // Timestamp should be positive and recent
        assert!(timestamp > 0);
        
        // Timestamp should be within the last hour
        let hour_ago = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64 - 3600 * 1000;
        
        assert!(timestamp > hour_ago);
    }
    
    #[test]
    fn test_measure_time() {
        let result = measure_time("test_operation", || {
            // Simulate work
            std::thread::sleep(Duration::from_millis(10));
            42
        });
        
        assert_eq!(result, 42);
    }
    
    #[tokio::test]
    async fn test_retry_with_backoff() {
        // Test successful operation
        let mut counter = 0;
        let result = retry_with_backoff(
            || async {
                counter += 1;
                Ok::<_, &'static str>(counter)
            },
            3,
            Duration::from_millis(1),
        )
        .await;
        
        assert_eq!(result, Ok(1));
        assert_eq!(counter, 1); // Operation succeeded on first try
        
        // Test failing operation with retries
        let mut counter = 0;
        let result: Result<(), &'static str> = retry_with_backoff(
            || async {
                counter += 1;
                if counter < 3 {
                    Err("not ready yet")
                } else {
                    Ok(())
                }
            },
            3,
            Duration::from_millis(1),
        )
        .await;
        
        assert_eq!(result, Ok(()));
        assert_eq!(counter, 3); // Operation succeeded after 3 tries
        
        // Test operation that always fails
        let mut counter = 0;
        let result: Result<(), &'static str> = retry_with_backoff(
            || async {
                counter += 1;
                Err("always fails")
            },
            2,
            Duration::from_millis(1),
        )
        .await;
        
        assert_eq!(result, Err("always fails"));
        assert_eq!(counter, 3); // Initial attempt + 2 retries
    }
    
    #[test]
    fn test_hex_conversion() {
        let bytes = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let hex = bytes_to_hex(&bytes);
        
        assert_eq!(hex, "123456789abcdef0");
        
        let decoded = hex_to_bytes(&hex).unwrap();
        assert_eq!(decoded, bytes);
        
        // Test invalid hex
        assert!(hex_to_bytes("invalid").is_err());
    }
} 