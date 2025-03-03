//! Cryptographic primitives for the Verifiable RDS AVS
//!
//! This module provides cryptographic primitives with domain separation
//! for use in the verification system.

mod hasher;

pub use hasher::SecureHasher;
pub use hasher::Sha256Hasher;

use sha2::{Sha256, Digest};
use constant_time_eq::constant_time_eq;

/// Create a domain-separated secure hash using SHA-256
///
/// # Arguments
///
/// * `domain` - Domain prefix (e.g., "LEAF", "NODE")
/// * `data` - Data to hash
///
/// # Returns
///
/// A 32-byte secure hash with domain separation
pub fn secure_hash(domain: &str, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    
    // Add domain prefix for domain separation
    hasher.update(domain.as_bytes());
    
    // Add domain length as a single byte for additional protection
    // This prevents extension attacks even with variable-length domains
    hasher.update(&[domain.len() as u8]);
    
    // Add the actual data
    hasher.update(data);
    
    // Finalize and return
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Create a domain-separated secure hash of multiple inputs
///
/// # Arguments
///
/// * `domain` - Domain prefix (e.g., "LEAF", "NODE")
/// * `data` - Vector of data to hash
///
/// # Returns
///
/// A 32-byte secure hash with domain separation
pub fn secure_hash_multiple(domain: &str, data: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    
    // Add domain prefix for domain separation
    hasher.update(domain.as_bytes());
    
    // Add domain length as a single byte for additional protection
    hasher.update(&[domain.len() as u8]);
    
    // Add number of elements as a protection against concatenation attacks
    hasher.update(&[data.len() as u8]);
    
    // Add each element with its length prefix
    for element in data {
        // Add a 4-byte length prefix in big-endian format
        hasher.update(&(element.len() as u32).to_be_bytes());
        
        // Add the actual data
        hasher.update(*element);
    }
    
    // Finalize and return
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Verify a hash in constant time to prevent timing attacks
///
/// # Arguments
///
/// * `expected` - Expected hash value
/// * `actual` - Actual hash value to verify
///
/// # Returns
///
/// True if the hashes match, false otherwise
pub fn verify_hash(expected: &[u8; 32], actual: &[u8; 32]) -> bool {
    constant_time_eq(expected, actual)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_hash() {
        let data = b"test data";
        let hash = secure_hash("TEST", data);
        
        // Same inputs should produce the same hash
        let hash2 = secure_hash("TEST", data);
        assert_eq!(hash, hash2);
        
        // Different domain should produce different hash
        let hash3 = secure_hash("DIFFERENT", data);
        assert_ne!(hash, hash3);
        
        // Different data should produce different hash
        let hash4 = secure_hash("TEST", b"different data");
        assert_ne!(hash, hash4);
    }
    
    #[test]
    fn test_secure_hash_multiple() {
        let data1 = b"data1";
        let data2 = b"data2";
        
        let hash = secure_hash_multiple("TEST", &[data1, data2]);
        
        // Same inputs should produce the same hash
        let hash2 = secure_hash_multiple("TEST", &[data1, data2]);
        assert_eq!(hash, hash2);
        
        // Different domain should produce different hash
        let hash3 = secure_hash_multiple("DIFFERENT", &[data1, data2]);
        assert_ne!(hash, hash3);
        
        // Different data should produce different hash
        let hash4 = secure_hash_multiple("TEST", &[data2, data1]);
        assert_ne!(hash, hash4);
        
        // Concatenation should not work
        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(data1);
        concatenated.extend_from_slice(data2);
        let hash5 = secure_hash("TEST", &concatenated);
        assert_ne!(hash, hash5);
    }
    
    #[test]
    fn test_verify_hash() {
        let data = b"test data";
        let hash = secure_hash("TEST", data);
        
        // Correct hash should verify
        assert!(verify_hash(&hash, &hash));
        
        // Different hash should not verify
        let different_hash = secure_hash("TEST", b"different data");
        assert!(!verify_hash(&hash, &different_hash));
    }
} 