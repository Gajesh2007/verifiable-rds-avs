//! Secure hasher implementation with domain separation
//!
//! This module provides a trait for secure hasher implementations
//! and concrete implementations using different hash algorithms.

use sha2::{Sha256, Digest};
use blake2::{Blake2b512, Blake2s256};
use sha3::Keccak256;
use std::fmt::Debug;

/// SecureHasher trait for domain-separated hashing
pub trait SecureHasher: Debug + Send + Sync + 'static {
    /// Create a new instance of the hasher
    fn new_instance() -> Box<dyn SecureHasher>
    where
        Self: Sized;
    
    /// Update the hasher with new data
    fn update(&mut self, data: &[u8]);
    
    /// Finalize the hash and return the result
    fn finalize(&mut self) -> [u8; 32];
    
    /// Hash data with domain separation
    fn hash_with_domain(&mut self, domain: &str, data: &[u8]) -> [u8; 32] {
        // Add domain prefix for domain separation
        self.update(domain.as_bytes());
        
        // Add domain length as a single byte for additional protection
        self.update(&[domain.len() as u8]);
        
        // Add the actual data
        self.update(data);
        
        // Finalize and return
        self.finalize()
    }
    
    /// Hash multiple data elements with domain separation
    fn hash_multiple_with_domain(&mut self, domain: &str, data: &[&[u8]]) -> [u8; 32] {
        // Add domain prefix for domain separation
        self.update(domain.as_bytes());
        
        // Add domain length as a single byte for additional protection
        self.update(&[domain.len() as u8]);
        
        // Add number of elements as a protection against concatenation attacks
        self.update(&[data.len() as u8]);
        
        // Add each element with its length prefix
        for element in data {
            // Add a 4-byte length prefix in big-endian format
            self.update(&(element.len() as u32).to_be_bytes());
            
            // Add the actual data
            self.update(*element);
        }
        
        // Finalize and return
        self.finalize()
    }
    
    /// Clone the hasher
    fn clone_box(&self) -> Box<dyn SecureHasher>;
}

/// SHA-256 implementation of SecureHasher
#[derive(Debug, Clone)]
pub struct Sha256Hasher {
    inner: Sha256,
}

impl Sha256Hasher {
    /// Create a new SHA-256 hasher
    pub fn new() -> Self {
        Sha256Hasher {
            inner: Sha256::new(),
        }
    }
}

impl SecureHasher for Sha256Hasher {
    fn new_instance() -> Box<dyn SecureHasher> {
        Box::new(Self::new())
    }
    
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    
    fn finalize(&mut self) -> [u8; 32] {
        let result = self.inner.clone().finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }
    
    fn clone_box(&self) -> Box<dyn SecureHasher> {
        Box::new(self.clone())
    }
}

/// Blake2s implementation of SecureHasher
#[derive(Debug, Clone)]
pub struct Blake2sHasher {
    inner: Blake2s256,
}

impl Blake2sHasher {
    /// Create a new Blake2s hasher
    pub fn new() -> Self {
        Blake2sHasher {
            inner: Blake2s256::new(),
        }
    }
}

impl SecureHasher for Blake2sHasher {
    fn new_instance() -> Box<dyn SecureHasher> {
        Box::new(Self::new())
    }
    
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    
    fn finalize(&mut self) -> [u8; 32] {
        let result = self.inner.clone().finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }
    
    fn clone_box(&self) -> Box<dyn SecureHasher> {
        Box::new(self.clone())
    }
}

/// Keccak-256 implementation of SecureHasher
#[derive(Debug, Clone)]
pub struct KeccakHasher {
    inner: Keccak256,
}

impl KeccakHasher {
    /// Create a new Keccak-256 hasher
    pub fn new() -> Self {
        KeccakHasher {
            inner: Keccak256::new(),
        }
    }
}

impl SecureHasher for KeccakHasher {
    fn new_instance() -> Box<dyn SecureHasher> {
        Box::new(Self::new())
    }
    
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    
    fn finalize(&mut self) -> [u8; 32] {
        let result = self.inner.clone().finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }
    
    fn clone_box(&self) -> Box<dyn SecureHasher> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn test_hasher_implementation<H: SecureHasher>(hasher: H) {
        let mut h1 = hasher.new_instance();
        let mut h2 = hasher.new_instance();
        
        // Test basic hashing
        let data = b"test data";
        h1.update(data);
        let hash1 = h1.finalize();
        
        // Same data should produce same hash
        h2.update(data);
        let hash2 = h2.finalize();
        assert_eq!(hash1, hash2);
        
        // Test domain separation
        let mut h3 = hasher.new_instance();
        let mut h4 = hasher.new_instance();
        
        let hash3 = h3.hash_with_domain("DOMAIN1", data);
        let hash4 = h4.hash_with_domain("DOMAIN2", data);
        
        // Different domains should produce different hashes
        assert_ne!(hash3, hash4);
        
        // Test multiple inputs
        let mut h5 = hasher.new_instance();
        let mut h6 = hasher.new_instance();
        
        let data1 = b"data1";
        let data2 = b"data2";
        
        let hash5 = h5.hash_multiple_with_domain("TEST", &[data1, data2]);
        let hash6 = h6.hash_multiple_with_domain("TEST", &[data2, data1]);
        
        // Different order should produce different hashes
        assert_ne!(hash5, hash6);
    }
    
    #[test]
    fn test_sha256_hasher() {
        test_hasher_implementation(Sha256Hasher::new());
    }
    
    #[test]
    fn test_blake2s_hasher() {
        test_hasher_implementation(Blake2sHasher::new());
    }
    
    #[test]
    fn test_keccak_hasher() {
        test_hasher_implementation(KeccakHasher::new());
    }
} 