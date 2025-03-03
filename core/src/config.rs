//! Configuration for the core crate
//!
//! This module provides configuration options for the core crate,
//! including cryptographic settings, resource limits, and more.

use std::time::Duration;
use serde::{Serialize, Deserialize};
use crate::utils::resource::ResourceLimits;

/// Hash algorithm to use
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA-256
    Sha256,
    
    /// Blake2s
    Blake2s,
    
    /// Keccak-256
    Keccak256,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        HashAlgorithm::Sha256
    }
}

/// Merkle tree configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleConfig {
    /// Hash algorithm to use for the Merkle tree
    pub hash_algorithm: HashAlgorithm,
    
    /// Whether to use domain separation
    pub use_domain_separation: bool,
    
    /// Whether to salt leaf nodes
    pub salt_leaves: bool,
    
    /// Maximum tree height
    pub max_height: usize,
}

impl Default for MerkleConfig {
    fn default() -> Self {
        MerkleConfig {
            hash_algorithm: HashAlgorithm::default(),
            use_domain_separation: true,
            salt_leaves: true,
            max_height: 32,
        }
    }
}

/// Verification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationConfig {
    /// Resource limits for verification
    pub resource_limits: ResourceLimits,
    
    /// Timeout for verification operations
    pub verification_timeout: Duration,
    
    /// Maximum number of concurrent verifications
    pub max_concurrent_verifications: usize,
    
    /// Whether to verify all operations
    pub verify_all_operations: bool,
    
    /// Whether to verify state transitions
    pub verify_state_transitions: bool,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        VerificationConfig {
            resource_limits: ResourceLimits::default(),
            verification_timeout: Duration::from_secs(30),
            max_concurrent_verifications: 4,
            verify_all_operations: true,
            verify_state_transitions: true,
        }
    }
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// PostgreSQL version
    pub postgres_version: String,
    
    /// Maximum number of connections
    pub max_connections: usize,
    
    /// Connection timeout
    pub connection_timeout: Duration,
    
    /// Statement timeout
    pub statement_timeout: Duration,
    
    /// Whether to use prepared statements
    pub use_prepared_statements: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            postgres_version: "14.0".to_string(),
            max_connections: 10,
            connection_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(30),
            use_prepared_statements: true,
        }
    }
}

/// Challenge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeConfig {
    /// Base bond coefficient
    pub base_bond_coefficient: u64,
    
    /// Load factor
    pub load_factor: u64,
    
    /// Maximum number of challenges
    pub max_challenges: u64,
    
    /// Challenge verification timeout
    pub challenge_timeout: Duration,
    
    /// Challenge priority levels
    pub priority_levels: usize,
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        ChallengeConfig {
            base_bond_coefficient: 50,
            load_factor: 10,
            max_challenges: 100,
            challenge_timeout: Duration::from_secs(300),
            priority_levels: 3,
        }
    }
}

/// Core configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    /// Merkle tree configuration
    pub merkle: MerkleConfig,
    
    /// Verification configuration
    pub verification: VerificationConfig,
    
    /// Database configuration
    pub database: DatabaseConfig,
    
    /// Challenge configuration
    pub challenge: ChallengeConfig,
    
    /// Log level
    pub log_level: String,
    
    /// Whether to enable debug mode
    pub debug_mode: bool,
}

impl Default for CoreConfig {
    fn default() -> Self {
        CoreConfig {
            merkle: MerkleConfig::default(),
            verification: VerificationConfig::default(),
            database: DatabaseConfig::default(),
            challenge: ChallengeConfig::default(),
            log_level: "info".to_string(),
            debug_mode: false,
        }
    }
}

impl CoreConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Load configuration from a JSON file
    pub fn from_file(path: &str) -> Result<Self, crate::error::CoreError> {
        let file = std::fs::File::open(path)
            .map_err(|e| crate::error::CoreError::IoError(e))?;
        
        let config = serde_json::from_reader(file)
            .map_err(|e| crate::error::CoreError::JsonError(e))?;
        
        Ok(config)
    }
    
    /// Save configuration to a JSON file
    pub fn to_file(&self, path: &str) -> Result<(), crate::error::CoreError> {
        let file = std::fs::File::create(path)
            .map_err(|e| crate::error::CoreError::IoError(e))?;
        
        serde_json::to_writer_pretty(file, self)
            .map_err(|e| crate::error::CoreError::JsonError(e))?;
        
        Ok(())
    }
    
    /// Create a development configuration
    pub fn development() -> Self {
        let mut config = Self::default();
        config.debug_mode = true;
        config.log_level = "debug".to_string();
        config
    }
    
    /// Create a production configuration
    pub fn production() -> Self {
        let mut config = Self::default();
        config.debug_mode = false;
        config.log_level = "info".to_string();
        config.verification.verify_all_operations = true;
        config
    }
    
    /// Create a testing configuration
    pub fn testing() -> Self {
        let mut config = Self::default();
        config.debug_mode = true;
        config.log_level = "debug".to_string();
        config.verification.verification_timeout = Duration::from_secs(5);
        config.database.max_connections = 2;
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_default_config() {
        let config = CoreConfig::default();
        
        // Check default values
        assert_eq!(config.merkle.hash_algorithm, HashAlgorithm::Sha256);
        assert!(config.merkle.use_domain_separation);
        assert_eq!(config.verification.max_concurrent_verifications, 4);
        assert_eq!(config.database.postgres_version, "14.0");
        assert_eq!(config.challenge.priority_levels, 3);
        assert_eq!(config.log_level, "info");
        assert!(!config.debug_mode);
    }
    
    #[test]
    fn test_development_config() {
        let config = CoreConfig::development();
        
        assert!(config.debug_mode);
        assert_eq!(config.log_level, "debug");
    }
    
    #[test]
    fn test_production_config() {
        let config = CoreConfig::production();
        
        assert!(!config.debug_mode);
        assert_eq!(config.log_level, "info");
        assert!(config.verification.verify_all_operations);
    }
    
    #[test]
    fn test_testing_config() {
        let config = CoreConfig::testing();
        
        assert!(config.debug_mode);
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.verification.verification_timeout, Duration::from_secs(5));
        assert_eq!(config.database.max_connections, 2);
    }
    
    #[test]
    fn test_config_serialization() {
        let config = CoreConfig::default();
        
        // Serialize to JSON
        let json = serde_json::to_string_pretty(&config).unwrap();
        
        // Deserialize from JSON
        let deserialized: CoreConfig = serde_json::from_str(&json).unwrap();
        
        // Check that the deserialized config matches the original
        assert_eq!(deserialized.merkle.hash_algorithm, config.merkle.hash_algorithm);
        assert_eq!(deserialized.merkle.use_domain_separation, config.merkle.use_domain_separation);
        assert_eq!(deserialized.verification.max_concurrent_verifications, config.verification.max_concurrent_verifications);
        assert_eq!(deserialized.database.postgres_version, config.database.postgres_version);
        assert_eq!(deserialized.challenge.priority_levels, config.challenge.priority_levels);
        assert_eq!(deserialized.log_level, config.log_level);
        assert_eq!(deserialized.debug_mode, config.debug_mode);
    }
    
    #[test]
    fn test_config_file_io() {
        let config = CoreConfig::default();
        
        // Create a temporary file
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();
        
        // Save config to file
        config.to_file(path).unwrap();
        
        // Load config from file
        let loaded_config = CoreConfig::from_file(path).unwrap();
        
        // Check that the loaded config matches the original
        assert_eq!(loaded_config.merkle.hash_algorithm, config.merkle.hash_algorithm);
        assert_eq!(loaded_config.verification.max_concurrent_verifications, config.verification.max_concurrent_verifications);
        assert_eq!(loaded_config.database.postgres_version, config.database.postgres_version);
    }
} 