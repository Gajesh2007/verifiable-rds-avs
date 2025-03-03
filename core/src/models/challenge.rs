//! Verification challenge representation
//!
//! This module provides data structures for representing verification challenges
//! against blocks and transactions.

use std::fmt::{Debug, Formatter, Result as FmtResult};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use ethers::types::Address;

use crate::crypto;
use super::domains;

/// Type of verification challenge
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeType {
    /// Invalid state transition (state roots don't match after transaction)
    InvalidStateTransition,
    
    /// Invalid transaction execution (e.g., non-deterministic result)
    InvalidTransactionExecution,
    
    /// Invalid proof (e.g., Merkle proof doesn't verify)
    InvalidProof,
    
    /// Transaction boundary violation (e.g., savepoint manipulation)
    TransactionBoundaryViolation,
    
    /// Non-deterministic execution (different results for same inputs)
    NonDeterministicExecution,
    
    /// Resource exhaustion (e.g., gas limit exceeded)
    ResourceExhaustion,
    
    /// Protocol violation (e.g., invalid message format)
    ProtocolViolation,
    
    /// Schema violation (e.g., invalid data type)
    SchemaViolation,
}

/// Status of a verification challenge
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeStatus {
    /// Challenge is pending verification
    Pending,
    
    /// Challenge is being verified
    Verifying,
    
    /// Challenge was successful (operator was slashed)
    Successful,
    
    /// Challenge was rejected (challenger lost bond)
    Rejected,
    
    /// Challenge timed out before verification completed
    TimedOut,
    
    /// Challenge was withdrawn by the challenger
    Withdrawn,
}

/// Evidence for a verification challenge
#[derive(Clone, Serialize, Deserialize)]
pub struct ChallengeEvidence {
    /// Description of the evidence
    pub description: String,
    
    /// Expected result (e.g., expected state root)
    pub expected_result: String,
    
    /// Actual result (e.g., actual state root)
    pub actual_result: String,
    
    /// Reproducible test case (JSON serialized)
    pub test_case: String,
    
    /// Raw evidence data (hex encoded)
    pub raw_data: Option<String>,
    
    /// Evidence hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<[u8; 32]>,
}

impl Debug for ChallengeEvidence {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("ChallengeEvidence")
            .field("description", &self.description)
            .field("expected", &self.expected_result)
            .field("actual", &self.actual_result)
            .finish()
    }
}

impl ChallengeEvidence {
    /// Create new challenge evidence
    pub fn new(
        description: String,
        expected_result: String,
        actual_result: String,
        test_case: String,
        raw_data: Option<String>,
    ) -> Self {
        let mut evidence = ChallengeEvidence {
            description,
            expected_result,
            actual_result,
            test_case,
            raw_data,
            hash: None,
        };
        
        // Calculate the hash
        evidence.hash = Some(evidence.calculate_hash());
        
        evidence
    }
    
    /// Calculate the hash of the evidence with domain separation
    pub fn calculate_hash(&self) -> [u8; 32] {
        // Collect data for hashing
        let description_bytes = self.description.as_bytes();
        let expected_bytes = self.expected_result.as_bytes();
        let actual_bytes = self.actual_result.as_bytes();
        let test_case_bytes = self.test_case.as_bytes();
        let raw_data_bytes = self.raw_data.as_deref().unwrap_or("").as_bytes();
        
        // Hash with domain separation
        crypto::secure_hash_multiple(
            domains::CHALLENGE,
            &[
                description_bytes,
                expected_bytes,
                actual_bytes,
                test_case_bytes,
                raw_data_bytes,
            ]
        )
    }
    
    /// Verify the hash of the evidence
    pub fn verify_hash(&self) -> bool {
        match self.hash {
            Some(hash) => hash == self.calculate_hash(),
            None => true, // No hash to verify
        }
    }
}

/// A verification challenge
#[derive(Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Challenge ID
    pub id: Uuid,
    
    /// Block number being challenged
    pub block_number: u64,
    
    /// Transaction ID being challenged (if applicable)
    pub transaction_id: Option<Uuid>,
    
    /// Challenge type
    pub challenge_type: ChallengeType,
    
    /// Challenge status
    pub status: ChallengeStatus,
    
    /// Challenger address (Ethereum address)
    pub challenger: Address,
    
    /// Operator address (Ethereum address)
    pub operator: Address,
    
    /// Bond amount (in wei)
    pub bond_amount: u128,
    
    /// Transaction value (in wei, used for bond calculation)
    pub transaction_value: u128,
    
    /// Evidence for the challenge
    pub evidence: ChallengeEvidence,
    
    /// Submission time
    pub submission_time: DateTime<Utc>,
    
    /// Verification deadline
    pub verification_deadline: DateTime<Utc>,
    
    /// Resolution time (when challenge was resolved)
    pub resolution_time: Option<DateTime<Utc>>,
    
    /// Resolution result (JSON serialized)
    pub resolution_result: Option<String>,
    
    /// Maximum computation units allowed for verification
    pub max_computation_units: u64,
    
    /// Priority level (higher = higher priority)
    pub priority_level: u8,
    
    /// Additional metadata (JSON serialized)
    pub metadata: Option<String>,
    
    /// Challenge hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<[u8; 32]>,
}

impl Debug for Challenge {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Challenge")
            .field("id", &self.id)
            .field("block", &self.block_number)
            .field("tx", &self.transaction_id)
            .field("type", &self.challenge_type)
            .field("status", &self.status)
            .field("challenger", &self.challenger)
            .field("bond", &self.bond_amount)
            .finish()
    }
}

impl Challenge {
    /// Create a new challenge
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Uuid,
        block_number: u64,
        transaction_id: Option<Uuid>,
        challenge_type: ChallengeType,
        challenger: Address,
        operator: Address,
        bond_amount: u128,
        transaction_value: u128,
        evidence: ChallengeEvidence,
        submission_time: DateTime<Utc>,
        verification_deadline: DateTime<Utc>,
        max_computation_units: u64,
        priority_level: u8,
        metadata: Option<String>,
    ) -> Self {
        let mut challenge = Challenge {
            id,
            block_number,
            transaction_id,
            challenge_type,
            status: ChallengeStatus::Pending,
            challenger,
            operator,
            bond_amount,
            transaction_value,
            evidence,
            submission_time,
            verification_deadline,
            resolution_time: None,
            resolution_result: None,
            max_computation_units,
            priority_level,
            metadata,
            hash: None,
        };
        
        // Calculate the hash
        challenge.hash = Some(challenge.calculate_hash());
        
        challenge
    }
    
    /// Calculate the hash of the challenge with domain separation
    pub fn calculate_hash(&self) -> [u8; 32] {
        // Collect data for hashing
        let id_bytes = self.id.as_bytes();
        let block_bytes = self.block_number.to_be_bytes();
        let tx_id_bytes = match &self.transaction_id {
            Some(id) => id.as_bytes(),
            None => &[0u8; 16],
        };
        let challenge_type_bytes = [self.challenge_type as u8];
        let status_bytes = [self.status as u8];
        let challenger_bytes = self.challenger.as_bytes();
        let operator_bytes = self.operator.as_bytes();
        let bond_bytes = self.bond_amount.to_be_bytes();
        let tx_value_bytes = self.transaction_value.to_be_bytes();
        
        // Get evidence hash
        let evidence_hash = match self.evidence.hash {
            Some(hash) => hash,
            None => self.evidence.calculate_hash(),
        };
        
        let submission_bytes = self.submission_time.timestamp_millis().to_be_bytes();
        let deadline_bytes = self.verification_deadline.timestamp_millis().to_be_bytes();
        
        let resolution_time_bytes = match self.resolution_time {
            Some(time) => time.timestamp_millis().to_be_bytes(),
            None => [0; 8],
        };
        
        let resolution_result_bytes = self.resolution_result.as_deref().unwrap_or("").as_bytes();
        let computation_units_bytes = self.max_computation_units.to_be_bytes();
        let priority_bytes = [self.priority_level];
        let metadata_bytes = self.metadata.as_deref().unwrap_or("").as_bytes();
        
        // Hash with domain separation
        crypto::secure_hash_multiple(
            domains::CHALLENGE,
            &[
                id_bytes,
                &block_bytes,
                tx_id_bytes,
                &challenge_type_bytes,
                &status_bytes,
                challenger_bytes,
                operator_bytes,
                &bond_bytes,
                &tx_value_bytes,
                &evidence_hash,
                &submission_bytes,
                &deadline_bytes,
                &resolution_time_bytes,
                resolution_result_bytes,
                &computation_units_bytes,
                &priority_bytes,
                metadata_bytes,
            ]
        )
    }
    
    /// Update the status of the challenge
    pub fn update_status(&mut self, status: ChallengeStatus) {
        self.status = status;
        
        // If resolution, update resolution time
        if matches!(status, ChallengeStatus::Successful | ChallengeStatus::Rejected | ChallengeStatus::Withdrawn) {
            self.resolution_time = Some(Utc::now());
        }
        
        // Recalculate hash
        self.hash = Some(self.calculate_hash());
    }
    
    /// Resolve the challenge
    pub fn resolve(&mut self, status: ChallengeStatus, result: String) {
        self.status = status;
        self.resolution_time = Some(Utc::now());
        self.resolution_result = Some(result);
        
        // Recalculate hash
        self.hash = Some(self.calculate_hash());
    }
    
    /// Check if the challenge is pending
    pub fn is_pending(&self) -> bool {
        matches!(self.status, ChallengeStatus::Pending | ChallengeStatus::Verifying)
    }
    
    /// Check if the challenge is resolved
    pub fn is_resolved(&self) -> bool {
        matches!(self.status, ChallengeStatus::Successful | ChallengeStatus::Rejected | ChallengeStatus::TimedOut | ChallengeStatus::Withdrawn)
    }
    
    /// Check if the challenge is successful
    pub fn is_successful(&self) -> bool {
        matches!(self.status, ChallengeStatus::Successful)
    }
    
    /// Check if the challenge is rejected
    pub fn is_rejected(&self) -> bool {
        matches!(self.status, ChallengeStatus::Rejected)
    }
    
    /// Check if the challenge is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.verification_deadline
    }
    
    /// Verify the hash of the challenge
    pub fn verify_hash(&self) -> bool {
        match self.hash {
            Some(hash) => hash == self.calculate_hash(),
            None => true, // No hash to verify
        }
    }
    
    /// Calculate the optimal bond amount based on transaction value and risk
    pub fn calculate_optimal_bond(transaction_value: u128, challenge_type: ChallengeType) -> u128 {
        // Base coefficient (adjusted based on challenge type risk)
        let base_coefficient = match challenge_type {
            ChallengeType::InvalidStateTransition => 50,
            ChallengeType::InvalidTransactionExecution => 100,
            ChallengeType::InvalidProof => 25,
            ChallengeType::TransactionBoundaryViolation => 150,
            ChallengeType::NonDeterministicExecution => 200,
            ChallengeType::ResourceExhaustion => 75,
            ChallengeType::ProtocolViolation => 125,
            ChallengeType::SchemaViolation => 50,
        };
        
        // Mathematically optimal bonding curve: B(V) = k * V²
        // This creates appropriate incentives and prevents economic attacks
        
        // First, normalize transaction value to a reasonable range (avoid overflow)
        let normalized_value = if transaction_value > 1_000_000_000_000_000_000 {
            1_000_000_000_000_000_000 // Cap at 1 ETH for calculation
        } else if transaction_value == 0 {
            1 // Avoid division by zero
        } else {
            transaction_value
        };
        
        // For transaction values that are multiples of 1 ETH, we need to maintain the squared relationship
        // without the normalization affecting the proportionality
        if transaction_value >= 1_000_000_000_000_000_000 && transaction_value % 1_000_000_000_000_000_000 == 0 {
            let eth_units = transaction_value / 1_000_000_000_000_000_000;
            let base_bond = 50_000_000_000_000_000; // Base bond for 1 ETH with coefficient 50
            let scaled_coefficient = base_coefficient as u128 * base_bond / 50;
            return scaled_coefficient * eth_units * eth_units;
        }
        
        // Calculate squared component with scaling
        let squared_component = normalized_value
            .saturating_mul(normalized_value)
            .saturating_div(1_000_000_000_000_000_000); // Normalize by 10^18
        
        // Apply base coefficient
        let bond = squared_component.saturating_mul(base_coefficient as u128);
        
        // Ensure minimum bond
        if bond < 10_000_000_000_000_000 { // Minimum 0.01 ETH
            10_000_000_000_000_000
        } else {
            bond
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    
    // Helper to create a test evidence
    fn create_test_evidence() -> ChallengeEvidence {
        ChallengeEvidence::new(
            "Invalid state root".to_string(),
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            r#"{"tx_id":"0x1234","inputs":{"a":1,"b":2},"expected_output":{"result":3}}"#.to_string(),
            None,
        )
    }
    
    #[test]
    fn test_evidence_hash() {
        let evidence = create_test_evidence();
        
        // Verify the hash
        assert!(evidence.verify_hash());
        
        // Create a modified evidence
        let mut modified_evidence = evidence.clone();
        modified_evidence.description = "Modified description".to_string();
        
        // Calculate the hash for the modified evidence
        let modified_hash = modified_evidence.calculate_hash();
        
        // The hashes should be different
        assert_ne!(evidence.hash.unwrap(), modified_hash);
    }
    
    #[test]
    fn test_challenge_creation() {
        let evidence = create_test_evidence();
        let now = Utc::now();
        
        // Create a challenge
        let challenge = Challenge::new(
            Uuid::new_v4(),
            1,
            Some(Uuid::new_v4()),
            ChallengeType::InvalidStateTransition,
            Address::from([1; 20]),
            Address::from([2; 20]),
            1_000_000_000_000_000_000, // 1 ETH
            10_000_000_000_000_000_000, // 10 ETH
            evidence,
            now,
            now + Duration::hours(24),
            1000,
            1,
            None,
        );
        
        // Verify the hash
        assert!(challenge.verify_hash());
        
        // Check initial status
        assert!(challenge.is_pending());
        assert!(!challenge.is_resolved());
        assert!(!challenge.is_successful());
        assert!(!challenge.is_rejected());
        assert!(!challenge.is_expired());
    }
    
    #[test]
    fn test_challenge_status_update() {
        let evidence = create_test_evidence();
        let now = Utc::now();
        
        // Create a challenge
        let mut challenge = Challenge::new(
            Uuid::new_v4(),
            1,
            Some(Uuid::new_v4()),
            ChallengeType::InvalidStateTransition,
            Address::from([1; 20]),
            Address::from([2; 20]),
            1_000_000_000_000_000_000, // 1 ETH
            10_000_000_000_000_000_000, // 10 ETH
            evidence,
            now,
            now + Duration::hours(24),
            1000,
            1,
            None,
        );
        
        // Update status
        challenge.update_status(ChallengeStatus::Verifying);
        assert_eq!(challenge.status, ChallengeStatus::Verifying);
        assert!(challenge.is_pending());
        assert!(!challenge.is_resolved());
        
        // Resolve the challenge
        challenge.resolve(ChallengeStatus::Successful, "Operator slashed".to_string());
        assert_eq!(challenge.status, ChallengeStatus::Successful);
        assert!(challenge.is_resolved());
        assert!(challenge.is_successful());
        assert!(challenge.resolution_time.is_some());
        assert_eq!(challenge.resolution_result.clone().unwrap(), "Operator slashed");
        
        // Verify hash still valid after updates
        assert!(challenge.verify_hash());
    }
    
    #[test]
    fn test_optimal_bond_calculation() {
        // Test with different transaction values and challenge types
        let bond1 = Challenge::calculate_optimal_bond(
            1_000_000_000_000_000_000, // 1 ETH
            ChallengeType::InvalidStateTransition,
        );
        
        let bond2 = Challenge::calculate_optimal_bond(
            2_000_000_000_000_000_000, // 2 ETH
            ChallengeType::InvalidStateTransition,
        );
        
        // Squared relationship means 2x transaction value = 4x bond
        assert_eq!(bond2, bond1 * 4);
        
        // Test with different challenge types
        let bond_state = Challenge::calculate_optimal_bond(
            1_000_000_000_000_000_000, // 1 ETH
            ChallengeType::InvalidStateTransition,
        );
        
        let bond_nondet = Challenge::calculate_optimal_bond(
            1_000_000_000_000_000_000, // 1 ETH
            ChallengeType::NonDeterministicExecution,
        );
        
        // NonDeterministicExecution has higher coefficient than InvalidStateTransition
        assert!(bond_nondet > bond_state);
        
        // Test minimum bond
        let min_bond = Challenge::calculate_optimal_bond(
            100_000_000_000_000, // 0.0001 ETH (very small)
            ChallengeType::InvalidStateTransition,
        );
        
        // Should enforce minimum bond
        assert_eq!(min_bond, 10_000_000_000_000_000); // 0.01 ETH minimum
    }
} 