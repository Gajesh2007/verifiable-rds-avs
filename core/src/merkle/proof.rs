//! Merkle tree proof implementation
//!
//! This module provides a proof structure for verifying inclusion in a Merkle tree.

use std::fmt::{Debug, Formatter, Result as FmtResult};
use serde::{Serialize, Deserialize};

use crate::crypto;
use super::domains;

/// Direction of a proof item (left or right)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofDirection {
    /// Proof item is the left child
    Left,
    
    /// Proof item is the right child
    Right,
}

/// Item in a Merkle proof
#[derive(Clone, Serialize, Deserialize)]
pub struct ProofItem {
    /// Hash of the sibling node
    pub hash: [u8; 32],
    
    /// Direction of the sibling (whether it's a left or right child)
    pub direction: ProofDirection,
}

impl Debug for ProofItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "ProofItem {{ hash: {}, direction: {:?} }}",
            hex::encode(&self.hash[0..4]), // Show first 4 bytes of hash
            self.direction
        )
    }
}

/// A proof of inclusion in a Merkle tree
#[derive(Clone, Serialize, Deserialize)]
pub struct SecureMerkleProof {
    /// The leaf data being proven
    pub leaf_data: Vec<u8>,
    
    /// The position of the leaf in the tree
    pub position: usize,
    
    /// The proof items (siblings along the path from leaf to root)
    pub items: Vec<ProofItem>,
}

impl Debug for SecureMerkleProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "SecureMerkleProof {{ position: {}, items: {:?} }}",
            self.position,
            self.items
        )
    }
}

impl SecureMerkleProof {
    /// Create a new proof
    pub fn new(leaf_data: Vec<u8>, position: usize, items: Vec<ProofItem>) -> Self {
        SecureMerkleProof {
            leaf_data,
            position,
            items,
        }
    }
    
    /// Verify the proof against a given root hash
    pub fn verify(&self, root_hash: &[u8; 32]) -> bool {
        // Generate the expected leaf hash
        let leaf_hash = crypto::secure_hash(domains::LEAF_NODE, &self.leaf_data);
        
        // Calculate the root hash from the proof
        let mut current_hash = leaf_hash;
        
        for item in &self.items {
            match item.direction {
                ProofDirection::Left => {
                    // Current is the right child, sibling is the left child
                    current_hash = crypto::secure_hash_multiple(
                        domains::INTERNAL_NODE,
                        &[&item.hash, &current_hash]
                    );
                }
                ProofDirection::Right => {
                    // Current is the left child, sibling is the right child
                    current_hash = crypto::secure_hash_multiple(
                        domains::INTERNAL_NODE,
                        &[&current_hash, &item.hash]
                    );
                }
            }
        }
        
        // Apply final root domain separation
        let calculated_root = crypto::secure_hash(domains::ROOT_NODE, &current_hash);
        
        // Compare with the provided root hash
        calculated_root == *root_hash
    }
    
    /// Get the leaf hash (with domain separation)
    pub fn leaf_hash(&self) -> [u8; 32] {
        crypto::secure_hash(domains::LEAF_NODE, &self.leaf_data)
    }
    
    /// Calculate the root hash from the proof
    pub fn calculate_root(&self) -> [u8; 32] {
        let mut current_hash = self.leaf_hash();
        
        for item in &self.items {
            match item.direction {
                ProofDirection::Left => {
                    // Current is the right child, sibling is the left child
                    current_hash = crypto::secure_hash_multiple(
                        domains::INTERNAL_NODE,
                        &[&item.hash, &current_hash]
                    );
                }
                ProofDirection::Right => {
                    // Current is the left child, sibling is the right child
                    current_hash = crypto::secure_hash_multiple(
                        domains::INTERNAL_NODE,
                        &[&current_hash, &item.hash]
                    );
                }
            }
        }
        
        // Apply final root domain separation
        crypto::secure_hash(domains::ROOT_NODE, &current_hash)
    }
    
    /// Get the number of proof items
    pub fn len(&self) -> usize {
        self.items.len()
    }
    
    /// Check if the proof is empty
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_proof_verification() {
        // Create a simple proof (mimicking a tree with the following structure:
        //        root
        //       /    \
        //     n1      n2
        //    / \     / \
        //   a   b   c   d
        
        // We want to prove 'a' exists
        let leaf_data = b"a".to_vec();
        let leaf_hash = crypto::secure_hash(domains::LEAF_NODE, &leaf_data);
        
        // Create hash for 'b'
        let b_hash = crypto::secure_hash(domains::LEAF_NODE, b"b");
        
        // Create hash for 'n2'
        let c_hash = crypto::secure_hash(domains::LEAF_NODE, b"c");
        let d_hash = crypto::secure_hash(domains::LEAF_NODE, b"d");
        let n2_hash = crypto::secure_hash_multiple(
            domains::INTERNAL_NODE,
            &[&c_hash, &d_hash]
        );
        
        // Calculate n1 hash (will be used to calculate root)
        let n1_hash = crypto::secure_hash_multiple(
            domains::INTERNAL_NODE,
            &[&leaf_hash, &b_hash]
        );
        
        // Calculate root hash
        let root_internal = crypto::secure_hash_multiple(
            domains::INTERNAL_NODE,
            &[&n1_hash, &n2_hash]
        );
        let root_hash = crypto::secure_hash(domains::ROOT_NODE, &root_internal);
        
        // Create the proof for 'a'
        let items = vec![
            ProofItem {
                hash: b_hash,
                direction: ProofDirection::Right,
            },
            ProofItem {
                hash: n2_hash,
                direction: ProofDirection::Right,
            },
        ];
        
        let proof = SecureMerkleProof::new(leaf_data, 0, items);
        
        // Verify the proof
        assert!(proof.verify(&root_hash));
        
        // Tamper with the proof data
        let mut tampered_proof = proof.clone();
        tampered_proof.leaf_data = b"x".to_vec();
        
        // The proof should no longer verify
        assert!(!tampered_proof.verify(&root_hash));
        
        // Tamper with a proof item
        let mut tampered_proof2 = proof.clone();
        tampered_proof2.items[0].hash[0] ^= 0xFF; // Flip bits
        
        // The proof should no longer verify
        assert!(!tampered_proof2.verify(&root_hash));
    }
    
    #[test]
    fn test_calculate_root() {
        // Similar setup as the previous test
        let leaf_data = b"a".to_vec();
        let leaf_hash = crypto::secure_hash(domains::LEAF_NODE, &leaf_data);
        
        let b_hash = crypto::secure_hash(domains::LEAF_NODE, b"b");
        
        let c_hash = crypto::secure_hash(domains::LEAF_NODE, b"c");
        let d_hash = crypto::secure_hash(domains::LEAF_NODE, b"d");
        let n2_hash = crypto::secure_hash_multiple(
            domains::INTERNAL_NODE,
            &[&c_hash, &d_hash]
        );
        
        let n1_hash = crypto::secure_hash_multiple(
            domains::INTERNAL_NODE,
            &[&leaf_hash, &b_hash]
        );
        
        let root_internal = crypto::secure_hash_multiple(
            domains::INTERNAL_NODE,
            &[&n1_hash, &n2_hash]
        );
        let expected_root = crypto::secure_hash(domains::ROOT_NODE, &root_internal);
        
        // Create the proof for 'a'
        let items = vec![
            ProofItem {
                hash: b_hash,
                direction: ProofDirection::Right,
            },
            ProofItem {
                hash: n2_hash,
                direction: ProofDirection::Right,
            },
        ];
        
        let proof = SecureMerkleProof::new(leaf_data, 0, items);
        
        // Calculate the root hash
        let calculated_root = proof.calculate_root();
        
        // Verify the calculated root matches the expected root
        assert_eq!(calculated_root, expected_root);
    }
} 