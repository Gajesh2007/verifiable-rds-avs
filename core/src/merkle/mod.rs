//! Secure Merkle tree implementation with domain separation
//!
//! This module provides a cryptographically secure Merkle tree implementation
//! with domain separation for different tree elements to prevent second-preimage attacks.

mod tree;
mod proof;

pub use tree::{SecureMerkleTree, TreeNode, NodeType};
pub use proof::{SecureMerkleProof, ProofItem, ProofDirection};

/// Domain constants for Merkle tree operations
pub mod domains {
    /// Domain for leaf nodes
    pub const LEAF_NODE: &str = "VERIFIABLEDB_MERKLE_LEAF";
    
    /// Domain for internal nodes
    pub const INTERNAL_NODE: &str = "VERIFIABLEDB_MERKLE_NODE";
    
    /// Domain for empty nodes
    pub const EMPTY_NODE: &str = "VERIFIABLEDB_MERKLE_EMPTY";
    
    /// Domain for root node
    pub const ROOT_NODE: &str = "VERIFIABLEDB_MERKLE_ROOT";
    
    /// Domain for proof items
    pub const PROOF_ITEM: &str = "VERIFIABLEDB_MERKLE_PROOF";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    
    #[test]
    fn test_domain_separation() {
        // Generate hashes using different domains but same data
        let data = b"test data";
        
        let leaf_hash = crypto::secure_hash(domains::LEAF_NODE, data);
        let internal_hash = crypto::secure_hash(domains::INTERNAL_NODE, data);
        let empty_hash = crypto::secure_hash(domains::EMPTY_NODE, data);
        let root_hash = crypto::secure_hash(domains::ROOT_NODE, data);
        let proof_hash = crypto::secure_hash(domains::PROOF_ITEM, data);
        
        // All hashes should be different
        assert_ne!(leaf_hash, internal_hash);
        assert_ne!(leaf_hash, empty_hash);
        assert_ne!(leaf_hash, root_hash);
        assert_ne!(leaf_hash, proof_hash);
        assert_ne!(internal_hash, empty_hash);
        assert_ne!(internal_hash, root_hash);
        assert_ne!(internal_hash, proof_hash);
        assert_ne!(empty_hash, root_hash);
        assert_ne!(empty_hash, proof_hash);
        assert_ne!(root_hash, proof_hash);
    }
} 