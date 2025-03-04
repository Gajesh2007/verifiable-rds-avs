//! Secure Merkle tree implementation
//! 
//! This module provides a cryptographically secure Merkle tree implementation for
//! database state verification, with domain separation and protection against
//! various attacks.

use crate::error::{ProxyError, Result};
use log::{debug, warn, info};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Domain separators to prevent second-preimage attacks
const LEAF_DOMAIN: &[u8; 4] = b"LEAF";
const NODE_DOMAIN: &[u8; 4] = b"NODE";

/// Position of a node in the Merkle tree
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct NodePosition {
    /// Level in the tree (0 = leaves)
    pub level: u8,
    
    /// Index at this level
    pub index: u64,
}

/// A Merkle tree leaf
#[derive(Debug, Clone)]
pub struct MerkleLeaf {
    /// Data in the leaf
    pub data: Vec<u8>,
    
    /// Hash of the leaf
    pub hash: [u8; 32],
    
    /// Index of the leaf
    pub index: u64,
}

/// A node in a Merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofNode {
    /// Hash of the sibling
    pub sibling_hash: [u8; 32],
    
    /// Whether the sibling is on the left
    pub is_left: bool,
}

/// A proof of inclusion in a Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Leaf hash being proven
    pub leaf_hash: [u8; 32],
    
    /// Path from leaf to root
    pub path: Vec<ProofNode>,
    
    /// Expected root hash
    pub root_hash: [u8; 32],
    
    /// Leaf index
    pub leaf_index: u64,
    
    /// Total number of leaves in the tree
    pub leaf_count: u64,
    
    /// Whether the proof has been verified
    pub verified: bool,
}

/// A secure Merkle tree
/// Uses domain separation and salting to prevent second-preimage attacks
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Leaves of the tree
    leaves: Vec<MerkleLeaf>,
    
    /// Internal nodes of the tree, organized by level and index
    nodes: HashMap<NodePosition, [u8; 32]>,
    
    /// Root hash of the tree
    root: Option<[u8; 32]>,
    
    /// Height of the tree
    height: u8,
    
    /// Salt for added security
    salt: [u8; 32],
    
    /// Whether the tree has been built
    built: bool,
}

impl MerkleTree {
    /// Create a new empty Merkle tree
    pub fn new() -> Self {
        // Generate a random salt for added security
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt).expect("Failed to generate random salt");
        
        Self {
            leaves: Vec::new(),
            nodes: HashMap::new(),
            root: None,
            height: 0,
            salt,
            built: false,
        }
    }
    
    /// Create a new Merkle tree with a specific salt
    pub fn with_salt(salt: [u8; 32]) -> Self {
        Self {
            leaves: Vec::new(),
            nodes: HashMap::new(),
            root: None,
            height: 0,
            salt,
            built: false,
        }
    }
    
    /// Add a leaf to the tree
    pub fn add_leaf(&mut self, data: Vec<u8>) -> u64 {
        if self.built {
            warn!("Adding leaf to already built tree. This will trigger a rebuild.");
            self.built = false;
        }
        
        let index = self.leaves.len() as u64;
        let hash = self.hash_leaf(&data);
        
        self.leaves.push(MerkleLeaf {
            data,
            hash,
            index,
        });
        
        index
    }
    
    /// Build the tree
    pub fn build(&mut self) -> Result<()> {
        if self.leaves.is_empty() {
            return Err(ProxyError::Verification("Cannot build tree with no leaves".to_string()));
        }
        
        if self.built {
            // Already built
            return Ok(());
        }
        
        // Clear existing nodes
        self.nodes.clear();
        
        // Calculate the height of the tree
        self.height = (self.leaves.len() as f64).log2().ceil() as u8;
        
        // Insert leaf hashes as level 0
        for (index, leaf) in self.leaves.iter().enumerate() {
            self.nodes.insert(
                NodePosition { level: 0, index: index as u64 },
                leaf.hash,
            );
        }
        
        // Build each level of the tree
        let mut current_level_size = self.leaves.len();
        for level in 1..=self.height {
            let parent_level_size = (current_level_size + 1) / 2;
            
            for parent_index in 0..parent_level_size {
                let left_index = parent_index * 2;
                let right_index = left_index + 1;
                
                let left_pos = NodePosition { level: level - 1, index: left_index as u64 };
                let right_pos = NodePosition { level: level - 1, index: right_index as u64 };
                
                let left_hash = self.nodes.get(&left_pos)
                    .ok_or_else(|| ProxyError::Verification(format!(
                        "Missing left child at level {} index {}", level - 1, left_index
                    )))?;
                
                let right_hash = if right_index < current_level_size {
                    self.nodes.get(&right_pos)
                        .ok_or_else(|| ProxyError::Verification(format!(
                            "Missing right child at level {} index {}", level - 1, right_index
                        )))?
                } else {
                    // If there's no right child, use the left child (padding)
                    left_hash
                };
                
                let parent_hash = self.hash_node(left_hash, right_hash);
                self.nodes.insert(
                    NodePosition { level, index: parent_index as u64 },
                    parent_hash,
                );
            }
            
            current_level_size = parent_level_size;
        }
        
        // Set the root hash
        self.root = self.nodes.get(&NodePosition { level: self.height, index: 0 }).cloned();
        self.built = true;
        
        Ok(())
    }
    
    /// Get the root hash of the tree
    pub fn root_hash(&self) -> Option<[u8; 32]> {
        if !self.built {
            None
        } else {
            self.root
        }
    }
    
    /// Generate a Merkle proof for a leaf
    pub fn generate_proof(&self, leaf_index: u64) -> Result<MerkleProof> {
        if !self.built {
            return Err(ProxyError::Verification("Tree not built".to_string()));
        }
        
        if leaf_index >= self.leaves.len() as u64 {
            return Err(ProxyError::Verification(format!(
                "Leaf index {} out of bounds (max {})", 
                leaf_index, self.leaves.len() - 1
            )));
        }
        
        let leaf = &self.leaves[leaf_index as usize];
        let mut path = Vec::new();
        
        let mut current_index = leaf_index;
        
        for level in 0..self.height {
            let sibling_index = if current_index % 2 == 0 {
                // Current node is left child, sibling is right
                current_index + 1
            } else {
                // Current node is right child, sibling is left
                current_index - 1
            };
            
            let sibling_pos = NodePosition { level, index: sibling_index };
            
            // If the sibling exists, use it; otherwise use a dummy hash
            let sibling_hash = if sibling_index < self.node_count_at_level(level) {
                *self.nodes.get(&sibling_pos).ok_or_else(|| {
                    ProxyError::Verification(format!(
                        "Missing sibling at level {} index {}", level, sibling_index
                    ))
                })?
            } else {
                // This shouldn't happen with a properly built tree
                // But just in case, use a dummy hash
                [0; 32]
            };
            
            path.push(ProofNode {
                sibling_hash,
                is_left: current_index % 2 == 1, // Sibling is left if current is right
            });
            
            // Move to parent
            current_index /= 2;
        }
        
        let root_hash = self.root.ok_or_else(|| {
            ProxyError::Verification("Tree has no root".to_string())
        })?;
        
        Ok(MerkleProof {
            leaf_hash: leaf.hash,
            path,
            root_hash,
            leaf_index,
            leaf_count: self.leaves.len() as u64,
            verified: false,
        })
    }
    
    /// Verify a Merkle proof
    pub fn verify_proof(&self, proof: &MerkleProof) -> Result<bool> {
        // Start with the leaf hash
        let mut current_hash = proof.leaf_hash;
        
        // Apply each step in the proof path
        for node in &proof.path {
            if node.is_left {
                // Sibling is on the left
                current_hash = self.hash_node(&node.sibling_hash, &current_hash);
            } else {
                // Sibling is on the right
                current_hash = self.hash_node(&current_hash, &node.sibling_hash);
            }
        }
        
        // Check if the computed root matches the expected root
        Ok(current_hash == proof.root_hash)
    }
    
    /// Calculate the number of nodes at a specific level
    fn node_count_at_level(&self, level: u8) -> u64 {
        let leaf_count = self.leaves.len() as u64;
        (leaf_count + (1 << level) - 1) >> level
    }
    
    /// Hash a leaf with domain separation
    pub fn hash_leaf(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        // Use domain separation to prevent second-preimage attacks
        hasher.update(LEAF_DOMAIN);
        
        // Add salt for extra security
        hasher.update(&self.salt);
        
        // Add the leaf index for domain separation between leaves
        let index = self.leaves.len() as u64;
        let index_bytes = index.to_be_bytes();
        hasher.update(&index_bytes);
        
        // Add the actual data
        hasher.update(data);
        
        let result = hasher.finalize();
        
        let mut hash = [0; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Hash two child nodes with domain separation
    pub fn hash_node(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        // Use domain separation to prevent second-preimage attacks
        hasher.update(NODE_DOMAIN);
        
        // Add salt for extra security
        hasher.update(&self.salt);
        
        // Add the left and right child hashes
        hasher.update(left);
        hasher.update(right);
        
        let result = hasher.finalize();
        
        let mut hash = [0; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Get the number of leaves in the tree
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }
    
    /// Check if the tree is built
    pub fn is_built(&self) -> bool {
        self.built
    }
    
    /// Get the height of the tree
    pub fn height(&self) -> u8 {
        self.height
    }
    
    /// Get the leaf at the specified index
    pub fn get_leaf(&self, index: u64) -> Option<&MerkleLeaf> {
        self.leaves.get(index as usize)
    }
    
    /// Clear the tree
    pub fn clear(&mut self) {
        self.leaves.clear();
        self.nodes.clear();
        self.root = None;
        self.height = 0;
        self.built = false;
    }
    
    /// Rebuild the tree after making changes
    pub fn rebuild(&mut self) -> Result<()> {
        self.built = false;
        self.build()
    }
    
    /// Update a leaf and rebuild only the affected path
    pub fn update_leaf(&mut self, index: u64, data: Vec<u8>) -> Result<()> {
        if index >= self.leaves.len() as u64 {
            return Err(ProxyError::Verification(format!(
                "Leaf index {} out of bounds (max {})", 
                index, self.leaves.len() - 1
            )));
        }
        
        // Update the leaf
        let new_hash = self.hash_leaf(&data);
        self.leaves[index as usize] = MerkleLeaf {
            data,
            hash: new_hash,
            index,
        };
        
        // Update the node at level 0
        self.nodes.insert(
            NodePosition { level: 0, index },
            new_hash,
        );
        
        // Update the path to the root
        let mut current_index = index;
        for level in 1..=self.height {
            let parent_index = current_index / 2;
            let sibling_index = if current_index % 2 == 0 { current_index + 1 } else { current_index - 1 };
            
            let sibling_pos = NodePosition { level: level - 1, index: sibling_index };
            let current_pos = NodePosition { level: level - 1, index: current_index };
            let parent_pos = NodePosition { level, index: parent_index };
            
            // Get the current and sibling hashes
            let current_hash = self.nodes.get(&current_pos)
                .ok_or_else(|| ProxyError::Verification(format!(
                    "Missing current node at level {} index {}", level - 1, current_index
                )))?;
            
            let sibling_hash = if sibling_index < self.node_count_at_level(level - 1) {
                *self.nodes.get(&sibling_pos).unwrap_or(current_hash)
            } else {
                *current_hash // Use current hash as padding if sibling doesn't exist
            };
            
            // Calculate new parent hash
            let parent_hash = if current_index % 2 == 0 {
                self.hash_node(current_hash, &sibling_hash)
            } else {
                self.hash_node(&sibling_hash, current_hash)
            };
            
            // Update parent
            self.nodes.insert(parent_pos, parent_hash);
            
            // Move to parent for next iteration
            current_index = parent_index;
        }
        
        // Update root
        self.root = self.nodes.get(&NodePosition { level: self.height, index: 0 }).cloned();
        
        Ok(())
    }
}

/// Create a Sparse Merkle Tree for efficient updates
pub struct SparseMerkleTree {
    /// Default hashes at each level
    default_hashes: Vec<[u8; 32]>,
    
    /// Non-empty nodes
    nodes: HashMap<NodePosition, [u8; 32]>,
    
    /// Height of the tree
    height: u8,
    
    /// Salt for security
    salt: [u8; 32],
}

impl SparseMerkleTree {
    /// Create a new sparse Merkle tree with the specified height
    pub fn new(height: u8) -> Self {
        // Generate a random salt
        let mut salt = [0u8; 32];
        // In a real implementation, use a secure random source
        for i in 0..32 {
            salt[i] = i as u8;
        }
        
        Self::new_with_salt(height, salt)
    }
    
    pub fn new_with_salt(height: u8, salt: [u8; 32]) -> Self {
        // Initialize default hashes
        let mut default_hashes = vec![[0u8; 32]; height as usize + 1];
        
        // Calculate default hash for each level
        for level in 0..=height as usize {
            if level == 0 {
                // Empty leaf hash
                let mut hasher = Sha256::new();
                hasher.update(&salt);
                hasher.update(b"empty_leaf");
                default_hashes[level].copy_from_slice(&hasher.finalize());
            } else {
                // Default internal node hash
                let mut hasher = Sha256::new();
                hasher.update(&salt);
                hasher.update(b"default_node");
                hasher.update(&[level as u8]);
                hasher.update(&default_hashes[level - 1]);
                hasher.update(&default_hashes[level - 1]);
                default_hashes[level].copy_from_slice(&hasher.finalize());
            }
        }
        
        SparseMerkleTree {
            default_hashes,
            nodes: HashMap::new(),
            height,
            salt,
        }
    }
    
    /// Get the default hash at a specific level
    pub fn default_hash(&self, level: u8) -> [u8; 32] {
        self.default_hashes[level as usize]
    }
    
    /// Update a leaf in the tree
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<[u8; 32]> {
        // Calculate the leaf hash
        let mut hasher = Sha256::new();
        hasher.update(LEAF_DOMAIN);
        hasher.update(&self.salt);
        hasher.update(value);
        
        let hash = hasher.finalize();
        let mut leaf_hash = [0; 32];
        leaf_hash.copy_from_slice(&hash);
        
        // Calculate the leaf position
        let mut path = [0u8; 32];
        {
            let mut hasher = Sha256::new();
            hasher.update(key);
            let digest = hasher.finalize();
            path.copy_from_slice(&digest);
        }
        
        // Update the leaf
        let leaf_pos = self.path_to_position(&path, 0);
        self.nodes.insert(leaf_pos, leaf_hash);
        
        // Update the path to the root
        let mut current_hash = leaf_hash;
        for level in 1..=self.height {
            let current_pos = self.path_to_position(&path, level);
            let is_right = self.is_right(&path, self.height - level);
            
            let (left_pos, right_pos) = if is_right {
                (NodePosition { level: level - 1, index: current_pos.index * 2 }, 
                 NodePosition { level: level - 1, index: current_pos.index * 2 + 1 })
            } else {
                (NodePosition { level: level - 1, index: current_pos.index * 2 }, 
                 NodePosition { level: level - 1, index: current_pos.index * 2 + 1 })
            };
            
            let left_hash = self.nodes.get(&left_pos).unwrap_or(&self.default_hashes[level as usize - 1]);
            let right_hash = self.nodes.get(&right_pos).unwrap_or(&self.default_hashes[level as usize - 1]);
            
            // Calculate the parent hash
            let mut hasher = Sha256::new();
            hasher.update(NODE_DOMAIN);
            hasher.update(&self.salt);
            hasher.update(left_hash);
            hasher.update(right_hash);
            
            let hash = hasher.finalize();
            current_hash.copy_from_slice(&hash);
            
            // Update the parent node
            self.nodes.insert(current_pos, current_hash);
        }
        
        // Return the root hash
        Ok(current_hash)
    }
    
    /// Get the root hash of the tree
    pub fn root_hash(&self) -> [u8; 32] {
        let root_pos = NodePosition { level: self.height, index: 0 };
        *self.nodes.get(&root_pos).unwrap_or(&self.default_hashes[self.height as usize])
    }
    
    /// Check if a key exists in the tree
    pub fn contains(&self, key: &[u8]) -> bool {
        let mut path = [0u8; 32];
        {
            let mut hasher = Sha256::new();
            hasher.update(key);
            let digest = hasher.finalize();
            path.copy_from_slice(&digest);
        }
        
        let leaf_pos = self.path_to_position(&path, 0);
        self.nodes.contains_key(&leaf_pos)
    }
    
    /// Generate a Merkle proof for a key
    pub fn generate_proof(&self, key: &[u8]) -> Result<Vec<ProofNode>> {
        let mut path = [0u8; 32];
        {
            let mut hasher = Sha256::new();
            hasher.update(key);
            let digest = hasher.finalize();
            path.copy_from_slice(&digest);
        }
        
        let mut proof = Vec::with_capacity(self.height as usize);
        
        for level in 0..self.height {
            let is_right = self.is_right(&path, self.height - level - 1);
            let sibling_pos = if is_right {
                NodePosition { level, index: self.path_to_index(&path, level) - 1 }
            } else {
                NodePosition { level, index: self.path_to_index(&path, level) + 1 }
            };
            
            let sibling_hash = *self.nodes.get(&sibling_pos).unwrap_or(&self.default_hashes[level as usize]);
            
            proof.push(ProofNode {
                sibling_hash,
                is_left: !is_right,
            });
        }
        
        Ok(proof)
    }
    
    /// Verify a Merkle proof
    pub fn verify_proof(&self, key: &[u8], value: &[u8], proof: &[ProofNode]) -> Result<bool> {
        if proof.len() != self.height as usize {
            return Err(ProxyError::Verification(format!(
                "Invalid proof length. Expected {}, got {}", self.height, proof.len()
            )));
        }
        
        // Calculate the leaf hash
        let mut hasher = Sha256::new();
        hasher.update(LEAF_DOMAIN);
        hasher.update(&self.salt);
        hasher.update(value);
        
        let hash = hasher.finalize();
        let mut current_hash = [0; 32];
        current_hash.copy_from_slice(&hash);
        
        // Calculate the path
        let mut path = [0u8; 32];
        {
            let mut hasher = Sha256::new();
            hasher.update(key);
            let digest = hasher.finalize();
            path.copy_from_slice(&digest);
        }
        
        // Apply the proof
        for (level, node) in proof.iter().enumerate() {
            let is_right = self.is_right(&path, self.height - level as u8 - 1);
            
            // Calculate the parent hash
            let mut hasher = Sha256::new();
            hasher.update(NODE_DOMAIN);
            hasher.update(&self.salt);
            
            if is_right {
                hasher.update(&node.sibling_hash);
                hasher.update(&current_hash);
            } else {
                hasher.update(&current_hash);
                hasher.update(&node.sibling_hash);
            }
            
            let hash = hasher.finalize();
            current_hash.copy_from_slice(&hash);
        }
        
        // Verify against the root hash
        let root_hash = self.root_hash();
        Ok(current_hash == root_hash)
    }
    
    /// Convert a path and level to a node position
    fn path_to_position(&self, path: &[u8; 32], level: u8) -> NodePosition {
        NodePosition {
            level,
            index: self.path_to_index(path, level),
        }
    }
    
    /// Convert a path and level to a node index
    fn path_to_index(&self, path: &[u8; 32], level: u8) -> u64 {
        let mut index = 0u64;
        for i in 0..level {
            index = (index << 1) | (self.is_right(path, self.height - i - 1) as u64);
        }
        index
    }
    
    /// Check if a path should go right at a specific bit
    fn is_right(&self, path: &[u8; 32], bit: u8) -> bool {
        let byte_idx = bit / 8;
        let bit_idx = bit % 8;
        (path[byte_idx as usize] & (1 << bit_idx)) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_empty_tree() {
        let mut tree = MerkleTree::new();
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.is_built(), false);
        assert_eq!(tree.root_hash(), None);
        
        // Building an empty tree should fail
        assert!(tree.build().is_err());
    }
    
    #[test]
    fn test_single_leaf() {
        let mut tree = MerkleTree::new();
        let data = b"test data".to_vec();
        
        let index = tree.add_leaf(data.clone());
        assert_eq!(index, 0);
        assert_eq!(tree.leaf_count(), 1);
        
        assert!(tree.build().is_ok());
        assert!(tree.is_built());
        assert!(tree.root_hash().is_some());
        
        // With a single leaf, the root hash should equal the leaf hash
        let leaf = tree.get_leaf(0).unwrap();
        assert_eq!(tree.root_hash().unwrap(), leaf.hash);
    }
    
    #[test]
    fn test_multiple_leaves() {
        let mut tree = MerkleTree::new();
        
        // Add some leaves
        let indices: Vec<u64> = (0..10).map(|i| {
            let data = format!("test data {}", i).into_bytes();
            tree.add_leaf(data)
        }).collect();
        
        assert_eq!(tree.leaf_count(), 10);
        assert_eq!(indices, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        
        assert!(tree.build().is_ok());
        assert!(tree.is_built());
        assert!(tree.root_hash().is_some());
        
        // Height should be ceiling of log2(10)
        assert_eq!(tree.height(), 4);
    }
    
    #[test]
    fn test_proof_verification() {
        let mut tree = MerkleTree::new();
        
        // Add some leaves
        for i in 0..10 {
            let data = format!("test data {}", i).into_bytes();
            tree.add_leaf(data);
        }
        
        assert!(tree.build().is_ok());
        
        // Generate a proof for leaf 5
        let proof = tree.generate_proof(5).unwrap();
        
        // Verify the proof
        assert!(tree.verify_proof(&proof).unwrap());
        
        // Tamper with the leaf hash
        let mut invalid_proof = proof.clone();
        let mut tampered_hash = invalid_proof.leaf_hash;
        tampered_hash[0] ^= 0xff;
        invalid_proof.leaf_hash = tampered_hash;
        
        // Verification should fail
        assert!(!tree.verify_proof(&invalid_proof).unwrap());
    }
    
    #[test]
    fn test_update_leaf() {
        let mut tree = MerkleTree::new();
        
        // Add some leaves
        for i in 0..10 {
            let data = format!("test data {}", i).into_bytes();
            tree.add_leaf(data);
        }
        
        assert!(tree.build().is_ok());
        let original_root = tree.root_hash().unwrap();
        
        // Update leaf 5
        let new_data = b"updated data".to_vec();
        assert!(tree.update_leaf(5, new_data.clone()).is_ok());
        
        // Root should have changed
        assert_ne!(tree.root_hash().unwrap(), original_root);
        
        // Leaf should have been updated
        let leaf = tree.get_leaf(5).unwrap();
        assert_eq!(leaf.data, new_data);
        
        // Generate and verify a proof for the updated leaf
        let proof = tree.generate_proof(5).unwrap();
        assert!(tree.verify_proof(&proof).unwrap());
    }
    
    #[test]
    fn test_domain_separation() {
        // Create a Merkle tree with a specific salt
        let salt = [1u8; 32];
        let mut tree = MerkleTree::with_salt(salt);
        
        // Add the same data twice
        let data = b"test data".to_vec();
        tree.add_leaf(data.clone());
        tree.add_leaf(data.clone());
        
        assert!(tree.build().is_ok());
        
        // Get the leaf hashes
        let leaf1 = tree.get_leaf(0).unwrap();
        let leaf2 = tree.get_leaf(1).unwrap();
        
        // Even though the data is identical, the leaf hashes should be different
        // because we use domain separation with index in the leaf hash
        assert_ne!(leaf1.hash, leaf2.hash);
        
        // Create a new tree with different salt
        let different_salt = [2u8; 32];
        let mut tree2 = MerkleTree::with_salt(different_salt);
        
        // Add the same leaves
        tree2.add_leaf(data.clone());
        tree2.add_leaf(data.clone());
        
        assert!(tree2.build().is_ok());
        
        // The root hash should be different due to different salt
        assert_ne!(tree.root_hash().unwrap(), tree2.root_hash().unwrap());
    }
    
    #[test]
    fn test_sparse_merkle_tree() {
        // Create two different sparse Merkle trees with different salts
        let salt1 = [1u8; 32];
        let salt2 = [2u8; 32];
        let mut tree1 = SparseMerkleTree::new_with_salt(10, salt1); // 10 levels, 2^10 leaves
        let mut tree2 = SparseMerkleTree::new_with_salt(10, salt2); // 10 levels, 2^10 leaves
        
        // Get the initial root hashes (empty trees)
        let empty_root1 = tree1.root_hash();
        let empty_root2 = tree2.root_hash();
        
        // Root hashes should be different due to different salts
        assert_ne!(empty_root1, empty_root2);
        
        // Update some leaves in both trees
        let key = b"key1".to_vec();
        let value = b"value1".to_vec();
        
        let root1 = tree1.update(&key, &value).unwrap();
        let root2 = tree2.update(&key, &value).unwrap();
        
        // Root hashes should be different with different salts
        assert_ne!(root1, root2);
    }
} 