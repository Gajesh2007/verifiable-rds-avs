//! Secure Merkle tree implementation
//!
//! This module provides a cryptographically secure Merkle tree implementation
//! with domain separation for different tree nodes.

use std::collections::HashMap;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use serde::{Serialize, Deserialize};

use crate::crypto::{self};
use super::domains;
use super::proof::{SecureMerkleProof, ProofItem, ProofDirection};

/// Type of node in the Merkle tree
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeType {
    /// Leaf node containing actual data
    Leaf,
    
    /// Internal node with children
    Internal,
    
    /// Empty node (for sparse trees)
    Empty,
}

/// Node in the Merkle tree
#[derive(Clone, Serialize, Deserialize)]
pub struct TreeNode {
    /// Type of the node
    pub node_type: NodeType,
    
    /// Hash of the node
    pub hash: [u8; 32],
    
    /// Original data (only for leaf nodes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    
    /// Index of the node in the tree
    pub index: usize,
    
    /// Height of the node in the tree (0 for leaves)
    pub height: usize,
}

impl Debug for TreeNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "TreeNode {{ type: {:?}, hash: {}, index: {}, height: {} }}",
            self.node_type,
            hex::encode(&self.hash[0..4]), // Show first 4 bytes of hash
            self.index,
            self.height
        )
    }
}

impl TreeNode {
    /// Create a new leaf node
    pub fn new_leaf(data: &[u8], index: usize) -> Self {
        let hash = crypto::secure_hash(domains::LEAF_NODE, data);
        
        TreeNode {
            node_type: NodeType::Leaf,
            hash,
            data: Some(data.to_vec()),
            index,
            height: 0,
        }
    }
    
    /// Create a new internal node
    pub fn new_internal(left: &TreeNode, right: &TreeNode, index: usize, height: usize) -> Self {
        // Hash the concatenation of the left and right child hashes with domain separation
        let hash = crypto::secure_hash_multiple(
            domains::INTERNAL_NODE,
            &[&left.hash, &right.hash]
        );
        
        TreeNode {
            node_type: NodeType::Internal,
            hash,
            data: None,
            index,
            height,
        }
    }
    
    /// Create a new empty node
    pub fn new_empty(height: usize, index: usize) -> Self {
        // Use height in the empty node hash for different default values at different heights
        let height_bytes = height.to_be_bytes();
        let index_bytes = index.to_be_bytes();
        
        let hash = crypto::secure_hash_multiple(
            domains::EMPTY_NODE,
            &[&height_bytes, &index_bytes]
        );
        
        TreeNode {
            node_type: NodeType::Empty,
            hash,
            data: None,
            index,
            height,
        }
    }
    
    /// Check if the node is a leaf
    pub fn is_leaf(&self) -> bool {
        self.node_type == NodeType::Leaf
    }
    
    /// Check if the node is an internal node
    pub fn is_internal(&self) -> bool {
        self.node_type == NodeType::Internal
    }
    
    /// Check if the node is empty
    pub fn is_empty(&self) -> bool {
        self.node_type == NodeType::Empty
    }
}

/// A cryptographically secure Merkle tree with domain separation
#[derive(Clone, Serialize, Deserialize)]
pub struct SecureMerkleTree {
    /// Nodes of the tree
    nodes: HashMap<usize, TreeNode>,
    
    /// Root hash of the tree
    root_hash: [u8; 32],
    
    /// Height of the tree
    height: usize,
    
    /// Number of leaves
    num_leaves: usize,
    
    /// Maximum number of leaves
    max_leaves: usize,
}

impl Debug for SecureMerkleTree {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "SecureMerkleTree {{ root_hash: {}, height: {}, num_leaves: {}, max_leaves: {} }}",
            hex::encode(&self.root_hash[0..4]), // Show first 4 bytes of hash
            self.height,
            self.num_leaves,
            self.max_leaves
        )
    }
}

impl SecureMerkleTree {
    /// Create a new empty Merkle tree with a specified capacity
    pub fn new(capacity: usize) -> Self {
        // Calculate the minimum height needed for the capacity
        let height = (capacity as f64).log2().ceil() as usize;
        let max_leaves = 2_usize.pow(height as u32);
        
        // Create an empty tree with the calculated height
        let mut tree = SecureMerkleTree {
            nodes: HashMap::new(),
            root_hash: [0; 32],
            height,
            num_leaves: 0,
            max_leaves,
        };
        
        // Create the empty root node
        let root_node = TreeNode::new_empty(height, 1);
        tree.root_hash = root_node.hash;
        tree.nodes.insert(1, root_node);
        
        tree
    }
    
    /// Create a new Merkle tree from a list of data items
    pub fn from_leaves(leaves: &[Vec<u8>]) -> Self {
        let capacity = leaves.len();
        let mut tree = Self::new(capacity);
        
        for (i, leaf_data) in leaves.iter().enumerate() {
            tree.update_leaf(i, leaf_data);
        }
        
        tree
    }
    
    /// Get the root hash of the tree
    pub fn root_hash(&self) -> [u8; 32] {
        // Apply domain separation to the root hash for additional security
        crypto::secure_hash(domains::ROOT_NODE, &self.root_hash)
    }
    
    /// Get the number of leaves in the tree
    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }
    
    /// Get the maximum number of leaves the tree can hold
    pub fn max_leaves(&self) -> usize {
        self.max_leaves
    }
    
    /// Get the height of the tree
    pub fn height(&self) -> usize {
        self.height
    }
    
    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.num_leaves == 0
    }
    
    /// Get a node by its index
    pub fn get_node(&self, index: usize) -> Option<&TreeNode> {
        self.nodes.get(&index)
    }
    
    /// Calculate the index of the left child of a node
    fn left_child_index(index: usize) -> usize {
        index * 2
    }
    
    /// Calculate the index of the right child of a node
    fn right_child_index(index: usize) -> usize {
        index * 2 + 1
    }
    
    /// Calculate the index of the parent of a node
    fn parent_index(index: usize) -> usize {
        index / 2
    }
    
    /// Calculate the index of a leaf node based on its position
    fn leaf_index(&self, position: usize) -> usize {
        let offset = 2_usize.pow(self.height as u32);
        offset + position
    }
    
    /// Get the sibling index of a node
    fn sibling_index(index: usize) -> usize {
        if index % 2 == 0 {
            // Left child, sibling is right child
            index + 1
        } else {
            // Right child, sibling is left child
            index - 1
        }
    }
    
    /// Update a leaf node and recompute the path to the root
    pub fn update_leaf(&mut self, position: usize, data: &[u8]) {
        if position >= self.max_leaves {
            panic!("Leaf position out of bounds");
        }
        
        // Calculate the index of the leaf
        let leaf_index = self.leaf_index(position);
        
        // Create the new leaf node
        let leaf_node = TreeNode::new_leaf(data, leaf_index);
        
        // Insert the leaf into the tree
        self.nodes.insert(leaf_index, leaf_node);
        
        // Update num_leaves if this is a new leaf
        if position >= self.num_leaves {
            self.num_leaves = position + 1;
        }
        
        // Update the path from the leaf to the root
        self.update_path(leaf_index);
    }
    
    /// Update the path from a leaf to the root
    fn update_path(&mut self, start_index: usize) {
        let mut current_index = start_index;
        
        // Traverse up the tree, updating each node
        while current_index > 1 {
            let parent_index = Self::parent_index(current_index);
            let sibling_index = Self::sibling_index(current_index);
            
            // Get the sibling node, creating an empty one if it doesn't exist
            let sibling = self.nodes.get(&sibling_index).cloned().unwrap_or_else(|| {
                let height = self.height - (sibling_index as f64).log2().floor() as usize;
                TreeNode::new_empty(height, sibling_index)
            });
            
            // Get the current node
            let current = self.nodes.get(&current_index).unwrap().clone();
            
            // Create the parent node
            let height = self.height - (parent_index as f64).log2().floor() as usize;
            let (left, right) = if current_index % 2 == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };
            
            let parent = TreeNode::new_internal(&left, &right, parent_index, height);
            
            // Insert the parent into the tree
            self.nodes.insert(parent_index, parent.clone());
            
            // If the parent is the root, update the root hash
            if parent_index == 1 {
                self.root_hash = parent.hash;
            }
            
            // Move up to the parent
            current_index = parent_index;
        }
    }
    
    /// Generate a proof for a leaf
    pub fn generate_proof(&self, position: usize) -> SecureMerkleProof {
        if position >= self.num_leaves {
            panic!("Leaf position out of bounds");
        }
        
        let leaf_index = self.leaf_index(position);
        let mut current_index = leaf_index;
        let mut proof_items = Vec::new();
        
        // Traverse up the tree
        while current_index > 1 {
            let sibling_index = Self::sibling_index(current_index);
            
            // Get the sibling node
            let sibling = self.nodes.get(&sibling_index).cloned().unwrap_or_else(|| {
                let height = self.height - (sibling_index as f64).log2().floor() as usize;
                TreeNode::new_empty(height, sibling_index)
            });
            
            let direction = if current_index % 2 == 0 {
                ProofDirection::Left
            } else {
                ProofDirection::Right
            };
            
            // Add the sibling to the proof
            proof_items.push(ProofItem {
                hash: sibling.hash,
                direction,
            });
            
            // Move up to the parent
            current_index = Self::parent_index(current_index);
        }
        
        // Get the leaf node and its data
        let leaf = self.nodes.get(&leaf_index).unwrap();
        let leaf_data = leaf.data.clone().unwrap_or_default();
        
        // Create the proof
        SecureMerkleProof {
            leaf_data,
            position,
            items: proof_items,
        }
    }
    
    /// Verify a proof against the root hash
    pub fn verify_proof(&self, proof: &SecureMerkleProof) -> bool {
        // Generate the expected leaf hash
        let leaf_hash = crypto::secure_hash(domains::LEAF_NODE, &proof.leaf_data);
        
        // Calculate the root hash from the proof
        let mut current_hash = leaf_hash;
        
        for item in &proof.items {
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
        
        // Compare with the tree's root hash
        calculated_root == self.root_hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_empty_tree() {
        let tree = SecureMerkleTree::new(10);
        assert_eq!(tree.num_leaves(), 0);
        assert_eq!(tree.height(), 4); // log2(10) rounded up = 4
        assert_eq!(tree.max_leaves(), 16);
        assert!(tree.is_empty());
    }
    
    #[test]
    fn test_single_leaf() {
        let mut tree = SecureMerkleTree::new(10);
        let data = b"test data".to_vec();
        
        tree.update_leaf(0, &data);
        
        assert_eq!(tree.num_leaves(), 1);
        assert!(!tree.is_empty());
        
        // Get the leaf node
        let leaf_index = tree.leaf_index(0);
        let leaf = tree.get_node(leaf_index).unwrap();
        
        assert_eq!(leaf.node_type, NodeType::Leaf);
        assert_eq!(leaf.data.as_ref().unwrap(), &data);
    }
    
    #[test]
    fn test_multiple_leaves() {
        let mut tree = SecureMerkleTree::new(10);
        
        for i in 0..5 {
            let data = format!("test data {}", i).into_bytes();
            tree.update_leaf(i, &data);
        }
        
        assert_eq!(tree.num_leaves(), 5);
        
        // Verify all leaves
        for i in 0..5 {
            let leaf_index = tree.leaf_index(i);
            let leaf = tree.get_node(leaf_index).unwrap();
            
            assert_eq!(leaf.node_type, NodeType::Leaf);
            assert_eq!(
                leaf.data.as_ref().unwrap(),
                &format!("test data {}", i).into_bytes()
            );
        }
    }
    
    #[test]
    fn test_from_leaves() {
        let leaves: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("test data {}", i).into_bytes())
            .collect();
        
        let tree = SecureMerkleTree::from_leaves(&leaves);
        
        assert_eq!(tree.num_leaves(), 5);
        
        // Verify all leaves
        for i in 0..5 {
            let leaf_index = tree.leaf_index(i);
            let leaf = tree.get_node(leaf_index).unwrap();
            
            assert_eq!(leaf.node_type, NodeType::Leaf);
            assert_eq!(
                leaf.data.as_ref().unwrap(),
                &format!("test data {}", i).into_bytes()
            );
        }
    }
    
    #[test]
    fn test_update_leaf() {
        let mut tree = SecureMerkleTree::new(10);
        let data1 = b"test data 1".to_vec();
        let data2 = b"test data 2".to_vec();
        
        // Insert initial data
        tree.update_leaf(0, &data1);
        
        // Get the root hash before update
        let root_hash_before = tree.root_hash();
        
        // Update the leaf
        tree.update_leaf(0, &data2);
        
        // Get the root hash after update
        let root_hash_after = tree.root_hash();
        
        // The root hash should change
        assert_ne!(root_hash_before, root_hash_after);
        
        // Get the leaf node
        let leaf_index = tree.leaf_index(0);
        let leaf = tree.get_node(leaf_index).unwrap();
        
        // Verify the leaf data was updated
        assert_eq!(leaf.data.as_ref().unwrap(), &data2);
    }
    
    #[test]
    fn test_proof_generation_and_verification() {
        let mut tree = SecureMerkleTree::new(10);
        
        for i in 0..5 {
            let data = format!("test data {}", i).into_bytes();
            tree.update_leaf(i, &data);
        }
        
        // Generate proof for each leaf
        for i in 0..5 {
            let proof = tree.generate_proof(i);
            
            // Verify the proof
            assert!(tree.verify_proof(&proof));
            
            // Verify the leaf data
            assert_eq!(
                proof.leaf_data,
                format!("test data {}", i).into_bytes()
            );
        }
    }
    
    #[test]
    fn test_tampered_proof() {
        let mut tree = SecureMerkleTree::new(10);
        let data = b"test data".to_vec();
        
        tree.update_leaf(0, &data);
        
        // Generate a valid proof
        let mut proof = tree.generate_proof(0);
        
        // Tamper with the leaf data
        proof.leaf_data = b"tampered data".to_vec();
        
        // The proof should no longer verify
        assert!(!tree.verify_proof(&proof));
        
        // Restore the leaf data but tamper with a proof item
        proof.leaf_data = data;
        if !proof.items.is_empty() {
            proof.items[0].hash[0] ^= 0xFF; // Flip bits
            
            // The proof should no longer verify
            assert!(!tree.verify_proof(&proof));
        }
    }
} 