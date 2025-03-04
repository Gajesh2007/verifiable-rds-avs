use sha2::{Sha256, Digest};
use std::collections::HashMap;

/// A secure Merkle tree implementation with domain separation
pub struct SecureMerkleTree {
    /// Domain separator for leaf nodes
    leaf_domain: [u8; 4],
    
    /// Domain separator for internal nodes
    node_domain: [u8; 4],
    
    /// Salt for preventing rainbow table attacks
    salt: [u8; 32],
    
    /// Leaf hashes
    leaves: Vec<[u8; 32]>,
    
    /// Root hash
    root: [u8; 32],
    
    /// Additional checksum using different algorithm
    independent_checksum: [u8; 32],
}

impl SecureMerkleTree {
    /// Create a new empty Merkle tree
    pub fn new() -> Self {
        Self {
            leaf_domain: *b"LEAF",
            node_domain: *b"NODE",
            salt: [0; 32], // In production, this would be randomly generated
            leaves: Vec::new(),
            root: [0; 32],
            independent_checksum: [0; 32],
        }
    }
    
    /// Add a leaf to the tree
    pub fn add_leaf(&mut self, data: &[u8]) {
        let leaf_hash = self.hash_leaf(data);
        self.leaves.push(leaf_hash);
        self.update_root();
    }
    
    /// Hash a leaf with domain separation
    fn hash_leaf(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        // Domain separation to prevent length extension attacks
        hasher.update(&self.leaf_domain);
        
        // Salt to prevent rainbow table attacks
        hasher.update(&self.salt);
        
        // The actual data
        hasher.update(data);
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Hash two child nodes to create a parent node
    fn hash_internal(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        // Domain separation for internal nodes
        hasher.update(&self.node_domain);
        
        // Hash the children
        hasher.update(left);
        hasher.update(right);
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Update the root hash
    fn update_root(&mut self) {
        if self.leaves.is_empty() {
            self.root = [0; 32];
            return;
        }
        
        // Create a copy of the leaves to work with
        let mut current_level = self.leaves.clone();
        
        // Keep combining nodes until we have just one (the root)
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for i in (0..current_level.len()).step_by(2) {
                if i + 1 < current_level.len() {
                    // We have two nodes to combine
                    let parent = self.hash_internal(&current_level[i], &current_level[i + 1]);
                    next_level.push(parent);
                } else {
                    // Odd number of nodes, promote the last one
                    next_level.push(current_level[i]);
                }
            }
            
            current_level = next_level;
        }
        
        // The last remaining node is the root
        self.root = current_level[0];
        
        // Update the independent checksum
        self.update_independent_checksum();
    }
    
    /// Update the independent checksum using a different method
    fn update_independent_checksum(&mut self) {
        // In a real implementation, this would use a different hash algorithm
        // For simplicity, we'll just use SHA-256 again but with different domain
        let mut hasher = Sha256::new();
        
        // Use a different domain
        hasher.update(b"CHKSUM");
        
        // Hash all leaves together
        for leaf in &self.leaves {
            hasher.update(leaf);
        }
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        self.independent_checksum = hash;
    }
    
    /// Get the current root hash
    pub fn get_root(&self) -> [u8; 32] {
        self.root
    }
    
    /// Verify the integrity of the tree
    pub fn verify_integrity(&self) -> bool {
        // Recompute the independent checksum and compare
        let mut hasher = Sha256::new();
        hasher.update(b"CHKSUM");
        
        for leaf in &self.leaves {
            hasher.update(leaf);
        }
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        
        hash == self.independent_checksum
    }
    
    /// Generate a proof for a specific leaf
    pub fn generate_proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }
        
        let mut proof_nodes = Vec::new();
        let mut current_index = leaf_index;
        let mut level_size = self.leaves.len();
        let mut level_start = 0;
        
        let mut current_level = self.leaves.clone();
        
        while level_size > 1 {
            let sibling_index = if current_index % 2 == 0 { 
                current_index + 1 
            } else { 
                current_index - 1 
            };
            
            if sibling_index < level_size {
                let sibling_hash = current_level[sibling_index];
                proof_nodes.push(ProofNode {
                    sibling_hash,
                    is_left: current_index % 2 == 1,
                    node_index: sibling_index,
                });
            }
            
            // Move to the next level
            let mut next_level = Vec::new();
            for i in (0..level_size).step_by(2) {
                if i + 1 < level_size {
                    let parent = self.hash_internal(&current_level[i], &current_level[i + 1]);
                    next_level.push(parent);
                } else {
                    next_level.push(current_level[i]);
                }
            }
            
            current_level = next_level;
            current_index /= 2;
            level_size = current_level.len();
            level_start = 0;
        }
        
        Some(MerkleProof {
            leaf_hash: self.leaves[leaf_index],
            path: proof_nodes,
            root_hash: self.root,
            proof_metadata: ProofMetadata {
                tree_height: self.calculate_tree_height(),
                leaf_index: leaf_index as u64,
                timestamp: chrono::Utc::now().timestamp() as u64,
                version: 1,
                leaf_domain: self.leaf_domain,
                node_domain: self.node_domain,
            },
        })
    }
    
    /// Calculate the height of the tree
    fn calculate_tree_height(&self) -> u8 {
        if self.leaves.is_empty() {
            return 0;
        }
        
        // Calculate height based on number of leaves
        (32 - self.leaves.len().leading_zeros()) as u8
    }
}

/// A node in a Merkle proof
pub struct ProofNode {
    /// Hash of the sibling node
    pub sibling_hash: [u8; 32],
    
    /// Whether the sibling is on the left
    pub is_left: bool,
    
    /// Index of the node in the tree
    pub node_index: usize,
}

/// Metadata for a Merkle proof
pub struct ProofMetadata {
    /// Height of the Merkle tree
    pub tree_height: u8,
    
    /// Index of the leaf in the tree
    pub leaf_index: u64,
    
    /// Timestamp when proof was generated
    pub timestamp: u64,
    
    /// Proof protocol version
    pub version: u32,
    
    /// Domain separator for leaf nodes
    pub leaf_domain: [u8; 4],
    
    /// Domain separator for internal nodes
    pub node_domain: [u8; 4],
}

/// A Merkle proof for a specific leaf
pub struct MerkleProof {
    /// Hash of the leaf being proven
    pub leaf_hash: [u8; 32],
    
    /// Path from leaf to root
    pub path: Vec<ProofNode>,
    
    /// Root hash
    pub root_hash: [u8; 32],
    
    /// Additional data for proof verification
    pub proof_metadata: ProofMetadata,
}

impl MerkleProof {
    /// Verify the proof
    pub fn verify(&self, data: &[u8]) -> bool {
        // Create a temporary tree with the same domain separators
        let mut temp_tree = SecureMerkleTree::new();
        temp_tree.leaf_domain = self.proof_metadata.leaf_domain;
        temp_tree.node_domain = self.proof_metadata.node_domain;
        
        // Hash the leaf data using the same method
        let leaf_hash = temp_tree.hash_leaf(data);
        
        // Verify the leaf hash matches
        if leaf_hash != self.leaf_hash {
            return false;
        }
        
        // Verify the path
        let mut current_hash = leaf_hash;
        
        for node in &self.path {
            if node.is_left {
                // Sibling is on the left
                current_hash = temp_tree.hash_internal(&node.sibling_hash, &current_hash);
            } else {
                // Sibling is on the right
                current_hash = temp_tree.hash_internal(&current_hash, &node.sibling_hash);
            }
        }
        
        // Verify the root
        current_hash == self.root_hash
    }
} 