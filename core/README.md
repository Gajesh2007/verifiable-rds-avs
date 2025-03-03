# Core

This directory contains the core data structures and utilities used throughout the Verifiable RDS AVS project.

## Overview

The Core module provides the fundamental building blocks for the verification system, including:

- Data structures for representing database state
- Cryptographic primitives with domain separation
- Transaction record structures
- Challenge system data models
- Secure Merkle tree implementation
- Common utilities for all components

## Components

### Data Structures

- `TableState`: Represents the state of a database table including schema and rows
- `Row`: Represents a single row in a table with its values and hash
- `TransactionRecord`: Complete record of a transaction including pre/post state
- `BlockState`: Represents the state of the database at a specific block
- `Challenge`: Data model for challenges submitted against invalid state transitions

### Cryptographic Primitives

- `SecureHasher`: Domain-separated cryptographic hash function
- `SecureMerkleTree`: Merkle tree implementation with protection against second-preimage attacks
- `SecureMerkleProof`: Proof structure for verifying inclusion in a Merkle tree

### Utilities

- `BondingCurve`: Implementation of the optimal challenge bonding curve
- `QueryClassifier`: Query classification and analysis
- `ResourceLimiter`: Resource usage tracking and limiting
- `SchemaManager`: Database schema management utilities

## Usage

This module is used by the Proxy, Verification, and Client components to ensure consistent data structures and cryptographic primitives across the system.

## Security Considerations

All cryptographic operations in this module use domain separation for security against length extension attacks and other cryptographic vulnerabilities. The Merkle tree implementation includes protections against second-preimage attacks and provides constant-time operations where appropriate. 