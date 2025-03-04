# Client

This directory contains client libraries and verification tools for the Verifiable RDS AVS.

## Overview

The Client module provides tools and libraries for interacting with the Verifiable RDS AVS. It includes a command-line verification client, libraries for various programming languages, and utilities for proof verification and challenge submission.

## Components

### Command-Line Tools

- `verifiable-db-cli`: Main command-line interface for verification operations
  - `state-root`: Get state root for a specific block
  - `transaction`: Get transaction details
  - `proof`: Generate and verify proofs
  - `verify`: Verify transactions and state transitions
  - `challenge`: Submit challenges for invalid state transitions

### Client Libraries

- `verifiable-db-js`: TypeScript/JavaScript client library
- `verifiable-db-rs`: Rust client library
- `verifiable-db-py`: Python client library
- `verifiable-db-go`: Go client library

### Verification Utilities

- `ProofVerifier`: Utility for verifying Merkle proofs
- `TransactionVerifier`: Utility for verifying transactions
- `ChallengeGenerator`: Utility for generating challenges
- `EvidenceCollector`: Utility for collecting evidence for challenges
- `BondCalculator`: Utility for calculating challenge bonds

### Integration Tools

- `DatabaseAdapter`: Adapter for integrating with existing applications
- `VerificationMiddleware`: Middleware for automatic verification
- `BlockExplorer`: Tool for exploring verified blocks and transactions
- `VerificationMonitor`: Tool for monitoring verification status
- `SecurityScanner`: Tool for scanning for potential security issues

## Recent Improvements

The client now supports enhanced features for working with the improved Verifiable RDS AVS system:

### Enhanced Deterministic Functions

The client now supports working with enhanced deterministic functions that replace non-deterministic PostgreSQL operations:

```sql
-- Use deterministic timestamp 
SELECT verification_timestamp();

-- Use deterministic random generator
SELECT verification_random();

-- Use deterministic UUID generation
SELECT verification_uuid();
```

### Improved Merkle Tree Support

The client includes improved support for working with the enhanced domain-separated Merkle trees:

- Better proof generation and verification
- Support for incremental Merkle tree updates
- Improved security with domain separation in cryptographic operations

### Query Analyzer Integration

The client now integrates with the enhanced Query Analyzer to:

- Detect non-deterministic operations in queries
- Facilitate automatic query rewriting for determinism
- Provide feedback on query security properties

## Usage

### Command-Line Interface

```bash
# Get state root for block 1000
verifiable-db-cli state-root 1000

# Get transaction details
verifiable-db-cli transaction 12345

# Generate proof for a row
verifiable-db-cli proof row users "id = 42"

# Verify a transaction
verifiable-db-cli verify transaction 12345

# Submit a challenge
verifiable-db-cli challenge submit --block 1000 --transaction 12345 --evidence evidence.json

# Analyze query for determinism
verifiable-db-cli analyze "SELECT NOW() FROM users"

# Rewrite query for determinism
verifiable-db-cli rewrite "SELECT NOW() FROM users"
```

### TypeScript/JavaScript Library

```typescript
import { VerifiableDB } from 'verifiable-db-js';

const db = new VerifiableDB({
  endpoint: 'https://api.verifiable-db.example.com',
});

// Get state root
const stateRoot = await db.getStateRoot(1000);

// Verify a transaction
const isValid = await db.verifyTransaction(12345);

// Generate proof for a row
const proof = await db.generateProof('users', 'id = 42');

// Verify a proof
const isValid = await db.verifyProof(proof);

// Analyze query for determinism
const analysis = await db.analyzeQuery('SELECT NOW() FROM users');

// Rewrite query for determinism
const rewrittenQuery = await db.rewriteQuery('SELECT NOW() FROM users');
```

## Development

To build the client tools:

```bash
# Build Rust CLI
cd client/cli
cargo build --release

# Build TypeScript library
cd client/js
npm install
npm run build

# Build Python library
cd client/py
pip install -e .

# Build Go library
cd client/go
go build ./...
```

## Security Considerations

The client libraries implement several security features:

- Cryptographic verification of server responses
- Multiple verification methods for cross-validation
- Secure storage of cryptographic material
- Protection against tampering with verification data
- Proper handling of cryptographic operations
- Domain separation in cryptographic functions
- Enhanced security for Merkle tree operations

All client libraries are designed to be secure by default and provide clear error messages for potential security issues. 