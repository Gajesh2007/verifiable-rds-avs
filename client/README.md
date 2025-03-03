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

All client libraries are designed to be secure by default and provide clear error messages for potential security issues. 