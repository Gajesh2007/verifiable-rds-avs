# Verifiable RDS AVS

A Verifiable Database AVS built on EigenLayer that provides PostgreSQL-compatible functionality with cryptographic verification capabilities.

## Overview

Verifiable RDS AVS is a system that enables permissionless verification of database operations through Merkle tree-based state commitments, creating a migration path from traditional RDS to verifiable database services.

The system leverages existing PostgreSQL databases but adds a verification layer that:
1. Captures database state changes
2. Creates cryptographic proofs of state transitions
3. Enables challenges for incorrect state transitions
4. Provides integration with EigenLayer for decentralized verification

## System Architecture

The Verifiable RDS AVS consists of several key components:

```
┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  PostgreSQL     │     │  Verification     │     │  EigenLayer    │
│  Database       │◄────┤  Proxy           │◄────┤  Integration   │
└─────────────────┘     └──────────────────┘     └────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │  Verification    │
                        │  Engine         │
                        └──────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │  State Capture   │
                        │  & Merkle Trees  │
                        └──────────────────┘
```

### Core Components

1. **PostgreSQL Proxy**
   - Wire protocol compatible with standard PostgreSQL clients
   - Intercepts and analyzes database queries
   - Manages connections between clients and the database

2. **Verification Engine**
   - Captures pre and post states for database operations
   - Deterministically replays transactions for verification
   - Builds Merkle trees of the database state

3. **State Capture System**
   - Efficiently tracks database schema and data changes
   - Builds incremental updates to state Merkle trees
   - Provides proof generation for specific rows

4. **EigenLayer Integration**
   - Commits state roots to EigenLayer contracts
   - Handles verification challenges
   - Manages operator registration and rewards

## Project Structure

- `/proxy` - PostgreSQL wire protocol proxy and query interception
- `/verification` - Cryptographic verification, Merkle trees, and state tracking
- `/contracts` - Smart contracts for EigenLayer integration
- `/client` - Client libraries and verification tools
- `/core` - Shared code and utilities

## Getting Started

### Prerequisites

- Rust 1.70 or later
- PostgreSQL 14 or later
- Node.js 18 or later (for smart contracts)
- Docker and Docker Compose (for development)

### Quick Start

1. Clone the repository:
   ```
   git clone https://github.com/Gajesh2007/verifiable-rds-avs.git
   cd verifiable-rds-avs
   ```

2. Start the development environment:
   ```
   docker-compose up -d
   ```

3. Build the proxy:
   ```
   cd proxy
   cargo build --release
   ```

4. Run the proxy:
   ```
   ./target/release/verifiable-db-proxy --config config/development.toml
   ```

5. Connect to the proxy with any PostgreSQL client:
   ```
   psql -h localhost -p 5433 -U postgres -d postgres
   ```

## Security Features

The Verifiable RDS AVS incorporates several security features:

- Secure Merkle tree implementation with domain separation
- Deterministic query handling for non-deterministic functions
- Transaction boundary protection
- DoS prevention through rate limiting and resource quotas
- Challenge economic security with optimal bonding curve

## Development Status

This project is currently in MVP development. Key components that are implemented:

- PostgreSQL wire protocol handler
- Query analysis and interception
- Merkle tree implementation
- State capture system
- Verification environment
- EigenLayer integration

Upcoming features:
- More comprehensive transaction validation
- Enhanced security features
- Performance optimizations
- Client libraries for multiple languages

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Implemented Components

### 1. PostgreSQL Wire Protocol Handler

The proxy module implements a complete PostgreSQL wire protocol handler, which intercepts and processes database queries. This enables the system to:
- Parse and analyze SQL queries
- Rewrite queries for deterministic execution
- Track transactions and their boundaries
- Capture state before and after transactions

### 2. Transaction Boundary Protection

The transaction module provides robust transaction boundary protection through WAL-level capture:
- Tracks transaction boundaries (BEGIN, COMMIT, ROLLBACK)
- Monitors savepoints within transactions
- Detects incomplete or improperly handled savepoints
- Validates transaction integrity

### 3. State Capture and Merkleization

The verification module implements state capture and Merkleization:
- Captures database state before and after transactions
- Creates Merkle trees of table state
- Generates cryptographic proofs for verifying data
- Supports incremental state updates

### 4. Deterministic Execution

The system provides comprehensive deterministic execution:
- Replaces non-deterministic functions like NOW(), RANDOM(), UUID_GENERATE_V4() with deterministic versions
- Enforces deterministic ordering for unordered queries
- Applies query hints to enforce deterministic query plans
- Detects and reports non-deterministic patterns in queries

### 5. EigenLayer Integration

The EigenLayer integration connects the verification system to the blockchain:
- Commits state roots to EigenLayer
- Supports submission and resolution of challenges
- Handles operator registration and management
- Provides cryptographic proofs for on-chain verification

### 6. Client Libraries

Client libraries for interacting with the verification system:
- Verification client for checking transaction validity
- Query client for executing queries with verification
- Challenge client for submitting and monitoring challenges
- Command-line tools for common operations

## Usage

### Starting the Proxy

```bash
cargo run --bin proxy -- --config config.json
```

### Connecting to the Database

Connect to the proxy using any PostgreSQL client:

```bash
psql -h localhost -p 5432 -U postgres -d postgres
```

### Verifying Transactions

Use the verification client to verify transactions:

```rust
let client = VerificationClient::new("http://localhost:8080");
let result = client.verify_transaction(transaction_id).await?;
```

### Executing Queries with Verification

Use the query client to execute queries with verification:

```rust
let client = QueryClient::new("postgres://postgres:postgres@localhost:5432/postgres")
    .with_verification_client(VerificationClient::new("http://localhost:8080"))
    .with_verification(true);

let result = client.query("SELECT * FROM users").await?;
```

### Submitting Challenges

Use the verification client to submit challenges:

```rust
let client = VerificationClient::new("http://localhost:8080");
let challenge = client.submit_challenge(state_root, block_number, evidence).await?;
``` 