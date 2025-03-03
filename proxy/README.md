# Proxy

This directory contains the PostgreSQL wire protocol proxy implementation for the Verifiable RDS AVS.

## Overview

The Proxy module implements a PostgreSQL-compatible wire protocol handler that intercepts and analyzes database operations for verification. It serves as the primary interface between client applications and the underlying PostgreSQL database.

## Components

### PostgreSQL Wire Protocol Handler

- `WireProtocolServer`: TCP server that listens on PostgreSQL port (5432)
- `AuthHandler`: Authentication handler for PostgreSQL clients
- `MessageParser`: Parser for PostgreSQL wire protocol messages
- `MessageFormatter`: Formatter for PostgreSQL wire protocol responses
- `ConnectionManager`: Manager for client connections
- `ProtocolValidator`: Validator for PostgreSQL protocol correctness

### Query Interception & Analysis

- `QueryInterceptor`: Intercepts SQL queries for analysis
- `SQLParser`: Parses SQL queries to extract structure
- `DeterminismAnalyzer`: Analyzes queries for non-deterministic elements
- `QueryRewriter`: Rewrites queries for deterministic execution
- `QueryClassifier`: Classifies queries by type and complexity

### Transaction Management

- `TransactionTracker`: Tracks transaction boundaries
- `SavepointManager`: Manages savepoints within transactions
- `WALCapture`: Captures Write-Ahead Log records
- `StateCaptureManager`: Manages pre/post state capture
- `TransactionBoundaryValidator`: Validates transaction boundaries

### Security Features

- `RateLimiter`: Rate limiting for clients
- `DoSProtection`: Protection against denial of service attacks
- `AnomalyDetector`: Detection of anomalous query patterns
- `SecurityGateway`: Protocol-aware security gateway
- `TrafficAnalyzer`: Analysis of client traffic patterns

## Usage

The proxy is started with:

```bash
cargo run --bin verifiable-db-proxy
```

This will start the proxy server on port 5432 (default PostgreSQL port). Client applications can connect to the proxy using standard PostgreSQL connection strings.

## Configuration

The proxy can be configured using environment variables or a configuration file:

- `PROXY_PORT`: TCP port to listen on (default: 5432)
- `PG_HOST`: PostgreSQL host to connect to (default: localhost)
- `PG_PORT`: PostgreSQL port to connect to (default: 5433)
- `PG_USER`: PostgreSQL user for backend connection
- `PG_PASSWORD`: PostgreSQL password for backend connection
- `PG_DATABASE`: PostgreSQL database for backend connection
- `VERIFICATION_ENABLED`: Enable/disable verification (default: true)
- `RATE_LIMIT`: Rate limit for client connections (default: 1000 per minute)

## Security Considerations

The proxy implements several security features:

- Deep packet inspection of PostgreSQL wire protocol
- Protocol state validation to prevent out-of-sequence attacks
- Rate limiting with client reputation tracking
- Traffic pattern analysis to detect anomalous query patterns
- Transaction boundary protection

All these features work together to prevent exploitation of the proxy architecture and ensure secure operation of the system. 