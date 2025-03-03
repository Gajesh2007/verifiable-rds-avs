# Verifiable Database AVS Contracts

This directory contains the smart contracts for the Verifiable Database AVS system. The contracts are responsible for:

1. Recording state roots from the verification system
2. Managing operators who can submit state roots
3. Handling challenge submissions and resolutions
4. Managing the economic security of the system

## Key Components

### VerifiableDBAvs.sol

The main contract for the AVS system. It includes:

- **Operator Management**: Registration, deregistration, freezing/unfreezing of operators
- **State Commitment**: Recording the state roots of the database for verification
- **Transaction Recording**: Tracking transactions for verification
- **Challenge System**: Handling challenge submissions, responses, and resolutions
- **Economic Security**: Bond calculations, slashing, and rewards

## Getting Started

### Prerequisites

- [Foundry](https://getfoundry.sh/)
- [Solidity](https://soliditylang.org/) (^0.8.25)

### Installation

1. Clone the repository
2. Install dependencies:

```bash
cd contracts
forge install
```

### Compilation

```bash
forge build
```

### Testing

```bash
forge test
```

### Deployment

1. Configure your environment variables:

```bash
cp .env.example .env
```

2. Edit the `.env` file to set your private key and other parameters
3. Deploy the contract:

```bash
forge script script/Deploy.s.sol --rpc-url <your-rpc-url> --broadcast --verify
```

## Contract Integration

The contract integrates with your application using the `proxy/src/verification/contract.rs` module. This module provides a Rust API for interacting with the contract:

```rust
use crate::verification::contract::{ContractManager, ContractConfig};

// Create a contract manager
let config = ContractConfig {
    enabled: true,
    contract_address: "0x123...".to_string(),
    rpc_endpoint: "https://...".to_string(),
    operator_private_key: Some("0x...".to_string()),
    commit_frequency_seconds: 3600,
    max_gas_price_gwei: 100,
    chain_id: 1,
};

let contract_manager = ContractManager::new(config);
contract_manager.initialize().await?;

// Commit a state root
let state_root = [0u8; 32]; // Your state root
let commitment = contract_manager.commit_state(state_root).await?;

// Submit a challenge
let challenge = contract_manager.submit_challenge(
    transaction_id,
    pre_state_root,
    post_state_root,
    proof
).await?;
```

## Contract Configuration

The contract can be configured using the following parameters in your `.env` file:

- `PRIVATE_KEY`: Your private key for deployment and transactions
- `INITIAL_OPERATORS`: Comma-separated list of operator addresses
- `CHALLENGE_PERIOD`: Duration of the challenge period in seconds
- `BASE_CHALLENGE_BOND`: Base bond amount for challenges
- `SLASH_AMOUNT`: Amount to slash from operators when challenges succeed
- `CHALLENGE_RESOLUTION_WINDOW`: Time window for challenge resolution

## Security Considerations

The contract includes several security features:

- **Ownable**: Only the owner can register/deregister operators and update parameters
- **Pausable**: The contract can be paused in case of emergencies
- **ReentrancyGuard**: Prevents reentrancy attacks
- **Bond System**: Challengers must bond tokens, discouraging frivolous challenges
- **Freezing Mechanism**: Operators can be frozen if they behave maliciously

## Architecture

The contract follows a simplified architecture, focusing on core verification functionality:

```
VerifiableDBAvs (Main Contract)
├── Operator Management
│   ├── Registration
│   ├── Deregistration
│   └── Freezing/Unfreezing
├── State Commitments
│   └── State Root Recording
├── Transaction Recording
├── Challenge System
│   ├── Challenge Submission
│   ├── Challenge Response
│   └── Challenge Resolution
└── Economic Security
    └── Bond Calculation
```

## Future Integration

In future versions, this contract may be integrated with the complete EigenLayer ecosystem, including:

- **EigenLayer Staking**: Leveraging EigenLayer's restaking mechanisms
- **Delegation**: Allowing delegation of AVS operation
- **Operator Scoring**: Advanced reputation systems for operators
- **Slashing Coordination**: Coordinated slashing with other AVSs

## License

MIT
