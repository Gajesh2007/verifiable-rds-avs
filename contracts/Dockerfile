FROM ghcr.io/foundry-rs/foundry:latest

WORKDIR /app

# Copy the contract files
COPY contracts/ .

# Expose anvil (Foundry's local Ethereum node) port
EXPOSE 8545

# Start anvil by default
CMD ["anvil", "--host", "0.0.0.0"] 