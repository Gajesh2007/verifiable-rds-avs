#!/bin/bash

# Kill any existing proxy processes
echo "Stopping any existing proxy processes..."
pkill -f verifiable-db-proxy || true

# Wait a moment
sleep 2

# Start the proxy with the correct parameters
echo "Starting verifiable-db-proxy with verification enabled..."
RUST_LOG=debug ./target/debug/verifiable-db-proxy \
  --pg-host localhost \
  --pg-port 5432 \
  --pg-user verifiable \
  --pg-password verifiable \
  --pg-database verifiable_db \
  --port 5434 \
  --verification-enabled true \
  --verification-service-url http://0.0.0.0:8080

# Note: If you want to run this in the background, add '&' at the end of the command
# and use 'fg' to bring it back to the foreground. 