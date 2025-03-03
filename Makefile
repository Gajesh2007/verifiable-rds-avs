.PHONY: help setup dev test build clean lint format contracts

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Set up development environment
	@echo "Setting up development environment..."
	@mkdir -p .pgdata
	@if [ ! -d "core/target" ]; then cd core && cargo build; fi
	@if [ ! -d "proxy/target" ]; then cd proxy && cargo build; fi
	@if [ ! -d "verification/target" ]; then cd verification && cargo build; fi
	@if [ ! -d "client/target" ]; then cd client && cargo build; fi
	@if [ ! -d "contracts/node_modules" ]; then cd contracts && npm install; fi
	@echo "Setup complete."

dev: ## Start development environment
	@echo "Starting development environment..."
	@docker-compose up -d
	@echo "Development environment running."

dev-stop: ## Stop development environment
	@echo "Stopping development environment..."
	@docker-compose down
	@echo "Development environment stopped."

test: ## Run all tests
	@echo "Running tests..."
	@cd core && cargo test
	@cd proxy && cargo test
	@cd verification && cargo test
	@cd client && cargo test
	@cd contracts && npm test
	@echo "All tests passed."

test-core: ## Run core tests
	@echo "Running core tests..."
	@cd core && cargo test
	@echo "Core tests passed."

test-proxy: ## Run proxy tests
	@echo "Running proxy tests..."
	@cd proxy && cargo test
	@echo "Proxy tests passed."

test-verification: ## Run verification tests
	@echo "Running verification tests..."
	@cd verification && cargo test
	@echo "Verification tests passed."

test-client: ## Run client tests
	@echo "Running client tests..."
	@cd client && cargo test
	@echo "Client tests passed."

test-contracts: ## Run contract tests
	@echo "Running contract tests..."
	@cd contracts && npm test
	@echo "Contract tests passed."

build: ## Build all components
	@echo "Building all components..."
	@cd core && cargo build --release
	@cd proxy && cargo build --release
	@cd verification && cargo build --release
	@cd client && cargo build --release
	@cd contracts && npm run build
	@echo "Build complete."

clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@cd core && cargo clean
	@cd proxy && cargo clean
	@cd verification && cargo clean
	@cd client && cargo clean
	@cd contracts && npm run clean
	@echo "Clean complete."

lint: ## Run linters
	@echo "Running linters..."
	@cd core && cargo clippy
	@cd proxy && cargo clippy
	@cd verification && cargo clippy
	@cd client && cargo clippy
	@cd contracts && npm run lint
	@echo "Linting complete."

format: ## Format code
	@echo "Formatting code..."
	@cd core && cargo fmt
	@cd proxy && cargo fmt
	@cd verification && cargo fmt
	@cd client && cargo fmt
	@cd contracts && npm run format
	@echo "Formatting complete."

contracts: ## Build and deploy contracts to local network
	@echo "Building and deploying contracts..."
	@cd contracts && npm run deploy:local
	@echo "Contracts deployed."

pg-cli: ## Connect to PostgreSQL via proxy
	@echo "Connecting to PostgreSQL via proxy..."
	@PGPASSWORD=verifiable psql -h localhost -p 5432 -U verifiable -d verifiable_db

pg-direct: ## Connect directly to PostgreSQL (bypass proxy)
	@echo "Connecting directly to PostgreSQL..."
	@PGPASSWORD=verifiable psql -h localhost -p 5433 -U verifiable -d verifiable_db

logs: ## View logs from containers
	@docker-compose logs -f

init-db: ## Initialize database with sample schema
	@echo "Initializing database with sample schema..."
	@PGPASSWORD=verifiable psql -h localhost -p 5433 -U verifiable -d verifiable_db -f scripts/init_db.sql
	@echo "Database initialized." 