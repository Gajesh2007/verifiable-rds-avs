//! Verification environment for deterministic transaction replay
//! 
//! This module provides functionality to create a clean database environment
//! for transaction verification, execute transactions deterministically,
//! and compare the resulting state against the captured state.

use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_postgres::{Client, Socket, config::Config, NoTls};
use tokio::sync::RwLock as TokioRwLock;
use tokio::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use log::{debug, warn, error};
use std::sync::atomic::{AtomicU64, Ordering};
use regex::Regex;
// Add deadpool-postgres imports
use deadpool_postgres::{Pool, PoolConfig, Manager, RecyclingMethod};

use crate::error::{Result, ProxyError};
use crate::verification::state::{StateCaptureManager};
use verifiable_db_core::models::{Value, ColumnDefinition, RowId, BlockState as CoreDatabaseState, TableSchema, Row};
use crate::interception::analyzer::QueryMetadata;
use crate::protocol::transaction::TransactionState;
use crate::verification::deterministic::DeterministicSqlFunctions;

// For proper SQL parameter handling in PostgreSQL queries
use tokio_postgres::types::ToSql;

/// Configuration for the verification environment
#[derive(Debug, Clone)]
pub struct VerificationEnvironmentConfig {
    /// Database connection string for the verification database
    pub connection_string: String,
    
    /// Timeout for transaction execution (milliseconds)
    pub execution_timeout_ms: u64,
    
    /// Maximum number of operations allowed in a single transaction
    pub max_operations: usize,
    
    /// Whether to enable detailed logging during verification
    pub detailed_logging: bool,
    
    /// Schema to use for verification tables
    pub verification_schema: String,
    
    /// Connection pool size
    pub pool_size: usize,
    
    /// Connection timeout in seconds
    pub connection_timeout: u64,
}

impl Default for VerificationEnvironmentConfig {
    fn default() -> Self {
        Self {
            connection_string: "host=localhost user=verifier password=verifier dbname=verification_db".to_string(),
            execution_timeout_ms: 10000, // 10 seconds
            max_operations: 1000,
            detailed_logging: false,
            verification_schema: "verification".to_string(),
            pool_size: 5,
            connection_timeout: 30,
        }
    }
}

/// Verification result containing state comparison and execution details
#[derive(Debug, Clone)]
pub struct VerificationExecutionResult {
    /// Whether the verification succeeded
    pub success: bool,
    
    /// Expected state after transaction execution
    pub expected_state: Option<CoreDatabaseState>,
    
    /// Actual state after transaction execution
    pub actual_state: Option<CoreDatabaseState>,
    
    /// List of mismatched tables between expected and actual states
    pub mismatched_tables: Vec<String>,
    
    /// List of mismatched rows between expected and actual states
    pub mismatched_rows: HashMap<String, Vec<RowId>>,
    
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    
    /// Error message if verification failed
    pub error: Option<String>,
    
    /// Number of operations executed
    pub operations_executed: usize,
}

/// Verification environment for deterministic execution and verification
#[derive(Debug)]
pub struct VerificationEnvironment {
    /// Configuration for the verification environment
    config: VerificationEnvironmentConfig,
    
    /// State capture manager for retrieving and updating state
    state_capture: Arc<StateCaptureManager>,
    
    /// Database connection pool for verification databases
    connection_pool: Arc<Pool>,
    
    /// Deterministic SQL functions
    deterministic_functions: Arc<Mutex<DeterministicSqlFunctions>>,
    
    /// AtomicU64 to track the current transaction ID
    current_transaction_id: AtomicU64,
}

impl VerificationEnvironment {
    /// Create a new verification environment with the given configuration
    pub fn new(config: VerificationEnvironmentConfig, state_capture: Arc<StateCaptureManager>) -> Result<Self> {
        let deterministic_functions = Arc::new(Mutex::new(
            DeterministicSqlFunctions::new(0, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), 0)
        ));
        
        // Parse the connection string into a PostgreSQL config
        let pg_config = config.connection_string.parse::<Config>()
            .map_err(|e| ProxyError::Config(format!("Failed to parse connection string: {}", e)))?;
            
        // Create a deadpool manager with the PostgreSQL config
        let mgr = Manager::new(pg_config, NoTls);
        
        // Configure the connection pool
        let pool_cfg = PoolConfig {
            max_size: config.pool_size as usize,
            ..Default::default()
        };
        
        // Build the connection pool with the manager and configuration
        let pool = Pool::builder(mgr)
            .config(pool_cfg)
            .build()
            .map_err(|e| ProxyError::Database(format!("Failed to create connection pool: {}", e)))?;
        
        Ok(Self {
            config,
            state_capture,
            connection_pool: Arc::new(pool),
            deterministic_functions,
            current_transaction_id: AtomicU64::new(0),
        })
    }
    
    // Helper method to convert Value to SQL parameter
    fn value_to_param<'a>(&self, value: &'a Value) -> Result<Box<dyn ToSql + Sync + 'a>> {
        match value {
            Value::Null => Ok(Box::new(None::<String>)), // Represent SQL NULL
            Value::Text(t) => Ok(Box::new(t.clone())),
            Value::Integer(i) => Ok(Box::new(*i)),
            Value::BigInt(bi) => Ok(Box::new(*bi)),
            Value::Float(f) => Ok(Box::new(*f)),
            Value::Boolean(b) => Ok(Box::new(*b)),
            // Add other types like Uuid, Timestamp, Binary, Json as needed
            _ => Err(ProxyError::Database(format!(
                "Unsupported value type for SQL parameter: {:?}",
                value
            ))),
        }
    }

    // Helper to get value as string representation for row ID
    fn value_to_string(&self, value: &Value) -> String {
        match value {
            Value::Null => "NULL".to_string(),
            Value::Text(t) => t.clone(),
            Value::Integer(i) => i.to_string(),
            Value::BigInt(bi) => bi.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Boolean(b) => b.to_string(),
            // Add other types like Uuid, Timestamp, Binary, Json as needed
            Value::Uuid(u) => u.to_string(),
            Value::Timestamp(ts) => ts.to_string(),
            Value::Binary(bin) => format!("{:?}", bin), // Or hex encode?
            Value::Json(j) => j.clone(),
            // Consider a more robust default or error handling
        }
    }
    
    /// Initialize the verification environment
    pub async fn initialize(&self) -> Result<()> {
        // Test the connection pool by getting a client
        let client = self.get_client().await?;
        
        // Create the verification schema if it doesn't exist
        let schema = &self.config.verification_schema;
        let create_schema_query = format!("CREATE SCHEMA IF NOT EXISTS {}", schema);
        client.execute(&create_schema_query, &[])
            .await
            .map_err(|e| ProxyError::Database(format!("Failed to create schema: {}", e)))?;
        
        debug!("Initialized verification environment with schema '{}'", schema);
        
        Ok(())
    }
    
    /// Create a new database connection
    async fn create_connection(&self) -> Result<(Client, tokio_postgres::Connection<Socket, tokio_postgres::tls::NoTlsStream>)> {
        let config = self.config.connection_string.parse::<Config>()
            .map_err(|e| ProxyError::Config(format!("Failed to parse connection string: {}", e)))?;
            
        let (client, connection) = config.connect(NoTls).await
            .map_err(|e| ProxyError::Database(format!("Failed to connect to verification database: {}", e)))?;
            
        Ok((client, connection))
    }
    
    /// Get a client from the connection pool
    async fn get_client(&self) -> Result<deadpool_postgres::Client> {
        let timeout = Duration::from_secs(self.config.connection_timeout);
        
        // Get a client from the pool with timeout
        let client = tokio::time::timeout(timeout, self.connection_pool.get())
            .await
            .map_err(|_| ProxyError::Database("Connection pool timeout".to_string()))?
            .map_err(|e| ProxyError::Database(format!("Failed to get database connection from pool: {}", e)))?;
            
        debug!("Acquired database connection from pool");
        Ok(client)
    }
    
    /// Release a client back to the pool
    fn release_client(&self, _client: &deadpool_postgres::Client) {
        // No need to release client explicitly with deadpool-postgres
        // The client will be returned to the pool when it's dropped
        debug!("Client connection automatically returned to the pool");
    }
    
    /// Set up a clean database state for verification based on the pre-state
    async fn setup_clean_environment(&self, client: &deadpool_postgres::Client, pre_state: &CoreDatabaseState) -> Result<()> {
        // Create the verification schema if it doesn't exist
        client.execute(&format!("CREATE SCHEMA IF NOT EXISTS {}", self.config.verification_schema), &[]).await
            .map_err(|e| ProxyError::Database(format!("Failed to create verification schema: {}", e)))?;
            
        // For each table in the pre-state, create the table structure and populate with data
        for (table_name, table_state) in pre_state.tables().iter() {
            // Create the table with the correct schema
            self.create_table(client, &table_state.table_schema).await?;
            
            // Insert all rows into the table
            for (_, row) in table_state.rows.iter() {
                self.insert_row(client, &table_state.table_schema, row).await?;
            }
        }
        
        Ok(())
    }
    
    /// Create a table in the verification database
    async fn create_table(&self, client: &deadpool_postgres::Client, schema: &TableSchema) -> Result<()> {
        // Build the CREATE TABLE statement
        let mut create_stmt = format!(
            "CREATE TABLE IF NOT EXISTS {}.{} (",
            self.config.verification_schema,
            schema.name
        );
        
        // Add column definitions
        let mut column_defs = Vec::new();
        for col in &schema.columns {
            let nullable = if col.nullable { "NULL" } else { "NOT NULL" };
            let default = match &col.default_value {
                Some(val) => format!("DEFAULT {}", val),
                None => "".to_string(),
            };
            
            column_defs.push(format!("{} {} {} {}", col.name, col.data_type, nullable, default));
        }
        
        create_stmt.push_str(&column_defs.join(", "));
        
        // Add primary key if defined
        if !schema.primary_key.is_empty() {
            create_stmt.push_str(&format!(", PRIMARY KEY ({})", schema.primary_key.join(", ")));
        }
        
        create_stmt.push_str(")");
        
        // Execute the CREATE TABLE statement
        client.execute(&create_stmt, &[])
            .await
            .map_err(|e| ProxyError::Database(format!("Failed to create table {}: {}", schema.name, e)))?;
            
        Ok(())
    }
    
    /// Insert a row into a table
    async fn insert_row(&self, client: &deadpool_postgres::Client, schema: &TableSchema, row: &Row) -> Result<()> {
        // Build the INSERT statement
        let mut insert_stmt = format!(
            "INSERT INTO {}.{} (",
            self.config.verification_schema,
            schema.name
        );
        
        // Add column names
        let columns: Vec<String> = row.values.keys().cloned().collect();
        insert_stmt.push_str(&columns.join(", "));
        
        insert_stmt.push_str(") VALUES (");
        
        // Add placeholders for values
        let placeholders: Vec<String> = (1..=columns.len()).map(|i| format!("${}", i)).collect();
        insert_stmt.push_str(&placeholders.join(", "));
        
        insert_stmt.push_str(")");
        
        // Build the params vector
        let mut params: Vec<Box<dyn ToSql + Sync>> = Vec::new();
        for column in &columns {
            if let Some(value) = row.values.get(column) {
                // Convert the value to a PostgreSQL type
                // This is a simplified conversion - in reality, you'd need to handle all PostgreSQL types
                params.push(self.value_to_param(value)?);
            } else {
                params.push(Box::new(None::<String>));
            }
        }
        
        // Execute the insert statement
        let param_refs: Vec<&(dyn ToSql + Sync)> = params.iter().map(|p| p.as_ref()).collect();
        client.execute(&insert_stmt, &param_refs[..])
            .await
            .map_err(|e| ProxyError::Database(format!("Failed to insert row: {}", e)))?;
            
        Ok(())
    }
    
    /// Set deterministic parameters for the session
    async fn set_deterministic_parameters(&self, client: &deadpool_postgres::Client) -> Result<()> {
        // Set timezone to UTC
        client.execute("SET timezone TO 'UTC'", &[])
            .await
            .map_err(|e| ProxyError::Database(format!("Failed to set timezone: {}", e)))?;
            
        // Disable parallel query execution for determinism
        client.execute("SET max_parallel_workers_per_gather TO 0", &[])
            .await
            .map_err(|e| ProxyError::Database(format!("Failed to disable parallel queries: {}", e)))?;
            
        // Set a fixed search path
        client.execute(&format!("SET search_path TO {}", self.config.verification_schema), &[])
            .await
            .map_err(|e| ProxyError::Database(format!("Failed to set search path: {}", e)))?;
            
        // Disable JIT compilation for determinism
        client.execute("SET jit TO off", &[])
            .await
            .map_err(|e| ProxyError::Database(format!("Failed to disable JIT: {}", e)))?;
            
        Ok(())
    }
    
    /// Execute a transaction deterministically and verify the result
    pub async fn verify_transaction(
        &self,
        transaction_id: u64,
        queries: Vec<String>,
        metadata: Vec<QueryMetadata>,
        pre_state: CoreDatabaseState,
        expected_post_state: CoreDatabaseState,
    ) -> Result<VerificationExecutionResult> {
        let start_time = Instant::now();
        
        let mut result = VerificationExecutionResult {
            success: false,
            expected_state: None,
            actual_state: None,
            mismatched_tables: Vec::new(),
            mismatched_rows: HashMap::new(),
            error: None,
            execution_time_ms: 0,
            operations_executed: 0,
        };
        
        // Get a client from the pool
        let client = match self.get_client().await {
            Ok(client) => client,
            Err(e) => {
                result.error = Some(format!("Failed to get database connection: {}", e));
                return Ok(result);
            }
        };
        
        // Setup the clean environment for verification
        match tokio::time::timeout(
            Duration::from_millis(self.config.execution_timeout_ms),
            self.setup_clean_environment(&client, &pre_state)
        ).await {
            Ok(setup_result) => {
                if let Err(e) = setup_result {
                    self.release_client(&client);
                    result.error = Some(format!("Error setting up verification environment: {}", e));
                    return Ok(result);
                }
            },
            Err(e) => {
                self.release_client(&client);
                result.error = Some(format!("Timeout setting up verification environment: {}", e));
                return Ok(result);
            }
        }
        
        // Begin a transaction
        match tokio::time::timeout(
            Duration::from_millis(self.config.execution_timeout_ms),
            client.execute("BEGIN", &[])
        ).await {
            Ok(begin_result) => {
                if let Err(e) = begin_result {
                    self.release_client(&client);
                    result.error = Some(format!("Failed to begin transaction: {}", e));
                    return Ok(result);
                }
            },
            Err(e) => {
                self.release_client(&client);
                result.error = Some(format!("Timeout beginning transaction: {}", e));
                return Ok(result);
            }
        }
        
        // Set deterministic parameters
        match tokio::time::timeout(
            Duration::from_millis(self.config.execution_timeout_ms),
            self.set_deterministic_parameters(&client)
        ).await {
            Ok(param_result) => {
                if let Err(e) = param_result {
                    if let Err(rollback_err) = client.execute("ROLLBACK", &[]).await {
                        warn!("Failed to rollback after error: {}", rollback_err);
                    }
                    self.release_client(&client);
                    result.error = Some(format!("Failed to set deterministic parameters: {}", e));
                    return Ok(result);
                }
            },
            Err(e) => {
                if let Err(rollback_err) = client.execute("ROLLBACK", &[]).await {
                    warn!("Failed to rollback after error: {}", rollback_err);
                }
                self.release_client(&client);
                result.error = Some(format!("Timeout setting deterministic parameters: {}", e));
                return Ok(result);
            }
        }
        
        // Execute each query in the transaction
        for (i, query) in queries.iter().enumerate() {
            match tokio::time::timeout(
                Duration::from_millis(self.config.execution_timeout_ms),
                self.execute_query_with_client(&client, query)
            ).await {
                Ok(query_result) => {
                    if let Err(e) = query_result {
                        if let Err(rollback_err) = client.execute("ROLLBACK", &[]).await {
                            warn!("Failed to rollback after error: {}", rollback_err);
                        }
                        self.release_client(&client);
                        result.error = Some(format!("Query execution error for query {}: {}", i + 1, e));
                        return Ok(result);
                    }
                },
                Err(e) => {
                    if let Err(rollback_err) = client.execute("ROLLBACK", &[]).await {
                        warn!("Failed to rollback after error: {}", rollback_err);
                    }
                    self.release_client(&client);
                    result.error = Some(format!("Query execution timeout for query {}: {}", i + 1, e));
                    return Ok(result);
                }
            }
            
            result.operations_executed += 1;
        }
        
        // Commit the transaction
        match tokio::time::timeout(
            Duration::from_millis(self.config.execution_timeout_ms),
            client.execute("COMMIT", &[])
        ).await {
            Ok(commit_result) => {
                if let Err(e) = commit_result {
                    if let Err(rollback_err) = client.execute("ROLLBACK", &[]).await {
                        warn!("Failed to rollback after error: {}", rollback_err);
                    }
                    self.release_client(&client);
                    result.error = Some(format!("Failed to commit transaction: {}", e));
                    return Ok(result);
                }
            },
            Err(e) => {
                if let Err(rollback_err) = client.execute("ROLLBACK", &[]).await {
                    warn!("Failed to rollback after error: {}", rollback_err);
                }
                self.release_client(&client);
                result.error = Some(format!("Timeout committing transaction: {}", e));
                return Ok(result);
            }
        }
        
        // Capture the actual state after execution
        match self.capture_actual_state(&client, &expected_post_state).await {
            Ok(actual_state) => {
                result.actual_state = Some(actual_state.clone());
                // Compare expected and actual states
                let (mismatched_tables, mismatched_rows) = self.compare_states(&expected_post_state, &actual_state);
                result.mismatched_tables = mismatched_tables;
                result.mismatched_rows = mismatched_rows;
                result.success = result.mismatched_tables.is_empty() && result.mismatched_rows.is_empty();
            },
            Err(e) => {
                result.error = Some(format!("Failed to capture actual state: {}", e));
            }
        }
        
        // Release the client back to the pool
        self.release_client(&client);
        
        // Calculate execution time
        result.execution_time_ms = start_time.elapsed().as_millis() as u64;
        
        // Update the current transaction ID
        self.current_transaction_id.store(transaction_id + 1, Ordering::SeqCst);
        
        Ok(result)
    }
    
    /// Execute a query against a verification database
    async fn execute_query_with_client(&self, client: &deadpool_postgres::Client, query: &str) -> Result<Vec<tokio_postgres::Row>> {
        let mut rewritten_query = query.to_string();
        
        // Get transaction ID before processing
        let tx_id = self.current_transaction_id.load(Ordering::SeqCst);
        
        // Handle deterministic functions in the query
        if query.contains("verification_") {
            // Replace deterministic function calls with their values
            // In a real implementation, we would parse the query and replace function calls properly
            // For now, we'll use a simple approach
            
            if query.contains("verification_timestamp()") {
                let value = self.execute_deterministic_function("verification_timestamp", tx_id).await?;
                rewritten_query = rewritten_query.replace("verification_timestamp()", &format!("'{}'", value));
            }
            
            if query.contains("verification_random(") {
                let value = self.execute_deterministic_function("verification_random", tx_id).await?;
                // This is a simplified approach - in a real implementation, we would parse the function call properly
                let regex = Regex::new(r"verification_random\(\s*\d+\s*,\s*\d+\s*\)").unwrap();
                rewritten_query = regex.replace_all(&rewritten_query, value.as_str()).to_string();
            }
            
            if query.contains("verification_uuid(") {
                let value = self.execute_deterministic_function("verification_uuid", tx_id).await?;
                // This is a simplified approach - in a real implementation, we would parse the function call properly
                let regex = Regex::new(r"verification_uuid\(\s*\d+\s*,\s*\d+\s*\)").unwrap();
                rewritten_query = regex.replace_all(&rewritten_query, &format!("'{}'", value)).to_string();
            }
        }
        
        // Then execute the rewritten query instead of the original:
        let result = client.query(&rewritten_query, &[]).await;
        
        // Update the current transaction ID
        self.current_transaction_id.store(tx_id + 1, Ordering::SeqCst);
        
        result.map_err(|e| ProxyError::Database(format!("Failed to execute query: {}", e)))
    }
    
    /// Capture the actual state of the database after transaction execution
    async fn capture_actual_state(&self, client: &deadpool_postgres::Client, expected_state: &CoreDatabaseState) -> Result<CoreDatabaseState> {
        let mut actual_state = CoreDatabaseState::new();
        
        // For each table in the expected state, capture the actual state
        for (table_name, expected_table) in expected_state.tables().iter() {
            debug!("Capturing actual state for table {}", table_name);
            
            // Create a new table state
            let mut table_state = core_models::TableState {
                name: table_name.clone(),
                table_schema: expected_table.table_schema.clone(),
                rows: HashMap::new(),
                ..Default::default()
            };
            
            // Query all rows from the table
            let select_stmt = format!("SELECT * FROM {}.{}", self.config.verification_schema, table_name);
            let rows = client.query(&select_stmt, &[])
                .await
                .map_err(|e| ProxyError::Database(format!("Failed to query rows from table {}: {}", table_name, e)))?;
                
            // Process each row
            for pg_row in rows {
                let row = self.convert_pg_row_to_db_row(&pg_row, &table_state.table_schema)?;
                
                // Add the row to the table state
                table_state.upsert_row(row);
            }
            
            // Build the Merkle tree for the table
            if let Err(e) = table_state.build_merkle_tree() {
                warn!("Failed to build Merkle tree for table {}: {}", table_name, e);
            }
            
            // Add the table state to the database state
            if let Err(e) = actual_state.update_table(table_state) {
                warn!("Failed to update table state for {}: {}", table_name, e);
            }
        }
        
        // Calculate the root hash for the database state
        if let Err(e) = actual_state.calculate_root_hash() {
            warn!("Failed to calculate root hash for database state: {}", e);
        }
        
        Ok(actual_state)
    }
    
    /// Compare the expected and actual states
    fn compare_states(&self, expected: &CoreDatabaseState, actual: &CoreDatabaseState) -> (Vec<String>, HashMap<String, Vec<RowId>>) {
        let mut mismatched_tables = Vec::new();
        let mut mismatched_rows = HashMap::new();
        
        // Compare each table in the expected state with the actual state
        for (name, expected_table) in expected.tables().iter() {
            match actual.tables().get(name) {
                None => {
                    debug!("Table {} not found in actual state", name);
                    mismatched_tables.push(name.clone());
                },
                Some(actual_table) => {
                    // Compare the Merkle tree roots first for quick comparison
                    if expected_table.root_hash() != actual_table.root_hash() {
                        debug!("Merkle tree root mismatch for table {}", name);
                        
                        // Check each row for differences
                        for (row_id, expected_row) in expected_table.rows.iter() {
                            match actual_table.rows.get(row_id) {
                                None => {
                                    debug!("Row {:?} not found in actual state for table {}", row_id, name);
                                    mismatched_rows.entry(name.clone())
                                        .or_insert_with(Vec::new)
                                        .push(row_id.clone());
                                },
                                Some(actual_row) => {
                                    // Direct comparison now possible
                                    for (col, expected_value) in expected_row.values.iter() {
                                        match actual_row.values.get(col) {
                                            None => {
                                                debug!("Column {} not found in actual row {:?} for table {}", 
                                                    col, row_id, name);
                                                mismatched_rows.entry(name.clone())
                                                    .or_insert_with(Vec::new)
                                                    .push(row_id.clone());
                                                break;
                                            },
                                            Some(actual_value) => {
                                                if expected_value != actual_value {
                                                    debug!("Value mismatch for column {} in row {:?} for table {}: expected {:?}, actual {:?}", 
                                                        col, row_id, name, expected_value, actual_value);
                                                    mismatched_rows.entry(name.clone())
                                                        .or_insert_with(Vec::new)
                                                        .push(row_id.clone());
                                                    break; // Row mismatch found, move to next row
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Check for rows in actual that are not in expected
                        for (row_id, _) in actual_table.rows.iter() {
                            if !expected_table.rows.contains_key(row_id) {
                                debug!("Unexpected row {:?} found in actual state for table {}", row_id, name);
                                mismatched_rows.entry(name.clone())
                                    .or_insert_with(Vec::new)
                                    .push(row_id.clone());
                            }
                        }
                    } else {
                        debug!("Merkle tree root match for table {}", name);
                    }
                }
            }
        }
        
        // Check for tables in actual that are not in expected
        for name in actual.tables().keys() {
            if !expected.tables().contains_key(name) {
                debug!("Unexpected table {} found in actual state", name);
                mismatched_tables.push(name.clone());
            }
        }
        
        (mismatched_tables, mismatched_rows)
    }
    
    /// Execute a deterministic SQL function
    pub async fn execute_deterministic_function(&self, function_name: &str, transaction_id: u64) -> Result<String> {
        let mut functions = self.deterministic_functions.lock().unwrap();
        
        // Execute the requested function
        let result = match function_name {
            "now" | "current_timestamp" => functions.timestamp(),
            "random" => functions.random().to_string(),
            "uuid" | "gen_random_uuid" => functions.uuid(),
            "txid_current" => functions.txid().to_string(),
            _ => return Err(ProxyError::Verification(format!("Unknown deterministic function: {}", function_name))),
        };
        
        // Update the transaction ID
        self.current_transaction_id.store(transaction_id + 1, Ordering::SeqCst);
        
        Ok(result)
    }

    /// Close all connections in the pool
    pub async fn cleanup(&self) -> Result<()> {
        // With deadpool-postgres, we just need to drop all clients
        // The pool will automatically close idle connections
        debug!("Cleaning up verification environment connection pool");
        Ok(())
    }
    
    // Helper method to convert tokio-postgres row to our database row representation
    fn convert_pg_row_to_db_row(&self, pg_row: &tokio_postgres::Row, table_schema: &TableSchema) -> Result<Row> {
        let mut row_values = HashMap::new();
        let mut row_id_values = HashMap::new();

        // Process each column
        for (i, column) in table_schema.columns.iter().enumerate() {
            let data_type = column.data_type.to_lowercase();

            // Extract the value according to the data type
            let value = match data_type.as_str() {
                "integer" | "int" | "int4" => {
                    match pg_row.try_get::<_, Option<i32>>(i) {
                        Ok(Some(v)) => Value::Integer(v),
                        Ok(None) => Value::Null,
                        Err(e) => return Err(ProxyError::Database(format!("Failed to get int column '{}': {}", column.name, e)))
                    }
                },
                "bigint" | "int8" => {
                    match pg_row.try_get::<_, Option<i64>>(i) {
                        Ok(Some(v)) => Value::BigInt(v),
                        Ok(None) => Value::Null,
                        Err(e) => return Err(ProxyError::Database(format!("Failed to get bigint column '{}': {}", column.name, e)))
                    }
                },
                "text" | "varchar" | "char" | "character varying" => {
                    match pg_row.try_get::<_, Option<String>>(i) {
                        Ok(Some(v)) => Value::Text(v),
                        Ok(None) => Value::Null,
                        Err(e) => return Err(ProxyError::Database(format!("Failed to get text column '{}': {}", column.name, e)))
                    }
                },
                "float" | "float4" | "float8" | "real" | "double precision" => {
                    match pg_row.try_get::<_, Option<f64>>(i) {
                        Ok(Some(v)) => Value::Float(v),
                        Ok(None) => Value::Null,
                        Err(e) => return Err(ProxyError::Database(format!("Failed to get float column '{}': {}", column.name, e)))
                    }
                },
                "boolean" | "bool" => {
                    match pg_row.try_get::<_, Option<bool>>(i) {
                        Ok(Some(v)) => Value::Boolean(v),
                        Ok(None) => Value::Null,
                        Err(e) => return Err(ProxyError::Database(format!("Failed to get boolean column '{}': {}", column.name, e)))
                    }
                },
                // Add more specific types like timestamp, uuid, json, bytea here
                _ => {
                    // Fallback: Try to get as string for unknown/unhandled types
                    warn!("Unhandled data type '{}' for column '{}', attempting to read as text.", data_type, column.name);
                    match pg_row.try_get::<_, Option<String>>(i) {
                        Ok(Some(v)) => Value::Text(v),
                        Ok(None) => Value::Null,
                        Err(e) => {
                            error!("Failed to get column '{}' as fallback text: {}", column.name, e);
                            Value::Null // Or return error?
                        }
                    }
                }
            };

            row_values.insert(column.name.clone(), value.clone());

            // If this column is part of the primary key, add it to the row ID
            if table_schema.primary_key.contains(&column.name) {
                let id_value = self.value_to_string(&value);
                row_id_values.insert(column.name.clone(), id_value);
            }
        }

        // Create the row ID
        let row_id = RowId {
            values: row_id_values,
        };

        // Create the row
        let row = Row {
            id: row_id,
            values: row_values,
        };

        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;
    use std::time::{SystemTime, UNIX_EPOCH};
    
    // Create a helper function for test table schema creation
    fn create_test_table_schema() -> TableSchema {
        TableSchema {
            name: "test_table".to_string(),
            schema: "public".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    data_type: "INTEGER".to_string(),
                    nullable: false,
                    default_value: None,
                    position: 1,
                }
            ],
            primary_key: vec!["id".to_string()],
            version: 1,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            modified_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
    
    #[test]
    fn test_environment_creation() {
        // Create a minimal configuration
        let config = VerificationEnvironmentConfig {
            connection_string: "postgres://localhost:5432/testdb".to_string(),
            execution_timeout_ms: 10000,
            max_operations: 1000,
            detailed_logging: false,
            verification_schema: "verification".to_string(),
            pool_size: 5,
            connection_timeout: 30,
        };
        
        let state_capture = Arc::new(StateCaptureManager::new());
        
        // This should not panic
        let _env = VerificationEnvironment::new(config, state_capture).unwrap();
    }
    
    #[test]
    fn test_environment_cleanup() {
        // Create a minimal configuration
        let config = VerificationEnvironmentConfig {
            connection_string: "postgres://localhost:5432/testdb".to_string(),
            execution_timeout_ms: 10000,
            max_operations: 1000,
            detailed_logging: false,
            verification_schema: "verification".to_string(),
            pool_size: 5,
            connection_timeout: 30,
        };
        
        let state_capture = Arc::new(StateCaptureManager::new());
        
        // Create the environment
        let env = VerificationEnvironment::new(config, state_capture).unwrap();
        
        // Create a runtime to run the async cleanup
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            // This should not panic even when there are no connections
            let result = env.cleanup().await;
            assert!(result.is_ok());
        });
    }
}