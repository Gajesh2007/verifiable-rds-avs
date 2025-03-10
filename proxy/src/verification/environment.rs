//! Verification environment for deterministic transaction replay
//! 
//! This module provides functionality to create a clean database environment
//! for transaction verification, execute transactions deterministically,
//! and compare the resulting state against the captured state.

use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_postgres::{Client, Socket, config::Config, NoTls};
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::RwLock as TokioRwLock;
use tokio::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use log::{debug, warn, error};
use std::sync::atomic::{AtomicU64, Ordering};
use regex::Regex;

use crate::error::{Result, ProxyError};
use crate::verification::state::{StateCaptureManager, DatabaseState, TableState, Row, RowId, TableSchema, ColumnDefinition};
use crate::interception::analyzer::QueryMetadata;
use crate::protocol::transaction::TransactionState;
use crate::verification::deterministic::DeterministicSqlFunctions;

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

    /// Whether to reuse connections for multiple verifications
    pub reuse_connections: bool,
    
    /// Connection pool size
    pub pool_size: usize,
}

impl Default for VerificationEnvironmentConfig {
    fn default() -> Self {
        Self {
            connection_string: "host=localhost user=verifier password=verifier dbname=verification_db".to_string(),
            execution_timeout_ms: 10000, // 10 seconds
            max_operations: 1000,
            detailed_logging: false,
            verification_schema: "verification".to_string(),
            reuse_connections: true,
            pool_size: 5,
        }
    }
}

/// Verification result containing state comparison and execution details
#[derive(Debug, Clone)]
pub struct VerificationExecutionResult {
    /// Whether the verification succeeded
    pub success: bool,
    
    /// Expected state after transaction execution
    pub expected_state: Option<DatabaseState>,
    
    /// Actual state after transaction execution
    pub actual_state: Option<DatabaseState>,
    
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

/// A pool entry for a database connection
#[derive(Debug)]
struct PoolEntry {
    /// Client connection
    client: Client,
    
    /// Whether the connection is in use
    in_use: bool,
    
    /// When the connection was last used
    last_used: Instant,
}

/// Verification environment for deterministic execution and verification
#[derive(Debug)]
pub struct VerificationEnvironment {
    /// Configuration for the verification environment
    config: VerificationEnvironmentConfig,
    
    /// State capture manager for retrieving and updating state
    state_capture: Arc<StateCaptureManager>,
    
    /// Connection pool for verification databases
    connection_pool: Mutex<Vec<PoolEntry>>,
    
    /// Deterministic SQL functions
    deterministic_functions: Arc<Mutex<DeterministicSqlFunctions>>,
    
    /// AtomicU64 to track the current transaction ID
    current_transaction_id: AtomicU64,
}

impl VerificationEnvironment {
    /// Create a new verification environment with the given configuration
    pub fn new(config: VerificationEnvironmentConfig, state_capture: Arc<StateCaptureManager>) -> Self {
        let deterministic_functions = Arc::new(Mutex::new(
            DeterministicSqlFunctions::new(0, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), 0)
        ));
        
        Self {
            config,
            state_capture,
            connection_pool: Mutex::new(Vec::new()),
            deterministic_functions,
            current_transaction_id: AtomicU64::new(0),
        }
    }
    
    /// Initialize the verification environment
    pub async fn initialize(&self) -> Result<()> {
        if self.config.reuse_connections {
            let mut pool = self.connection_pool.lock().unwrap();
            
            // Initialize the connection pool
            for _ in 0..self.config.pool_size {
                let (client, connection) = self.create_connection().await?;
                
                // Spawn a task to handle the connection
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        error!("Connection error: {}", e);
                    }
                });
                
                pool.push(PoolEntry {
                    client,
                    in_use: false,
                    last_used: Instant::now(),
                });
            }
            
            debug!("Initialized connection pool with {} connections", self.config.pool_size);
        }
        
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
    
    /// Get a client from the connection pool or create a new one
    async fn get_client(&self) -> Result<Client> {
        let mut pool = self.connection_pool.lock().unwrap();
        let now = Instant::now();
        
        // First, check if there are any idle connections we can reuse
        if self.config.reuse_connections {
            for entry in pool.iter_mut() {
                if !entry.in_use {
                    // Found an idle connection
                    debug!("Reusing existing database connection");
                    entry.in_use = true;
                    entry.last_used = now;
                    // Since Client doesn't have clone, we need a different approach
                    // This is a placeholder - in a real implementation, you would need to implement
                    // proper connection pooling with cloneable clients
                    return Err(ProxyError::Database("Client.clone() not implemented".to_string()));
                }
            }
        }
        
        // No idle connections available, check if we can create a new one
        if pool.len() < self.config.pool_size {
            debug!("Creating new database connection (pool size: {}/{})", pool.len(), self.config.pool_size);
            let (client, connection) = self.create_connection().await?;
            
            // Spawn a task to handle the connection
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    error!("Connection error: {}", e);
                }
            });
            
            // We don't need to store in the pool since Client can't be cloned
            // Just return the client directly
            return Ok(client);
        }
        
        // No available connections and pool is full
        return Err(ProxyError::Database("Connection pool is full".to_string()));
    }
    
    /// Release a client back to the pool
    fn release_client(&self, _client: &Client) {
        let pool = self.connection_pool.lock().unwrap();
        debug!("Released client connection back to the pool. Available: {}", pool.len());
    }
    
    /// Set up a clean database state for verification based on the pre-state
    async fn setup_clean_environment(&self, client: &Client, pre_state: &DatabaseState) -> Result<()> {
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
    async fn create_table(&self, client: &Client, schema: &crate::verification::state::TableSchema) -> Result<()> {
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
    async fn insert_row(&self, client: &Client, schema: &crate::verification::state::TableSchema, row: &Row) -> Result<()> {
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
        let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = Vec::new();
        for column in &columns {
            if let Some(value) = row.values.get(column) {
                // Convert the value to a PostgreSQL type
                // This is a simplified conversion - in reality, you'd need to handle all PostgreSQL types
                match value {
                    crate::verification::state::Value::Null => params.push(&None::<String>),
                    crate::verification::state::Value::String(s) => params.push(s),
                    crate::verification::state::Value::Integer(i) => params.push(i),
                    crate::verification::state::Value::Float(f) => params.push(f),
                    crate::verification::state::Value::Boolean(b) => params.push(b),
                    // For more complex types, you'd need to convert them appropriately
                    _ => return Err(ProxyError::Database(format!("Unsupported value type for column {}", column))),
                }
            } else {
                params.push(&None::<String>);
            }
        }
        
        // Execute the INSERT statement
        client.execute(&insert_stmt, &params)
            .await
            .map_err(|e| ProxyError::Database(format!("Failed to insert row into {}: {}", schema.name, e)))?;
            
        Ok(())
    }
    
    /// Set deterministic parameters for the session
    async fn set_deterministic_parameters(&self, client: &Client) -> Result<()> {
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
        pre_state: DatabaseState,
        expected_post_state: DatabaseState,
    ) -> Result<VerificationExecutionResult> {
        let start_time = Instant::now();
        let mut result = VerificationExecutionResult {
            success: false,
            expected_state: Some(expected_post_state.clone()),
            actual_state: None,
            mismatched_tables: Vec::new(),
            mismatched_rows: HashMap::new(),
            execution_time_ms: 0,
            error: None,
            operations_executed: 0,
        };
        
        // Get a client from the pool or create a new one
        let client = match self.get_client().await {
            Ok(client) => client,
            Err(e) => {
                result.error = Some(format!("Failed to get database client: {}", e));
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
    async fn execute_query_with_client(&self, client: &Client, query: &str) -> Result<Vec<tokio_postgres::Row>> {
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
    async fn capture_actual_state(&self, client: &Client, expected_state: &DatabaseState) -> Result<DatabaseState> {
        let mut actual_state = DatabaseState::new();
        
        // For each table in the expected state, capture the actual state
        for (table_name, expected_table) in expected_state.tables().iter() {
            let schema_name = &expected_table.schema;
            
            // Capture the table schema
            let table_schema = expected_table.table_schema.clone();
            
            // Capture the table data
            let query = format!(
                "SELECT * FROM {}.{}",
                self.config.verification_schema,
                table_name
            );
            
            let rows = client.query(&query, &[]).await
                .map_err(|e| ProxyError::Database(format!("Failed to query table {}: {}", table_name, e)))?;
                
            let mut table_state = TableState::new(table_name, schema_name, table_schema);
            
            // Convert rows to Row structs
            for pg_row in rows {
                let mut row_values = HashMap::new();
                let mut row_id_values = HashMap::new();
                
                for (i, column) in table_state.table_schema.columns.iter().enumerate() {
                    let value = match column.data_type.as_str() {
                        "integer" | "int" | "int4" => {
                            let val: Option<i32> = pg_row.get(i);
                            match val {
                                Some(v) => crate::verification::state::Value::Integer(v as i64),
                                None => crate::verification::state::Value::Null,
                            }
                        },
                        "bigint" | "int8" => {
                            let val: Option<i64> = pg_row.get(i);
                            match val {
                                Some(v) => crate::verification::state::Value::Integer(v),
                                None => crate::verification::state::Value::Null,
                            }
                        },
                        "text" | "varchar" | "char" | "character varying" => {
                            let val: Option<String> = pg_row.get(i);
                            match val {
                                Some(v) => crate::verification::state::Value::String(v),
                                None => crate::verification::state::Value::Null,
                            }
                        },
                        "float" | "float4" | "float8" | "real" | "double precision" => {
                            let val: Option<f64> = pg_row.get(i);
                            match val {
                                Some(v) => crate::verification::state::Value::Float(v),
                                None => crate::verification::state::Value::Null,
                            }
                        },
                        "boolean" | "bool" => {
                            let val: Option<bool> = pg_row.get(i);
                            match val {
                                Some(v) => crate::verification::state::Value::Boolean(v),
                                None => crate::verification::state::Value::Null,
                            }
                        },
                        // Add more types as needed
                        _ => {
                            // For unknown types, try to get as string
                            let val: Option<String> = pg_row.get(i);
                            match val {
                                Some(v) => crate::verification::state::Value::String(v),
                                None => crate::verification::state::Value::Null,
                            }
                        }
                    };
                    
                    row_values.insert(column.name.clone(), value.clone());
                    
                    // If this column is part of the primary key, add it to the row ID
                    if table_state.table_schema.primary_key.contains(&column.name) {
                        let id_value = match value {
                            crate::verification::state::Value::String(ref s) => s.clone(),
                            crate::verification::state::Value::Integer(i) => i.to_string(),
                            crate::verification::state::Value::Float(f) => f.to_string(),
                            crate::verification::state::Value::Boolean(b) => b.to_string(),
                            crate::verification::state::Value::Null => "NULL".to_string(),
                            _ => format!("{:?}", value),
                        };
                        
                        row_id_values.insert(column.name.clone(), id_value);
                    }
                }
                
                let row_id = RowId {
                    values: row_id_values,
                };
                
                let row = Row {
                    id: row_id,
                    values: row_values,
                    modified_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };
                
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
    fn compare_states(&self, expected: &DatabaseState, actual: &DatabaseState) -> (Vec<String>, HashMap<String, Vec<RowId>>) {
        let mut mismatched_tables = Vec::new();
        let mut mismatched_rows = HashMap::new();
        
        // Compare root hashes
        if expected.root_hash() != actual.root_hash() {
            debug!("Root hash mismatch: expected {:?}, got {:?}", 
                expected.root_hash(), actual.root_hash());
            
            // Compare individual tables
            for (table_name, expected_table) in expected.tables().iter() {
                let table_name_str = table_name.as_str();
                // Check if the table exists in both states
                if let Some(actual_table) = actual.get_table(table_name_str) {
                    // Compare table root hashes
                    if expected_table.root_hash != actual_table.root_hash {
                        debug!("Table root hash mismatch for {}: expected {:?}, actual {:?}",
                            table_name, expected_table.root_hash, actual_table.root_hash);
                        
                        mismatched_tables.push(table_name.clone());
                        
                        // Track mismatched rows for this table
                        let mut table_mismatched_rows = Vec::new();
                        
                        // Check for rows in expected that are missing or different in actual
                        for (row_id, expected_row) in &expected_table.rows {
                            if let Some(actual_row) = actual_table.rows.get(row_id) {
                                // Compare row values (manually compare keys and values)
                                let mut values_match = true;
                                if expected_row.values.len() != actual_row.values.len() {
                                    values_match = false;
                                } else {
                                    for (key, exp_value) in &expected_row.values {
                                        if let Some(act_value) = actual_row.values.get(key) {
                                            // Compare values as strings for simplicity
                                            if format!("{:?}", exp_value) != format!("{:?}", act_value) {
                                                values_match = false;
                                                break;
                                            }
                                        } else {
                                            values_match = false;
                                            break;
                                        }
                                    }
                                }
                                
                                if !values_match {
                                    debug!("Row value mismatch in table {} for ID {:?}",
                                        table_name, row_id);
                                    table_mismatched_rows.push(row_id.clone());
                                }
                            } else {
                                // Row is missing in actual
                                debug!("Missing row in actual state for table {} with ID {:?}",
                                    table_name, row_id);
                                table_mismatched_rows.push(row_id.clone());
                            }
                        }
                        
                        // Check for rows in actual that are not in expected
                        for (row_id, _) in &actual_table.rows {
                            if !expected_table.rows.contains_key(row_id) {
                                debug!("Extra row in actual state for table {} with ID {:?}",
                                    table_name, row_id);
                                table_mismatched_rows.push(row_id.clone());
                            }
                        }
                        
                        if !table_mismatched_rows.is_empty() {
                            mismatched_rows.insert(table_name.clone(), table_mismatched_rows);
                        }
                    }
                } else {
                    // Table missing from actual state
                    debug!("Table {} missing from actual state", table_name);
                    mismatched_tables.push(table_name.clone());
                }
            }
            
            // Check for tables in actual that are not in expected
            for (table_name, _) in actual.tables().iter() {
                let table_name_str = table_name.as_str();
                if !expected.has_table(table_name_str) {
                    debug!("Extra table {} in actual state", table_name);
                    mismatched_tables.push(table_name.clone());
                }
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
        let mut pool = self.connection_pool.lock().unwrap();
        
        // Close all database connections
        for entry in pool.iter_mut() {
            // Only attempt to close connections that are not already closed
            if !entry.in_use {
                // No need to actually close connections - they'll be dropped
                // Just mark them as in_use so we don't try to reuse them
                entry.in_use = true;
            }
        }
        
        // Clear the pool
        pool.clear();
        
        Ok(())
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
            reuse_connections: true,
            pool_size: 5,
        };
        
        let state_capture = Arc::new(StateCaptureManager::new());
        
        // This should not panic
        let _env = VerificationEnvironment::new(config, state_capture);
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
            reuse_connections: true,
            pool_size: 5,
        };
        
        let state_capture = Arc::new(StateCaptureManager::new());
        
        // Create the environment
        let env = VerificationEnvironment::new(config, state_capture);
        
        // Create a runtime to run the async cleanup
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            // This should not panic even when there are no connections
            let result = env.cleanup().await;
            assert!(result.is_ok());
        });
    }
} 