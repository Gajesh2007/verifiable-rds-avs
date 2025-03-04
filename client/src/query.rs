//! Query client for executing SQL queries against the verifiable database
//!
//! This module provides a client for executing SQL queries against the
//! verifiable database with verification features.

use std::collections::HashMap;
use std::time::Duration;
use postgres::{Client, NoTls, Row};
use serde::{Serialize, Deserialize};
use thiserror::Error;
use crate::verification::{VerificationClient, VerificationResult};

/// Error type for query operations
#[derive(Error, Debug)]
pub enum QueryError {
    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] postgres::Error),
    
    /// Verification error
    #[error("Verification error: {0}")]
    Verification(String),
    
    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),
    
    /// Timeout error
    #[error("Timeout error: {0}")]
    Timeout(String),
    
    /// Other error
    #[error("Other error: {0}")]
    Other(String),
}

/// Result type for query operations
pub type Result<T> = std::result::Result<T, QueryError>;

/// Query result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// Result rows
    pub rows: Vec<HashMap<String, serde_json::Value>>,
    
    /// Affected row count
    pub row_count: i64,
    
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    
    /// Transaction ID
    pub transaction_id: Option<u64>,
    
    /// Whether this query was verified
    pub verified: bool,
    
    /// Verification result (if verified)
    pub verification_result: Option<VerificationResult>,
}

/// Query client for executing SQL queries
pub struct QueryClient {
    /// Database connection string
    connection_string: String,
    
    /// Database client
    client: Option<Client>,
    
    /// Verification client
    verification_client: Option<VerificationClient>,
    
    /// Whether to verify queries
    verify_queries: bool,
    
    /// Connection timeout
    timeout: Duration,
}

impl QueryClient {
    /// Create a new query client
    pub fn new(connection_string: &str) -> Self {
        Self {
            connection_string: connection_string.to_string(),
            client: None,
            verification_client: None,
            verify_queries: false,
            timeout: Duration::from_secs(30),
        }
    }
    
    /// Set the verification client
    pub fn with_verification_client(mut self, verification_client: VerificationClient) -> Self {
        self.verification_client = Some(verification_client);
        self.verify_queries = true;
        self
    }
    
    /// Set whether to verify queries
    pub fn with_verification(mut self, verify: bool) -> Self {
        self.verify_queries = verify;
        self
    }
    
    /// Set the connection timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    
    /// Connect to the database
    pub fn connect(&mut self) -> Result<()> {
        // Connect directly using the connection string
        let client = Client::connect(&self.connection_string, NoTls)?;
        self.client = Some(client);
        
        Ok(())
    }
    
    /// Execute a query
    pub async fn query(&mut self, query: &str) -> Result<QueryResult> {
        // Ensure we're connected
        if self.client.is_none() {
            self.connect()?;
        }
        
        let client = self.client.as_mut()
            .ok_or_else(|| QueryError::Connection("Not connected".to_string()))?;
            
        // Execute the query
        let start = std::time::Instant::now();
        let result = client.query(query, &[])?;
        let execution_time = start.elapsed();
        
        // Convert rows to maps
        let rows = result.iter()
            .map(|row| row_to_map(row))
            .collect();
            
        // Create basic result
        let mut query_result = QueryResult {
            rows,
            row_count: result.len() as i64,
            execution_time_ms: execution_time.as_millis() as u64,
            transaction_id: None,
            verified: false,
            verification_result: None,
        };
        
        // Verify if requested and verification client is available
        if self.verify_queries && self.verification_client.is_some() {
            // In a real implementation, we would extract the transaction ID
            // from the response headers or a special query
            // For now, we'll assume transaction ID 0
            let transaction_id = 0;
            
            if transaction_id > 0 {
                query_result.transaction_id = Some(transaction_id);
                
                // Verify the transaction
                if let Some(verification_client) = &self.verification_client {
                    match verification_client.verify_transaction(transaction_id).await {
                        Ok(verification_result) => {
                            query_result.verified = true;
                            query_result.verification_result = Some(verification_result);
                        },
                        Err(e) => {
                            return Err(QueryError::Verification(e.to_string()));
                        }
                    }
                }
            }
        }
        
        Ok(query_result)
    }
    
    /// Execute a query and return a single value
    pub async fn query_single<T>(&mut self, query: &str) -> Result<T>
    where
        for<'a> T: postgres::types::FromSql<'a>,
    {
        // Ensure we're connected
        if self.client.is_none() {
            self.connect()?;
        }
        
        let client = self.client.as_mut()
            .ok_or_else(|| QueryError::Connection("Not connected".to_string()))?;
            
        // Execute the query
        let result = client.query_one(query, &[])?;
        
        // Get the value
        let value: T = result.get(0);
        
        Ok(value)
    }
    
    /// Begin a transaction
    pub fn begin(&mut self) -> Result<()> {
        // Ensure we're connected
        if self.client.is_none() {
            self.connect()?;
        }
        
        let client = self.client.as_mut()
            .ok_or_else(|| QueryError::Connection("Not connected".to_string()))?;
            
        // Begin the transaction
        client.execute("BEGIN", &[])?;
        
        Ok(())
    }
    
    /// Commit a transaction
    pub fn commit(&mut self) -> Result<()> {
        // Ensure we're connected
        if self.client.is_none() {
            return Err(QueryError::Connection("Not connected".to_string()));
        }
        
        let client = self.client.as_mut()
            .ok_or_else(|| QueryError::Connection("Not connected".to_string()))?;
            
        // Commit the transaction
        client.execute("COMMIT", &[])?;
        
        Ok(())
    }
    
    /// Rollback a transaction
    pub fn rollback(&mut self) -> Result<()> {
        // Ensure we're connected
        if self.client.is_none() {
            return Err(QueryError::Connection("Not connected".to_string()));
        }
        
        let client = self.client.as_mut()
            .ok_or_else(|| QueryError::Connection("Not connected".to_string()))?;
            
        // Rollback the transaction
        client.execute("ROLLBACK", &[])?;
        
        Ok(())
    }
    
    /// Close the connection
    pub fn close(&mut self) -> Result<()> {
        self.client = None;
        Ok(())
    }
    
    /// Analyze a query for determinism and security without executing it
    pub async fn analyze_query(&mut self, query: &str) -> Result<crate::verification::QueryAnalysisResult> {
        if let Some(ref verification_client) = self.verification_client {
            match verification_client.analyze_query(query).await {
                Ok(result) => Ok(result),
                Err(e) => Err(QueryError::Verification(e.to_string())),
            }
        } else {
            Err(QueryError::Verification("No verification client provided".to_string()))
        }
    }
    
    /// Rewrite a query for deterministic execution without executing it
    pub async fn rewrite_query(&mut self, query: &str) -> Result<String> {
        if let Some(ref verification_client) = self.verification_client {
            match verification_client.rewrite_query(query).await {
                Ok(result) => Ok(result),
                Err(e) => Err(QueryError::Verification(e.to_string())),
            }
        } else {
            Err(QueryError::Verification("No verification client provided".to_string()))
        }
    }
    
    /// Get information about available deterministic functions
    pub async fn get_deterministic_functions(&mut self) -> Result<Vec<String>> {
        if let Some(ref verification_client) = self.verification_client {
            match verification_client.get_deterministic_functions().await {
                Ok(result) => Ok(result),
                Err(e) => Err(QueryError::Verification(e.to_string())),
            }
        } else {
            Err(QueryError::Verification("No verification client provided".to_string()))
        }
    }
    
    /// Execute a query with automatic rewriting for determinism
    pub async fn query_with_rewrite(&mut self, query: &str) -> Result<QueryResult> {
        if let Some(ref verification_client) = self.verification_client {
            // First try to rewrite the query for determinism
            let rewritten_query = match verification_client.rewrite_query(query).await {
                Ok(result) => result,
                Err(e) => {
                    // Fall back to original query if rewriting fails
                    eprintln!("Warning: Query rewriting failed: {}", e);
                    query.to_string()
                }
            };
            
            // Execute the rewritten query
            self.query(&rewritten_query).await
        } else {
            // If no verification client, just execute the original query
            self.query(query).await
        }
    }
}

/// Convert a PostgreSQL row to a map
fn row_to_map(row: &Row) -> HashMap<String, serde_json::Value> {
    let mut map = HashMap::new();
    
    for column in row.columns() {
        let name = column.name();
        let type_info = column.type_();
        
        // Convert the value to a serde_json::Value
        let value = if type_info.name() == "bool" {
            let val: Option<bool> = row.get(name);
            match val {
                Some(v) => serde_json::Value::Bool(v),
                None => serde_json::Value::Null,
            }
        } else if type_info.name() == "int2" || type_info.name() == "int4" {
            let val: Option<i32> = row.get(name);
            match val {
                Some(v) => serde_json::Value::Number(serde_json::Number::from(v)),
                None => serde_json::Value::Null,
            }
        } else if type_info.name() == "int8" {
            let val: Option<i64> = row.get(name);
            match val {
                Some(v) => serde_json::json!(v),
                None => serde_json::Value::Null,
            }
        } else if type_info.name() == "float4" || type_info.name() == "float8" {
            let val: Option<f64> = row.get(name);
            match val {
                Some(v) => serde_json::json!(v),
                None => serde_json::Value::Null,
            }
        } else if type_info.name() == "text" || type_info.name() == "varchar" {
            let val: Option<String> = row.get(name);
            match val {
                Some(v) => serde_json::Value::String(v),
                None => serde_json::Value::Null,
            }
        } else if type_info.name() == "json" || type_info.name() == "jsonb" {
            // Get the JSON as a string first, then parse it
            let val: Option<String> = row.get(name);
            match val {
                Some(v) => {
                    // Parse the JSON string
                    match serde_json::from_str(&v) {
                        Ok(json_val) => json_val,
                        Err(_) => serde_json::Value::String(v), // Fallback: treat as string
                    }
                },
                None => serde_json::Value::Null,
            }
        } else {
            // For other types, convert to string
            let val: Option<String> = row.get(name);
            match val {
                Some(v) => serde_json::Value::String(v),
                None => serde_json::Value::Null,
            }
        };
        
        map.insert(name.to_string(), value);
    }
    
    map
} 