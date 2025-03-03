//! Query interception and analysis module
//! 
//! This module handles query parsing, analysis, rewriting and integration
//! with the verification engine.

pub mod analyzer;
pub mod execution;
pub mod rewrite;
pub mod verification;

pub use analyzer::{QueryAnalyzer, QueryMetadata, QueryType};
pub use execution::{QueryExecutor, ExecutionPlan, ExecutionResult, ExecutorConfig};
pub use rewrite::{QueryRewriter, RewriteAction, RewriteReason, RewriterConfig};
pub use verification::{VerificationManager, VerificationResult, VerificationStatus, VerificationConfig};

use crate::error::{ProxyError, Result};
use crate::protocol::{FrontendMessage, BackendMessage};
use log::{debug, info, warn, error};
use std::sync::Arc;

/// Interception manager responsible for query analysis, transformation and verification
#[derive(Debug)]
pub struct InterceptionManager {
    /// Query analyzer to extract metadata and classify queries
    analyzer: QueryAnalyzer,
    
    /// Query rewriter to transform queries when needed
    rewriter: QueryRewriter,
    
    /// Query executor for special queries
    executor: QueryExecutor,
    
    /// Verification manager for integration with the core verification engine
    verifier: VerificationManager,
    
    /// Configuration for the interception manager
    config: InterceptionConfig,
}

/// Configuration for the interception manager
#[derive(Debug, Clone)]
pub struct InterceptionConfig {
    /// Whether to enable rewriting of queries
    pub enable_rewriting: bool,
    
    /// Maximum query size to analyze
    pub max_query_size: usize,
    
    /// Whether to capture state for verification
    pub capture_state: bool,
    
    /// Whether to enforce verification
    pub enforce_verification: bool,
    
    /// Whether to track query dependencies
    pub track_dependencies: bool,
    
    /// Rate limit for complex queries (per minute)
    pub complex_query_rate_limit: Option<u32>,
}

impl Default for InterceptionConfig {
    fn default() -> Self {
        Self {
            enable_rewriting: true,
            max_query_size: 1 << 20, // 1MB
            capture_state: true,
            enforce_verification: false, // Default to off for now
            track_dependencies: true,
            complex_query_rate_limit: Some(100),
        }
    }
}

impl InterceptionManager {
    /// Create a new interception manager
    pub fn new(config: InterceptionConfig) -> Self {
        let analyzer = QueryAnalyzer::new();
        let rewriter = QueryRewriter::new(RewriterConfig::default());
        let executor = QueryExecutor::new(ExecutorConfig::default());
        let verifier = VerificationManager::new(VerificationConfig::default());
        
        Self {
            analyzer,
            rewriter,
            executor,
            verifier: tokio::runtime::Runtime::new()
                .expect("Failed to create runtime")
                .block_on(verifier),
            config,
        }
    }
    
    /// Process a query message, potentially transforming it
    pub fn process_query(&mut self, query: &str) -> Result<QueryProcessingResult> {
        // Skip processing if query is too large
        if query.len() > self.config.max_query_size {
            warn!("Query exceeds maximum size for analysis: {} bytes", query.len());
            return Ok(QueryProcessingResult {
                action: QueryAction::Forward,
                transformed_query: None,
                metadata: None,
            });
        }
        
        // First, analyze the query
        debug!("Analyzing query: {}", query);
        let metadata = match self.analyzer.analyze(query) {
            Ok(meta) => meta,
            Err(e) => {
                warn!("Failed to analyze query: {}", e);
                return Ok(QueryProcessingResult {
                    action: QueryAction::Forward,
                    transformed_query: None,
                    metadata: None,
                });
            }
        };
        
        debug!("Query metadata: {:?}", metadata);
        
        // Decide if we need to rewrite the query
        let rewrite_result = if self.config.enable_rewriting {
            self.rewriter.rewrite(query, &metadata)?
        } else {
            (query.to_string(), RewriteAction::NoAction)
        };
        
        debug!("Query rewritten: {}", rewrite_result.0);
        debug!("Rewrite reason: {:?}", rewrite_result.1);
        
        // Check if this is a special query we should handle ourselves
        if metadata.is_special_handling() {
            debug!("Special handling for query");
            return Ok(QueryProcessingResult {
                action: QueryAction::Handle,
                transformed_query: Some(rewrite_result.0),
                metadata: Some(metadata),
            });
        }
        
        // Perform verification checks
        if self.config.capture_state && metadata.modifies_data() {
            debug!("Capturing state for verification");
            // Use a different method since capture_state doesn't exist
            tokio::runtime::Runtime::new()
                .expect("Failed to create runtime")
                .block_on(self.verifier.prepare_verification(&metadata))?;
        }
        
        // Return the processing result
        Ok(QueryProcessingResult {
            action: QueryAction::Forward,
            transformed_query: Some(rewrite_result.0),
            metadata: Some(metadata),
        })
    }
    
    /// Process backend response for analysis and verification
    pub fn process_response(&mut self, message: &BackendMessage, metadata: Option<&QueryMetadata>) -> Result<()> {
        // Skip if no metadata
        let metadata = match metadata {
            Some(meta) => meta,
            None => return Ok(()),
        };
        
        match message {
            BackendMessage::DataRow(_) => {
                // Track row results if needed
                if self.config.track_dependencies {
                    self.analyzer.track_result_row(metadata);
                }
            }
            BackendMessage::CommandComplete(cmd) => {
                // Command complete tag is a string in this implementation
                let tag = match cmd {
                    BackendMessage::CommandComplete(tag_str) => tag_str,
                    _ => unreachable!(),
                };
                
                debug!("Processing command completion: {}", tag);
                
                // For DML operations, verify affected rows
                if metadata.modifies_data() {
                    if let Some(num_rows) = Self::extract_affected_rows(tag) {
                        debug!("DML affected {} rows", num_rows);
                    }
                    
                    // If verification is enabled, verify the state
                    if self.config.enforce_verification {
                        // Use a different method since verify_state doesn't exist
                        tokio::runtime::Runtime::new()
                            .expect("Failed to create runtime")
                            .block_on(self.verifier.verify_transaction(metadata))?;
                    }
                }
            }
            BackendMessage::ErrorResponse(err) => {
                // Log errors
                debug!("Query execution error: {:?}", err);
            }
            _ => {
                // Ignore other message types
            }
        }
        
        Ok(())
    }
    
    /// Execute a special query directly
    pub fn execute_special_query(&mut self, query: &str, metadata: &QueryMetadata) -> Result<Vec<BackendMessage>> {
        let result = self.executor.execute_query(query, metadata)?;
        Ok(result.messages)
    }
    
    /// Extract the number of affected rows from a command completion tag
    fn extract_affected_rows(tag: &str) -> Option<u64> {
        // Command tags have format: "INSERT 0 1" or "UPDATE 5"
        let parts: Vec<&str> = tag.split_whitespace().collect();
        if parts.len() >= 2 {
            if parts[0] == "INSERT" && parts.len() >= 3 {
                // For INSERT, the count is the third word
                parts[2].parse::<u64>().ok()
            } else {
                // For UPDATE, DELETE, etc. the count is the second word
                parts[1].parse::<u64>().ok()
            }
        } else {
            None
        }
    }
}

/// Result of query processing
#[derive(Debug)]
pub struct QueryProcessingResult {
    /// Action to take with the query
    pub action: QueryAction,
    
    /// Transformed query, if rewritten
    pub transformed_query: Option<String>,
    
    /// Query metadata if analysis was successful
    pub metadata: Option<QueryMetadata>,
}

/// Action to take with a processed query
#[derive(Debug, PartialEq, Eq)]
pub enum QueryAction {
    /// Forward the query to the database
    Forward,
    
    /// Handle the query directly without forwarding
    Handle,
    
    /// Reject the query
    Reject,
} 