use axum::{
    Router,
    routing::{get, post},
    extract::{Path, Query, State, Json as AxumJson},
    response::{IntoResponse, Json},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use serde_json::Value;
use crate::state::{DatabaseState, TableState};

/// Common response type that can be either data or an error
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ApiResponse<T> {
    Success(T),
    Error { error: String }
}

/// The shared application state
pub struct AppState {
    /// Current database state
    pub db_state: RwLock<Option<DatabaseState>>,
    
    /// History of database states
    pub state_history: RwLock<HashMap<u64, DatabaseState>>,
}

/// Create a new API router with the specified state
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/state-root/:block_number", get(get_state_root))
        .route("/api/v1/state-root/latest", get(get_latest_state_root))
        .route("/api/v1/table-state/:table_name", get(get_table_state))
        .route("/api/v1/proof/row/:table/:primary_key", get(get_row_proof))
        .route("/api/v1/verify/transaction", post(verify_transaction))
        .route("/api/v1/challenge", post(submit_challenge))
        .with_state(state)
}

/// Response for state root endpoint
#[derive(Debug, Serialize)]
struct StateRootResponse {
    block_number: u64,
    state_root: String,
    timestamp: u64,
    version: u64,
}

/// Get the state root for a specific block
async fn get_state_root(
    State(state): State<Arc<AppState>>,
    Path(block_number): Path<u64>,
) -> impl IntoResponse {
    let state_history = state.state_history.read().await;
    
    let response = match state_history.get(&block_number) {
        Some(db_state) => {
            let data = StateRootResponse {
                block_number,
                state_root: hex::encode(db_state.merkle_root),
                timestamp: db_state.timestamp,
                version: db_state.version,
            };
            
            (StatusCode::OK, Json(ApiResponse::Success(data)))
        },
        None => {
            (
                StatusCode::NOT_FOUND, 
                Json(ApiResponse::Error { 
                    error: "State root not found for the specified block number".to_string() 
                })
            )
        }
    };
    
    response
}

/// Get the latest state root
async fn get_latest_state_root(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let db_state = state.db_state.read().await;
    
    let response = match &*db_state {
        Some(db_state) => {
            let data = StateRootResponse {
                block_number: db_state.version, // Use version as block number for simplicity
                state_root: hex::encode(db_state.merkle_root),
                timestamp: db_state.timestamp,
                version: db_state.version,
            };
            
            (StatusCode::OK, Json(ApiResponse::Success(data)))
        },
        None => {
            (
                StatusCode::NOT_FOUND, 
                Json(ApiResponse::Error { 
                    error: "No state root available yet".to_string() 
                })
            )
        }
    };
    
    response
}

/// Response for table state endpoint
#[derive(Debug, Serialize)]
struct TableStateResponse {
    table_name: String,
    schema: String,
    merkle_root: String,
    row_count: usize,
    version: u64,
}

/// Get the state of a specific table
async fn get_table_state(
    State(state): State<Arc<AppState>>,
    Path(table_name): Path<String>,
) -> impl IntoResponse {
    let db_state = state.db_state.read().await;
    
    let response = match &*db_state {
        Some(db_state) => {
            match db_state.tables.get(&table_name) {
                Some(table_state) => {
                    let data = TableStateResponse {
                        table_name: table_state.name.clone(),
                        schema: table_state.schema.clone(),
                        merkle_root: hex::encode(table_state.merkle_root),
                        row_count: table_state.rows.len(),
                        version: table_state.version,
                    };
                    
                    (StatusCode::OK, Json(ApiResponse::Success(data)))
                },
                None => {
                    (
                        StatusCode::NOT_FOUND, 
                        Json(ApiResponse::Error { 
                            error: "Table not found".to_string() 
                        })
                    )
                }
            }
        },
        None => {
            (
                StatusCode::NOT_FOUND, 
                Json(ApiResponse::Error { 
                    error: "No database state available yet".to_string() 
                })
            )
        }
    };
    
    response
}

/// Query parameters for row proof
#[derive(Debug, Deserialize)]
struct RowProofQuery {
    block_number: Option<u64>,
}

/// Response for row proof endpoint
#[derive(Debug, Serialize)]
struct RowProofResponse {
    table_name: String,
    primary_key: String,
    proof: String,
    merkle_root: String,
    block_number: u64,
}

/// Get proof for a specific row
async fn get_row_proof(
    State(state): State<Arc<AppState>>,
    Path((table_name, primary_key)): Path<(String, String)>,
    Query(params): Query<RowProofQuery>,
) -> impl IntoResponse {
    // In a real implementation, this would generate a proper Merkle proof
    // For this simplified version, we'll just return a placeholder
    
    let db_state = match params.block_number {
        Some(block_number) => {
            let state_history = state.state_history.read().await;
            match state_history.get(&block_number) {
                Some(db_state) => Some(db_state.clone()),
                None => None,
            }
        },
        None => {
            let db_state = state.db_state.read().await;
            match &*db_state {
                Some(db_state) => Some(db_state.clone()),
                None => None,
            }
        }
    };
    
    let response = match db_state {
        Some(db_state) => {
            let data = RowProofResponse {
                table_name,
                primary_key,
                proof: "0x1234567890abcdef".to_string(), // Placeholder proof
                merkle_root: hex::encode(db_state.merkle_root),
                block_number: db_state.version,
            };
            
            (StatusCode::OK, Json(ApiResponse::Success(data)))
        },
        None => {
            (
                StatusCode::NOT_FOUND, 
                Json(ApiResponse::Error { 
                    error: "Database state not found".to_string() 
                })
            )
        }
    };
    
    response
}

/// Request for verifying a transaction
#[derive(Debug, Deserialize)]
struct VerifyTransactionRequest {
    transaction_id: u64,
    query: String,
    pre_state_root: String,
    block_number: u64,
}

/// Response for transaction verification
#[derive(Debug, Serialize)]
struct VerifyTransactionResponse {
    transaction_id: u64,
    is_valid: bool,
    calculated_state_root: String,
    expected_state_root: String,
    details: Option<String>,
}

/// Verify a transaction
async fn verify_transaction(
    State(state): State<Arc<AppState>>,
    AxumJson(request): AxumJson<VerifyTransactionRequest>,
) -> impl IntoResponse {
    // In a real implementation, this would:
    // 1. Restore the database to the pre-state
    // 2. Execute the transaction
    // 3. Calculate the new state root
    // 4. Compare with the expected state root
    
    // For this simplified version, we'll just return a placeholder response
    let response = VerifyTransactionResponse {
        transaction_id: request.transaction_id,
        is_valid: true,
        calculated_state_root: request.pre_state_root.clone(), // Placeholder
        expected_state_root: request.pre_state_root,
        details: Some("Transaction verified successfully".to_string()),
    };
    
    (StatusCode::OK, Json(response))
}

/// Request for submitting a challenge
#[derive(Debug, Deserialize)]
struct ChallengeRequest {
    block_number: u64,
    transaction_id: u64,
    evidence: String,
    challenger_address: String,
}

/// Response for challenge submission
#[derive(Debug, Serialize)]
struct ChallengeResponse {
    challenge_id: u64,
    status: String,
    bond_amount: String,
    details: String,
}

/// Submit a challenge
async fn submit_challenge(
    State(state): State<Arc<AppState>>,
    AxumJson(request): AxumJson<ChallengeRequest>,
) -> impl IntoResponse {
    // In a real implementation, this would:
    // 1. Validate the challenge
    // 2. Verify the evidence
    // 3. Process the challenge through the EigenLayer contract
    
    // For this simplified version, we'll just return a placeholder response
    let response = ChallengeResponse {
        challenge_id: 12345, // Placeholder
        status: "pending".to_string(),
        bond_amount: "1000000000000000000".to_string(), // 1 ETH in wei
        details: "Challenge submitted successfully".to_string(),
    };
    
    (StatusCode::OK, Json(response))
} 