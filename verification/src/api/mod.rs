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
use verifiable_db_core::models::{
    BlockState, 
    BlockHeader, 
    Challenge, ChallengeType, ChallengeStatus, 
    TransactionRecord
};
use verifiable_db_core::merkle::SecureMerkleProof;

/// Common response type that can be either data or an error
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ApiResponse<T> {
    Success(T),
    Error { error: String }
}

/// The shared application state using core::BlockState
pub struct AppState {
    /// Current database state (latest block)
    pub db_state: RwLock<Option<BlockState>>,
    
    /// History of database states (blocks)
    pub state_history: RwLock<HashMap<u64, BlockState>>,
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

/// Response for state root endpoint - aligned with core::BlockHeader
#[derive(Debug, Serialize)]
struct StateRootResponse {
    block_number: u64,
    state_root: String, // hex encoded
    timestamp: u64,
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
                block_number: db_state.header.number, // Use core field name
                state_root: hex::encode(db_state.header.state_root), // Use core field name
                timestamp: db_state.header.timestamp, // Use core field name
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
                block_number: db_state.header.number, // Use core field name
                state_root: hex::encode(db_state.header.state_root), // Use core field name
                timestamp: db_state.header.timestamp, // Use core field name
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

/// Response for table state endpoint - Simplified as BlockState only has roots
#[derive(Debug, Serialize)]
struct TableStateResponse {
    table_name: String,
    table_root: String, // hex encoded root hash
    block_number: u64,
}

/// Get the state (root hash) of a specific table at the latest block
async fn get_table_state(
    State(state): State<Arc<AppState>>,
    Path(table_name): Path<String>,
) -> impl IntoResponse {
    let db_state = state.db_state.read().await;
    
    let response = match &*db_state {
        Some(db_state) => {
            // Access table_roots from core::BlockState
            match db_state.table_roots.get(&table_name) {
                Some(table_root) => {
                    let data = TableStateResponse {
                        table_name: table_name.clone(),
                        table_root: hex::encode(table_root),
                        block_number: db_state.header.number,
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

/// Response for row proof endpoint - Aligned with core structures
#[derive(Debug, Serialize)]
struct RowProofResponse {
    table_name: String,
    primary_key: String, // Assuming primary key is still a string for identification
    proof: SecureMerkleProof, // Use the core proof type
    state_root: String, // hex encoded root of the overall state tree
    block_number: u64,
}

/// Get proof for a specific row
async fn get_row_proof(
    State(state): State<Arc<AppState>>,
    Path((table_name, primary_key)): Path<(String, String)>,
    Query(params): Query<RowProofQuery>,
) -> impl IntoResponse {
    // Logic needs significant update to use core::BlockState and generate proofs
    // Placeholder logic remains for now
    
    let maybe_db_state = match params.block_number {
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
    
    match maybe_db_state {
        Some(db_state) => {
            // TODO: Implement actual proof generation using db_state.table_roots
            // and potentially fetching TableState/Row data from another source or cache.
            // This placeholder just uses the overall state root.
            let proof = SecureMerkleProof::default(); // Placeholder proof
            let data = RowProofResponse {
                table_name,
                primary_key,
                proof, // Placeholder
                state_root: hex::encode(db_state.header.state_root),
                block_number: db_state.header.number,
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
    }
}

/// Request for verifying a transaction - Update if it uses core types
#[derive(Debug, Deserialize)]
struct VerifyTransactionRequest {
    transaction_id: u64, // Assuming using u64 based on memo item #4
    // Include other necessary fields like pre/post state roots, operations etc.
    // These might need to align with core::TransactionRecord or core::Operation
    pre_state_root: String, // hex encoded
    post_state_root: String, // hex encoded
    operations: Vec<String>, // Placeholder: Needs proper Operation type alignment
}

/// Response for transaction verification - Update if it uses core types
#[derive(Debug, Serialize)]
struct VerifyTransactionResponse {
    transaction_id: u64,
    verified: bool,
    reason: Option<String>,
}

// TODO: Update verify_transaction logic based on core types and actual verification flow
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
        verified: true,
        reason: Some("Transaction verified successfully".to_string()),
    };
    
    (StatusCode::OK, Json(response))
}

/// Request for submitting a challenge - Update if it uses core types
#[derive(Debug, Deserialize)]
struct ChallengeRequest {
    challenge_type: String, // e.g., "StateTransition", "RowInclusion"
    block_number: u64,
    details: serde_json::Value, // Using serde_json::Value for flexibility, might need refinement
    // Potentially align with core::Challenge
}

/// Response for challenge submission - Update if it uses core types
#[derive(Debug, Serialize)]
struct ChallengeResponse {
    challenge_id: String, // Placeholder: Use ID from core::Challenge?
    status: String, // e.g., "Submitted", "Failed"
}

// TODO: Update submit_challenge logic based on core::Challenge and actual challenge flow
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
        challenge_id: "12345".to_string(), // Placeholder
        status: "pending".to_string(),
    };
    
    (StatusCode::OK, Json(response))
}