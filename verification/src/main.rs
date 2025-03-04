mod merkle;
mod state;
mod api;

use axum::{
    routing::{get, post},
    Router,
    response::{IntoResponse, Json},
    Extension,
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tokio_postgres::Client;
use serde_json::Value;

use api::AppState;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting verification service");

    // Create application state
    let app_state = Arc::new(AppState {
        db_state: RwLock::new(None),
        state_history: RwLock::new(HashMap::new()),
    });

    // Get API port from environment variable
    let port = std::env::var("API_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("API_PORT must be a valid port number");

    // Create the API router
    let api_router = api::create_router(app_state.clone());

    // Create the main router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/status", get(status))
        .nest("/api", api_router);

    // Run the API server
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> impl IntoResponse {
    Json(json!({ "status": "healthy" }))
}

async fn status() -> impl IntoResponse {
    Json(json!({
        "status": "operational",
        "version": env!("CARGO_PKG_VERSION"),
        "service": "verification",
        "features": {
            "merkle_trees": true,
            "state_capture": true,
            "eigenlayer_integration": false  // Not implemented yet
        }
    }))
} 