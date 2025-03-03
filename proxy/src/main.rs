use anyhow::Result;
use clap::Parser;
use log::{info, error};
use std::net::SocketAddr;
use verifiable_db_proxy::server::ProxyServer;
use verifiable_db_proxy::config::ProxyConfig;

#[derive(Parser, Debug)]
#[clap(author, version, about = "Verifiable RDS PostgreSQL Wire Protocol Proxy")]
struct Args {
    /// Config file path
    #[clap(short, long, env = "PROXY_CONFIG")]
    config: Option<String>,

    /// PostgreSQL host to connect to
    #[clap(long, env = "PG_HOST")]
    pg_host: Option<String>,

    /// PostgreSQL port to connect to
    #[clap(long, env = "PG_PORT")]
    pg_port: Option<u16>,

    /// PostgreSQL user for backend connection
    #[clap(long, env = "PG_USER")]
    pg_user: Option<String>,

    /// PostgreSQL password for backend connection
    #[clap(long, env = "PG_PASSWORD")]
    pg_password: Option<String>,

    /// PostgreSQL database for backend connection
    #[clap(long, env = "PG_DATABASE")]
    pg_database: Option<String>,

    /// TCP port to listen on
    #[clap(short, long, env = "PROXY_PORT")]
    port: Option<u16>,

    /// Enable verification
    #[clap(long, env = "VERIFICATION_ENABLED")]
    verification_enabled: Option<bool>,

    /// Rate limit for client connections
    #[clap(long, env = "RATE_LIMIT")]
    rate_limit: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    // Parse command-line arguments
    let args = Args::parse();

    // Load configuration
    let mut config = ProxyConfig::new();
    
    if let Some(config_path) = args.config {
        config = ProxyConfig::from_file(&config_path)?;
    }

    // Override config with command-line arguments
    if let Some(pg_host) = args.pg_host {
        config.pg_host = pg_host;
    }
    if let Some(pg_port) = args.pg_port {
        config.pg_port = pg_port;
    }
    if let Some(pg_user) = args.pg_user {
        config.pg_user = pg_user;
    }
    if let Some(pg_password) = args.pg_password {
        config.pg_password = pg_password;
    }
    if let Some(pg_database) = args.pg_database {
        config.pg_database = pg_database;
    }
    if let Some(port) = args.port {
        config.proxy_port = port;
    }
    if let Some(verification_enabled) = args.verification_enabled {
        config.verification_enabled = verification_enabled;
    }
    if let Some(rate_limit) = args.rate_limit {
        config.rate_limiter_config.max_requests_per_second = rate_limit;
    }

    // Create proxy server
    let server = ProxyServer::new(config)?;
    
    // Get server address
    let addr = SocketAddr::from(([0, 0, 0, 0], server.config().proxy_port));
    
    info!("Starting PostgreSQL wire protocol proxy on {}", addr);
    info!("Backend PostgreSQL: {}:{}", server.config().pg_host, server.config().pg_port);
    
    // Start server
    server.start().await?;
    
    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    
    // Stop server
    server.stop();
    
    info!("Server stopped");
    
    Ok(())
} 