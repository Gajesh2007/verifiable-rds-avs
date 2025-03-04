use anyhow::Result;
use clap::Parser;
use log::{info, error};
use std::net::SocketAddr;
use verifiable_db_proxy::server::ProxyServer;
use verifiable_db_proxy::config::ProxyConfig;
use tokio::signal::unix::{signal, SignalKind};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Config file path
    #[arg(short, long, value_parser)]
    config: Option<String>,

    /// PostgreSQL host
    #[arg(short, long, value_parser)]
    pg_host: Option<String>,

    /// PostgreSQL port
    #[arg(short, long, value_parser)]
    pg_port: Option<u16>,

    /// PostgreSQL user
    #[arg(short, long, value_parser)]
    pg_user: Option<String>,

    /// PostgreSQL password
    #[arg(short, long, value_parser)]
    pg_password: Option<String>,

    /// PostgreSQL database
    #[arg(short, long, value_parser)]
    pg_database: Option<String>,

    /// Proxy port
    #[arg(short, long, value_parser)]
    port: Option<u16>,

    /// Enable or disable verification
    #[arg(short, long, value_parser)]
    verification_enabled: Option<bool>,

    /// Rate limit
    #[arg(short, long, value_parser)]
    rate_limit: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let args = Args::parse();

    // Load config file if provided
    let mut config = if let Some(config_path) = &args.config {
        ProxyConfig::from_file(config_path)?
    } else {
        ProxyConfig::default()
    };

    // Override config with command line arguments
    if let Some(pg_host) = args.pg_host {
        if let Some(port) = args.pg_port {
            config.backend_addr = format!("{}:{}", pg_host, port).parse()?;
        } else {
            // Keep existing port but update host
            let port = config.backend_addr.port();
            let new_addr = format!("{}:{}", pg_host, port).parse()?;
            config.backend_addr = new_addr;
        }
    } else if let Some(pg_port) = args.pg_port {
        // Keep existing host but update port
        let host = config.backend_addr.ip();
        config.backend_addr = SocketAddr::new(host, pg_port);
    }
    
    if let Some(pg_user) = args.pg_user {
        // Update username in auth config (if the structure allows)
        // Check the actual structure of AuthConfig to see how to set this
        // For now, we'll just log it
        info!("Setting PostgreSQL user to: {}", pg_user);
        // Uncomment and modify this line based on the actual structure
        // config.auth_config.users.insert(pg_user, ...);
    }
    
    if let Some(pg_password) = args.pg_password {
        // Update password in auth config (if the structure allows)
        info!("Setting PostgreSQL password");
        // Uncomment and modify this line based on the actual structure
        // config.auth_config.users.insert(pg_user, pg_password);
    }
    
    // Note: Not handling pg_database as it might not be directly configurable in ProxyConfig

    if let Some(port) = args.port {
        // Update listen_addr with the new port but keep the host
        let host = config.listen_addr.ip();
        config.listen_addr = SocketAddr::new(host, port);
    }
    
    if let Some(verification_enabled) = args.verification_enabled {
        // Enable/disable verification
        config.verification_config.enabled = verification_enabled;
    }
    
    if let Some(rate_limit) = args.rate_limit {
        // Set rate limit
        config.rate_limiter_config.enabled = true;
        config.rate_limiter_config.rate_limit = rate_limit;
    }

    // Create proxy server
    let proxy = ProxyServer::new(config)?;
    
    // Log startup information
    info!("Proxy listening on {}", proxy.config().listen_addr);
    info!("Backend PostgreSQL: {}", proxy.config().backend_addr);

    // Start the proxy server
    proxy.start().await?;

    // Create a signal handler future
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    
    // Wait for termination signal
    tokio::select! {
        _ = sigterm.recv() => info!("Received SIGTERM"),
        _ = sigint.recv() => info!("Received SIGINT"),
    }

    // Clean shutdown
    info!("Shutting down proxy server");
    proxy.stop().await?;  // Ensure we properly shut down the server
    
    // Give background tasks time to exit
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    
    info!("Proxy server shutdown complete");
    Ok(())
} 