use anyhow::Result;
use clap::Parser;
use log::{info, error};
use std::net::{SocketAddr, ToSocketAddrs};
use verifiable_db_proxy::server::ProxyServer;
use verifiable_db_proxy::config::ProxyConfig;
use tokio::signal::unix::{signal, SignalKind};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Config file path
    #[arg(short = 'c', long)]
    config: Option<String>,

    /// PostgreSQL host
    #[arg(short = 'H', long)]
    pg_host: Option<String>,

    /// PostgreSQL port
    #[arg(short = 'P', long)]
    pg_port: Option<u16>,

    /// PostgreSQL user
    #[arg(short = 'u', long)]
    pg_user: Option<String>,

    /// PostgreSQL password
    #[arg(short = 'w', long)]
    pg_password: Option<String>,

    /// PostgreSQL database
    #[arg(short = 'd', long)]
    pg_database: Option<String>,

    /// Proxy port
    #[arg(short = 'p', long)]
    port: Option<u16>,

    /// Enable or disable verification
    #[arg(short = 'v', long)]
    verification_enabled: Option<bool>,

    /// Verification service URL
    #[arg(short = 's', long)]
    verification_service_url: Option<String>,

    /// Rate limit
    #[arg(short = 'r', long)]
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
            // Use proper DNS resolution for hostnames
            let socket_str = format!("{}:{}", pg_host, port);
            match socket_str.to_socket_addrs() {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        config.backend_addr = addr;
                    } else {
                        return Err(format!("Could not resolve hostname: {}", socket_str).into());
                    }
                },
                Err(e) => {
                    return Err(format!("Invalid host or port: {} - {}", socket_str, e).into());
                }
            }
        } else {
            // Keep existing port but update host
            let port = config.backend_addr.port();
            let socket_str = format!("{}:{}", pg_host, port);
            match socket_str.to_socket_addrs() {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        config.backend_addr = addr;
                    } else {
                        return Err(format!("Could not resolve hostname: {}", socket_str).into());
                    }
                },
                Err(e) => {
                    return Err(format!("Invalid host or port: {} - {}", socket_str, e).into());
                }
            }
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
        // Also update the db_user field in ProxyConfig
        config.db_user = Some(pg_user);
    }
    
    if let Some(pg_password) = args.pg_password {
        // Update password in auth config (if the structure allows)
        info!("Setting PostgreSQL password");
        // Update the db_password field in ProxyConfig
        config.db_password = Some(pg_password);
    }
    
    if let Some(pg_database) = args.pg_database {
        // Update the db_name field in ProxyConfig
        info!("Setting PostgreSQL database to: {}", pg_database);
        config.db_name = Some(pg_database);
    }

    if let Some(port) = args.port {
        // Update listen_addr with the new port but keep the host
        let host = config.listen_addr.ip();
        config.listen_addr = SocketAddr::new(host, port);
    }
    
    if let Some(verification_enabled) = args.verification_enabled {
        // Enable/disable verification
        config.verification_config.enabled = verification_enabled;
    }
    
    if let Some(verification_service_url) = args.verification_service_url {
        // Set verification service URL
        config.verification_config.verification_service_url = Some(verification_service_url);
    }
    
    if let Some(rate_limit) = args.rate_limit {
        // Set rate limit
        config.rate_limiter_config.enabled = true;
        config.rate_limiter_config.rate_limit = rate_limit;
    } else {
        // Set a high default rate limit (1000 requests per minute) to avoid blocking during development
        config.rate_limiter_config.rate_limit = 1000;
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