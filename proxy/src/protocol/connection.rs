//! Connection manager for client connections
use crate::config::ProxyConfig;
use crate::error::{ProxyError, Result};
use crate::protocol::auth::AuthHandler;
use crate::protocol::message::{BackendMessage, FrontendMessage, TransactionStatus};
use crate::protocol::parser::MessageParser;
use crate::protocol::formatter::MessageFormatter;
use crate::protocol::validator::ProtocolValidator;
use crate::query::interceptor::QueryInterceptor;
use crate::transaction::tracker::TransactionTracker;
use bytes::{Bytes, BytesMut};
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tokio_postgres::config::Config as PgConfig;
use tokio_postgres::Client;

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    /// Initial state
    Initial,
    
    /// Authenticating
    Authenticating,
    
    /// Ready for queries
    Ready,
    
    /// In transaction
    InTransaction,
    
    /// In failed transaction
    InFailedTransaction,
    
    /// Closing
    Closing,
    
    /// Closed
    Closed,
}

/// Connection statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Number of queries executed
    pub queries_executed: usize,
    
    /// Number of transactions executed
    pub transactions_executed: usize,
    
    /// Number of rows returned
    pub rows_returned: usize,
    
    /// Number of rows affected
    pub rows_affected: usize,
    
    /// Total bytes received
    pub bytes_received: usize,
    
    /// Total bytes sent
    pub bytes_sent: usize,
    
    /// Connection start time
    pub start_time: std::time::Instant,
    
    /// Last activity time
    pub last_activity: std::time::Instant,
}

/// Client connection
pub struct ClientConnection {
    /// Client socket
    socket: TcpStream,
    
    /// Client address
    addr: SocketAddr,
    
    /// Connection state
    state: ConnectionState,
    
    /// PostgreSQL backend client
    pg_client: Option<Client>,
    
    /// Message parser
    parser: MessageParser,
    
    /// Message formatter
    formatter: MessageFormatter,
    
    /// Authentication handler
    auth_handler: AuthHandler,
    
    /// Protocol validator
    validator: ProtocolValidator,
    
    /// Query interceptor
    query_interceptor: QueryInterceptor,
    
    /// Transaction tracker
    transaction_tracker: Arc<Mutex<TransactionTracker>>,
    
    /// Configuration
    config: ProxyConfig,
    
    /// Connection statistics
    stats: ConnectionStats,
    
    /// Buffer for reading
    read_buffer: BytesMut,
    
    /// Buffer for writing
    write_buffer: BytesMut,
}

impl ClientConnection {
    /// Create a new client connection
    pub fn new(
        socket: TcpStream,
        addr: SocketAddr,
        config: ProxyConfig,
        transaction_tracker: Arc<Mutex<TransactionTracker>>,
    ) -> Self {
        Self {
            socket,
            addr,
            state: ConnectionState::Initial,
            pg_client: None,
            parser: MessageParser::new(),
            formatter: MessageFormatter::new(),
            auth_handler: AuthHandler::new(config.clone()),
            validator: ProtocolValidator::new(),
            query_interceptor: QueryInterceptor::new(config.clone()),
            transaction_tracker,
            config,
            stats: ConnectionStats {
                start_time: std::time::Instant::now(),
                last_activity: std::time::Instant::now(),
                ..Default::default()
            },
            read_buffer: BytesMut::with_capacity(8192),
            write_buffer: BytesMut::with_capacity(8192),
        }
    }
    
    /// Handle the connection
    pub async fn handle(&mut self) -> Result<()> {
        // Set socket options
        self.socket.set_nodelay(true)?;
        
        // Split socket into reader and writer
        let (reader, writer) = self.socket.split();
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);
        
        // Setup connection timeout
        let timeout_duration = Duration::from_secs(self.config.connection_timeout);
        
        // Process messages
        while self.state != ConnectionState::Closed {
            // Update last activity time
            self.stats.last_activity = std::time::Instant::now();
            
            // Read message with timeout
            let read_result = timeout(timeout_duration, self.read_message(&mut reader)).await;
            
            // Check for timeout
            if let Err(_) = read_result {
                warn!("Connection timeout from {}", self.addr);
                self.state = ConnectionState::Closing;
                break;
            }
            
            // Process read result
            let message = match read_result.unwrap() {
                Ok(Some(message)) => message,
                Ok(None) => {
                    debug!("Client disconnected: {}", self.addr);
                    self.state = ConnectionState::Closing;
                    break;
                }
                Err(e) => {
                    error!("Error reading message from {}: {}", self.addr, e);
                    self.state = ConnectionState::Closing;
                    break;
                }
            };
            
            // Update statistics
            self.stats.bytes_received += message.len();
            
            // Parse message
            let frontend_message = match self.parser.parse_frontend_message(&message) {
                Ok(msg) => msg,
                Err(e) => {
                    error!("Error parsing message from {}: {}", self.addr, e);
                    let error_response = self.formatter.format_error_response(
                        "ERROR",
                        "XX000",
                        &format!("Protocol error: {}", e),
                    );
                    writer.write_all(&error_response).await?;
                    writer.flush().await?;
                    self.state = ConnectionState::Closing;
                    break;
                }
            };
            
            // Validate protocol state
            if let Err(e) = self.validator.validate_message(&frontend_message, self.state) {
                error!("Protocol validation error from {}: {}", self.addr, e);
                let error_response = self.formatter.format_error_response(
                    "ERROR",
                    "XX000",
                    &format!("Protocol validation error: {}", e),
                );
                writer.write_all(&error_response).await?;
                writer.flush().await?;
                self.state = ConnectionState::Closing;
                break;
            }
            
            // Process message
            let backend_messages = self.process_message(frontend_message).await?;
            
            // Send responses
            for backend_message in backend_messages {
                let formatted = self.formatter.format_backend_message(&backend_message)?;
                writer.write_all(&formatted).await?;
                self.stats.bytes_sent += formatted.len();
                
                // Update state from ReadyForQuery message
                if let BackendMessage::ReadyForQuery(transaction_status) = &backend_message {
                    self.update_state_from_transaction_status(*transaction_status);
                }
            }
            
            writer.flush().await?;
            
            // Check if connection should be closed
            if self.state == ConnectionState::Closing {
                break;
            }
        }
        
        // Close connection
        if self.state != ConnectionState::Closed {
            self.state = ConnectionState::Closed;
            info!("Connection closed: {}", self.addr);
        }
        
        Ok(())
    }
    
    /// Read a message from the socket
    async fn read_message<R: AsyncReadExt + Unpin>(&mut self, reader: &mut R) -> Result<Option<Bytes>> {
        // Clear the buffer
        self.read_buffer.clear();
        
        // Read message type (first byte)
        let mut type_buf = [0u8; 1];
        if reader.read_exact(&mut type_buf).await.is_err() {
            return Ok(None); // Connection closed
        }
        
        // Add message type to buffer
        self.read_buffer.extend_from_slice(&type_buf);
        
        // Read message length
        let mut length_buf = [0u8; 4];
        reader.read_exact(&mut length_buf).await?;
        
        // Add length to buffer
        self.read_buffer.extend_from_slice(&length_buf);
        
        // Parse message length (excluding the length itself)
        let length = u32::from_be_bytes(length_buf) as usize - 4;
        
        // Ensure the message is not too large
        if length > self.config.max_query_length {
            return Err(ProxyError::Protocol(format!(
                "Message too large: {} bytes (max: {} bytes)",
                length,
                self.config.max_query_length
            )));
        }
        
        // Read message body
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).await?;
        
        // Add body to buffer
        self.read_buffer.extend_from_slice(&body);
        
        Ok(Some(self.read_buffer.clone().freeze()))
    }
    
    /// Process a frontend message and return backend messages
    async fn process_message(&mut self, message: FrontendMessage) -> Result<Vec<BackendMessage>> {
        match message {
            FrontendMessage::Startup { version_major, version_minor, parameters } => {
                self.state = ConnectionState::Authenticating;
                self.auth_handler.handle_startup(version_major, version_minor, parameters).await
            }
            
            FrontendMessage::Password(password) => {
                if self.state != ConnectionState::Authenticating {
                    return Err(ProxyError::Protocol("Unexpected password message".to_string()));
                }
                self.auth_handler.handle_password(password).await
            }
            
            FrontendMessage::Query(query) => {
                // Update statistics
                self.stats.queries_executed += 1;
                
                // Intercept and analyze query
                let (modified_query, analysis) = self.query_interceptor.intercept_query(&query).await?;
                
                // Track transaction state if enabled
                if self.config.transaction_boundary_protection {
                    let mut tracker = self.transaction_tracker.lock().await;
                    tracker.track_query(&query)?;
                }
                
                // TODO: Execute query on backend and capture results
                // For now, just return a simple response
                let response = vec![
                    BackendMessage::CommandComplete(format!("SELECT 1")),
                    BackendMessage::ReadyForQuery(TransactionStatus::Idle),
                ];
                
                Ok(response)
            }
            
            FrontendMessage::Terminate => {
                self.state = ConnectionState::Closing;
                Ok(vec![])
            }
            
            // Handle other message types
            // For now, just return a simple response
            _ => Ok(vec![
                BackendMessage::ErrorResponse(Default::default()),
                BackendMessage::ReadyForQuery(TransactionStatus::Idle),
            ]),
        }
    }
    
    /// Update connection state from transaction status
    fn update_state_from_transaction_status(&mut self, status: TransactionStatus) {
        self.state = match status {
            TransactionStatus::Idle => ConnectionState::Ready,
            TransactionStatus::InTransaction => ConnectionState::InTransaction,
            TransactionStatus::Failed => ConnectionState::InFailedTransaction,
        };
    }
}

/// Connection manager
pub struct ConnectionManager {
    /// Configuration
    config: ProxyConfig,
    
    /// Transaction tracker
    transaction_tracker: Arc<Mutex<TransactionTracker>>,
    
    /// Active connections
    active_connections: usize,
}

impl ConnectionManager {
    /// Create a new connection manager
    pub fn new(config: ProxyConfig) -> Result<Self> {
        let transaction_tracker = Arc::new(Mutex::new(TransactionTracker::new()));
        
        Ok(Self {
            config,
            transaction_tracker,
            active_connections: 0,
        })
    }
    
    /// Handle a new connection
    pub async fn handle_connection(&self, socket: TcpStream, addr: SocketAddr) -> Result<()> {
        // Check if we've reached the maximum number of connections
        if self.active_connections >= self.config.max_connections as usize {
            return Err(ProxyError::Connection("Maximum connections reached".to_string()));
        }
        
        // Create new connection
        let mut connection = ClientConnection::new(
            socket,
            addr,
            self.config.clone(),
            self.transaction_tracker.clone(),
        );
        
        // Handle connection
        connection.handle().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_connection_state() {
        assert_ne!(ConnectionState::Initial, ConnectionState::Ready);
        assert_ne!(ConnectionState::Authenticating, ConnectionState::Closed);
    }
    
    #[test]
    fn test_connection_stats() {
        let stats = ConnectionStats::default();
        assert_eq!(stats.queries_executed, 0);
        assert_eq!(stats.transactions_executed, 0);
    }
} 