//! Connection manager for client connections
use crate::config::ProxyConfig;
use crate::error::{ProxyError, Result};
use crate::protocol::auth::AuthHandler;
use crate::protocol::message::{
    BackendMessage, ErrorOrNoticeFields, FieldDescription,
    FrontendMessage, TransactionStatus,
};
use crate::protocol::parser::MessageParser;
use crate::protocol::formatter::MessageFormatter;
use crate::protocol::validator::ProtocolValidator;
use crate::transaction::TransactionManager;
use bytes::{Bytes, BytesMut};
use log::{debug, error, warn};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_postgres::config::Config as PgConfig;
use tokio_postgres::Client;

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    /// Initial state
    Initial,
    
    /// Startup state
    Startup,
    
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
#[derive(Debug, Clone)]
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
    
    /// Number of messages received
    pub messages_received: usize,
    
    /// Number of messages sent
    pub messages_sent: usize,
    
    /// Connection start time
    pub start_time: std::time::Instant,
    
    /// Last activity time
    pub last_activity: std::time::Instant,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        let now = std::time::Instant::now();
        Self {
            queries_executed: 0,
            transactions_executed: 0,
            rows_returned: 0,
            rows_affected: 0,
            bytes_received: 0,
            bytes_sent: 0,
            messages_received: 0,
            messages_sent: 0,
            start_time: now,
            last_activity: now,
        }
    }
}

/// A wrapper around tokio_postgres::Client that implements Clone
#[derive(Debug, Clone)]
pub struct ClientWrapper {
    /// The inner client
    inner: Arc<Client>,
}

impl ClientWrapper {
    /// Create a new client wrapper
    pub fn new(client: Client) -> Self {
        Self {
            inner: Arc::new(client),
        }
    }
    
    /// Get a reference to the inner client
    pub fn inner(&self) -> &Client {
        &self.inner
    }
    
    /// Get a mutable reference to the inner client
    pub fn inner_mut(&self) -> &Client {
        &self.inner
    }
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
    pg_client: Option<ClientWrapper>,
    
    /// Message parser
    parser: MessageParser,
    
    /// Message formatter
    formatter: MessageFormatter,
    
    /// Authentication handler
    auth_handler: AuthHandler,
    
    /// Protocol validator
    validator: ProtocolValidator,
    
    /// Transaction manager
    transaction_manager: Arc<Mutex<TransactionManager>>,
    
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
        transaction_manager: Arc<Mutex<TransactionManager>>,
    ) -> Self {
        Self {
            socket,
            addr,
            state: ConnectionState::Initial,
            pg_client: None,
            parser: MessageParser::new(),
            formatter: MessageFormatter::new(),
            auth_handler: AuthHandler::new(config.auth_config.clone()),
            validator: ProtocolValidator::new(config.validator_config.clone()),
            transaction_manager,
            config,
            stats: ConnectionStats::default(),
            read_buffer: BytesMut::with_capacity(8192),
            write_buffer: BytesMut::with_capacity(8192),
        }
    }
    
    /// Handle client connection
    pub async fn handle_connection(&mut self) -> Result<()> {
        // Enable TCP_NODELAY for better performance
        self.socket.set_nodelay(true)?;
        
        // Set up connection timeout
        let timeout_duration = Duration::from_secs(self.config.connection_timeout);
        let mut last_activity = Instant::now();
        
        // Initialize connection state
        self.state = ConnectionState::Startup;
        let mut transaction_status = TransactionStatus::Idle;
        
        debug!("Handling connection from {}", self.addr);
        
        loop {
            // Update last activity time
            last_activity = Instant::now();
            
            // Check for connection timeout
            if last_activity.elapsed() > timeout_duration {
                debug!("Connection timed out for {}", self.addr);
                return Err(ProxyError::ConnectionTimeout);
            }
            
            // Read a message from the client
            let frontend_message = match Self::read_frontend_message_with_timeout(
                &mut self.socket,
                &self.parser,
                timeout_duration,
                &self.addr
            ).await {
                Ok(message) => message,
                Err(e) => {
                    // Handle error
                    if let ProxyError::ConnectionClosed = e {
                        debug!("Connection closed by client: {}", self.addr);
                        break;
                    }
                    
                    error!("Error reading message from {}: {}", self.addr, e);
                    return Err(e);
                }
            };
            
            // Process message and get backend messages
            let backend_messages = match process_message(
                frontend_message, 
                &mut self.pg_client, 
                &mut self.auth_handler, 
                &mut self.validator, 
                &self.transaction_manager, 
                &self.config, 
                &mut self.stats, 
                &mut self.state,
                &mut transaction_status
            ).await {
                Ok(messages) => messages,
                Err(e) => {
                    error!("Error processing message from {}: {}", self.addr, e);
                    
                    // Write error response to client
                    if let Err(write_err) = Self::write_error_response(
                        &mut self.socket, 
                        &e.to_string(), 
                        &self.formatter
                    ).await {
                        error!("Failed to write error response to {}: {}", self.addr, write_err);
                    }
                    
                    return Err(e);
                }
            };
            
            // Write backend messages to client
            if let Err(e) = Self::write_backend_messages(
                &mut self.socket, 
                backend_messages, 
                &self.formatter,
                &mut self.stats,
                &mut self.state
            ).await {
                error!("Error writing messages to {}: {}", self.addr, e);
                return Err(e);
            }
            
            // If closing, break out of loop
            if self.state == ConnectionState::Closing {
                debug!("Closing connection to {}", self.addr);
                break;
            }
        }
        
        debug!("Connection closed: {}", self.addr);
        Ok(())
    }

    /// Read a frontend message with timeout
    async fn read_frontend_message_with_timeout<R>(
        reader: &mut R,
        parser: &MessageParser,
        timeout_duration: Duration,
        addr: &SocketAddr,
    ) -> Result<FrontendMessage>
    where
        R: AsyncRead + Unpin,
    {
        match timeout(timeout_duration, Self::read_message(reader, parser)).await {
            Ok(result) => result,
            Err(_) => {
                warn!("Connection from {} timed out waiting for message", addr);
                Err(ProxyError::ConnectionClosed)
            }
        }
    }
    
    /// Read a message from the client
    async fn read_message<R>(reader: &mut R, parser: &MessageParser) -> Result<FrontendMessage>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = BytesMut::with_capacity(4096);
        loop {
            let bytes_read = reader.read_buf(&mut buf).await?;
            if bytes_read == 0 {
                return Err(ProxyError::ConnectionClosed);
            }

            match parser.parse_frontend_message(&buf.clone().freeze()) {
                Ok(message) => return Ok(message),
                Err(ProxyError::Incomplete) => continue,
                Err(e) => return Err(e),
            }
        }
    }
    
    /// Process a frontend message and return backend messages
    async fn process_message_internal(&mut self, message: FrontendMessage) -> Result<Vec<BackendMessage>> {
        self.stats.messages_received += 1;
        let mut transaction_status = TransactionStatus::Idle;
        process_message(
            message,
            &mut self.pg_client,
            &mut self.auth_handler,
            &mut self.validator,
            &self.transaction_manager,
            &self.config,
            &mut self.stats,
            &mut self.state,
            &mut transaction_status
        ).await
    }
    
    /// Write an error response to the client
    async fn write_error_response<W>(
        writer: &mut W,
        error_msg: &str,
        formatter: &MessageFormatter,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut error_fields = ErrorOrNoticeFields::default();
        error_fields.severity = Some("ERROR".to_string());
        error_fields.code = Some("XX000".to_string());
        error_fields.message = Some(error_msg.to_string());
        
        let error_response = BackendMessage::ErrorResponse(error_fields);
        let bytes = formatter.format_backend_message(&error_response)?;
        writer.write_all(&bytes).await?;
        Ok(())
    }
    
    /// Write a message to the client
    async fn write_message<W>(
        writer: &mut W,
        message: &BackendMessage,
        formatter: &MessageFormatter,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let bytes = formatter.format_backend_message(message)?;
        writer.write_all(&bytes).await?;
        Ok(())
    }
    
    /// Write backend messages to the client
    async fn write_backend_messages<W>(
        writer: &mut W,
        messages: Vec<BackendMessage>,
        formatter: &MessageFormatter,
        stats: &mut ConnectionStats,
        state: &mut ConnectionState,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        for message in messages {
            // Check for TransactionStatus messages to update connection state
            if let BackendMessage::ReadyForQuery(transaction_status) = &message {
                update_state_from_transaction_status(state, *transaction_status);
            }

            Self::write_message(writer, &message, formatter).await?;
            stats.messages_sent += 1;
        }
        Ok(())
    }

    /// Handle backend messages
    async fn handle_backend_messages_internal<W>(&mut self, writer: &mut W, backend_messages: Vec<BackendMessage>) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        handle_backend_messages(
            writer,
            backend_messages,
            &self.formatter,
            &mut self.state,
            &self.transaction_manager
        ).await
    }
}

/// Connection manager
pub struct ConnectionManager {
    /// Configuration
    config: ProxyConfig,
    
    /// Transaction manager
    transaction_manager: Arc<Mutex<TransactionManager>>,
    
    /// Active connections
    active_connections: usize,
}

impl ConnectionManager {
    /// Create a new connection manager
    pub fn new(config: ProxyConfig) -> Result<Self> {
        let transaction_manager = Arc::new(Mutex::new(TransactionManager::new()));
        
        Ok(Self {
            config,
            transaction_manager,
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
            self.transaction_manager.clone(),
        );
        
        // Handle connection
        connection.handle_connection().await
    }
}

/// Update connection state from transaction status
fn update_state_from_transaction_status(
    state: &mut ConnectionState, 
    status: TransactionStatus
) {
    *state = match status {
        TransactionStatus::Idle => ConnectionState::Ready,
        TransactionStatus::InTransaction => ConnectionState::InTransaction,
        TransactionStatus::Failed => ConnectionState::InFailedTransaction,
    };
}

/// Process a frontend message and generate backend messages
async fn process_message(
    message: FrontendMessage,
    pg_client: &mut Option<ClientWrapper>,
    auth_handler: &mut AuthHandler,
    validator: &mut ProtocolValidator,
    transaction_manager: &Arc<Mutex<TransactionManager>>,
    config: &ProxyConfig,
    stats: &mut ConnectionStats,
    state: &mut ConnectionState,
    transaction_status: &mut TransactionStatus,
) -> Result<Vec<BackendMessage>> {
    // Validate message
    validator.validate_frontend_message(&message, state)?;
    
    // Update stats
    stats.messages_received += 1;
    
    // Process message based on type
    match message {
        FrontendMessage::Startup { version_major, version_minor, parameters } => {
            auth_handler.handle_startup(version_major, version_minor, &parameters)
        }
        FrontendMessage::Password(password) => {
            let auth_response = auth_handler.handle_password(password).await?;
            
            // Check if authentication was successful by looking for AuthenticationOk in the response
            let auth_successful = auth_response.iter().any(|msg| {
                if let BackendMessage::Authentication(auth_req) = msg {
                    matches!(auth_req, crate::protocol::message::AuthenticationRequest::Ok)
                } else {
                    false
                }
            });
            
            // If authentication was successful, connect to PostgreSQL
            if auth_successful && pg_client.is_none() {
                // Connect to PostgreSQL
                debug!("Authentication successful, connecting to PostgreSQL backend");
                
                // Extract host and port from backend_addr
                let host = config.backend_addr.ip().to_string();
                let port = config.backend_addr.port();
                
                // Use the database credentials configured on the command line
                // These are stored in the config object
                let username = config.db_user.clone().unwrap_or_else(|| {
                    // Fall back to the first user in the auth config if available
                    config.auth_config.users.keys()
                        .next()
                        .cloned()
                        .unwrap_or_else(|| "postgres".to_string())
                });
                
                let password = config.db_password.clone().unwrap_or_else(|| {
                    // Fall back to the first password in the auth config if available
                    config.auth_config.users.values()
                        .next()
                        .cloned()
                        .unwrap_or_else(|| "postgres".to_string())
                });
                
                let database = config.db_name.clone().unwrap_or_else(|| {
                    "postgres".to_string()
                });
                
                // Create connection string from config
                let conn_string = format!(
                    "host={} port={} user={} password={} dbname={}",
                    host, port, username, password, database
                );
                
                debug!("Connecting to PostgreSQL with connection string: host={} port={} user={} dbname={}", 
                       host, port, username, database);
                
                // Parse connection string and connect
                match connect_to_postgres(&conn_string).await {
                    Ok(client) => {
                        debug!("Connected to PostgreSQL backend");
                        *pg_client = Some(client);
                        // Update state to Ready
                        *state = ConnectionState::Ready;
                        
                        // Add necessary startup messages to the response
                        let mut response = auth_response;
                        
                        // Add BackendKeyData message (with dummy values)
                        response.push(BackendMessage::BackendKeyData {
                            process_id: 1000, // Dummy process ID
                            secret_key: 12345, // Dummy secret key
                        });
                        
                        // Add ParameterStatus messages that clients expect
                        response.push(BackendMessage::ParameterStatus {
                            name: "server_version".to_string(),
                            value: "14.0".to_string(),
                        });
                        response.push(BackendMessage::ParameterStatus {
                            name: "client_encoding".to_string(),
                            value: "UTF8".to_string(),
                        });
                        response.push(BackendMessage::ParameterStatus {
                            name: "DateStyle".to_string(),
                            value: "ISO, MDY".to_string(),
                        });
                        response.push(BackendMessage::ParameterStatus {
                            name: "integer_datetimes".to_string(),
                            value: "on".to_string(),
                        });
                        response.push(BackendMessage::ParameterStatus {
                            name: "standard_conforming_strings".to_string(),
                            value: "on".to_string(),
                        });
                        
                        // Add ReadyForQuery message
                        response.push(BackendMessage::ReadyForQuery(TransactionStatus::Idle));
                        
                        return Ok(response);
                    }
                    Err(e) => {
                        error!("Failed to connect to PostgreSQL backend: {}", e);
                        return Err(ProxyError::Database(format!("Failed to connect to PostgreSQL backend: {}", e)));
                    }
                }
            }
            
            Ok(auth_response)
        }
        FrontendMessage::Query(query) => {
            // Process query
            debug!("Processing query: {}", query);
            
            // Update transaction status if needed
            if query.trim().to_uppercase().starts_with("BEGIN") {
                *transaction_status = TransactionStatus::InTransaction;
            } else if query.trim().to_uppercase().starts_with("COMMIT") {
                *transaction_status = TransactionStatus::Idle;
            } else if query.trim().to_uppercase().starts_with("ROLLBACK") {
                *transaction_status = TransactionStatus::Idle;
            }
            
            // If we have a client, forward the query
            if let Some(client) = pg_client {
                // Execute query
                let rows = match client.inner().query(&query, &[]).await {
                    Ok(rows) => rows,
                    Err(e) => {
                        // Convert tokio_postgres::Error to ProxyError
                        return Err(ProxyError::Database(format!("Database error: {}", e)));
                    }
                };
                
                // Generate response
                let mut messages = Vec::new();
                
                // Add row descriptions
                if !rows.is_empty() {
                    let columns = rows[0].columns();
                    let field_descriptions = columns.iter().map(|col| {
                        FieldDescription {
                            name: col.name().to_string(),
                            table_oid: col.table_oid().unwrap_or(0) as i32,
                            column_id: col.column_id().unwrap_or(0) as i16,
                            data_type_oid: col.type_().oid() as i32,
                            data_type_size: 0, // Not available from tokio-postgres
                            type_modifier: -1, // Not available from tokio-postgres
                            format_code: 0, // Text format
                        }
                    }).collect::<Vec<_>>();
                    
                    messages.push(BackendMessage::RowDescription(field_descriptions));
                    
                    // Store row count before consuming rows
                    let row_count = rows.len();
                    
                    // Add data rows
                    for row in rows {
                        let mut data_row = Vec::new();
                        
                        for i in 0..row.len() {
                            // Try to get the value as a string
                            match row.try_get::<_, String>(i) {
                                Ok(val) => data_row.push(Some(Bytes::from(val))),
                                Err(_) => {
                                    // Try as an integer
                                    if let Ok(val) = row.try_get::<_, i32>(i) {
                                        data_row.push(Some(Bytes::from(val.to_string())));
                                    } else if let Ok(val) = row.try_get::<_, i64>(i) {
                                        data_row.push(Some(Bytes::from(val.to_string())));
                                    } else if let Ok(val) = row.try_get::<_, bool>(i) {
                                        data_row.push(Some(Bytes::from(val.to_string())));
                                    } else {
                                        // NULL or unsupported type
                                        data_row.push(None);
                                    }
                                }
                            }
                        }
                        
                        messages.push(BackendMessage::DataRow(data_row));
                    }
                    
                    // Add command complete
                    messages.push(BackendMessage::CommandComplete(format!("SELECT {}", row_count)));
                } else {
                    // For non-SELECT queries
                    messages.push(BackendMessage::CommandComplete(query.split_whitespace().next().unwrap_or("").to_string()));
                }
                
                // Add ready for query
                messages.push(BackendMessage::ReadyForQuery(*transaction_status));
                
                Ok(messages)
            } else {
                // No client, return error
                Err(ProxyError::Database("Not connected to database".to_string()))
            }
        }
        FrontendMessage::Terminate => {
            // Client is terminating the connection
            debug!("Client terminated connection");
            Ok(vec![])
        }
        FrontendMessage::SSLRequest => {
            // Handle SSL request - respond with 'N' (SSL not supported) for now
            debug!("SSL request received, responding with 'N'");
            Ok(vec![BackendMessage::SSLResponse(false)])
        }
        FrontendMessage::CancelRequest { process_id, secret_key } => {
            // Handle cancel request
            debug!("Cancel request received for process ID {} with secret key {}", process_id, secret_key);
            // Pass through to database
            if let Some(client) = pg_client {
                // In a real implementation, we would need to handle this properly
                // For now, just acknowledge it
                Ok(vec![])
            } else {
                // No client connection
                Ok(vec![])
            }
        }
        // Add handling for extended protocol messages
        FrontendMessage::Parse { name, query, param_types } => {
            debug!("Parse message received: {}", query);
            // Pass through to database if we have a client
            if let Some(_client) = pg_client {
                // In a real implementation, we would pass this to the database
                // For now, just respond with ParseComplete
                Ok(vec![BackendMessage::ParseComplete])
            } else {
                Err(ProxyError::Database("Not connected to database".to_string()))
            }
        }
        FrontendMessage::Bind { .. } => {
            debug!("Bind message received");
            // In a real implementation, we would pass this to the database
            // For now, just respond with BindComplete
            Ok(vec![BackendMessage::BindComplete])
        }
        FrontendMessage::Execute { .. } => {
            debug!("Execute message received");
            // In a real implementation, we would pass this to the database
            // For now, just respond with EmptyQueryResponse
            Ok(vec![BackendMessage::EmptyQueryResponse])
        }
        FrontendMessage::Sync => {
            debug!("Sync message received");
            // Respond with ReadyForQuery
            Ok(vec![BackendMessage::ReadyForQuery(*transaction_status)])
        }
        // For all other messages, log and pass through
        _ => {
            // Instead of rejecting, log the unknown message and continue
            warn!("Unknown message type: {:?} - passing through", message);
            // Respond with ReadyForQuery to allow the connection to proceed
            Ok(vec![BackendMessage::ReadyForQuery(*transaction_status)])
        }
    }
}

/// Connect to PostgreSQL and return a ClientWrapper
async fn connect_to_postgres(connection_string: &str) -> Result<ClientWrapper> {
    // Parse connection string
    let config = connection_string.parse::<tokio_postgres::config::Config>()
        .map_err(|e| ProxyError::Database(format!("Failed to parse connection string: {}", e)))?;
    
    // Connect to PostgreSQL
    let (client, connection) = config.connect(tokio_postgres::NoTls).await
        .map_err(|e| ProxyError::Database(format!("Failed to connect to PostgreSQL: {}", e)))?;
    
    // Spawn a task to drive the connection
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!("Connection error: {}", e);
        }
    });
    
    // Create and return the client wrapper
    Ok(ClientWrapper::new(client))
}

/// Handle backend messages
async fn handle_backend_messages(
    writer: &mut (impl AsyncWrite + Unpin),
    messages: Vec<BackendMessage>,
    formatter: &MessageFormatter,
    state: &mut ConnectionState,
    transaction_manager: &Arc<Mutex<TransactionManager>>,
) -> Result<()> {
    for message in messages {
        // Update connection state based on message
        if let BackendMessage::ReadyForQuery(transaction_status) = &message {
            update_state_from_transaction_status(state, *transaction_status);
        }

        // Format and write message
        let bytes = formatter.format_backend_message(&message)?;
        writer.write_all(&bytes).await?;
    }

    writer.flush().await?;
    Ok(())
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
