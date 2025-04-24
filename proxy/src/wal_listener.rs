// WAL Listener Service using Logical Replication

use crate::config::ProxyConfig;
use crate::error::{ProxyError, Result};
use crate::verification::state::StateCaptureManager;
use tokio_postgres::{Client, NoTls, Error as PgError, SimpleQueryMessage};
use std::sync::Arc;
use log::{info, error, warn, debug};
use std::time::Duration;
use bytes::Bytes;
use futures_util::stream::TryStreamExt;

/// Listens to PostgreSQL WAL stream via logical replication
pub struct WalListener {
    config: Arc<ProxyConfig>,
    state_manager: Arc<StateCaptureManager>,
}

impl WalListener {
    pub fn new(config: Arc<ProxyConfig>, state_manager: Arc<StateCaptureManager>) -> Result<Self> {
        // Ensure necessary configuration is present
        if config.replication_connection_string.is_none() || config.replication_slot_name.is_none() {
            return Err(ProxyError::Config("Replication connection string and slot name must be configured for WAL listener".to_string()));
        }
        Ok(Self {
            config,
            state_manager,
        })
    }

    /// Runs the WAL listener loop
    pub async fn run(&self) -> Result<()> {
        let conn_str = self.config.replication_connection_string.as_ref().unwrap();
        let slot_name = self.config.replication_slot_name.as_ref().unwrap();
        info!("Starting WAL Listener for slot '{}' using connection: {}", slot_name, conn_str);

        loop {
            match self.connect_and_listen(conn_str, slot_name).await {
                Ok(_) => {
                    warn!("WAL listener stream ended unexpectedly. Attempting to reconnect...");
                }
                Err(e) => {
                    error!("WAL listener connection error: {}. Attempting to reconnect after delay...", e);
                }
            }
            // Wait before attempting to reconnect
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    async fn connect_and_listen(&self, conn_str: &str, slot_name: &str) -> Result<()> {
        // Connect using standard tokio_postgres::connect
        // Ensure the connection string includes `replication=database` parameter
        let (mut client, connection) = tokio_postgres::connect(conn_str, NoTls).await
            .map_err(|e| ProxyError::ReplicationError(format!("Failed to connect replication client: {}", e)))?;

        // Spawn the connection task
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!("PostgreSQL connection error: {}", e);
            }
        });

        info!("WAL Listener connected successfully.");

        // TODO: Optionally check if slot exists and create if not using standard SQL query

        // Start logical replication using COPY protocol
        let replication_query = format!(
            "START_REPLICATION SLOT \"{}\" LOGICAL 0/0", // TODO: Use actual LSN?
            slot_name
        );
        // Use copy_out to get the stream of replication messages
        let mut copy_stream = client.copy_out(replication_query.as_str()).await
            .map_err(|e| ProxyError::ReplicationError(format!("Failed to start replication: {}", e)))?;

        info!("Logical replication started on slot '{}'.", slot_name);

        // Main message processing loop consuming the CopyOutStream
        loop {
            tokio::select! {
                // Check for messages from the replication stream
                 result = copy_stream.try_next() => { // Use try_next from TryStreamExt
                    match result {
                        Ok(Some(bytes)) => {
                            // Process the received raw WAL message bytes
                            // The actual message type (XLogData, PrimaryKeepalive) is encoded within these bytes.
                            // A parser is needed here.
                            // Example: Check message type byte
                            if !bytes.is_empty() {
                                match bytes[0] {
                                    b'w' => { // XLogData (WAL data)
                                        self.process_wal_message(bytes).await?;
                                        // TODO: Extract LSN from the message and send periodic StandbyStatusUpdate
                                    }
                                    b'k' => { // PrimaryKeepalive
                                         // TODO: Handle keepalive: extract LSN, reply_requested flag
                                         // Need to send StandbyStatusUpdate back if requested or periodically
                                         debug!("Received KeepAlive");
                                         // TODO: Send StandbyStatusUpdate if needed
                                    }
                                    _ => {
                                        warn!("Received unknown replication message type: {}", bytes[0]);
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            info!("Replication stream closed by server.");
                            return Ok(()); // End the stream processing
                        }
                        Err(e) => {
                            error!("Error reading replication stream: {}", e);
                            // Attempt to gracefully close the client connection?
                            // client.close().await; // `close` is not a method on Client
                            return Err(ProxyError::ReplicationError(format!("Error reading stream: {}", e)));
                        }
                    }
                }
                // Allow graceful shutdown (optional)
                // _ = tokio::signal::ctrl_c() => {
                //     info!("WAL Listener shutting down...");
                //     // TODO: Send Terminate message? Or just close connection?
                //     return Ok(());
                // }
            }
        }
    }

    // Modify to accept raw Bytes
    async fn process_wal_message(&self, raw_data: Bytes) -> Result<()> {
        // TODO: Implement robust parsing of the raw_data (e.g., pgoutput format)
        // This requires a dedicated parser library or custom implementation based on PostgreSQL protocol docs.
        // The raw_data contains the WAL data itself (Begin, Commit, Insert, Update, Delete messages)
        // encoded within the XLogData structure.

        warn!("WAL message parsing and state update logic needs full implementation using a pgoutput parser.");
        // Placeholder: Log received data length
        debug!("Received WAL data chunk of length: {}", raw_data.len());


        // Example conceptual flow AFTER parsing:
        /*
        let parsed_message = parse_pgoutput(raw_data)?; // This function needs implementation
        match parsed_message {
             PgOutputMessage::Begin(txn) => {
                 self.state_manager.begin_wal_transaction(txn.transaction_id).await?;
             }
             PgOutputMessage::Insert(insert_op) => {
                 self.state_manager.apply_wal_insert(insert_op).await?;
             }
             PgOutputMessage::Update(update_op) => {
                 self.state_manager.apply_wal_update(update_op).await?;
             }
             PgOutputMessage::Delete(delete_op) => {
                 self.state_manager.apply_wal_delete(delete_op).await?;
             }
             PgOutputMessage::Commit(commit_info) => {
                 // Use commit_info.commit_lsn from the parsed message
                 self.state_manager.commit_wal_transaction(commit_info.commit_lsn).await?;
             }
             _ => { warn!("Ignoring unhandled pgoutput message type"); }
         }
        */

        Ok(())
    }
}
