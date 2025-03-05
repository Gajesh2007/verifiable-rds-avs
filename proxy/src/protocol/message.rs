//! Message types for the PostgreSQL wire protocol
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;

/// Frontend (client-to-server) message types
#[derive(Debug, Clone, PartialEq)]
pub enum FrontendMessage {
    /// Startup message with protocol version and parameters
    Startup {
        /// Major protocol version (should be 3)
        version_major: i16,
        /// Minor protocol version (should be 0)
        version_minor: i16,
        /// Parameters (key-value pairs)
        parameters: HashMap<String, String>,
    },
    
    /// SSL request
    SSLRequest,
    
    /// Cancel request
    CancelRequest {
        /// Process ID to cancel
        process_id: i32,
        /// Secret key
        secret_key: i32,
    },
    
    /// Password message (in response to authentication request)
    Password(String),
    
    /// Query message (simple query protocol)
    Query(String),
    
    /// Parse message (extended query protocol)
    Parse {
        /// Prepared statement name
        name: String,
        /// Query string
        query: String,
        /// Parameter types (OIDs)
        param_types: Vec<i32>,
    },
    
    /// Bind message (extended query protocol)
    Bind {
        /// Portal name
        portal: String,
        /// Prepared statement name
        statement: String,
        /// Parameter format codes
        param_formats: Vec<i16>,
        /// Parameter values
        param_values: Vec<Option<Bytes>>,
        /// Result format codes
        result_formats: Vec<i16>,
    },
    
    /// Describe message (extended query protocol)
    Describe {
        /// Object type ('S' for statement, 'P' for portal)
        object_type: u8,
        /// Object name
        name: String,
    },
    
    /// Execute message (extended query protocol)
    Execute {
        /// Portal name
        portal: String,
        /// Maximum row count (0 for unlimited)
        max_rows: i32,
    },
    
    /// Sync message (extended query protocol)
    Sync,
    
    /// Flush message (extended query protocol)
    Flush,
    
    /// Close message (extended query protocol)
    Close {
        /// Object type ('S' for statement, 'P' for portal)
        object_type: u8,
        /// Object name
        name: String,
    },
    
    /// Terminate message
    Terminate,
    
    /// COPY data message
    CopyData(Bytes),
    
    /// COPY done message
    CopyDone,
    
    /// COPY fail message
    CopyFail(String),
    
    /// Function call message
    FunctionCall {
        /// Function OID
        function_oid: i32,
        /// Argument format codes
        arg_formats: Vec<i16>,
        /// Argument values
        arg_values: Vec<Option<Bytes>>,
        /// Result format code
        result_format: i16,
    },
    
    /// Unknown message type
    Unknown {
        /// Message type
        tag: u8,
        /// Message body
        body: Bytes,
    },
}

/// Backend (server-to-client) message types
#[derive(Debug, Clone, PartialEq)]
pub enum BackendMessage {
    /// Authentication request
    Authentication(AuthenticationRequest),
    
    /// Backend key data
    BackendKeyData {
        /// Process ID
        process_id: i32,
        /// Secret key
        secret_key: i32,
    },
    
    /// Parameter status
    ParameterStatus {
        /// Parameter name
        name: String,
        /// Parameter value
        value: String,
    },
    
    /// Ready for query
    ReadyForQuery(TransactionStatus),
    
    /// Command complete
    CommandComplete(String),
    
    /// Row description
    RowDescription(Vec<FieldDescription>),
    
    /// Data row
    DataRow(Vec<Option<Bytes>>),
    
    /// Empty query response
    EmptyQueryResponse,
    
    /// Error response
    ErrorResponse(ErrorOrNoticeFields),
    
    /// Notice response
    NoticeResponse(ErrorOrNoticeFields),
    
    /// Parse complete
    ParseComplete,
    
    /// Bind complete
    BindComplete,
    
    /// Portal suspended
    PortalSuspended,
    
    /// No data
    NoData,
    
    /// Parameter description
    ParameterDescription(Vec<i32>),
    
    /// Close complete
    CloseComplete,
    
    /// Function call response
    FunctionCallResponse(Option<Bytes>),
    
    /// SSL response (single byte 'S' for SSL allowed, 'N' for SSL not allowed)
    SSLResponse(bool),
    
    /// Negotiation response
    NegotiateProtocolVersion {
        /// Latest minor protocol version supported by the server
        version_minor: i32,
        /// Options not recognized by the server
        options: Vec<String>,
    },
    
    /// Copy in response
    CopyInResponse {
        /// Format (0 for text, 1 for binary)
        format: i8,
        /// Column formats
        column_formats: Vec<i16>,
    },
    
    /// Copy out response
    CopyOutResponse {
        /// Format (0 for text, 1 for binary)
        format: i8,
        /// Column formats
        column_formats: Vec<i16>,
    },
    
    /// Copy both response
    CopyBothResponse {
        /// Format (0 for text, 1 for binary)
        format: i8,
        /// Column formats
        column_formats: Vec<i16>,
    },
    
    /// Copy data
    CopyData(Bytes),
    
    /// Copy done
    CopyDone,
    
    /// Copy fail
    CopyFail(String),
    
    /// Unknown message type
    Unknown {
        /// Message type
        tag: u8,
        /// Message body
        body: Bytes,
    },
}

/// Authentication request types
#[derive(Debug, Clone, PartialEq)]
pub enum AuthenticationRequest {
    /// Authentication successful
    Ok,
    
    /// Kerberos V5 authentication required
    KerberosV5,
    
    /// Cleartext password required
    CleartextPassword,
    
    /// MD5 password required
    Md5Password {
        /// Salt for MD5 authentication
        salt: [u8; 4],
    },
    
    /// SCM credentials required
    SCMCredential,
    
    /// GSS authentication required
    GSS,
    
    /// SSPI authentication required
    SSPI,
    
    /// GSSAPI continuation
    GSSContinue {
        /// GSSAPI data
        data: Bytes,
    },
    
    /// SASL authentication required
    SASL {
        /// SASL authentication mechanisms
        mechanisms: Vec<String>,
    },
    
    /// SASL continuation
    SASLContinue {
        /// SASL data
        data: Bytes,
    },
    
    /// SASL final
    SASLFinal {
        /// SASL data
        data: Bytes,
    },
}

/// Transaction status
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransactionStatus {
    /// Idle (not in a transaction)
    Idle,
    
    /// In a transaction block
    InTransaction,
    
    /// In a failed transaction block
    Failed,
}

impl TransactionStatus {
    /// Convert from a byte to a transaction status
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'I' => Some(TransactionStatus::Idle),
            b'T' => Some(TransactionStatus::InTransaction),
            b'E' => Some(TransactionStatus::Failed),
            _ => None,
        }
    }
    
    /// Convert to a byte
    pub fn to_byte(self) -> u8 {
        match self {
            TransactionStatus::Idle => b'I',
            TransactionStatus::InTransaction => b'T',
            TransactionStatus::Failed => b'E',
        }
    }
}

/// Field description for row description message
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDescription {
    /// Field name
    pub name: String,
    
    /// Table OID (0 if not from a table)
    pub table_oid: i32,
    
    /// Column attribute number (0 if not from a table)
    pub column_id: i16,
    
    /// Data type OID
    pub data_type_oid: i32,
    
    /// Data type size
    pub data_type_size: i16,
    
    /// Type modifier
    pub type_modifier: i32,
    
    /// Format code (0 for text, 1 for binary)
    pub format_code: i16,
}

/// Error and notice message fields
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ErrorOrNoticeFields {
    /// Severity (localized)
    pub severity: Option<String>,
    
    /// Severity (non-localized)
    pub severity_non_localized: Option<String>,
    
    /// SQLSTATE code
    pub code: Option<String>,
    
    /// Primary message
    pub message: Option<String>,
    
    /// Detail message
    pub detail: Option<String>,
    
    /// Hint message
    pub hint: Option<String>,
    
    /// Position (character count)
    pub position: Option<i32>,
    
    /// Internal position (character count)
    pub internal_position: Option<i32>,
    
    /// Internal query
    pub internal_query: Option<String>,
    
    /// Context
    pub context: Option<String>,
    
    /// Schema name
    pub schema_name: Option<String>,
    
    /// Table name
    pub table_name: Option<String>,
    
    /// Column name
    pub column_name: Option<String>,
    
    /// Data type name
    pub data_type_name: Option<String>,
    
    /// Constraint name
    pub constraint_name: Option<String>,
    
    /// Source file
    pub file: Option<String>,
    
    /// Source line
    pub line: Option<i32>,
    
    /// Source routine
    pub routine: Option<String>,
    
    /// All fields (including unknown ones)
    pub fields: HashMap<u8, String>,
} 