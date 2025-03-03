//! Message parser for PostgreSQL wire protocol messages
use crate::error::{ProxyError, Result};
use crate::protocol::message::{
    AuthenticationRequest, BackendMessage, ErrorOrNoticeFields, FieldDescription, FrontendMessage,
    TransactionStatus,
};
use bytes::{Buf, Bytes, BytesMut};
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::Cursor;

/// Message parser for PostgreSQL wire protocol
pub struct MessageParser;

impl MessageParser {
    /// Create a new message parser
    pub fn new() -> Self {
        Self
    }
    
    /// Parse a frontend message from bytes
    pub fn parse_frontend_message(&self, bytes: &Bytes) -> Result<FrontendMessage> {
        let mut cursor = Cursor::new(bytes);
        
        // Check if we have enough data
        if cursor.remaining() < 1 {
            return Err(ProxyError::Protocol("Empty message".to_string()));
        }
        
        // Get message type
        let message_type = cursor.get_u8();
        
        // Parse different message types
        match message_type {
            // Startup message (no message type byte)
            _ if message_type == 0 => {
                // Reset cursor to start of message
                cursor = Cursor::new(bytes);
                
                // Check if we have enough data for a startup message
                if cursor.remaining() < 8 {
                    return Err(ProxyError::Protocol("Invalid startup message".to_string()));
                }
                
                // Length is the first 4 bytes (including itself)
                let _length = cursor.get_u32();
                
                // Protocol version is the next 4 bytes (major, minor)
                let protocol_version = cursor.get_u32();
                let version_major = ((protocol_version >> 16) & 0xFFFF) as i16;
                let version_minor = (protocol_version & 0xFFFF) as i16;
                
                // Special protocol version values
                match protocol_version {
                    // SSL request
                    80877103 => return Ok(FrontendMessage::SSLRequest),
                    
                    // Cancel request
                    80877102 => {
                        if cursor.remaining() < 8 {
                            return Err(ProxyError::Protocol("Invalid cancel request".to_string()));
                        }
                        let process_id = cursor.get_i32();
                        let secret_key = cursor.get_i32();
                        
                        return Ok(FrontendMessage::CancelRequest {
                            process_id,
                            secret_key,
                        });
                    }
                    
                    // Normal startup message (protocol version 3.0)
                    _ => {
                        if version_major != 3 {
                            return Err(ProxyError::Protocol(format!(
                                "Unsupported protocol version: {}.{}",
                                version_major, version_minor
                            )));
                        }
                        
                        // Parse parameters (null-terminated key-value pairs)
                        let mut parameters = HashMap::new();
                        
                        while cursor.has_remaining() {
                            // Read key
                            let key = self.read_cstring(&mut cursor)?;
                            if key.is_empty() {
                                break; // End of parameters
                            }
                            
                            // Read value
                            let value = self.read_cstring(&mut cursor)?;
                            
                            // Add to parameters
                            parameters.insert(key, value);
                        }
                        
                        return Ok(FrontendMessage::Startup {
                            version_major,
                            version_minor,
                            parameters,
                        });
                    }
                }
            }
            
            // Password message
            b'p' => {
                let password = self.read_cstring(&mut cursor)?;
                Ok(FrontendMessage::Password(password))
            }
            
            // Query message
            b'Q' => {
                // Length is the next 4 bytes (not including type)
                let _length = cursor.get_u32();
                
                // Query string
                let query = self.read_cstring(&mut cursor)?;
                
                Ok(FrontendMessage::Query(query))
            }
            
            // Parse message
            b'P' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Statement name
                let name = self.read_cstring(&mut cursor)?;
                
                // Query string
                let query = self.read_cstring(&mut cursor)?;
                
                // Parameter types
                let param_count = cursor.get_i16() as usize;
                let mut param_types = Vec::with_capacity(param_count);
                
                for _ in 0..param_count {
                    param_types.push(cursor.get_i32());
                }
                
                Ok(FrontendMessage::Parse {
                    name,
                    query,
                    param_types,
                })
            }
            
            // Bind message
            b'B' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Portal name
                let portal = self.read_cstring(&mut cursor)?;
                
                // Statement name
                let statement = self.read_cstring(&mut cursor)?;
                
                // Parameter format codes
                let format_count = cursor.get_i16() as usize;
                let mut param_formats = Vec::with_capacity(format_count);
                
                for _ in 0..format_count {
                    param_formats.push(cursor.get_i16());
                }
                
                // Parameter values
                let param_count = cursor.get_i16() as usize;
                let mut param_values = Vec::with_capacity(param_count);
                
                for _ in 0..param_count {
                    let param_length = cursor.get_i32();
                    
                    if param_length == -1 {
                        // NULL value
                        param_values.push(None);
                    } else {
                        // Non-NULL value
                        let param_length = param_length as usize;
                        let mut param_value = BytesMut::with_capacity(param_length);
                        let mut param_data = vec![0u8; param_length];
                        cursor.copy_to_slice(&mut param_data);
                        param_value.extend_from_slice(&param_data);
                        param_values.push(Some(param_value.freeze()));
                    }
                }
                
                // Result format codes
                let result_format_count = cursor.get_i16() as usize;
                let mut result_formats = Vec::with_capacity(result_format_count);
                
                for _ in 0..result_format_count {
                    result_formats.push(cursor.get_i16());
                }
                
                Ok(FrontendMessage::Bind {
                    portal,
                    statement,
                    param_formats,
                    param_values,
                    result_formats,
                })
            }
            
            // Describe message
            b'D' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Object type (S for statement, P for portal)
                let object_type = cursor.get_u8();
                
                // Object name
                let name = self.read_cstring(&mut cursor)?;
                
                Ok(FrontendMessage::Describe {
                    object_type,
                    name,
                })
            }
            
            // Execute message
            b'E' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Portal name
                let portal = self.read_cstring(&mut cursor)?;
                
                // Maximum row count
                let max_rows = cursor.get_i32();
                
                Ok(FrontendMessage::Execute {
                    portal,
                    max_rows,
                })
            }
            
            // Sync message
            b'S' => {
                Ok(FrontendMessage::Sync)
            }
            
            // Flush message
            b'H' => {
                Ok(FrontendMessage::Flush)
            }
            
            // Close message
            b'C' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Object type (S for statement, P for portal)
                let object_type = cursor.get_u8();
                
                // Object name
                let name = self.read_cstring(&mut cursor)?;
                
                Ok(FrontendMessage::Close {
                    object_type,
                    name,
                })
            }
            
            // Terminate message
            b'X' => {
                Ok(FrontendMessage::Terminate)
            }
            
            // Copy data message
            b'd' => {
                // Length is the next 4 bytes
                let length = cursor.get_u32() as usize - 4;
                let mut data = BytesMut::with_capacity(length);
                let mut data_bytes = vec![0u8; length];
                cursor.copy_to_slice(&mut data_bytes);
                data.extend_from_slice(&data_bytes);
                
                Ok(FrontendMessage::CopyData(data.freeze()))
            }
            
            // Copy done message
            b'c' => {
                Ok(FrontendMessage::CopyDone)
            }
            
            // Copy fail message
            b'f' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Error message
                let error_message = self.read_cstring(&mut cursor)?;
                
                Ok(FrontendMessage::CopyFail(error_message))
            }
            
            // Function call message
            b'F' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Function OID
                let function_oid = cursor.get_i32();
                
                // Argument format codes
                let format_count = cursor.get_i16() as usize;
                let mut arg_formats = Vec::with_capacity(format_count);
                
                for _ in 0..format_count {
                    arg_formats.push(cursor.get_i16());
                }
                
                // Argument values
                let arg_count = cursor.get_i16() as usize;
                let mut arg_values = Vec::with_capacity(arg_count);
                
                for _ in 0..arg_count {
                    let arg_length = cursor.get_i32();
                    
                    if arg_length == -1 {
                        // NULL value
                        arg_values.push(None);
                    } else {
                        // Non-NULL value
                        let arg_length = arg_length as usize;
                        let mut arg_value = BytesMut::with_capacity(arg_length);
                        let mut arg_data = vec![0u8; arg_length];
                        cursor.copy_to_slice(&mut arg_data);
                        arg_value.extend_from_slice(&arg_data);
                        arg_values.push(Some(arg_value.freeze()));
                    }
                }
                
                // Result format code
                let result_format = cursor.get_i16();
                
                Ok(FrontendMessage::FunctionCall {
                    function_oid,
                    arg_formats,
                    arg_values,
                    result_format,
                })
            }
            
            // Unknown message type
            _ => {
                let body = bytes.slice(1..);
                Ok(FrontendMessage::Unknown {
                    tag: message_type,
                    body,
                })
            }
        }
    }
    
    /// Parse a backend message from bytes
    pub fn parse_backend_message(&self, bytes: &Bytes) -> Result<BackendMessage> {
        let mut cursor = Cursor::new(bytes);
        
        // Check if we have enough data
        if cursor.remaining() < 1 {
            return Err(ProxyError::Protocol("Empty message".to_string()));
        }
        
        // Get message type
        let message_type = cursor.get_u8();
        
        // Parse different message types
        match message_type {
            // Authentication response
            b'R' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Authentication type
                let auth_type = cursor.get_i32();
                
                match auth_type {
                    0 => Ok(BackendMessage::Authentication(AuthenticationRequest::Ok)),
                    2 => Ok(BackendMessage::Authentication(AuthenticationRequest::KerberosV5)),
                    3 => Ok(BackendMessage::Authentication(AuthenticationRequest::CleartextPassword)),
                    5 => {
                        // MD5 password
                        let mut salt = [0u8; 4];
                        cursor.copy_to_slice(&mut salt);
                        
                        Ok(BackendMessage::Authentication(AuthenticationRequest::Md5Password {
                            salt,
                        }))
                    }
                    6 => Ok(BackendMessage::Authentication(AuthenticationRequest::SCMCredential)),
                    7 => Ok(BackendMessage::Authentication(AuthenticationRequest::GSS)),
                    9 => Ok(BackendMessage::Authentication(AuthenticationRequest::SSPI)),
                    8 => {
                        // GSSAPI continuation
                        let data_length = cursor.remaining();
                        let mut data = BytesMut::with_capacity(data_length);
                        let mut data_bytes = vec![0u8; data_length];
                        cursor.copy_to_slice(&mut data_bytes);
                        data.extend_from_slice(&data_bytes);
                        
                        Ok(BackendMessage::Authentication(AuthenticationRequest::GSSContinue {
                            data: data.freeze(),
                        }))
                    }
                    10 => {
                        // SASL
                        let mut mechanisms = Vec::new();
                        
                        while cursor.has_remaining() {
                            let mechanism = self.read_cstring(&mut cursor)?;
                            if mechanism.is_empty() {
                                break;
                            }
                            
                            mechanisms.push(mechanism);
                        }
                        
                        Ok(BackendMessage::Authentication(AuthenticationRequest::SASL {
                            mechanisms,
                        }))
                    }
                    11 => {
                        // SASL continuation
                        let data_length = cursor.remaining();
                        let mut data = BytesMut::with_capacity(data_length);
                        let mut data_bytes = vec![0u8; data_length];
                        cursor.copy_to_slice(&mut data_bytes);
                        data.extend_from_slice(&data_bytes);
                        
                        Ok(BackendMessage::Authentication(AuthenticationRequest::SASLContinue {
                            data: data.freeze(),
                        }))
                    }
                    12 => {
                        // SASL final
                        let data_length = cursor.remaining();
                        let mut data = BytesMut::with_capacity(data_length);
                        let mut data_bytes = vec![0u8; data_length];
                        cursor.copy_to_slice(&mut data_bytes);
                        data.extend_from_slice(&data_bytes);
                        
                        Ok(BackendMessage::Authentication(AuthenticationRequest::SASLFinal {
                            data: data.freeze(),
                        }))
                    }
                    _ => Err(ProxyError::Protocol(format!("Unknown authentication type: {}", auth_type))),
                }
            }
            
            // Backend key data
            b'K' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Process ID
                let process_id = cursor.get_i32();
                
                // Secret key
                let secret_key = cursor.get_i32();
                
                Ok(BackendMessage::BackendKeyData {
                    process_id,
                    secret_key,
                })
            }
            
            // Parameter status
            b'S' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Parameter name
                let name = self.read_cstring(&mut cursor)?;
                
                // Parameter value
                let value = self.read_cstring(&mut cursor)?;
                
                Ok(BackendMessage::ParameterStatus {
                    name,
                    value,
                })
            }
            
            // Ready for query
            b'Z' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Transaction status
                let status_byte = cursor.get_u8();
                let status = TransactionStatus::from_byte(status_byte)
                    .ok_or_else(|| ProxyError::Protocol(format!("Unknown transaction status: {}", status_byte)))?;
                
                Ok(BackendMessage::ReadyForQuery(status))
            }
            
            // Command complete
            b'C' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Command tag
                let tag = self.read_cstring(&mut cursor)?;
                
                Ok(BackendMessage::CommandComplete(tag))
            }
            
            // Row description
            b'T' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Number of fields
                let field_count = cursor.get_i16() as usize;
                let mut fields = Vec::with_capacity(field_count);
                
                for _ in 0..field_count {
                    // Field name
                    let name = self.read_cstring(&mut cursor)?;
                    
                    // Table OID
                    let table_oid = cursor.get_i32();
                    
                    // Column attribute number
                    let column_id = cursor.get_i16();
                    
                    // Data type OID
                    let data_type_oid = cursor.get_i32();
                    
                    // Data type size
                    let data_type_size = cursor.get_i16();
                    
                    // Type modifier
                    let type_modifier = cursor.get_i32();
                    
                    // Format code
                    let format_code = cursor.get_i16();
                    
                    fields.push(FieldDescription {
                        name,
                        table_oid,
                        column_id,
                        data_type_oid,
                        data_type_size,
                        type_modifier,
                        format_code,
                    });
                }
                
                Ok(BackendMessage::RowDescription(fields))
            }
            
            // Data row
            b'D' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Number of columns
                let column_count = cursor.get_i16() as usize;
                let mut columns = Vec::with_capacity(column_count);
                
                for _ in 0..column_count {
                    // Column length
                    let column_length = cursor.get_i32();
                    
                    if column_length == -1 {
                        // NULL value
                        columns.push(None);
                    } else {
                        // Non-NULL value
                        let column_length = column_length as usize;
                        let mut column_value = BytesMut::with_capacity(column_length);
                        let mut column_data = vec![0u8; column_length];
                        cursor.copy_to_slice(&mut column_data);
                        column_value.extend_from_slice(&column_data);
                        columns.push(Some(column_value.freeze()));
                    }
                }
                
                Ok(BackendMessage::DataRow(columns))
            }
            
            // Empty query response
            b'I' => {
                Ok(BackendMessage::EmptyQueryResponse)
            }
            
            // Error response
            b'E' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Parse error fields
                let fields = self.parse_error_fields(&mut cursor)?;
                
                Ok(BackendMessage::ErrorResponse(fields))
            }
            
            // Notice response
            b'N' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Parse notice fields
                let fields = self.parse_error_fields(&mut cursor)?;
                
                Ok(BackendMessage::NoticeResponse(fields))
            }
            
            // Parse complete
            b'1' => {
                Ok(BackendMessage::ParseComplete)
            }
            
            // Bind complete
            b'2' => {
                Ok(BackendMessage::BindComplete)
            }
            
            // Portal suspended
            b's' => {
                Ok(BackendMessage::PortalSuspended)
            }
            
            // No data
            b'n' => {
                Ok(BackendMessage::NoData)
            }
            
            // Parameter description
            b't' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Number of parameters
                let param_count = cursor.get_i16() as usize;
                let mut params = Vec::with_capacity(param_count);
                
                for _ in 0..param_count {
                    params.push(cursor.get_i32());
                }
                
                Ok(BackendMessage::ParameterDescription(params))
            }
            
            // Close complete
            b'3' => {
                Ok(BackendMessage::CloseComplete)
            }
            
            // Function call response
            b'V' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Result length
                let result_length = cursor.get_i32();
                
                if result_length == -1 {
                    // NULL result
                    Ok(BackendMessage::FunctionCallResponse(None))
                } else {
                    // Non-NULL result
                    let result_length = result_length as usize;
                    let mut result_value = BytesMut::with_capacity(result_length);
                    let mut result_data = vec![0u8; result_length];
                    cursor.copy_to_slice(&mut result_data);
                    result_value.extend_from_slice(&result_data);
                    
                    Ok(BackendMessage::FunctionCallResponse(Some(result_value.freeze())))
                }
            }
            
            // Negotiate protocol version
            b'v' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Minor protocol version
                let version_minor = cursor.get_i32();
                
                // Number of options
                let option_count = cursor.get_i32() as usize;
                let mut options = Vec::with_capacity(option_count);
                
                for _ in 0..option_count {
                    options.push(self.read_cstring(&mut cursor)?);
                }
                
                Ok(BackendMessage::NegotiateProtocolVersion {
                    version_minor,
                    options,
                })
            }
            
            // Copy in response
            b'G' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Format
                let format = cursor.get_i8();
                
                // Number of columns
                let column_count = cursor.get_i16() as usize;
                let mut column_formats = Vec::with_capacity(column_count);
                
                for _ in 0..column_count {
                    column_formats.push(cursor.get_i16());
                }
                
                Ok(BackendMessage::CopyInResponse {
                    format,
                    column_formats,
                })
            }
            
            // Copy out response
            b'H' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Format
                let format = cursor.get_i8();
                
                // Number of columns
                let column_count = cursor.get_i16() as usize;
                let mut column_formats = Vec::with_capacity(column_count);
                
                for _ in 0..column_count {
                    column_formats.push(cursor.get_i16());
                }
                
                Ok(BackendMessage::CopyOutResponse {
                    format,
                    column_formats,
                })
            }
            
            // Copy both response
            b'W' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Format
                let format = cursor.get_i8();
                
                // Number of columns
                let column_count = cursor.get_i16() as usize;
                let mut column_formats = Vec::with_capacity(column_count);
                
                for _ in 0..column_count {
                    column_formats.push(cursor.get_i16());
                }
                
                Ok(BackendMessage::CopyBothResponse {
                    format,
                    column_formats,
                })
            }
            
            // Copy data
            b'd' => {
                // Length is the next 4 bytes
                let length = cursor.get_u32() as usize - 4;
                let mut data = BytesMut::with_capacity(length);
                let mut data_bytes = vec![0u8; length];
                cursor.copy_to_slice(&mut data_bytes);
                data.extend_from_slice(&data_bytes);
                
                Ok(BackendMessage::CopyData(data.freeze()))
            }
            
            // Copy done
            b'c' => {
                Ok(BackendMessage::CopyDone)
            }
            
            // Copy fail
            b'f' => {
                // Length is the next 4 bytes
                let _length = cursor.get_u32();
                
                // Error message
                let error_message = self.read_cstring(&mut cursor)?;
                
                Ok(BackendMessage::CopyFail(error_message))
            }
            
            // SSL response
            b'S' => {
                // Only one byte
                let supports_ssl = true;
                
                Ok(BackendMessage::SSLResponse(supports_ssl))
            }
            
            // Unknown message type
            _ => {
                let body = bytes.slice(1..);
                Ok(BackendMessage::Unknown {
                    tag: message_type,
                    body,
                })
            }
        }
    }
    
    /// Read a null-terminated string from the cursor
    fn read_cstring(&self, cursor: &mut Cursor<&Bytes>) -> Result<String> {
        let mut bytes = Vec::new();
        
        while cursor.has_remaining() {
            let b = cursor.get_u8();
            if b == 0 {
                break;
            }
            bytes.push(b);
        }
        
        String::from_utf8(bytes).map_err(|e| ProxyError::Protocol(format!("Invalid UTF-8: {}", e)))
    }
    
    /// Parse error and notice fields
    fn parse_error_fields(&self, cursor: &mut Cursor<&Bytes>) -> Result<ErrorOrNoticeFields> {
        let mut fields = ErrorOrNoticeFields::default();
        let mut all_fields = HashMap::new();
        
        while cursor.has_remaining() {
            let field_type = cursor.get_u8();
            if field_type == 0 {
                break;
            }
            
            let field_value = self.read_cstring(cursor)?;
            all_fields.insert(field_type, field_value.clone());
            
            match field_type {
                b'S' => fields.severity = Some(field_value),
                b'V' => fields.severity_non_localized = Some(field_value),
                b'C' => fields.code = Some(field_value),
                b'M' => fields.message = Some(field_value),
                b'D' => fields.detail = Some(field_value),
                b'H' => fields.hint = Some(field_value),
                b'P' => fields.position = Some(field_value.parse().map_err(|e| {
                    ProxyError::Protocol(format!("Invalid position: {}", e))
                })?),
                b'p' => fields.internal_position = Some(field_value.parse().map_err(|e| {
                    ProxyError::Protocol(format!("Invalid internal position: {}", e))
                })?),
                b'q' => fields.internal_query = Some(field_value),
                b'W' => fields.context = Some(field_value),
                b's' => fields.schema_name = Some(field_value),
                b't' => fields.table_name = Some(field_value),
                b'c' => fields.column_name = Some(field_value),
                b'd' => fields.data_type_name = Some(field_value),
                b'n' => fields.constraint_name = Some(field_value),
                b'F' => fields.file = Some(field_value),
                b'L' => fields.line = Some(field_value.parse().map_err(|e| {
                    ProxyError::Protocol(format!("Invalid line: {}", e))
                })?),
                b'R' => fields.routine = Some(field_value),
                _ => {} // Unknown field, already added to all_fields
            }
        }
        
        fields.fields = all_fields;
        
        Ok(fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    
    #[test]
    fn test_parse_startup_message() {
        let mut buf = BytesMut::new();
        
        // Length (including length itself)
        buf.put_u32(24);
        
        // Protocol version (3.0)
        buf.put_u32(196608);
        
        // Parameters
        buf.put_slice(b"user\0postgres\0database\0mydb\0\0");
        
        let parser = MessageParser::new();
        let bytes = buf.freeze();
        
        let result = parser.parse_frontend_message(&bytes).unwrap();
        
        match result {
            FrontendMessage::Startup { version_major, version_minor, parameters } => {
                assert_eq!(version_major, 3);
                assert_eq!(version_minor, 0);
                assert_eq!(parameters.get("user"), Some(&"postgres".to_string()));
                assert_eq!(parameters.get("database"), Some(&"mydb".to_string()));
            }
            _ => panic!("Expected Startup message"),
        }
    }
    
    #[test]
    fn test_parse_query_message() {
        let mut buf = BytesMut::new();
        
        // Message type
        buf.put_u8(b'Q');
        
        // Length (including length itself)
        buf.put_u32(20);
        
        // Query string
        buf.put_slice(b"SELECT 1;\0");
        
        let parser = MessageParser::new();
        let bytes = buf.freeze();
        
        let result = parser.parse_frontend_message(&bytes).unwrap();
        
        match result {
            FrontendMessage::Query(query) => {
                assert_eq!(query, "SELECT 1;");
            }
            _ => panic!("Expected Query message"),
        }
    }
    
    #[test]
    fn test_parse_error_response() {
        let mut buf = BytesMut::new();
        
        // Message type
        buf.put_u8(b'E');
        
        // Length (including length itself)
        buf.put_u32(92);
        
        // Fields
        buf.put_u8(b'S');
        buf.put_slice(b"ERROR\0");
        
        buf.put_u8(b'C');
        buf.put_slice(b"42P01\0");
        
        buf.put_u8(b'M');
        buf.put_slice(b"relation \"users\" does not exist\0");
        
        buf.put_u8(b'F');
        buf.put_slice(b"parse_relation.c\0");
        
        buf.put_u8(b'L');
        buf.put_slice(b"1234\0");
        
        buf.put_u8(0); // Terminator
        
        let parser = MessageParser::new();
        let bytes = buf.freeze();
        
        let result = parser.parse_backend_message(&bytes).unwrap();
        
        match result {
            BackendMessage::ErrorResponse(fields) => {
                assert_eq!(fields.severity, Some("ERROR".to_string()));
                assert_eq!(fields.code, Some("42P01".to_string()));
                assert_eq!(fields.message, Some("relation \"users\" does not exist".to_string()));
                assert_eq!(fields.file, Some("parse_relation.c".to_string()));
                assert_eq!(fields.line, Some(1234));
            }
            _ => panic!("Expected ErrorResponse message"),
        }
    }
} 