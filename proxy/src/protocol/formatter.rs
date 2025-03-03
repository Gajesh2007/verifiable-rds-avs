//! Message formatter for PostgreSQL wire protocol responses
//!
//! This module provides formatting functionality for PostgreSQL backend messages,
//! converting them to the wire format that can be sent to clients.

use crate::error::{ProxyError, Result};
use crate::protocol::message::{
    AuthenticationRequest, BackendMessage, ErrorOrNoticeFields, FieldDescription, TransactionStatus,
};
use bytes::{BufMut, Bytes, BytesMut};
use log::debug;
use std::collections::HashMap;

/// Message formatter for PostgreSQL wire protocol responses
#[derive(Debug, Default)]
pub struct MessageFormatter {}

impl MessageFormatter {
    /// Create a new message formatter
    pub fn new() -> Self {
        Self {}
    }

    /// Format a backend message for sending to the client
    pub fn format_backend_message(&self, message: &BackendMessage) -> Result<Bytes> {
        let mut buffer = BytesMut::new();
        
        match message {
            BackendMessage::Authentication(auth_request) => {
                self.write_authentication(&mut buffer, auth_request)?;
            },
            BackendMessage::BackendKeyData { process_id, secret_key } => {
                self.write_message_with_type(&mut buffer, b'K', |buf| {
                    buf.put_i32(*process_id);
                    buf.put_i32(*secret_key);
                })?;
            },
            BackendMessage::ParameterStatus { name, value } => {
                self.write_message_with_type(&mut buffer, b'S', |buf| {
                    self.write_string(buf, name);
                    self.write_string(buf, value);
                })?;
            },
            BackendMessage::ReadyForQuery(status) => {
                self.write_message_with_type(&mut buffer, b'Z', |buf| {
                    buf.put_u8(status.to_byte());
                })?;
            },
            BackendMessage::CommandComplete(tag) => {
                self.write_message_with_type(&mut buffer, b'C', |buf| {
                    self.write_string(buf, tag);
                })?;
            },
            BackendMessage::RowDescription(fields) => {
                self.write_message_with_type(&mut buffer, b'T', |buf| {
                    buf.put_i16(fields.len() as i16);
                    for field in fields {
                        self.write_string(buf, &field.name);
                        buf.put_i32(field.table_oid);
                        buf.put_i16(field.column_id);
                        buf.put_i32(field.data_type_oid);
                        buf.put_i16(field.data_type_size);
                        buf.put_i32(field.type_modifier);
                        buf.put_i16(field.format_code);
                    }
                })?;
            },
            BackendMessage::DataRow(values) => {
                self.write_message_with_type(&mut buffer, b'D', |buf| {
                    buf.put_i16(values.len() as i16);
                    for value in values {
                        match value {
                            Some(bytes) => {
                                buf.put_i32(bytes.len() as i32);
                                buf.put_slice(bytes);
                            },
                            None => {
                                buf.put_i32(-1); // NULL value
                            },
                        }
                    }
                })?;
            },
            BackendMessage::EmptyQueryResponse => {
                self.write_message_with_type(&mut buffer, b'I', |_| {})?;
            },
            BackendMessage::ErrorResponse(fields) => {
                self.write_error_or_notice(&mut buffer, b'E', fields)?;
            },
            BackendMessage::NoticeResponse(fields) => {
                self.write_error_or_notice(&mut buffer, b'N', fields)?;
            },
            BackendMessage::ParseComplete => {
                self.write_message_with_type(&mut buffer, b'1', |_| {})?;
            },
            BackendMessage::BindComplete => {
                self.write_message_with_type(&mut buffer, b'2', |_| {})?;
            },
            BackendMessage::PortalSuspended => {
                self.write_message_with_type(&mut buffer, b's', |_| {})?;
            },
            BackendMessage::NoData => {
                self.write_message_with_type(&mut buffer, b'n', |_| {})?;
            },
            BackendMessage::ParameterDescription(types) => {
                self.write_message_with_type(&mut buffer, b't', |buf| {
                    buf.put_i16(types.len() as i16);
                    for type_oid in types {
                        buf.put_i32(*type_oid);
                    }
                })?;
            },
            BackendMessage::CloseComplete => {
                self.write_message_with_type(&mut buffer, b'3', |_| {})?;
            },
            BackendMessage::FunctionCallResponse(value) => {
                self.write_message_with_type(&mut buffer, b'V', |buf| {
                    match value {
                        Some(bytes) => {
                            buf.put_i32(bytes.len() as i32);
                            buf.put_slice(bytes);
                        },
                        None => {
                            buf.put_i32(-1); // NULL value
                        },
                    }
                })?;
            },
            BackendMessage::NegotiateProtocolVersion { version_minor, options } => {
                self.write_message_with_type(&mut buffer, b'v', |buf| {
                    buf.put_i32(*version_minor);
                    buf.put_i32(options.len() as i32);
                    for option in options {
                        self.write_string(buf, option);
                    }
                })?;
            },
            BackendMessage::CopyInResponse { format, column_formats } => {
                self.write_message_with_type(&mut buffer, b'G', |buf| {
                    buf.put_i8(*format);
                    buf.put_i16(column_formats.len() as i16);
                    for format_code in column_formats {
                        buf.put_i16(*format_code);
                    }
                })?;
            },
            BackendMessage::CopyOutResponse { format, column_formats } => {
                self.write_message_with_type(&mut buffer, b'H', |buf| {
                    buf.put_i8(*format);
                    buf.put_i16(column_formats.len() as i16);
                    for format_code in column_formats {
                        buf.put_i16(*format_code);
                    }
                })?;
            },
            BackendMessage::CopyBothResponse { format, column_formats } => {
                self.write_message_with_type(&mut buffer, b'W', |buf| {
                    buf.put_i8(*format);
                    buf.put_i16(column_formats.len() as i16);
                    for format_code in column_formats {
                        buf.put_i16(*format_code);
                    }
                })?;
            },
            BackendMessage::CopyData(data) => {
                self.write_message_with_type(&mut buffer, b'd', |buf| {
                    buf.put_slice(data);
                })?;
            },
            BackendMessage::CopyDone => {
                self.write_message_with_type(&mut buffer, b'c', |_| {})?;
            },
            BackendMessage::CopyFail(message) => {
                self.write_message_with_type(&mut buffer, b'f', |buf| {
                    self.write_string(buf, message);
                })?;
            },
            BackendMessage::SSLResponse(supported) => {
                buffer.put_u8(if *supported { b'S' } else { b'N' });
            },
            BackendMessage::Unknown { tag, body } => {
                self.write_message_with_type(&mut buffer, *tag, |buf| {
                    buf.put_slice(body);
                })?;
            },
        }
        
        debug!("Formatted backend message: {:?} ({} bytes)", message, buffer.len());
        Ok(buffer.freeze())
    }

    /// Format an error response with the specified severity, code, and message
    pub fn format_error_response(&self, severity: &str, code: &str, message: &str) -> Bytes {
        let mut fields = ErrorOrNoticeFields {
            severity: Some(severity.to_string()),
            severity_non_localized: Some(severity.to_string()),
            code: Some(code.to_string()),
            message: Some(message.to_string()),
            detail: None,
            hint: None,
            position: None,
            internal_position: None,
            internal_query: None,
            context: None,
            schema_name: None,
            table_name: None,
            column_name: None,
            data_type_name: None,
            constraint_name: None,
            file: None,
            line: None,
            routine: None,
            fields: HashMap::new(),
        };
        
        fields.fields.insert(b'S', severity.to_string());
        fields.fields.insert(b'V', severity.to_string());
        fields.fields.insert(b'C', code.to_string());
        fields.fields.insert(b'M', message.to_string());
        
        let mut buffer = BytesMut::new();
        if let Err(e) = self.write_error_or_notice(&mut buffer, b'E', &fields) {
            debug!("Error formatting error response: {}", e);
            return Bytes::new();
        }
        
        buffer.freeze()
    }

    // Helper methods

    /// Write a message with the specified type code
    fn write_message_with_type<F>(&self, buffer: &mut BytesMut, type_code: u8, writer: F) -> Result<()>
    where
        F: FnOnce(&mut BytesMut),
    {
        buffer.put_u8(type_code);
        
        // Reserve space for length
        let length_pos = buffer.len();
        buffer.put_i32(0); // Placeholder
        
        // Write message body
        let body_start = buffer.len();
        writer(buffer);
        let body_end = buffer.len();
        
        // Update length (including length field itself, but not message type)
        let message_length = (body_end - body_start + 4) as i32;
        buffer[length_pos..length_pos + 4].copy_from_slice(&message_length.to_be_bytes());
        
        Ok(())
    }

    /// Write authentication message
    fn write_authentication(&self, buffer: &mut BytesMut, auth_request: &AuthenticationRequest) -> Result<()> {
        self.write_message_with_type(buffer, b'R', |buf| {
            match auth_request {
                AuthenticationRequest::Ok => {
                    buf.put_i32(0);
                },
                AuthenticationRequest::KerberosV5 => {
                    buf.put_i32(2);
                },
                AuthenticationRequest::CleartextPassword => {
                    buf.put_i32(3);
                },
                AuthenticationRequest::Md5Password { salt } => {
                    buf.put_i32(5);
                    buf.put_slice(salt);
                },
                AuthenticationRequest::SCMCredential => {
                    buf.put_i32(6);
                },
                AuthenticationRequest::GSS => {
                    buf.put_i32(7);
                },
                AuthenticationRequest::SSPI => {
                    buf.put_i32(9);
                },
                AuthenticationRequest::GSSContinue { data } => {
                    buf.put_i32(8);
                    buf.put_slice(data);
                },
                AuthenticationRequest::SASL { mechanisms } => {
                    buf.put_i32(10);
                    for mechanism in mechanisms {
                        self.write_string(buf, mechanism);
                    }
                    buf.put_u8(0); // Null terminator for the list
                },
                AuthenticationRequest::SASLContinue { data } => {
                    buf.put_i32(11);
                    buf.put_slice(data);
                },
                AuthenticationRequest::SASLFinal { data } => {
                    buf.put_i32(12);
                    buf.put_slice(data);
                },
            }
        })
    }

    /// Write error or notice message
    fn write_error_or_notice(&self, buffer: &mut BytesMut, type_code: u8, fields: &ErrorOrNoticeFields) -> Result<()> {
        self.write_message_with_type(buffer, type_code, |buf| {
            // Write all fields
            for (&field_type, field_value) in &fields.fields {
                buf.put_u8(field_type);
                self.write_string(buf, field_value);
            }
            
            // Null terminator
            buf.put_u8(0);
        })
    }

    /// Write a null-terminated string
    fn write_string(&self, buffer: &mut BytesMut, string: &str) {
        buffer.put_slice(string.as_bytes());
        buffer.put_u8(0); // Null terminator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::message::BackendMessage;

    #[test]
    fn test_format_simple_messages() {
        let formatter = MessageFormatter::new();
        
        // Test ReadyForQuery
        let message = BackendMessage::ReadyForQuery(TransactionStatus::Idle);
        let bytes = formatter.format_backend_message(&message).unwrap();
        assert_eq!(bytes[0], b'Z'); // Message type
        assert_eq!(bytes[1..5], 5_i32.to_be_bytes()); // Message length
        assert_eq!(bytes[5], b'I'); // Transaction status
        
        // Test EmptyQueryResponse
        let message = BackendMessage::EmptyQueryResponse;
        let bytes = formatter.format_backend_message(&message).unwrap();
        assert_eq!(bytes[0], b'I'); // Message type
        assert_eq!(bytes[1..5], 4_i32.to_be_bytes()); // Message length
        
        // Test CommandComplete
        let message = BackendMessage::CommandComplete("SELECT 1".to_string());
        let bytes = formatter.format_backend_message(&message).unwrap();
        assert_eq!(bytes[0], b'C'); // Message type
        assert_eq!(bytes[1..5], 12_i32.to_be_bytes()); // Message length (4 + 8 bytes)
        // "SELECT 1" + null terminator
        assert_eq!(&bytes[5..12], b"SELECT 1");
        assert_eq!(bytes[12], 0); // Null terminator
    }

    #[test]
    fn test_format_error_response() {
        let formatter = MessageFormatter::new();
        
        let bytes = formatter.format_error_response("ERROR", "XX000", "Test error message");
        assert_eq!(bytes[0], b'E'); // Message type
        
        // Check that the error fields are present
        assert!(bytes.windows(2).any(|w| w == [b'S', b'E'])); // Severity
        assert!(bytes.windows(2).any(|w| w == [b'C', b'X'])); // Code
        assert!(bytes.windows(2).any(|w| w == [b'M', b'T'])); // Message
    }
} 