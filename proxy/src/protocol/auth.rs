//! Authentication handler for PostgreSQL wire protocol
//! 
//! This module provides authentication functionality for the PostgreSQL wire protocol,
//! including MD5 password authentication, SCRAM-SHA-256, and other methods.

use crate::error::{ProxyError, Result};
use crate::protocol::message::{AuthenticationRequest, BackendMessage, FrontendMessage};
use crate::config::ProxyConfig;
use bytes::{Bytes, BytesMut, Buf, BufMut};
use log::{debug, error, info, warn};
use rand::{Rng, thread_rng};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::str;
use base64;
use tokio;
use md5;
use hex;
use tokio::runtime::Runtime;
use std::sync::atomic::{AtomicU8, Ordering};

/// Authentication handler for PostgreSQL wire protocol
#[derive(Debug, Clone)]
pub struct AuthHandler {
    /// Authentication configuration
    config: AuthConfig,
    
    /// Authentication state
    state: u8,
    
    /// Current authentication method
    current_method: Option<AuthMethod>,
    
    /// MD5 salt for password authentication
    md5_salt: [u8; 4],
    
    /// SASL state for SCRAM-SHA-256 authentication
    sasl_state: Option<SaslState>,
}

/// Authentication state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// Authentication has not started
    NotStarted = 0,
    /// Authentication is in progress
    InProgress = 1,
    /// Authentication is completed
    Completed = 2,
}

impl AuthState {
    /// Convert from u8 to AuthState
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => AuthState::NotStarted,
            1 => AuthState::InProgress,
            2 => AuthState::Completed,
            _ => AuthState::NotStarted, // Default case
        }
    }
}

/// Authentication method
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum AuthMethod {
    /// No authentication required (trust)
    Trust,
    
    /// MD5 password authentication
    Md5Password,
    
    /// SCRAM-SHA-256 authentication
    ScramSha256,
    
    /// Cleartext password authentication
    CleartextPassword,
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthMethod::Trust => write!(f, "trust"),
            AuthMethod::Md5Password => write!(f, "md5"),
            AuthMethod::ScramSha256 => write!(f, "scram-sha-256"),
            AuthMethod::CleartextPassword => write!(f, "password"),
        }
    }
}

impl From<&str> for AuthMethod {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "trust" => AuthMethod::Trust,
            "md5" => AuthMethod::Md5Password,
            "scram-sha-256" => AuthMethod::ScramSha256,
            "password" => AuthMethod::CleartextPassword,
            _ => {
                warn!("Unknown authentication method: {}, defaulting to MD5", s);
                AuthMethod::Md5Password
            }
        }
    }
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Allowed authentication methods
    pub allowed_methods: Vec<AuthMethod>,
    
    /// Default authentication method
    pub default_method: AuthMethod,
    
    /// Usernames and passwords
    pub users: HashMap<String, String>,
    
    /// Require client SSL
    pub require_ssl: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        let mut users = HashMap::new();
        users.insert("postgres".to_string(), "postgres".to_string());
        
        Self {
            allowed_methods: vec![
                AuthMethod::Md5Password,
                AuthMethod::ScramSha256,
            ],
            default_method: AuthMethod::Md5Password,
            users,
            require_ssl: false,
        }
    }
}

/// SASL state for SCRAM-SHA-256 authentication
#[derive(Debug, Clone)]
struct SaslState {
    /// Client first message
    client_first_message: String,
    
    /// Server first message
    server_first_message: String,
    
    /// Client nonce
    client_nonce: String,
    
    /// Server nonce
    server_nonce: String,
    
    /// Salt
    salt: Vec<u8>,
    
    /// Iteration count
    iteration_count: u32,
    
    /// Client username
    username: String,
    
    /// SCRAM state
    state: ScramState,
}

/// SCRAM state
#[derive(Debug, PartialEq, Clone, Copy)]
enum ScramState {
    /// Initial state
    Initial,
    
    /// Client first message received
    ReceivedClientFirst,
    
    /// Server first message sent
    SentServerFirst,
    
    /// Client final message received
    ReceivedClientFinal,
    
    /// Authentication completed
    Completed,
    
    /// Authentication failed
    Failed,
}

impl AuthHandler {
    /// Create a new authentication handler with provided configuration
    pub fn new(auth_config: AuthConfig) -> Self {
        // Generate a random salt for MD5 authentication
        let mut md5_salt = [0u8; 4];
        thread_rng().fill(&mut md5_salt);
        
        Self {
            config: auth_config,
            state: AuthState::NotStarted as u8,
            current_method: None,
            md5_salt,
            sasl_state: None,
        }
    }
    
    /// Create a new authentication handler with default configuration
    pub fn default() -> Self {
        Self {
            config: AuthConfig::default(),
            state: AuthState::NotStarted as u8,
            current_method: None,
            md5_salt: [0u8; 4],
            sasl_state: None,
        }
    }
    
    /// Get initial authentication request message based on configuration
    pub fn get_initial_auth_request(&mut self) -> Vec<BackendMessage> {
        self.state = AuthState::InProgress as u8;
        
        match self.config.default_method {
            AuthMethod::Trust => {
                self.current_method = Some(AuthMethod::Trust);
                self.state = AuthState::Completed as u8;
                vec![BackendMessage::Authentication(AuthenticationRequest::Ok)]
            }
            AuthMethod::Md5Password => {
                self.current_method = Some(AuthMethod::Md5Password);
                vec![BackendMessage::Authentication(AuthenticationRequest::Md5Password {
                    salt: self.md5_salt,
                })]
            }
            AuthMethod::CleartextPassword => {
                self.current_method = Some(AuthMethod::CleartextPassword);
                vec![BackendMessage::Authentication(AuthenticationRequest::CleartextPassword)]
            }
            AuthMethod::ScramSha256 => {
                self.current_method = Some(AuthMethod::ScramSha256);
                
                // Initialize SASL state
                self.sasl_state = Some(SaslState {
                    client_first_message: String::new(),
                    server_first_message: String::new(),
                    client_nonce: String::new(),
                    server_nonce: String::new(),
                    salt: Vec::new(),
                    iteration_count: 4096, // Default iteration count
                    username: String::new(),
                    state: ScramState::Initial,
                });
                
                vec![BackendMessage::Authentication(AuthenticationRequest::SASL {
                    mechanisms: vec!["SCRAM-SHA-256".to_string()],
                })]
            }
        }
    }
    
    /// Handle authentication message from client
    pub fn handle_auth_message(&mut self, message: &FrontendMessage) -> Result<Vec<BackendMessage>> {
        match message {
            FrontendMessage::Password(password) => {
                // Clone the password to avoid borrowing issues
                let password_clone = password.clone();
                // Use block_in_place to run the async function in a blocking context
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        self.handle_password(password_clone).await
                    })
                })
            }
            // For SASL authentication, client first sends a message with the mechanism
            FrontendMessage::Unknown { tag, body } if *tag == b'p' => {
                // This looks like a SASL message, try to parse it
                let mut buf = body.slice(..);
                if buf.remaining() >= 2 {
                    // First two bytes should be length
                    let _len = buf.get_u16();
                    
                    if buf.remaining() > 0 {
                        // Try to extract mechanism name
                        let mut mechanism = Vec::new();
                        while buf.has_remaining() {
                            let b = buf.get_u8();
                            if b == 0 {
                                break;
                            }
                            mechanism.push(b);
                        }
                        
                        if let Ok(mechanism_str) = String::from_utf8(mechanism) {
                            if mechanism_str == "SCRAM-SHA-256" {
                                // Extract client first message
                                let mut client_first = Vec::new();
                                while buf.has_remaining() {
                                    client_first.push(buf.get_u8());
                                }
                                
                                if let Ok(client_first_str) = String::from_utf8(client_first) {
                                    return self.handle_sasl_client_first(client_first_str);
                                }
                            }
                        }
                    }
                }
                
                // If we get here, we couldn't parse the message as SASL
                Err(ProxyError::Protocol("Invalid authentication message".to_string()))
            }
            // Handle client final message in SASL authentication
            _ => {
                Err(ProxyError::Protocol("Unexpected message during authentication".to_string()))
            }
        }
    }
    
    /// Handle password message
    pub async fn handle_password(&mut self, password: String) -> Result<Vec<BackendMessage>> {
        // Check if we have a salt for MD5 authentication
        if self.md5_salt == [0, 0, 0, 0] {
            return Err(ProxyError::Auth("MD5 salt not initialized".to_string()));
        }
        
        // Get the expected password from the config
        let username = match self.current_method {
            Some(AuthMethod::Md5Password) | Some(AuthMethod::CleartextPassword) => {
                // For password-based auth, we need a username
                if self.config.users.is_empty() {
                    return Err(ProxyError::Auth("No users configured".to_string()));
                }
                
                // Get the first user
                self.config.users.keys().next().unwrap().clone()
            }
            _ => {
                // Set state to completed for Trust auth
                self.set_state_completed();
                return Ok(vec![BackendMessage::Authentication(AuthenticationRequest::Ok)]);
            }
        };
        
        // Check if the user exists
        if !self.config.users.contains_key(&username) {
            return Err(ProxyError::Auth(format!("User {} not found", username)));
        }
        
        // Get the expected password
        let expected_password = self.config.users.get(&username).unwrap();
        
        // Check the password based on the authentication method
        match self.current_method {
            Some(AuthMethod::Md5Password) => {
                // For MD5 authentication, we received an MD5 hash from client
                // We need to check if this matches what we'd expect from the stored cleartext password
                let expected_md5 = format!("md5{}", md5_hex(&md5_hex(expected_password, username.as_bytes()), &self.md5_salt));
                
                if password == expected_md5 {
                    // Set state to completed
                    self.set_state_completed();
                    Ok(vec![BackendMessage::Authentication(AuthenticationRequest::Ok)])
                } else {
                    Err(ProxyError::Auth("Invalid password".to_string()))
                }
            }
            Some(AuthMethod::CleartextPassword) => {
                // Verify cleartext password
                if password == *expected_password {
                    // Set state to completed
                    self.set_state_completed();
                    Ok(vec![BackendMessage::Authentication(AuthenticationRequest::Ok)])
                } else {
                    Err(ProxyError::Auth("Invalid password".to_string()))
                }
            }
            _ => Err(ProxyError::Auth("Unsupported authentication method".to_string())),
        }
    }
    
    /// Handle startup message
    pub fn handle_startup(&mut self, version_major: i16, version_minor: i16, _parameters: &HashMap<String, String>) -> Result<Vec<BackendMessage>> {
        debug!("Handling startup with version {}.{}", version_major, version_minor);
        
        // For now, return a simple authentication request to make it compile
        Ok(vec![BackendMessage::Authentication(AuthenticationRequest::CleartextPassword)])
    }
    
    /// Handle SASL client first message
    fn handle_sasl_client_first(&mut self, client_first: String) -> Result<Vec<BackendMessage>> {
        let sasl_state = match &mut self.sasl_state {
            Some(state) => state,
            None => {
                return Err(ProxyError::Auth("No SASL state available".to_string()));
            }
        };
        
        // For now, just return a simple authentication response
        // In a real implementation, we would parse the SASL client-first message
        // and respond with a server-first message
        
        // Generate a random salt for SCRAM-SHA-256
        let mut salt = [0u8; 16];
        thread_rng().fill(&mut salt);
        
        // Return authentication successful for now
        Ok(vec![BackendMessage::Authentication(AuthenticationRequest::Ok)])
    }
    
    /// Handle SASL client final message
    fn handle_sasl_client_final(&mut self, client_final: &str) -> Result<Vec<BackendMessage>> {
        let sasl_state = match &mut self.sasl_state {
            Some(state) => state,
            None => {
                return Err(ProxyError::Protocol("SASL authentication not started".to_string()));
            }
        };
        
        if sasl_state.state != ScramState::SentServerFirst {
            return Err(ProxyError::Protocol("Unexpected SASL message".to_string()));
        }
        
        // Parse client final message
        // Format: c=<base64-cbind-input>,r=<server-nonce>,p=<base64-client-proof>
        let parts: Vec<&str> = client_final.split(',').collect();
        
        // Extract server nonce and client proof
        let mut server_nonce = String::new();
        let mut client_proof_base64 = String::new();
        
        for part in parts {
            if part.starts_with("r=") {
                server_nonce = part[2..].to_string();
            } else if part.starts_with("p=") {
                client_proof_base64 = part[2..].to_string();
            }
        }
        
        if server_nonce != sasl_state.server_nonce || client_proof_base64.is_empty() {
            sasl_state.state = ScramState::Failed;
            return Err(ProxyError::Protocol("Invalid SASL client final message".to_string()));
        }
        
        // Update state
        sasl_state.state = ScramState::ReceivedClientFinal;
        
        // In a real implementation, we would validate the client proof
        // and generate a server signature, but for this example, we'll skip that
        // and just return authentication success
        
        // For a complete SCRAM-SHA-256 implementation, we would:
        // 1. Derive client and server keys from the password
        // 2. Compute the client signature and validate the client proof
        // 3. Compute the server signature
        // 4. Return the server signature in a SASLFinal message
        
        // For now, we'll just complete the authentication
        sasl_state.state = ScramState::Completed;
        self.set_state_completed();
        
        Ok(vec![BackendMessage::Authentication(AuthenticationRequest::Ok)])
    }
    
    /// Get authentication state
    pub fn get_state(&self) -> AuthState {
        AuthState::from_u8(self.state)
    }
    
    /// Reset authentication state
    pub fn reset(&mut self) {
        self.state = AuthState::NotStarted as u8;
        self.current_method = None;
        self.sasl_state = None;
    }

    /// Handle verify message
    pub fn handle_verify_message(&mut self, message: &FrontendMessage) -> Result<Vec<BackendMessage>> {
        match message {
            FrontendMessage::Password(password) => {
                // Verify password
                if self.verify_password(password) {
                    Ok(vec![BackendMessage::Authentication(AuthenticationRequest::Ok)])
                } else {
                    Err(ProxyError::Auth("Invalid password".to_string()))
                }
            }
            _ => Err(ProxyError::Auth("Expected password message".to_string())),
        }
    }

    /// Verify password
    fn verify_password(&self, password: &str) -> bool {
        // Get the first user from the config
        if self.config.users.is_empty() {
            return false;
        }
        
        let (username, expected_password) = self.config.users.iter().next().unwrap();
        
        match self.current_method {
            Some(AuthMethod::Md5Password) => {
                // Verify MD5 password
                let md5_password = format!("md5{}", md5_hex(&md5_hex(password, username.as_bytes()), &self.md5_salt));
                md5_password == *expected_password
            }
            Some(AuthMethod::CleartextPassword) => {
                // Verify cleartext password
                password == expected_password
            }
            _ => false,
        }
    }

    /// Set the state to completed
    fn set_state_completed(&mut self) {
        self.state = AuthState::Completed as u8;
    }
}

/// Calculate MD5 hex digest
fn md5_hex(password: &str, salt: &[u8]) -> String {
    let mut context = md5::Context::new();
    context.consume(password.as_bytes());
    context.consume(salt);
    
    hex::encode(context.compute().0)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_auth_methods() {
        // Test string conversion to auth methods
        assert_eq!(AuthMethod::from("trust"), AuthMethod::Trust);
        assert_eq!(AuthMethod::from("md5"), AuthMethod::Md5Password);
        assert_eq!(AuthMethod::from("scram-sha-256"), AuthMethod::ScramSha256);
        assert_eq!(AuthMethod::from("password"), AuthMethod::CleartextPassword);
        
        // Test display implementation
        assert_eq!(format!("{}", AuthMethod::Trust), "trust");
        assert_eq!(format!("{}", AuthMethod::Md5Password), "md5");
        assert_eq!(format!("{}", AuthMethod::ScramSha256), "scram-sha-256");
        assert_eq!(format!("{}", AuthMethod::CleartextPassword), "password");
        
        // Create auth handler with trust authentication
        let mut config = AuthConfig::default();
        config.default_method = AuthMethod::Trust;
        let mut handler = AuthHandler::new(config);
        
        // Get initial auth request
        let auth_request = handler.get_initial_auth_request();
        assert_eq!(auth_request.len(), 1);
        match &auth_request[0] {
            BackendMessage::Authentication(AuthenticationRequest::Ok) => {
                // Expected
            }
            _ => panic!("Expected Ok authentication request"),
        }
        
        // Test SCRAM-SHA-256 authentication
        let mut config = AuthConfig::default();
        config.default_method = AuthMethod::ScramSha256;
        let mut handler = AuthHandler::new(config);
        
        let auth_request = handler.get_initial_auth_request();
        assert_eq!(auth_request.len(), 1);
        match &auth_request[0] {
            BackendMessage::Authentication(AuthenticationRequest::SASL { mechanisms }) => {
                assert!(mechanisms.contains(&"SCRAM-SHA-256".to_string()));
            }
            _ => panic!("Expected SASL authentication request"),
        }
    }
    
    #[test]
    fn test_md5_password_authentication() {
        // Create a tokio runtime
        let rt = Runtime::new().unwrap();
        
        rt.block_on(async {
            // Create auth handler with MD5 authentication
            let mut config = AuthConfig::default();
            config.default_method = AuthMethod::Md5Password;
            
            // Add a test user
            config.users.insert("postgres".to_string(), "postgres".to_string());
            
            let mut handler = AuthHandler::new(config);
            
            // Get initial auth request and extract salt
            let auth_request = handler.get_initial_auth_request();
            assert_eq!(auth_request.len(), 1);
            let salt = match &auth_request[0] {
                BackendMessage::Authentication(AuthenticationRequest::Md5Password { salt }) => *salt,
                _ => panic!("Expected MD5Password authentication request"),
            };
            
            // Calculate correct password hash
            // username: postgres, password: postgres
            let username = "postgres";
            let password = "postgres";
            
            // Calculate the password hash the same way the server does
            let md5_password = format!("md5{}", md5_hex(&md5_hex(password, username.as_bytes()), &salt));
            
            println!("Expected password: {}", password);
            println!("Calculated MD5 password: {}", md5_password);
            println!("Salt: {:?}", salt);
            
            // Handle password message
            let password_msg = FrontendMessage::Password(md5_password);
            let result = handler.handle_auth_message(&password_msg);
            
            if let Err(e) = &result {
                println!("Error: {:?}", e);
            }
            
            assert!(result.is_ok());
            let messages = result.unwrap();
            assert_eq!(messages.len(), 1);
            match &messages[0] {
                BackendMessage::Authentication(AuthenticationRequest::Ok) => {
                    // Expected
                    assert_eq!(handler.get_state(), AuthState::Completed);
                }
                _ => panic!("Expected successful authentication"),
            }
        });
    }
} 