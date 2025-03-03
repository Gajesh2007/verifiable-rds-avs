//! Authentication handler for PostgreSQL wire protocol
//! 
//! This module provides authentication functionality for the PostgreSQL wire protocol,
//! including MD5 password authentication, SCRAM-SHA-256, and other methods.

use crate::error::{ProxyError, Result};
use crate::protocol::message::{AuthenticationRequest, BackendMessage, FrontendMessage};
use crate::config::ProxyConfig;
use bytes::{Bytes, BytesMut};
use log::{debug, error, info, warn};
use rand::{Rng, thread_rng};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::str;

/// Authentication handler for PostgreSQL wire protocol
#[derive(Debug)]
pub struct AuthHandler {
    /// Authentication config
    config: AuthConfig,
    
    /// Authentication state
    state: AuthState,
    
    /// Current authentication method
    current_method: Option<AuthMethod>,
    
    /// Salt for MD5 authentication
    md5_salt: [u8; 4],
    
    /// SASL state for SCRAM-SHA-256 authentication
    sasl_state: Option<SaslState>,
}

/// Authentication state
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum AuthState {
    /// Not started
    NotStarted,
    
    /// In progress
    InProgress,
    
    /// Completed successfully
    Completed,
    
    /// Failed
    Failed,
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
#[derive(Debug)]
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
    /// Create a new authentication handler
    pub fn new(config: AuthConfig) -> Self {
        let mut md5_salt = [0u8; 4];
        thread_rng().fill(&mut md5_salt);
        
        Self {
            config,
            state: AuthState::NotStarted,
            current_method: None,
            md5_salt,
            sasl_state: None,
        }
    }
    
    /// Create a new authentication handler from proxy config
    pub fn from_proxy_config(config: &ProxyConfig) -> Self {
        let mut auth_config = AuthConfig::default();
        
        // Update config from proxy config
        if let Some(user) = config.pg_user.clone() {
            if let Some(password) = config.pg_password.clone() {
                auth_config.users.insert(user, password);
            }
        }
        
        // Determine auth method from connection parameters
        if let Some(method_str) = config.auth_method.as_deref() {
            let method = AuthMethod::from(method_str);
            auth_config.default_method = method;
            
            // Ensure the method is allowed
            if !auth_config.allowed_methods.contains(&method) {
                auth_config.allowed_methods.push(method);
            }
        }
        
        Self::new(auth_config)
    }
    
    /// Get initial authentication request message based on configuration
    pub fn get_initial_auth_request(&mut self) -> BackendMessage {
        self.state = AuthState::InProgress;
        
        match self.config.default_method {
            AuthMethod::Trust => {
                self.current_method = Some(AuthMethod::Trust);
                self.state = AuthState::Completed;
                BackendMessage::Authentication(AuthenticationRequest::Ok)
            }
            AuthMethod::Md5Password => {
                self.current_method = Some(AuthMethod::Md5Password);
                BackendMessage::Authentication(AuthenticationRequest::Md5Password {
                    salt: self.md5_salt,
                })
            }
            AuthMethod::CleartextPassword => {
                self.current_method = Some(AuthMethod::CleartextPassword);
                BackendMessage::Authentication(AuthenticationRequest::CleartextPassword)
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
                
                BackendMessage::Authentication(AuthenticationRequest::SASL {
                    mechanisms: vec!["SCRAM-SHA-256".to_string()],
                })
            }
        }
    }
    
    /// Handle authentication message from client
    pub fn handle_auth_message(&mut self, message: &FrontendMessage) -> Result<BackendMessage> {
        match message {
            FrontendMessage::Password(password) => {
                self.handle_password(password)
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
    fn handle_password(&mut self, password: &str) -> Result<BackendMessage> {
        match self.current_method {
            Some(AuthMethod::Md5Password) => {
                self.handle_md5_password(password)
            }
            Some(AuthMethod::CleartextPassword) => {
                self.handle_cleartext_password(password)
            }
            Some(AuthMethod::Trust) => {
                // Trust always succeeds
                self.state = AuthState::Completed;
                Ok(BackendMessage::Authentication(AuthenticationRequest::Ok))
            }
            _ => {
                Err(ProxyError::Protocol("Unexpected password message".to_string()))
            }
        }
    }
    
    /// Handle MD5 password
    fn handle_md5_password(&mut self, password: &str) -> Result<BackendMessage> {
        // Extract username and expected password from config
        // For simplicity in this example, we use a hard-coded user
        let username = "postgres";
        let expected_password = match self.config.users.get(username) {
            Some(pwd) => pwd,
            None => {
                self.state = AuthState::Failed;
                return Err(ProxyError::Protocol("User not found".to_string()));
            }
        };
        
        // Calculate expected MD5 hash
        // Format: md5(md5(password + username) + salt)
        let inner = format!("{}{}", expected_password, username);
        let inner_md5 = md5::compute(inner.as_bytes());
        let inner_hex = format!("{:x}", inner_md5);
        
        let outer = format!("{}{:?}", inner_hex, self.md5_salt);
        let outer_md5 = md5::compute(outer.as_bytes());
        let expected_hash = format!("md5{:x}", outer_md5);
        
        // Compare with received password
        if password == expected_hash {
            self.state = AuthState::Completed;
            Ok(BackendMessage::Authentication(AuthenticationRequest::Ok))
        } else {
            self.state = AuthState::Failed;
            Err(ProxyError::Protocol("Invalid password".to_string()))
        }
    }
    
    /// Handle cleartext password
    fn handle_cleartext_password(&mut self, password: &str) -> Result<BackendMessage> {
        // Extract username and expected password from config
        // For simplicity in this example, we use a hard-coded user
        let username = "postgres";
        let expected_password = match self.config.users.get(username) {
            Some(pwd) => pwd,
            None => {
                self.state = AuthState::Failed;
                return Err(ProxyError::Protocol("User not found".to_string()));
            }
        };
        
        // Compare with received password
        if password == expected_password {
            self.state = AuthState::Completed;
            Ok(BackendMessage::Authentication(AuthenticationRequest::Ok))
        } else {
            self.state = AuthState::Failed;
            Err(ProxyError::Protocol("Invalid password".to_string()))
        }
    }
    
    /// Handle SASL client first message
    fn handle_sasl_client_first(&mut self, client_first: String) -> Result<BackendMessage> {
        let sasl_state = match &mut self.sasl_state {
            Some(state) => state,
            None => {
                return Err(ProxyError::Protocol("SASL authentication not started".to_string()));
            }
        };
        
        // Parse client first message
        // Format: n,a=<authzid>,n=<username>,r=<client-nonce>
        let parts: Vec<&str> = client_first.split(',').collect();
        
        // Extract client nonce and username
        let mut client_nonce = String::new();
        let mut username = String::new();
        
        for part in parts {
            if part.starts_with("r=") {
                client_nonce = part[2..].to_string();
            } else if part.starts_with("n=") {
                username = part[2..].to_string();
            }
        }
        
        if client_nonce.is_empty() || username.is_empty() {
            return Err(ProxyError::Protocol("Invalid SASL client first message".to_string()));
        }
        
        // Store client first message and username
        sasl_state.client_first_message = client_first;
        sasl_state.client_nonce = client_nonce.clone();
        sasl_state.username = username;
        sasl_state.state = ScramState::ReceivedClientFirst;
        
        // Generate server nonce (client nonce + server random)
        let mut server_nonce = client_nonce;
        let server_random: String = thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(18)
            .map(char::from)
            .collect();
        server_nonce.push_str(&server_random);
        
        // Generate random salt
        let salt: Vec<u8> = thread_rng()
            .sample_iter(&rand::distributions::Standard)
            .take(16)
            .collect();
        
        // Store server nonce and salt
        sasl_state.server_nonce = server_nonce.clone();
        sasl_state.salt = salt.clone();
        
        // Create server first message
        // Format: r=<server-nonce>,s=<base64-salt>,i=<iteration-count>
        let server_first = format!(
            "r={},s={},i={}",
            server_nonce,
            base64::encode(&salt),
            sasl_state.iteration_count
        );
        
        // Store server first message
        sasl_state.server_first_message = server_first.clone();
        sasl_state.state = ScramState::SentServerFirst;
        
        // Return SASL continue message
        Ok(BackendMessage::Authentication(AuthenticationRequest::SASLContinue {
            data: Bytes::from(server_first.into_bytes()),
        }))
    }
    
    /// Handle SASL client final message
    fn handle_sasl_client_final(&mut self, client_final: &str) -> Result<BackendMessage> {
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
        self.state = AuthState::Completed;
        
        Ok(BackendMessage::Authentication(AuthenticationRequest::Ok))
    }
    
    /// Get authentication state
    pub fn get_state(&self) -> AuthState {
        self.state
    }
    
    /// Reset authentication state
    pub fn reset(&mut self) {
        self.state = AuthState::NotStarted;
        self.current_method = None;
        self.sasl_state = None;
        
        // Generate new salt for MD5 authentication
        thread_rng().fill(&mut self.md5_salt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_auth_method_from_str() {
        assert_eq!(AuthMethod::from("md5"), AuthMethod::Md5Password);
        assert_eq!(AuthMethod::from("MD5"), AuthMethod::Md5Password);
        assert_eq!(AuthMethod::from("trust"), AuthMethod::Trust);
        assert_eq!(AuthMethod::from("scram-sha-256"), AuthMethod::ScramSha256);
        assert_eq!(AuthMethod::from("password"), AuthMethod::CleartextPassword);
        assert_eq!(AuthMethod::from("unknown"), AuthMethod::Md5Password); // Default to MD5
    }
    
    #[test]
    fn test_auth_handler_initial_request() {
        // Test MD5 authentication
        let mut config = AuthConfig::default();
        config.default_method = AuthMethod::Md5Password;
        let mut handler = AuthHandler::new(config);
        
        match handler.get_initial_auth_request() {
            BackendMessage::Authentication(AuthenticationRequest::Md5Password { .. }) => {
                // Expected
            }
            _ => panic!("Expected MD5Password authentication request"),
        }
        
        // Test trust authentication
        let mut config = AuthConfig::default();
        config.default_method = AuthMethod::Trust;
        let mut handler = AuthHandler::new(config);
        
        match handler.get_initial_auth_request() {
            BackendMessage::Authentication(AuthenticationRequest::Ok) => {
                // Expected
            }
            _ => panic!("Expected Ok authentication request"),
        }
        
        // Test SCRAM-SHA-256 authentication
        let mut config = AuthConfig::default();
        config.default_method = AuthMethod::ScramSha256;
        let mut handler = AuthHandler::new(config);
        
        match handler.get_initial_auth_request() {
            BackendMessage::Authentication(AuthenticationRequest::SASL { mechanisms }) => {
                assert!(mechanisms.contains(&"SCRAM-SHA-256".to_string()));
            }
            _ => panic!("Expected SASL authentication request"),
        }
    }
    
    #[test]
    fn test_md5_password_authentication() {
        // Create auth handler with MD5 authentication
        let mut config = AuthConfig::default();
        config.default_method = AuthMethod::Md5Password;
        let mut handler = AuthHandler::new(config);
        
        // Get initial auth request and extract salt
        let salt = match handler.get_initial_auth_request() {
            BackendMessage::Authentication(AuthenticationRequest::Md5Password { salt }) => salt,
            _ => panic!("Expected MD5Password authentication request"),
        };
        
        // Calculate correct password hash
        // username: postgres, password: postgres
        let username = "postgres";
        let password = "postgres";
        
        let inner = format!("{}{}", password, username);
        let inner_md5 = md5::compute(inner.as_bytes());
        let inner_hex = format!("{:x}", inner_md5);
        
        let outer = format!("{}{:?}", inner_hex, salt);
        let outer_md5 = md5::compute(outer.as_bytes());
        let hashed_password = format!("md5{:x}", outer_md5);
        
        // Handle password message
        let password_msg = FrontendMessage::Password(hashed_password);
        match handler.handle_auth_message(&password_msg) {
            Ok(BackendMessage::Authentication(AuthenticationRequest::Ok)) => {
                // Expected
                assert_eq!(handler.get_state(), AuthState::Completed);
            }
            _ => panic!("Expected successful authentication"),
        }
    }
    
    #[test]
    fn test_cleartext_password_authentication() {
        // Create auth handler with cleartext authentication
        let mut config = AuthConfig::default();
        config.default_method = AuthMethod::CleartextPassword;
        let mut handler = AuthHandler::new(config);
        
        // Get initial auth request
        match handler.get_initial_auth_request() {
            BackendMessage::Authentication(AuthenticationRequest::CleartextPassword) => {
                // Expected
            }
            _ => panic!("Expected CleartextPassword authentication request"),
        }
        
        // Handle password message
        let password_msg = FrontendMessage::Password("postgres".to_string());
        match handler.handle_auth_message(&password_msg) {
            Ok(BackendMessage::Authentication(AuthenticationRequest::Ok)) => {
                // Expected
                assert_eq!(handler.get_state(), AuthState::Completed);
            }
            _ => panic!("Expected successful authentication"),
        }
    }
} 