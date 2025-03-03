//! Client library for interacting with the Verifiable Database
//!
//! This library provides a client for interacting with the verification
//! features of the Verifiable Database system.

pub mod verification;
pub mod query;

pub use verification::VerificationClient; 