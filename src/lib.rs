/// Verifiable RDS AVS - A verifiable database AVS for the Eigen Network
///
/// This is the root crate that provides workspace-level documentation.
/// Actual implementation is in the subcrates:
/// - `verifiable-db-core`: Core implementation of the verifiable database
/// - `verifiable-db-proxy`: Proxy server for the verifiable database
/// - `verifiable-db-client`: Client library for interacting with the verifiable database

/// This module is intentionally empty as the actual implementation
/// is in the subcrates.
/// Returns the version of the package.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
} 