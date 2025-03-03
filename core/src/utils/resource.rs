//! Resource limiting utilities
//!
//! This module provides utilities for limiting resource usage in the system,
//! such as memory, CPU, and time.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use std::future::Future;
use tokio::time::timeout;

/// Resource limit configuration
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum memory usage in bytes
    pub memory_limit: u64,
    
    /// Maximum CPU time in milliseconds
    pub cpu_time_limit: u64,
    
    /// Maximum wall time in milliseconds
    pub wall_time_limit: u64,
    
    /// Maximum concurrent operations
    pub max_concurrency: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        ResourceLimits {
            memory_limit: 100 * 1024 * 1024, // 100 MB
            cpu_time_limit: 10 * 1000,       // 10 seconds
            wall_time_limit: 30 * 1000,      // 30 seconds
            max_concurrency: 4,              // 4 concurrent operations
        }
    }
}

/// Error type for resource limiting operations
#[derive(Debug, thiserror::Error, Clone)]
pub enum ResourceError {
    /// Memory limit exceeded
    #[error("Memory limit exceeded: used {0} bytes, limit {1} bytes")]
    MemoryLimitExceeded(u64, u64),
    
    /// CPU time limit exceeded
    #[error("CPU time limit exceeded: used {0} ms, limit {1} ms")]
    CpuTimeLimitExceeded(u64, u64),
    
    /// Wall time limit exceeded
    #[error("Wall time limit exceeded: used {0} ms, limit {1} ms")]
    WallTimeLimitExceeded(u64, u64),
    
    /// Concurrency limit exceeded
    #[error("Concurrency limit exceeded")]
    ConcurrencyLimitExceeded,
    
    /// Operation cancelled
    #[error("Operation cancelled")]
    OperationCancelled,
    
    /// General resource error
    #[error("Resource error: {0}")]
    Other(String),
}

/// Result type for resource limiting operations
pub type ResourceResult<T> = Result<T, ResourceError>;

/// Resource limiter for controlling resource usage
#[derive(Debug, Clone)]
pub struct ResourceLimiter {
    /// Resource limits
    limits: ResourceLimits,
    
    /// Current memory usage in bytes
    memory_usage: Arc<AtomicU64>,
    
    /// Semaphore for concurrency control
    semaphore: Arc<Semaphore>,
    
    /// Whether the limiter is active
    active: bool,
}

impl ResourceLimiter {
    /// Create a new resource limiter with the given limits
    pub fn new(limits: ResourceLimits) -> Self {
        ResourceLimiter {
            memory_usage: Arc::new(AtomicU64::new(0)),
            semaphore: Arc::new(Semaphore::new(limits.max_concurrency)),
            limits,
            active: true,
        }
    }
    
    /// Create a new resource limiter with default limits
    pub fn default() -> Self {
        Self::new(ResourceLimits::default())
    }
    
    /// Set the active state of the limiter
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }
    
    /// Check if the limiter is active
    pub fn is_active(&self) -> bool {
        self.active
    }
    
    /// Reset the memory usage counter
    pub fn reset_memory_usage(&self) {
        self.memory_usage.store(0, Ordering::SeqCst);
    }
    
    /// Get the current memory usage
    pub fn get_memory_usage(&self) -> u64 {
        self.memory_usage.load(Ordering::SeqCst)
    }
    
    /// Allocate memory
    pub fn allocate_memory(&self, bytes: u64) -> ResourceResult<()> {
        if !self.active {
            return Ok(());
        }
        
        let current = self.memory_usage.fetch_add(bytes, Ordering::SeqCst);
        let new_usage = current + bytes;
        
        if new_usage > self.limits.memory_limit {
            // Rollback the allocation
            self.memory_usage.fetch_sub(bytes, Ordering::SeqCst);
            Err(ResourceError::MemoryLimitExceeded(
                new_usage,
                self.limits.memory_limit,
            ))
        } else {
            Ok(())
        }
    }
    
    /// Free memory
    pub fn free_memory(&self, bytes: u64) {
        if !self.active {
            return;
        }
        
        let current = self.memory_usage.load(Ordering::SeqCst);
        let new_usage = current.saturating_sub(bytes);
        self.memory_usage.store(new_usage, Ordering::SeqCst);
    }
    
    /// Execute a function with time limits
    pub async fn with_time_limit<F, Fut, T>(&self, f: F) -> ResourceResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        if !self.active {
            return Ok(f().await);
        }
        
        let start = Instant::now();
        
        // Apply wall time limit
        let result = match timeout(
            Duration::from_millis(self.limits.wall_time_limit),
            f(),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                return Err(ResourceError::WallTimeLimitExceeded(
                    self.limits.wall_time_limit,
                    self.limits.wall_time_limit,
                ))
            }
        };
        
        let elapsed = start.elapsed().as_millis() as u64;
        
        // Check CPU time limit (approximated as wall time in this implementation)
        if elapsed > self.limits.cpu_time_limit {
            return Err(ResourceError::CpuTimeLimitExceeded(
                elapsed,
                self.limits.cpu_time_limit,
            ));
        }
        
        Ok(result)
    }
    
    /// Execute a function with concurrency control
    pub async fn with_concurrency_limit<F, Fut, T>(&self, f: F) -> ResourceResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        if !self.active {
            return Ok(f().await);
        }
        
        let permit = match self.semaphore.try_acquire() {
            Ok(permit) => permit,
            Err(_) => return Err(ResourceError::ConcurrencyLimitExceeded),
        };
        
        let result = f().await;
        
        // Drop the permit when done
        drop(permit);
        
        Ok(result)
    }
    
    /// Execute a function with all resource limits
    pub async fn with_limits<F, Fut, T>(&self, f: F) -> ResourceResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ResourceResult<T>>,
    {
        if !self.active {
            return f().await;
        }
        
        self.with_concurrency_limit(|| self.with_time_limit(f)).await??
    }
}

/// Memory tracking wrapper for data structures
pub struct MemoryTracked<T: Clone> {
    /// The wrapped value
    value: T,
    
    /// The memory size in bytes
    size: u64,
    
    /// The resource limiter
    limiter: Arc<ResourceLimiter>,
}

impl<T: Clone> MemoryTracked<T> {
    /// Create a new memory tracked value
    pub fn new(value: T, size: u64, limiter: Arc<ResourceLimiter>) -> ResourceResult<Self> {
        limiter.allocate_memory(size)?;
        
        Ok(MemoryTracked {
            value,
            size,
            limiter,
        })
    }
    
    /// Get a reference to the value
    pub fn get(&self) -> &T {
        &self.value
    }
    
    /// Get a mutable reference to the value
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.value
    }
    
    /// Consume the wrapper and return the value
    pub fn into_inner(self) -> T {
        // Memory will be freed in Drop implementation
        self.value.clone()
    }
    
    /// Get the size of the value in bytes
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl<T: Clone> Drop for MemoryTracked<T> {
    fn drop(&mut self) {
        // Free the memory when the wrapper is dropped
        self.limiter.free_memory(self.size);
    }
}

/// Task that enforces resource limits
pub struct ResourceLimitedTask<T: Clone> {
    /// The task result
    result: ResourceResult<T>,
    
    /// The resource limiter
    limiter: Arc<ResourceLimiter>,
    
    /// Memory usage of the task
    memory_usage: u64,
}

impl<T: Clone> ResourceLimitedTask<T> {
    /// Create a new resource limited task
    pub fn new(result: ResourceResult<T>, limiter: Arc<ResourceLimiter>, memory_usage: u64) -> Self {
        ResourceLimitedTask {
            result,
            limiter,
            memory_usage,
        }
    }
    
    /// Get the result of the task
    pub fn result(&self) -> ResourceResult<T> {
        self.result.clone()
    }
    
    /// Get the memory usage of the task
    pub fn memory_usage(&self) -> u64 {
        self.memory_usage
    }
}

impl<T: Clone> Drop for ResourceLimitedTask<T> {
    fn drop(&mut self) {
        // Free the memory when the task is dropped
        self.limiter.free_memory(self.memory_usage);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        
        assert_eq!(limits.memory_limit, 100 * 1024 * 1024);
        assert_eq!(limits.cpu_time_limit, 10 * 1000);
        assert_eq!(limits.wall_time_limit, 30 * 1000);
        assert_eq!(limits.max_concurrency, 4);
    }
    
    #[test]
    fn test_resource_limiter_memory() {
        let limiter = ResourceLimiter::default();
        
        // Allocate some memory
        limiter.allocate_memory(1000).unwrap();
        assert_eq!(limiter.get_memory_usage(), 1000);
        
        // Allocate more memory
        limiter.allocate_memory(2000).unwrap();
        assert_eq!(limiter.get_memory_usage(), 3000);
        
        // Free some memory
        limiter.free_memory(1500);
        assert_eq!(limiter.get_memory_usage(), 1500);
        
        // Reset memory usage
        limiter.reset_memory_usage();
        assert_eq!(limiter.get_memory_usage(), 0);
    }
    
    #[test]
    fn test_resource_limiter_memory_limit() {
        let mut limits = ResourceLimits::default();
        limits.memory_limit = 1000; // Set a small limit for testing
        
        let limiter = ResourceLimiter::new(limits);
        
        // Allocate memory under the limit
        limiter.allocate_memory(500).unwrap();
        
        // Try to allocate more memory than the limit allows
        let result = limiter.allocate_memory(600);
        assert!(result.is_err());
        
        if let Err(ResourceError::MemoryLimitExceeded(used, limit)) = result {
            assert_eq!(used, 1100);
            assert_eq!(limit, 1000);
        } else {
            panic!("Expected MemoryLimitExceeded error");
        }
        
        // Memory usage should still be the original allocation
        assert_eq!(limiter.get_memory_usage(), 500);
    }
    
    #[test]
    fn test_memory_tracked() {
        let limiter = Arc::new(ResourceLimiter::default());
        
        // Create a tracked value
        let tracked = MemoryTracked::new(vec![1, 2, 3], 100, limiter.clone()).unwrap();
        assert_eq!(limiter.get_memory_usage(), 100);
        
        // Access the value
        assert_eq!(tracked.get().len(), 3);
        
        // Drop the tracked value and check that memory is freed
        drop(tracked);
        assert_eq!(limiter.get_memory_usage(), 0);
    }
    
    #[tokio::test]
    async fn test_with_time_limit() {
        let mut limits = ResourceLimits::default();
        limits.wall_time_limit = 100; // 100ms
        let limiter = ResourceLimiter::new(limits);
        
        // Test with a fast operation
        let result = limiter
            .with_time_limit(|| async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                42
            })
            .await;
        
        assert_eq!(result.unwrap(), 42);
        
        // Test with a slow operation that exceeds the limit
        let result = limiter
            .with_time_limit(|| async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                42
            })
            .await;
        
        assert!(result.is_err());
        if let Err(ResourceError::WallTimeLimitExceeded(_, limit)) = result {
            assert_eq!(limit, 100);
        } else {
            panic!("Expected WallTimeLimitExceeded error");
        }
    }
    
    #[tokio::test]
    async fn test_with_concurrency_limit() {
        let mut limits = ResourceLimits::default();
        limits.max_concurrency = 2; // Allow only 2 concurrent operations
        let limiter = Arc::new(ResourceLimiter::new(limits));
        
        // Start two operations that hold the permits for a while
        let op1 = tokio::spawn({
            let limiter = limiter.clone();
            async move {
                let _result = limiter
                    .with_concurrency_limit(|| async {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        1
                    })
                    .await;
            }
        });
        
        let op2 = tokio::spawn({
            let limiter = limiter.clone();
            async move {
                let _result = limiter
                    .with_concurrency_limit(|| async {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        2
                    })
                    .await;
            }
        });
        
        // Give time for the operations to start
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        // Try to start a third operation, which should fail due to the concurrency limit
        let result = limiter
            .with_concurrency_limit(|| async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                3
            })
            .await;
        
        assert!(result.is_err());
        assert!(matches!(result, Err(ResourceError::ConcurrencyLimitExceeded)));
        
        // Wait for the first two operations to complete
        let _ = tokio::join!(op1, op2);
        
        // Now the third operation should succeed
        let result = limiter
            .with_concurrency_limit(|| async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                3
            })
            .await;
        
        assert_eq!(result.unwrap(), 3);
    }
    
    #[test]
    fn test_inactive_limiter() {
        let mut limiter = ResourceLimiter::default();
        limiter.set_active(false);
        
        // Memory limit should be ignored
        limiter.allocate_memory(1_000_000_000_000).unwrap(); // Huge allocation, but should succeed
        
        // Memory usage should still be 0 since tracking is disabled
        assert_eq!(limiter.get_memory_usage(), 0);
    }
} 