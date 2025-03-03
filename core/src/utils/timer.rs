//! Timing utilities
//!
//! This module provides utilities for measuring execution time and managing timeouts.

use std::time::{Duration, Instant};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use log::{debug, info, warn};

/// Timer for measuring execution time
#[derive(Debug, Clone)]
pub struct Timer {
    /// Name of the timer
    name: String,
    
    /// Start time
    start: Instant,
    
    /// Optional warning threshold
    warning_threshold: Option<Duration>,
    
    /// Optional error threshold
    error_threshold: Option<Duration>,
    
    /// Whether to log automatically on drop
    log_on_drop: bool,
}

impl Timer {
    /// Create a new timer with the given name
    pub fn new(name: impl Into<String>) -> Self {
        Timer {
            name: name.into(),
            start: Instant::now(),
            warning_threshold: None,
            error_threshold: None,
            log_on_drop: true,
        }
    }
    
    /// Set a warning threshold for the timer
    pub fn with_warning_threshold(mut self, threshold: Duration) -> Self {
        self.warning_threshold = Some(threshold);
        self
    }
    
    /// Set an error threshold for the timer
    pub fn with_error_threshold(mut self, threshold: Duration) -> Self {
        self.error_threshold = Some(threshold);
        self
    }
    
    /// Disable automatic logging on drop
    pub fn without_auto_log(mut self) -> Self {
        self.log_on_drop = false;
        self
    }
    
    /// Get the elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
    
    /// Get the elapsed time in milliseconds
    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed().as_millis() as u64
    }
    
    /// Check if the timer has exceeded the warning threshold
    pub fn has_warning(&self) -> bool {
        if let Some(threshold) = self.warning_threshold {
            self.elapsed() > threshold
        } else {
            false
        }
    }
    
    /// Check if the timer has exceeded the error threshold
    pub fn has_error(&self) -> bool {
        if let Some(threshold) = self.error_threshold {
            self.elapsed() > threshold
        } else {
            false
        }
    }
    
    /// Reset the timer
    pub fn reset(&mut self) {
        self.start = Instant::now();
    }
    
    /// Stop the timer and return the elapsed time
    pub fn stop(&self) -> Duration {
        self.elapsed()
    }
    
    /// Log the elapsed time at debug level
    pub fn log_debug(&self, message: impl Into<String>) {
        let elapsed = self.elapsed();
        let msg = format!("{} {}: {:?}", self.name, message.into(), elapsed);
        debug!("{}", msg);
    }
    
    /// Log the elapsed time at info level
    pub fn log_info(&self, message: impl Into<String>) {
        let elapsed = self.elapsed();
        let msg = format!("{} {}: {:?}", self.name, message.into(), elapsed);
        info!("{}", msg);
    }
    
    /// Log the elapsed time at appropriate level based on thresholds
    pub fn log(&self, message: impl Into<String>) {
        let elapsed = self.elapsed();
        let msg = format!("{} {}: {:?}", self.name, message.into(), elapsed);
        
        if self.has_error() {
            warn!("{} [SLOW]", msg);
        } else if self.has_warning() {
            info!("{} [WARN]", msg);
        } else {
            debug!("{}", msg);
        }
    }
    
    /// Execute a closure and measure its execution time
    pub fn measure<F, T>(&self, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        let result = f();
        self.log("execution time");
        result
    }
    
    /// Execute a closure and measure its execution time with a custom message
    pub fn measure_with_message<F, T>(&self, message: impl Into<String>, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        let result = f();
        self.log(message);
        result
    }
    
    /// Create a checkpoint and log the time since the last checkpoint
    pub fn checkpoint(&mut self, name: impl Into<String>) -> Duration {
        let elapsed = self.elapsed();
        self.log(name);
        self.reset();
        elapsed
    }
}

impl Display for Timer {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}: {:?}", self.name, self.elapsed())
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if self.log_on_drop {
            self.log("completed");
        }
    }
}

/// Async timer for measuring execution time
#[derive(Clone)]
pub struct AsyncTimer {
    /// Inner timer
    inner: Timer,
}

impl AsyncTimer {
    /// Create a new async timer with the given name
    pub fn new(name: impl Into<String>) -> Self {
        AsyncTimer {
            inner: Timer::new(name),
        }
    }
    
    /// Set a warning threshold for the timer
    pub fn with_warning_threshold(mut self, threshold: Duration) -> Self {
        let inner = self.inner.clone();
        self.inner = inner.with_warning_threshold(threshold);
        self
    }
    
    /// Set an error threshold for the timer
    pub fn with_error_threshold(mut self, threshold: Duration) -> Self {
        let inner = self.inner.clone();
        self.inner = inner.with_error_threshold(threshold);
        self
    }
    
    /// Disable automatic logging on drop
    pub fn without_auto_log(mut self) -> Self {
        let inner = self.inner.clone();
        self.inner = inner.without_auto_log();
        self
    }
    
    /// Get the elapsed time
    pub fn elapsed(&self) -> Duration {
        self.inner.elapsed()
    }
    
    /// Get the elapsed time in milliseconds
    pub fn elapsed_ms(&self) -> u64 {
        self.inner.elapsed_ms()
    }
    
    /// Check if the timer has exceeded the warning threshold
    pub fn has_warning(&self) -> bool {
        self.inner.has_warning()
    }
    
    /// Check if the timer has exceeded the error threshold
    pub fn has_error(&self) -> bool {
        self.inner.has_error()
    }
    
    /// Reset the timer
    pub fn reset(&mut self) {
        self.inner.reset();
    }
    
    /// Stop the timer and return the elapsed time
    pub fn stop(&self) -> Duration {
        self.inner.stop()
    }
    
    /// Log the elapsed time at debug level
    pub fn log_debug(&self, message: impl Into<String>) {
        self.inner.log_debug(message);
    }
    
    /// Log the elapsed time at info level
    pub fn log_info(&self, message: impl Into<String>) {
        self.inner.log_info(message);
    }
    
    /// Log the elapsed time at appropriate level based on thresholds
    pub fn log(&self, message: impl Into<String>) {
        self.inner.log(message);
    }
    
    /// Execute an async closure and measure its execution time
    pub async fn measure<F, Fut, T>(&self, f: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let result = f().await;
        self.log("execution time");
        result
    }
    
    /// Execute an async closure and measure its execution time with a custom message
    pub async fn measure_with_message<F, Fut, T>(&self, message: impl Into<String>, f: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let result = f().await;
        self.log(message);
        result
    }
    
    /// Create a checkpoint and log the time since the last checkpoint
    pub fn checkpoint(&mut self, name: impl Into<String>) -> Duration {
        self.inner.checkpoint(name)
    }
    
    /// Apply a timeout to an async operation
    pub async fn with_timeout<F, Fut, T>(&self, timeout: Duration, f: F) -> Result<T, tokio::time::error::Elapsed>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let result = tokio::time::timeout(timeout, f()).await;
        if result.is_err() {
            warn!("{} timeout after {:?}", self.inner.name, timeout);
        }
        result
    }
}

impl Debug for AsyncTimer {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        std::fmt::Debug::fmt(&self.inner, f)
    }
}

impl Display for AsyncTimer {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        std::fmt::Display::fmt(&self.inner, f)
    }
}

impl Drop for AsyncTimer {
    fn drop(&mut self) {
        // The inner timer will handle logging on drop
    }
}

/// Helper function to create a timer
pub fn timer(name: impl Into<String>) -> Timer {
    Timer::new(name)
}

/// Helper function to create an async timer
pub fn async_timer(name: impl Into<String>) -> AsyncTimer {
    AsyncTimer::new(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    
    #[test]
    fn test_timer_basic() {
        let timer = Timer::new("test_timer").without_auto_log();
        thread::sleep(Duration::from_millis(10));
        let elapsed = timer.elapsed();
        
        assert!(elapsed >= Duration::from_millis(10));
        assert!(timer.elapsed_ms() >= 10);
    }
    
    #[test]
    fn test_timer_thresholds() {
        let timer = Timer::new("test_timer")
            .with_warning_threshold(Duration::from_millis(5))
            .with_error_threshold(Duration::from_millis(15))
            .without_auto_log();
        
        // Before warning threshold
        thread::sleep(Duration::from_millis(2));
        assert!(!timer.has_warning());
        assert!(!timer.has_error());
        
        // After warning threshold, before error threshold
        thread::sleep(Duration::from_millis(5));
        assert!(timer.has_warning());
        assert!(!timer.has_error());
        
        // After error threshold
        thread::sleep(Duration::from_millis(10));
        assert!(timer.has_warning());
        assert!(timer.has_error());
    }
    
    #[test]
    fn test_timer_reset() {
        let mut timer = Timer::new("test_timer").without_auto_log();
        thread::sleep(Duration::from_millis(10));
        assert!(timer.elapsed() >= Duration::from_millis(10));
        
        timer.reset();
        assert!(timer.elapsed() < Duration::from_millis(10));
    }
    
    #[test]
    fn test_timer_measure() {
        let timer = Timer::new("test_timer").without_auto_log();
        let result = timer.measure(|| {
            thread::sleep(Duration::from_millis(10));
            42
        });
        
        assert_eq!(result, 42);
        assert!(timer.elapsed() >= Duration::from_millis(10));
    }
    
    #[test]
    fn test_timer_checkpoint() {
        let mut timer = Timer::new("test_timer").without_auto_log();
        
        // First checkpoint
        thread::sleep(Duration::from_millis(10));
        let elapsed1 = timer.checkpoint("checkpoint1");
        assert!(elapsed1 >= Duration::from_millis(10));
        
        // Second checkpoint
        thread::sleep(Duration::from_millis(20));
        let elapsed2 = timer.checkpoint("checkpoint2");
        assert!(elapsed2 >= Duration::from_millis(20));
        
        // Timer should be reset after each checkpoint
        assert!(timer.elapsed() < Duration::from_millis(10));
    }
    
    #[tokio::test]
    async fn test_async_timer() {
        let timer = AsyncTimer::new("test_async_timer").without_auto_log();
        
        let result = timer.measure(|| async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            42
        }).await;
        
        assert_eq!(result, 42);
        assert!(timer.elapsed() >= Duration::from_millis(10));
    }
    
    #[tokio::test]
    async fn test_async_timer_timeout_success() {
        let timer = AsyncTimer::new("test_async_timer").without_auto_log();
        
        let result = timer.with_timeout(Duration::from_millis(50), || async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            42
        }).await;
        
        assert_eq!(result.unwrap(), 42);
    }
    
    #[tokio::test]
    async fn test_async_timer_timeout_failure() {
        let timer = AsyncTimer::new("test_async_timer").without_auto_log();
        
        let result = timer.with_timeout(Duration::from_millis(10), || async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            42
        }).await;
        
        assert!(result.is_err());
    }
} 