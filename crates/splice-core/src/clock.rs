//! Time source behind a trait (§5.3, D13).
//!
//! Presence tags are derived from the wall clock in 300 s buckets, and a device
//! is offline after 6 s without a beacon. Both rules need tests that move time
//! without sleeping, so every module that reads the clock takes a [`Clock`]
//! instead of calling [`SystemTime::now`] directly.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Wall-clock source. Times are durations since the Unix epoch.
pub trait Clock: Send + Sync + 'static {
    /// Seconds (and fraction) since 1970-01-01T00:00:00Z.
    ///
    /// A clock before the epoch yields zero rather than panicking: tag matching
    /// fails closed (no beacon matches), which is the safe direction.
    fn now(&self) -> Duration;
}

/// The real clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
    }
}

/// A clock that only moves when a test tells it to.
///
/// Cheap to clone; clones share one counter.
#[derive(Debug, Clone, Default)]
pub struct ManualClock {
    millis: Arc<AtomicU64>,
}

impl ManualClock {
    /// Start at the Unix epoch (bucket 0).
    pub fn new() -> Self {
        Self::default()
    }

    /// Start at a specific instant.
    pub fn at(instant: Duration) -> Self {
        let clock = Self::new();
        clock.set(instant);
        clock
    }

    /// Jump to `instant`.
    pub fn set(&self, instant: Duration) {
        self.millis
            .store(instant.as_millis() as u64, Ordering::SeqCst);
    }

    /// Move forward by `delta`.
    pub fn advance(&self, delta: Duration) {
        self.millis
            .fetch_add(delta.as_millis() as u64, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.millis.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_moves_only_when_asked() {
        let clock = ManualClock::at(Duration::from_secs(1_000));
        assert_eq!(clock.now(), Duration::from_secs(1_000));
        clock.advance(Duration::from_millis(1500));
        assert_eq!(clock.now(), Duration::from_millis(1_001_500));
        assert_eq!(clock.now(), Duration::from_millis(1_001_500));
    }

    #[test]
    fn clones_share_one_counter() {
        let clock = ManualClock::new();
        let copy = clock.clone();
        copy.advance(Duration::from_secs(7));
        assert_eq!(clock.now(), Duration::from_secs(7));
    }

    #[test]
    fn system_clock_is_after_the_epoch() {
        assert!(SystemClock.now() > Duration::ZERO);
    }
}
