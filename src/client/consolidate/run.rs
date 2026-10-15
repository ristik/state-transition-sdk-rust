//! Execution primitives of consolidation: cancellation, a clock for the total
//! deadline, and the executor of the independent exact-root wave. Pure
//! `alloc` + `core`; hosts (see the `std` types) supply threads and real time.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

/// A shareable cancellation flag. Clones observe the same flag.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A fresh, not cancelled token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancel every clone of this token.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether the token was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// A monotonic millisecond clock.
pub trait Clock: Sync {
    /// Milliseconds since an arbitrary fixed origin; never decreasing.
    fn now_ms(&self) -> u64;
}

/// The host clock (`std`).
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct SystemClock(std::time::Instant);

#[cfg(feature = "std")]
impl SystemClock {
    /// A clock starting now.
    pub fn new() -> Self {
        Self(std::time::Instant::now())
    }
}

#[cfg(feature = "std")]
impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Runs the independent jobs of one wave and returns their results in input
/// order. Implementations may run jobs concurrently but must run each exactly
/// once.
pub trait WaveExecutor {
    /// Run `job` for every input.
    fn run<I: Sync, T: Send>(&self, inputs: &[I], job: &(dyn Fn(&I) -> T + Sync)) -> Vec<T>;
}

/// Runs the jobs one after another on the calling thread.
#[derive(Debug, Clone, Copy, Default)]
pub struct SequentialExecutor;

impl WaveExecutor for SequentialExecutor {
    fn run<I: Sync, T: Send>(&self, inputs: &[I], job: &(dyn Fn(&I) -> T + Sync)) -> Vec<T> {
        inputs.iter().map(job).collect()
    }
}

/// Runs the jobs on at most `max_parallel` scoped threads (`std`).
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy)]
pub struct ThreadedExecutor {
    max_parallel: usize,
}

#[cfg(feature = "std")]
impl ThreadedExecutor {
    /// Default bound on concurrent requests.
    pub const DEFAULT_MAX_PARALLEL: usize = 4;

    /// Executor with the given bound (at least one thread).
    pub fn new(max_parallel: usize) -> Self {
        Self {
            max_parallel: max_parallel.max(1),
        }
    }
}

#[cfg(feature = "std")]
impl Default for ThreadedExecutor {
    fn default() -> Self {
        Self::new(Self::DEFAULT_MAX_PARALLEL)
    }
}

#[cfg(feature = "std")]
impl WaveExecutor for ThreadedExecutor {
    fn run<I: Sync, T: Send>(&self, inputs: &[I], job: &(dyn Fn(&I) -> T + Sync)) -> Vec<T> {
        use std::sync::atomic::AtomicUsize;
        use std::sync::Mutex;

        let workers = self.max_parallel.min(inputs.len());
        if workers <= 1 {
            return inputs.iter().map(job).collect();
        }
        let next = AtomicUsize::new(0);
        let results: Mutex<Vec<Option<T>>> = Mutex::new((0..inputs.len()).map(|_| None).collect());
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(input) = inputs.get(i) else { break };
                    let value = job(input);
                    results.lock().expect("result lock")[i] = Some(value);
                });
            }
        });
        results
            .into_inner()
            .expect("result lock")
            .into_iter()
            .map(|r| r.expect("every job ran exactly once"))
            .collect()
    }
}
