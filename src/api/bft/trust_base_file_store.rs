//! The optional file adapter of the Trust Base cache (feature `file-cache`, host only).
//!
//! One file per cache key in a caller-chosen directory. Reads are bounded and take no lock:
//! replacement is atomic (same-directory temporary file, flush, rename, directory flush where
//! supported), so a reader sees the old or the new complete bytes. A compare-and-swap takes an
//! exclusive lock by creating a lock directory (atomic); contention returns
//! [`StoreError::Busy`] at once. A lock left by a crash is **never stolen**: it is an
//! app-visible maintenance condition (see [`FileStore::lock_path`]), not permission to write
//! unlocked. There is no non-atomic fallback and no overwrite after a lock failure.
//!
//! The calls block the caller's thread (file I/O); wrap the store for an executor if needed.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::trust_base_cache::{
    Revision, StoreCas, StoreError, StoreKey, StoreRead, TrustBaseStore,
};
use crate::crypto::hash::sha256;

/// Largest stored value a compare-and-swap will read to compute the current revision.
const MAX_CAS_READ: u64 = 64 << 20;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A directory of cached bundles.
#[derive(Debug, Clone)]
pub struct FileStore {
    dir: PathBuf,
}

struct LockGuard(PathBuf);

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

fn map_err(e: io::Error) -> StoreError {
    match e.kind() {
        io::ErrorKind::PermissionDenied => StoreError::Permission,
        _ if e.raw_os_error() == Some(28) => StoreError::Quota, // ENOSPC
        _ if e.raw_os_error() == Some(122) => StoreError::Quota, // EDQUOT
        _ => StoreError::Io(e.to_string()),
    }
}

impl FileStore {
    /// A store in `dir` (created on the first write when missing).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        FileStore { dir: dir.into() }
    }

    fn stem(key: &StoreKey) -> String {
        // the key is hashed: a namespace never reaches the filesystem as a path component
        let h = sha256(key.0.as_bytes());
        format!("utb-{}", hex::encode(h.data()))
    }

    /// The file holding `key`.
    pub fn file_path(&self, key: &StoreKey) -> PathBuf {
        self.dir.join(format!("{}.cbor", Self::stem(key)))
    }

    /// The lock directory of `key`. If it exists while no writer is running (a crash), the app
    /// decides to remove it; the store never does.
    pub fn lock_path(&self, key: &StoreKey) -> PathBuf {
        self.dir.join(format!("{}.lock", Self::stem(key)))
    }

    fn read_file(path: &Path, max: u64) -> Result<Option<Vec<u8>>, StoreError> {
        let f = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(map_err(e)),
        };
        if f.metadata().map_err(map_err)?.len() > max {
            return Err(StoreError::TooLarge);
        }
        // the file may grow after the check: the read itself is bounded too
        let mut buf = Vec::new();
        f.take(max + 1).read_to_end(&mut buf).map_err(map_err)?;
        if buf.len() as u64 > max {
            return Err(StoreError::TooLarge);
        }
        Ok(Some(buf))
    }

    fn lock(&self, key: &StoreKey) -> Result<LockGuard, StoreError> {
        fs::create_dir_all(&self.dir).map_err(map_err)?;
        let p = self.lock_path(key);
        match fs::create_dir(&p) {
            Ok(()) => Ok(LockGuard(p)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(StoreError::Busy),
            Err(e) => Err(map_err(e)),
        }
    }

    fn write_atomic(&self, key: &StoreKey, bytes: &[u8]) -> Result<(), StoreError> {
        let target = self.file_path(key);
        let tmp = self.dir.join(format!(
            "{}.tmp-{}-{}",
            Self::stem(key),
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| -> io::Result<()> {
            let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, &target)?;
            // make the rename durable where the platform allows a directory flush
            #[cfg(unix)]
            File::open(&self.dir)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result.map_err(map_err)
    }
}

impl TrustBaseStore for FileStore {
    async fn read(&self, key: &StoreKey, max_bytes: usize) -> Result<StoreRead, StoreError> {
        match Self::read_file(&self.file_path(key), max_bytes as u64)? {
            None => Ok(StoreRead::Absent),
            Some(bytes) => Ok(StoreRead::Present {
                revision: Revision::of(&bytes),
                bytes,
            }),
        }
    }

    async fn compare_and_swap(
        &self,
        key: &StoreKey,
        expected: Option<&Revision>,
        bytes: &[u8],
    ) -> Result<StoreCas, StoreError> {
        let _lock = self.lock(key)?;
        let current = Self::read_file(&self.file_path(key), MAX_CAS_READ)?;
        let rev = current.as_deref().map(Revision::of);
        if rev.as_ref() != expected {
            return Ok(StoreCas::Changed);
        }
        self.write_atomic(key, bytes)?;
        Ok(StoreCas::Written(Revision::of(bytes)))
    }
}
