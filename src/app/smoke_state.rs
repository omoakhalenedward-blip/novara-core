use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

pub const SMOKE_TRANSACTION: &[u8] = b"NOVARA_SMOKE_INCREMENT_1";

const STATE_FILE_MAGIC: &[u8] = b"NOVARA_SMOKE_STATE_V1\0";
const STATE_HASH_DOMAIN: &[u8] = b"NOVARA::ABCI::SMOKE_STATE::V1\0";
const HASH_LENGTH: usize = 32;
const STATE_FILE_LENGTH: usize = STATE_FILE_MAGIC.len() + 1 + 8 + 8 + HASH_LENGTH;
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateSnapshot {
    pub height: i64,
    pub smoke_counter: u64,
    pub app_hash: [u8; HASH_LENGTH],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizeResult {
    pub state: StateSnapshot,
    pub successful_transactions: Vec<bool>,
}

#[derive(Debug)]
pub enum SmokeStateError {
    Io(std::io::Error),
    InvalidStateFile,
    InvalidInitialHeight(i64),
    AlreadyInitialized,
    NotInitialized,
    FinalizationPending,
    InvalidBlockHeight { expected: i64, actual: i64 },
    NoPendingBlock,
}

impl fmt::Display for SmokeStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "state persistence failed: {error}"),
            Self::InvalidStateFile => write!(formatter, "state file is invalid or corrupted"),
            Self::InvalidInitialHeight(height) => {
                write!(formatter, "initial height must be positive, got {height}")
            }
            Self::AlreadyInitialized => write!(formatter, "application is already initialized"),
            Self::NotInitialized => write!(formatter, "application has not been initialized"),
            Self::FinalizationPending => {
                write!(formatter, "a finalized block is awaiting commit")
            }
            Self::InvalidBlockHeight { expected, actual } => {
                write!(formatter, "expected block height {expected}, got {actual}")
            }
            Self::NoPendingBlock => write!(formatter, "there is no finalized block to commit"),
        }
    }
}

impl Error for SmokeStateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SmokeStateError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug)]
pub struct SmokeState {
    path: PathBuf,
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
struct Inner {
    committed: StateSnapshot,
    initialized: bool,
    staged: Option<StateSnapshot>,
}

impl SmokeState {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, SmokeStateError> {
        let path = path.into();
        let parent = parent_directory(&path);
        fs::create_dir_all(parent)?;

        let (committed, initialized) = match fs::read(&path) {
            Ok(bytes) => decode_state(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                (make_snapshot(0, 0), false)
            }
            Err(error) => return Err(error.into()),
        };

        Ok(Self {
            path,
            inner: Arc::new(Mutex::new(Inner {
                committed,
                initialized,
                staged: None,
            })),
        })
    }

    pub fn snapshot(&self) -> StateSnapshot {
        self.lock().committed
    }

    pub fn initialize(&self, initial_height: i64) -> Result<StateSnapshot, SmokeStateError> {
        if initial_height <= 0 {
            return Err(SmokeStateError::InvalidInitialHeight(initial_height));
        }

        let mut inner = self.lock();
        if inner.initialized {
            return Err(SmokeStateError::AlreadyInitialized);
        }

        let snapshot = make_snapshot(initial_height - 1, 0);
        persist_state(&self.path, snapshot, true)?;
        inner.committed = snapshot;
        inner.initialized = true;
        Ok(snapshot)
    }

    pub fn can_process_proposal(&self, height: i64, txs: &[impl AsRef<[u8]>]) -> bool {
        let inner = self.lock();
        if !inner.initialized || inner.staged.is_some() {
            return false;
        }

        let Some(expected_height) = inner.committed.height.checked_add(1) else {
            return false;
        };
        if height != expected_height {
            return false;
        }

        let mut resulting_counter = inner.committed.smoke_counter;
        txs.iter().all(|tx| {
            tx.as_ref() == SMOKE_TRANSACTION
                && resulting_counter
                    .checked_add(1)
                    .map(|next| resulting_counter = next)
                    .is_some()
        })
    }

    pub fn finalize_block(
        &self,
        height: i64,
        txs: &[impl AsRef<[u8]>],
    ) -> Result<FinalizeResult, SmokeStateError> {
        let mut inner = self.lock();
        if !inner.initialized {
            return Err(SmokeStateError::NotInitialized);
        }
        if inner.staged.is_some() {
            return Err(SmokeStateError::FinalizationPending);
        }

        let expected_height =
            inner
                .committed
                .height
                .checked_add(1)
                .ok_or(SmokeStateError::InvalidBlockHeight {
                    expected: i64::MAX,
                    actual: height,
                })?;
        if height != expected_height {
            return Err(SmokeStateError::InvalidBlockHeight {
                expected: expected_height,
                actual: height,
            });
        }

        let mut counter = inner.committed.smoke_counter;
        let successful_transactions = txs
            .iter()
            .map(|tx| {
                if tx.as_ref() != SMOKE_TRANSACTION {
                    return false;
                }
                match counter.checked_add(1) {
                    Some(next) => {
                        counter = next;
                        true
                    }
                    None => false,
                }
            })
            .collect();
        let snapshot = make_snapshot(height, counter);
        inner.staged = Some(snapshot);

        Ok(FinalizeResult {
            state: snapshot,
            successful_transactions,
        })
    }

    pub fn commit(&self) -> Result<StateSnapshot, SmokeStateError> {
        let mut inner = self.lock();
        let staged = inner.staged.ok_or(SmokeStateError::NoPendingBlock)?;
        let expected_height =
            inner
                .committed
                .height
                .checked_add(1)
                .ok_or(SmokeStateError::InvalidBlockHeight {
                    expected: i64::MAX,
                    actual: staged.height,
                })?;
        if staged.height != expected_height {
            return Err(SmokeStateError::InvalidBlockHeight {
                expected: expected_height,
                actual: staged.height,
            });
        }

        persist_state(&self.path, staged, true)?;
        inner.committed = staged;
        inner.staged = None;
        Ok(staged)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .expect("NOVARA smoke state mutex was poisoned")
    }
}

fn make_snapshot(height: i64, smoke_counter: u64) -> StateSnapshot {
    let mut hasher = Sha256::new();
    hasher.update(STATE_HASH_DOMAIN);
    hasher.update(height.to_be_bytes());
    hasher.update(smoke_counter.to_be_bytes());
    let digest = hasher.finalize();
    let mut app_hash = [0; HASH_LENGTH];
    app_hash.copy_from_slice(&digest);

    StateSnapshot {
        height,
        smoke_counter,
        app_hash,
    }
}

fn decode_state(bytes: &[u8]) -> Result<(StateSnapshot, bool), SmokeStateError> {
    if bytes.len() != STATE_FILE_LENGTH || !bytes.starts_with(STATE_FILE_MAGIC) {
        return Err(SmokeStateError::InvalidStateFile);
    }

    let mut cursor = STATE_FILE_MAGIC.len();
    let initialized = match bytes[cursor] {
        0 => false,
        1 => true,
        _ => return Err(SmokeStateError::InvalidStateFile),
    };
    cursor += 1;

    let height = i64::from_be_bytes(
        bytes[cursor..cursor + 8]
            .try_into()
            .map_err(|_| SmokeStateError::InvalidStateFile)?,
    );
    cursor += 8;
    let smoke_counter = u64::from_be_bytes(
        bytes[cursor..cursor + 8]
            .try_into()
            .map_err(|_| SmokeStateError::InvalidStateFile)?,
    );
    cursor += 8;

    if height < 0 || !initialized {
        return Err(SmokeStateError::InvalidStateFile);
    }

    let snapshot = make_snapshot(height, smoke_counter);
    if bytes[cursor..] != snapshot.app_hash {
        return Err(SmokeStateError::InvalidStateFile);
    }
    Ok((snapshot, initialized))
}

fn persist_state(
    path: &Path,
    snapshot: StateSnapshot,
    initialized: bool,
) -> Result<(), SmokeStateError> {
    let parent = parent_directory(path);
    let file_name = path
        .file_name()
        .ok_or(SmokeStateError::InvalidStateFile)?
        .to_string_lossy();
    let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| SmokeStateError::Io(std::io::Error::other(error)))?
        .as_nanos();
    let temporary_path = parent.join(format!(
        ".{file_name}.{}.{}.{}.tmp",
        std::process::id(),
        timestamp,
        sequence
    ));

    let write_result = (|| -> Result<(), std::io::Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)?;
        file.write_all(STATE_FILE_MAGIC)?;
        file.write_all(&[u8::from(initialized)])?;
        file.write_all(&snapshot.height.to_be_bytes())?;
        file.write_all(&snapshot.smoke_counter.to_be_bytes())?;
        file.write_all(&snapshot.app_hash)?;
        file.sync_all()
    })();

    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(error.into());
    }

    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error.into());
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}
