//! In-memory adapters for orchestrator kernel storage traits (unit tests).
//!
//! These implementations are deterministic and fast but not durable. They are
//! intended for unit testing of domain logic that depends on the kernel
//! storage contracts.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use apm2_core::orchestrator_kernel::{
    CursorStore, EffectExecutionState, EffectJournal, InDoubtResolution, IntentStore, KernelCursor,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::sqlite::IntentKeyed;

/// Maximum number of intents in the memory intent store. This mirrors the
/// production `SQLite` adapter's bounded design.
const MAX_MEMORY_INTENTS: usize = 8192;

/// Maximum number of intents per `enqueue_many` call. Mirrors the production
/// `SQLite` adapter's per-batch bound.
const MAX_ENQUEUE_BATCH: usize = 4096;

/// Maximum number of intents returned by a single `dequeue_batch` call.
/// Mirrors the production `SQLite` adapter's per-query bound.
const MAX_DEQUEUE_BATCH: usize = 4096;

// ---------------------------------------------------------------------------
// MemoryCursorStore
// ---------------------------------------------------------------------------

/// In-memory cursor store for unit tests.
///
/// # Synchronization protocol
///
/// Protected by `Mutex<C>`. Only one caller can read or write at a time.
/// No async suspension occurs while the lock is held.
#[derive(Debug)]
pub struct MemoryCursorStore<C: KernelCursor> {
    /// Protected cursor value. Single writer, single reader via Mutex.
    cursor: Mutex<C>,
}

impl<C: KernelCursor> Default for MemoryCursorStore<C> {
    fn default() -> Self {
        Self {
            cursor: Mutex::new(C::default()),
        }
    }
}

impl<C: KernelCursor> MemoryCursorStore<C> {
    /// Creates a new memory cursor store with the default cursor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<C: KernelCursor> CursorStore<C> for MemoryCursorStore<C> {
    type Error = String;

    async fn load(&self) -> Result<C, Self::Error> {
        Ok(self
            .cursor
            .lock()
            .map_err(|e| format!("memory cursor lock poisoned: {e}"))?
            .clone())
    }

    async fn save(&self, cursor: &C) -> Result<(), Self::Error> {
        *self
            .cursor
            .lock()
            .map_err(|e| format!("memory cursor lock poisoned: {e}"))? = cursor.clone();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MemoryIntentStore
// ---------------------------------------------------------------------------

/// Intent state in the memory store.
#[derive(Debug, Clone, PartialEq, Eq)]
enum IntentState {
    Pending,
    Completed,
    Blocked,
}

/// In-memory intent store for unit tests.
///
/// # Synchronization protocol
///
/// All fields are protected by a single `Mutex<MemoryIntentInner>`. No async
/// suspension occurs while the lock is held.
#[derive(Debug)]
pub struct MemoryIntentStore<I>
where
    I: Serialize + DeserializeOwned + IntentKeyed + Clone + Send + Sync + 'static,
{
    /// Protected inner state. Single lock for all fields.
    inner: Mutex<MemoryIntentInner<I>>,
}

#[derive(Debug)]
struct MemoryIntentInner<I> {
    /// FIFO queue of pending intent keys.
    pending: VecDeque<String>,
    /// Map of `intent_key` -> (intent, state).
    intents: HashMap<String, (I, IntentState)>,
}

impl<I> Default for MemoryIntentStore<I>
where
    I: Serialize + DeserializeOwned + IntentKeyed + Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self {
            inner: Mutex::new(MemoryIntentInner {
                pending: VecDeque::new(),
                intents: HashMap::new(),
            }),
        }
    }
}

impl<I> MemoryIntentStore<I>
where
    I: Serialize + DeserializeOwned + IntentKeyed + Clone + Send + Sync + 'static,
{
    /// Creates a new empty memory intent store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<I> IntentStore<I, String> for MemoryIntentStore<I>
where
    I: Serialize + DeserializeOwned + IntentKeyed + Clone + Send + Sync + 'static,
{
    type Error = String;

    async fn enqueue_many(&self, intents: &[I]) -> Result<usize, Self::Error> {
        if intents.len() > MAX_ENQUEUE_BATCH {
            return Err(format!(
                "enqueue_many batch size {} exceeds MAX_ENQUEUE_BATCH {MAX_ENQUEUE_BATCH}",
                intents.len()
            ));
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| format!("memory intent lock poisoned: {e}"))?;
        if inner.intents.len().saturating_add(intents.len()) > MAX_MEMORY_INTENTS {
            return Err(format!(
                "memory intent store capacity exceeded: {} + {} > {MAX_MEMORY_INTENTS}",
                inner.intents.len(),
                intents.len()
            ));
        }
        let mut inserted = 0usize;
        for intent in intents {
            let key = intent.intent_key();
            if inner.intents.contains_key(&key) {
                continue;
            }
            inner
                .intents
                .insert(key.clone(), (intent.clone(), IntentState::Pending));
            inner.pending.push_back(key);
            inserted = inserted.saturating_add(1);
        }
        Ok(inserted)
    }

    async fn dequeue_batch(&self, limit: usize) -> Result<Vec<I>, Self::Error> {
        let capped_limit = limit.min(MAX_DEQUEUE_BATCH);
        let inner = self
            .inner
            .lock()
            .map_err(|e| format!("memory intent lock poisoned: {e}"))?;
        let mut out = Vec::new();
        for key in inner.pending.iter().take(capped_limit) {
            if let Some((intent, IntentState::Pending)) = inner.intents.get(key) {
                out.push(intent.clone());
            }
        }
        Ok(out)
    }

    async fn mark_done(&self, key: &String) -> Result<(), Self::Error> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| format!("memory intent lock poisoned: {e}"))?;
        inner.pending.retain(|k| k != key);
        if let Some((_, state)) = inner.intents.get_mut(key) {
            *state = IntentState::Completed;
        }
        Ok(())
    }

    async fn mark_blocked(&self, key: &String, _reason: &str) -> Result<(), Self::Error> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| format!("memory intent lock poisoned: {e}"))?;
        inner.pending.retain(|k| k != key);
        if let Some((_, state)) = inner.intents.get_mut(key) {
            *state = IntentState::Blocked;
        }
        Ok(())
    }

    async fn mark_retryable(&self, key: &String, _reason: &str) -> Result<(), Self::Error> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| format!("memory intent lock poisoned: {e}"))?;
        if let Some((_, state)) = inner.intents.get_mut(key) {
            *state = IntentState::Pending;
        }
        // Move to back of queue
        inner.pending.retain(|k| k != key);
        inner.pending.push_back(key.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MemoryEffectJournal
// ---------------------------------------------------------------------------

/// In-memory effect journal for unit tests.
///
/// # Synchronization protocol
///
/// Protected by `Mutex<HashMap>`. No async suspension while locked.
#[derive(Debug, Default)]
pub struct MemoryEffectJournal {
    /// Protected state map. Single lock for all entries.
    states: Mutex<HashMap<String, EffectExecutionState>>,
}

impl MemoryEffectJournal {
    /// Creates a new empty memory effect journal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl EffectJournal<String> for MemoryEffectJournal {
    type Error = String;

    async fn query_state(&self, key: &String) -> Result<EffectExecutionState, Self::Error> {
        let states = self
            .states
            .lock()
            .map_err(|e| format!("memory effect journal lock poisoned: {e}"))?;
        Ok(states
            .get(key)
            .copied()
            .unwrap_or(EffectExecutionState::NotStarted))
    }

    async fn record_started(&self, key: &String) -> Result<(), Self::Error> {
        let mut states = self
            .states
            .lock()
            .map_err(|e| format!("memory effect journal lock poisoned: {e}"))?;
        if matches!(states.get(key), Some(EffectExecutionState::Completed)) {
            return Ok(());
        }
        states.insert(key.clone(), EffectExecutionState::Started);
        Ok(())
    }

    async fn record_completed(&self, key: &String) -> Result<(), Self::Error> {
        let mut states = self
            .states
            .lock()
            .map_err(|e| format!("memory effect journal lock poisoned: {e}"))?;
        states.insert(key.clone(), EffectExecutionState::Completed);
        Ok(())
    }

    async fn record_retryable(&self, key: &String) -> Result<(), Self::Error> {
        let mut states = self
            .states
            .lock()
            .map_err(|e| format!("memory effect journal lock poisoned: {e}"))?;
        match states.get(key) {
            Some(EffectExecutionState::Started | EffectExecutionState::Unknown) => {
                states.remove(key);
                Ok(())
            },
            Some(EffectExecutionState::Completed) => Err(format!(
                "cannot mark effect retryable for completed key '{key}'"
            )),
            _ => Err(format!(
                "cannot mark effect retryable for unknown key '{key}'"
            )),
        }
    }

    async fn resolve_in_doubt(&self, key: &String) -> Result<InDoubtResolution, Self::Error> {
        let mut states = self
            .states
            .lock()
            .map_err(|e| format!("memory effect journal lock poisoned: {e}"))?;
        states.insert(key.clone(), EffectExecutionState::Unknown);
        Ok(InDoubtResolution::Deny {
            reason: "effect execution state is in-doubt; manual reconciliation required"
                .to_string(),
        })
    }
}
