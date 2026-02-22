//! Observe -> Plan -> Execute -> Receipt loop driver.

use std::fmt::Display;

use crate::orchestrator_kernel::effect_journal::{
    EffectExecutionState, EffectJournal, InDoubtResolution,
};
use crate::orchestrator_kernel::intent_store::IntentStore;
use crate::orchestrator_kernel::ledger_tailer::{
    CursorEvent, CursorStore, LedgerReader, advance_cursor_with_event, sort_and_truncate_events,
};
use crate::orchestrator_kernel::types::{ExecutionOutcome, TickConfig, TickReport};

/// Domain contract for orchestrator runtime loops.
///
/// Implementations should keep `apply_events` and `plan` deterministic and free
/// of external side effects. `execute` is the only phase that may dispatch
/// effects and must return outcomes that preserve fail-closed semantics.
#[allow(async_fn_in_trait)]
pub trait OrchestratorDomain<Event, Intent, IntentKey, Receipt>: Send {
    /// Domain-specific error type.
    type Error;

    /// Returns the stable intent key for idempotency and durable state
    /// tracking.
    fn intent_key(&self, intent: &Intent) -> IntentKey;

    /// Applies observed events deterministically into domain state.
    ///
    /// Contract: this fold must be replay-stable for identical ordered inputs.
    async fn apply_events(&mut self, events: &[Event]) -> Result<(), Self::Error>;

    /// Produces planned intents from current domain state.
    ///
    /// Contract: returned intents are treated as data and durably enqueued
    /// before any execute call in the same tick.
    async fn plan(&mut self) -> Result<Vec<Intent>, Self::Error>;

    /// Executes a single intent.
    ///
    /// Contract:
    /// - `Completed` means all externally-visible effects for this intent have
    ///   finished and any receipt payload is ready for durable persistence.
    /// - `Retry` may only be returned when no external side effect was
    ///   dispatched.
    /// - `Blocked` must be used for fail-closed non-retryable outcomes.
    async fn execute(&mut self, intent: &Intent) -> Result<ExecutionOutcome<Receipt>, Self::Error>;
}

/// Durable sink for receipt events.
#[allow(async_fn_in_trait)]
pub trait ReceiptWriter<Receipt>: Send + Sync {
    /// Writer-specific error type.
    type Error;

    /// Persists receipt events durably.
    ///
    /// Contract: successful return indicates receipts are durable enough for
    /// downstream replay recovery to treat them as committed.
    async fn persist_many(&self, receipts: &[Receipt]) -> Result<(), Self::Error>;
}

/// Kernel tick execution errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControllerLoopError {
    /// Cursor load failed.
    #[error("cursor load failed: {0}")]
    CursorLoad(String),
    /// Ledger observe failed.
    #[error("observe failed: {0}")]
    Observe(String),
    /// Event apply failed.
    #[error("apply failed: {0}")]
    Apply(String),
    /// Planning failed.
    #[error("plan failed: {0}")]
    Plan(String),
    /// Intent enqueue failed.
    #[error("intent enqueue failed: {0}")]
    Enqueue(String),
    /// Intent dequeue failed.
    #[error("intent dequeue failed: {0}")]
    Dequeue(String),
    /// Effect-state query failed.
    #[error("effect-state query failed: {0}")]
    EffectState(String),
    /// In-doubt resolution failed.
    #[error("in-doubt resolution failed: {0}")]
    ResolveInDoubt(String),
    /// Journal pre-effect record failed.
    #[error("record_started failed: {0}")]
    RecordStarted(String),
    /// Domain execute failed.
    #[error("execute failed: {0}")]
    Execute(String),
    /// Journal post-effect record failed.
    #[error("record_completed failed: {0}")]
    RecordCompleted(String),
    /// Journal retryable rollback failed.
    #[error("record_retryable failed: {0}")]
    RecordRetryable(String),
    /// Mark-done failed.
    #[error("mark_done failed: {0}")]
    MarkDone(String),
    /// Mark-blocked failed.
    #[error("mark_blocked failed: {0}")]
    MarkBlocked(String),
    /// Mark-retryable failed.
    #[error("mark_retryable failed: {0}")]
    MarkRetryable(String),
    /// Receipt persistence failed.
    #[error("receipt persistence failed: {0}")]
    PersistReceipts(String),
    /// Cursor save failed.
    #[error("cursor save failed: {0}")]
    CursorSave(String),
}

/// Runs a single bounded kernel tick.
///
/// Ordering invariants:
/// - Observe cursor is loaded first and only advanced after durable
///   plan/receipt steps complete.
/// - Intents are durably enqueued before any external Execute phase call.
/// - For completed intents, receipts are persisted before completion is
///   acknowledged in the effect journal and intent store.
/// - Cursor is not advanced if any durable phase fails.
#[allow(clippy::too_many_arguments)]
#[allow(
    clippy::too_many_lines,
    clippy::future_not_send,
    clippy::missing_errors_doc
)]
pub async fn run_tick<D, LR, CS, IS, EJ, RW, Event, Intent, IntentKey, Receipt>(
    domain: &mut D,
    ledger_reader: &LR,
    cursor_store: &CS,
    intent_store: &IS,
    effect_journal: &EJ,
    receipt_writer: &RW,
    config: TickConfig,
) -> Result<TickReport, ControllerLoopError>
where
    D: OrchestratorDomain<Event, Intent, IntentKey, Receipt>,
    D::Error: Display,
    LR: LedgerReader<Event>,
    LR::Error: Display,
    CS: CursorStore,
    CS::Error: Display,
    IS: IntentStore<Intent, IntentKey>,
    IS::Error: Display,
    EJ: EffectJournal<IntentKey>,
    EJ::Error: Display,
    RW: ReceiptWriter<Receipt>,
    RW::Error: Display,
    Event: CursorEvent,
    Intent: Clone,
    IntentKey: Clone,
{
    let mut report = TickReport::default();
    let cursor = cursor_store
        .load()
        .await
        .map_err(|e| ControllerLoopError::CursorLoad(e.to_string()))?;

    let observed = sort_and_truncate_events(
        ledger_reader
            .poll(&cursor, config.observe_limit)
            .await
            .map_err(|e| ControllerLoopError::Observe(e.to_string()))?,
        config.observe_limit,
    );
    report.observed_events = observed.len();

    domain
        .apply_events(&observed)
        .await
        .map_err(|e| ControllerLoopError::Apply(e.to_string()))?;

    let planned = domain
        .plan()
        .await
        .map_err(|e| ControllerLoopError::Plan(e.to_string()))?;
    report.planned_intents = planned.len();

    if !planned.is_empty() {
        report.enqueued_intents = intent_store
            .enqueue_many(&planned)
            .await
            .map_err(|e| ControllerLoopError::Enqueue(e.to_string()))?;
    }

    let dequeued = intent_store
        .dequeue_batch(config.execute_limit)
        .await
        .map_err(|e| ControllerLoopError::Dequeue(e.to_string()))?;
    report.dequeued_intents = dequeued.len();

    for intent in &dequeued {
        let key = domain.intent_key(intent);
        let state = effect_journal
            .query_state(&key)
            .await
            .map_err(|e| ControllerLoopError::EffectState(e.to_string()))?;

        match state {
            EffectExecutionState::Completed => {
                intent_store
                    .mark_done(&key)
                    .await
                    .map_err(|e| ControllerLoopError::MarkDone(e.to_string()))?;
                report.skipped_completed_intents =
                    report.skipped_completed_intents.saturating_add(1);
                continue;
            },
            EffectExecutionState::Started => {
                intent_store
                    .mark_blocked(
                        &key,
                        "effect state is started; explicit operator reconciliation required",
                    )
                    .await
                    .map_err(|e| ControllerLoopError::MarkBlocked(e.to_string()))?;
                report.blocked_intents = report.blocked_intents.saturating_add(1);
                continue;
            },
            EffectExecutionState::Unknown => {
                let resolution = effect_journal
                    .resolve_in_doubt(&key)
                    .await
                    .map_err(|e| ControllerLoopError::ResolveInDoubt(e.to_string()))?;
                match resolution {
                    InDoubtResolution::Deny { reason } => {
                        intent_store
                            .mark_blocked(&key, &reason)
                            .await
                            .map_err(|e| ControllerLoopError::MarkBlocked(e.to_string()))?;
                        report.blocked_intents = report.blocked_intents.saturating_add(1);
                        continue;
                    },
                    InDoubtResolution::AllowReExecution => {},
                }
            },
            EffectExecutionState::NotStarted => {},
        }

        effect_journal
            .record_started(&key)
            .await
            .map_err(|e| ControllerLoopError::RecordStarted(e.to_string()))?;

        report.executed_intents = report.executed_intents.saturating_add(1);
        match domain.execute(intent).await {
            Ok(ExecutionOutcome::Completed {
                receipts: intent_receipts,
            }) => {
                if !intent_receipts.is_empty() {
                    receipt_writer
                        .persist_many(&intent_receipts)
                        .await
                        .map_err(|e| ControllerLoopError::PersistReceipts(e.to_string()))?;
                    report.persisted_receipts = report
                        .persisted_receipts
                        .saturating_add(intent_receipts.len());
                }
                effect_journal
                    .record_completed(&key)
                    .await
                    .map_err(|e| ControllerLoopError::RecordCompleted(e.to_string()))?;
                intent_store
                    .mark_done(&key)
                    .await
                    .map_err(|e| ControllerLoopError::MarkDone(e.to_string()))?;
                report.completed_intents = report.completed_intents.saturating_add(1);
            },
            Ok(ExecutionOutcome::Blocked { reason }) => {
                intent_store
                    .mark_blocked(&key, &reason)
                    .await
                    .map_err(|e| ControllerLoopError::MarkBlocked(e.to_string()))?;
                report.blocked_intents = report.blocked_intents.saturating_add(1);
            },
            Ok(ExecutionOutcome::Retry { reason }) => {
                effect_journal
                    .record_retryable(&key)
                    .await
                    .map_err(|e| ControllerLoopError::RecordRetryable(e.to_string()))?;
                intent_store
                    .mark_retryable(&key, &reason)
                    .await
                    .map_err(|e| ControllerLoopError::MarkRetryable(e.to_string()))?;
                report.retryable_intents = report.retryable_intents.saturating_add(1);
            },
            Err(e) => {
                intent_store
                    .mark_blocked(&key, &format!("execute error: {e}"))
                    .await
                    .map_err(|err| ControllerLoopError::MarkBlocked(err.to_string()))?;
                return Err(ControllerLoopError::Execute(e.to_string()));
            },
        }
    }

    if let Some(last) = observed.last() {
        let next_cursor = advance_cursor_with_event(&cursor, last);
        cursor_store
            .save(&next_cursor)
            .await
            .map_err(|e| ControllerLoopError::CursorSave(e.to_string()))?;
        report.cursor_advanced = true;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::orchestrator_kernel::effect_journal::{EffectExecutionState, InDoubtResolution};
    use crate::orchestrator_kernel::types::CompositeCursor;

    #[derive(Debug, Clone)]
    struct TestEvent {
        ts: u64,
        id: String,
    }

    impl CursorEvent for TestEvent {
        fn timestamp_ns(&self) -> u64 {
            self.ts
        }

        fn event_id(&self) -> &str {
            &self.id
        }
    }

    #[derive(Debug, Default)]
    struct TestLedgerReader {
        events: Vec<TestEvent>,
    }

    impl LedgerReader<TestEvent> for TestLedgerReader {
        type Error = String;

        async fn poll(
            &self,
            _cursor: &CompositeCursor,
            limit: usize,
        ) -> Result<Vec<TestEvent>, Self::Error> {
            Ok(self.events.iter().take(limit).cloned().collect())
        }
    }

    #[derive(Debug, Default)]
    struct TestCursorStore {
        cursor: Mutex<CompositeCursor>,
    }

    impl CursorStore for TestCursorStore {
        type Error = String;

        async fn load(&self) -> Result<CompositeCursor, Self::Error> {
            Ok(self.cursor.lock().map_err(|e| e.to_string())?.clone())
        }

        async fn save(&self, cursor: &CompositeCursor) -> Result<(), Self::Error> {
            let mut guard = self.cursor.lock().map_err(|e| e.to_string())?;
            *guard = cursor.clone();
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct TestIntentStore {
        pending: Mutex<VecDeque<String>>,
        done: Mutex<Vec<String>>,
        blocked: Mutex<Vec<(String, String)>>,
        retryable: Mutex<Vec<(String, String)>>,
    }

    impl IntentStore<String, String> for TestIntentStore {
        type Error = String;

        async fn enqueue_many(&self, intents: &[String]) -> Result<usize, Self::Error> {
            let mut pending = self.pending.lock().map_err(|e| e.to_string())?;
            let mut inserted = 0usize;
            for intent in intents {
                if !pending.contains(intent) {
                    pending.push_back(intent.clone());
                    inserted = inserted.saturating_add(1);
                }
            }
            Ok(inserted)
        }

        async fn dequeue_batch(&self, limit: usize) -> Result<Vec<String>, Self::Error> {
            let mut pending = self.pending.lock().map_err(|e| e.to_string())?;
            let mut out = Vec::new();
            for _ in 0..limit {
                let Some(next) = pending.pop_front() else {
                    break;
                };
                out.push(next);
            }
            Ok(out)
        }

        async fn mark_done(&self, key: &String) -> Result<(), Self::Error> {
            self.done
                .lock()
                .map_err(|e| e.to_string())?
                .push(key.clone());
            Ok(())
        }

        async fn mark_blocked(&self, key: &String, reason: &str) -> Result<(), Self::Error> {
            self.blocked
                .lock()
                .map_err(|e| e.to_string())?
                .push((key.clone(), reason.to_string()));
            Ok(())
        }

        async fn mark_retryable(&self, key: &String, reason: &str) -> Result<(), Self::Error> {
            let mut pending = self.pending.lock().map_err(|e| e.to_string())?;
            if !pending.contains(key) {
                pending.push_back(key.clone());
            }
            self.retryable
                .lock()
                .map_err(|e| e.to_string())?
                .push((key.clone(), reason.to_string()));
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct TestJournal {
        states: Mutex<HashMap<String, EffectExecutionState>>,
        unknown_deny: bool,
    }

    impl EffectJournal<String> for TestJournal {
        type Error = String;

        async fn query_state(&self, key: &String) -> Result<EffectExecutionState, Self::Error> {
            Ok(*self
                .states
                .lock()
                .map_err(|e| e.to_string())?
                .get(key)
                .unwrap_or(&EffectExecutionState::NotStarted))
        }

        async fn record_started(&self, key: &String) -> Result<(), Self::Error> {
            self.states
                .lock()
                .map_err(|e| e.to_string())?
                .insert(key.clone(), EffectExecutionState::Started);
            Ok(())
        }

        async fn record_completed(&self, key: &String) -> Result<(), Self::Error> {
            self.states
                .lock()
                .map_err(|e| e.to_string())?
                .insert(key.clone(), EffectExecutionState::Completed);
            Ok(())
        }

        async fn record_retryable(&self, key: &String) -> Result<(), Self::Error> {
            self.states
                .lock()
                .map_err(|e| e.to_string())?
                .insert(key.clone(), EffectExecutionState::NotStarted);
            Ok(())
        }

        async fn resolve_in_doubt(&self, _key: &String) -> Result<InDoubtResolution, Self::Error> {
            if self.unknown_deny {
                Ok(InDoubtResolution::Deny {
                    reason: "deny unknown in test".to_string(),
                })
            } else {
                Ok(InDoubtResolution::AllowReExecution)
            }
        }
    }

    #[derive(Debug, Default)]
    struct TestReceiptWriter {
        receipts: Mutex<Vec<String>>,
    }

    impl ReceiptWriter<String> for TestReceiptWriter {
        type Error = String;

        async fn persist_many(&self, receipts: &[String]) -> Result<(), Self::Error> {
            self.receipts
                .lock()
                .map_err(|e| e.to_string())?
                .extend_from_slice(receipts);
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FailingReceiptWriter;

    impl ReceiptWriter<String> for FailingReceiptWriter {
        type Error = String;

        async fn persist_many(&self, _receipts: &[String]) -> Result<(), Self::Error> {
            Err("forced receipt persistence failure".to_string())
        }
    }

    #[derive(Debug, Default)]
    struct TestDomain;

    impl OrchestratorDomain<TestEvent, String, String, String> for TestDomain {
        type Error = String;

        fn intent_key(&self, intent: &String) -> String {
            intent.clone()
        }

        async fn apply_events(&mut self, _events: &[TestEvent]) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn plan(&mut self) -> Result<Vec<String>, Self::Error> {
            Ok(vec![
                "intent-a".to_string(),
                "intent-b".to_string(),
                "intent-c".to_string(),
            ])
        }

        async fn execute(
            &mut self,
            intent: &String,
        ) -> Result<ExecutionOutcome<String>, Self::Error> {
            Ok(ExecutionOutcome::Completed {
                receipts: vec![format!("receipt-{intent}")],
            })
        }
    }

    #[derive(Debug, Default)]
    struct NoPlanDomain;

    impl OrchestratorDomain<TestEvent, String, String, String> for NoPlanDomain {
        type Error = String;

        fn intent_key(&self, intent: &String) -> String {
            intent.clone()
        }

        async fn apply_events(&mut self, _events: &[TestEvent]) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn plan(&mut self) -> Result<Vec<String>, Self::Error> {
            Ok(Vec::new())
        }

        async fn execute(
            &mut self,
            intent: &String,
        ) -> Result<ExecutionOutcome<String>, Self::Error> {
            Ok(ExecutionOutcome::Completed {
                receipts: vec![format!("receipt-{intent}")],
            })
        }
    }

    #[derive(Debug, Default)]
    struct RetryThenCompleteDomain {
        attempts: HashMap<String, usize>,
    }

    impl OrchestratorDomain<TestEvent, String, String, String> for RetryThenCompleteDomain {
        type Error = String;

        fn intent_key(&self, intent: &String) -> String {
            intent.clone()
        }

        async fn apply_events(&mut self, _events: &[TestEvent]) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn plan(&mut self) -> Result<Vec<String>, Self::Error> {
            Ok(Vec::new())
        }

        async fn execute(
            &mut self,
            intent: &String,
        ) -> Result<ExecutionOutcome<String>, Self::Error> {
            let attempt = self.attempts.entry(intent.clone()).or_insert(0);
            *attempt = attempt.saturating_add(1);
            if *attempt == 1 {
                Ok(ExecutionOutcome::Retry {
                    reason: "retry for test".to_string(),
                })
            } else {
                Ok(ExecutionOutcome::Completed {
                    receipts: vec![format!("receipt-{intent}")],
                })
            }
        }
    }

    #[derive(Debug, Default)]
    struct PersistentIntentStore {
        order: Mutex<Vec<String>>,
        states: Mutex<HashMap<String, String>>,
        blocked: Mutex<HashMap<String, String>>,
    }

    impl IntentStore<String, String> for PersistentIntentStore {
        type Error = String;

        async fn enqueue_many(&self, intents: &[String]) -> Result<usize, Self::Error> {
            let mut order = self.order.lock().map_err(|e| e.to_string())?;
            let mut states = self.states.lock().map_err(|e| e.to_string())?;
            let mut inserted = 0usize;
            for intent in intents {
                if states.contains_key(intent) {
                    continue;
                }
                states.insert(intent.clone(), "pending".to_string());
                order.push(intent.clone());
                inserted = inserted.saturating_add(1);
            }
            Ok(inserted)
        }

        async fn dequeue_batch(&self, limit: usize) -> Result<Vec<String>, Self::Error> {
            let order = self.order.lock().map_err(|e| e.to_string())?;
            let states = self.states.lock().map_err(|e| e.to_string())?;
            Ok(order
                .iter()
                .filter(|key| states.get(*key).is_some_and(|state| state == "pending"))
                .take(limit)
                .cloned()
                .collect())
        }

        async fn mark_done(&self, key: &String) -> Result<(), Self::Error> {
            self.states
                .lock()
                .map_err(|e| e.to_string())?
                .insert(key.clone(), "done".to_string());
            Ok(())
        }

        async fn mark_blocked(&self, key: &String, reason: &str) -> Result<(), Self::Error> {
            self.states
                .lock()
                .map_err(|e| e.to_string())?
                .insert(key.clone(), "blocked".to_string());
            self.blocked
                .lock()
                .map_err(|e| e.to_string())?
                .insert(key.clone(), reason.to_string());
            Ok(())
        }

        async fn mark_retryable(&self, key: &String, reason: &str) -> Result<(), Self::Error> {
            self.states
                .lock()
                .map_err(|e| e.to_string())?
                .insert(key.clone(), "pending".to_string());
            self.blocked
                .lock()
                .map_err(|e| e.to_string())?
                .insert(key.clone(), reason.to_string());
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct RestartableJournal {
        states: Mutex<HashMap<String, EffectExecutionState>>,
        simulate_restart: Mutex<bool>,
        allow_reexecution: Mutex<bool>,
    }

    impl RestartableJournal {
        fn set_simulate_restart(&self, value: bool) {
            if let Ok(mut guard) = self.simulate_restart.lock() {
                *guard = value;
            }
        }

        fn set_allow_reexecution(&self, value: bool) {
            if let Ok(mut guard) = self.allow_reexecution.lock() {
                *guard = value;
            }
        }
    }

    impl EffectJournal<String> for RestartableJournal {
        type Error = String;

        async fn query_state(&self, key: &String) -> Result<EffectExecutionState, Self::Error> {
            let state = *self
                .states
                .lock()
                .map_err(|e| e.to_string())?
                .get(key)
                .unwrap_or(&EffectExecutionState::NotStarted);
            let restart = *self.simulate_restart.lock().map_err(|e| e.to_string())?;
            if restart && state == EffectExecutionState::Started {
                Ok(EffectExecutionState::Unknown)
            } else {
                Ok(state)
            }
        }

        async fn record_started(&self, key: &String) -> Result<(), Self::Error> {
            self.states
                .lock()
                .map_err(|e| e.to_string())?
                .insert(key.clone(), EffectExecutionState::Started);
            Ok(())
        }

        async fn record_completed(&self, key: &String) -> Result<(), Self::Error> {
            self.states
                .lock()
                .map_err(|e| e.to_string())?
                .insert(key.clone(), EffectExecutionState::Completed);
            Ok(())
        }

        async fn record_retryable(&self, key: &String) -> Result<(), Self::Error> {
            self.states
                .lock()
                .map_err(|e| e.to_string())?
                .insert(key.clone(), EffectExecutionState::NotStarted);
            Ok(())
        }

        async fn resolve_in_doubt(&self, key: &String) -> Result<InDoubtResolution, Self::Error> {
            let allow = *self.allow_reexecution.lock().map_err(|e| e.to_string())?;
            if allow {
                self.states
                    .lock()
                    .map_err(|e| e.to_string())?
                    .insert(key.clone(), EffectExecutionState::NotStarted);
                Ok(InDoubtResolution::AllowReExecution)
            } else {
                Ok(InDoubtResolution::Deny {
                    reason: "deny unknown after restart in test".to_string(),
                })
            }
        }
    }

    #[derive(Debug, Default)]
    struct FailOnceReceiptWriter {
        fail_next: Mutex<bool>,
        receipts: Mutex<Vec<String>>,
    }

    impl FailOnceReceiptWriter {
        fn new_fail_once() -> Self {
            Self {
                fail_next: Mutex::new(true),
                receipts: Mutex::new(Vec::new()),
            }
        }
    }

    impl ReceiptWriter<String> for FailOnceReceiptWriter {
        type Error = String;

        async fn persist_many(&self, receipts: &[String]) -> Result<(), Self::Error> {
            let mut fail_next = self.fail_next.lock().map_err(|e| e.to_string())?;
            if *fail_next {
                *fail_next = false;
                return Err("forced fail-once receipt persistence error".to_string());
            }
            drop(fail_next);
            self.receipts
                .lock()
                .map_err(|e| e.to_string())?
                .extend_from_slice(receipts);
            Ok(())
        }
    }

    #[derive(Debug, Clone, Default)]
    struct CursorAwareLedgerReader {
        events: Vec<TestEvent>,
    }

    impl LedgerReader<TestEvent> for CursorAwareLedgerReader {
        type Error = String;

        async fn poll(
            &self,
            cursor: &CompositeCursor,
            limit: usize,
        ) -> Result<Vec<TestEvent>, Self::Error> {
            let mut out: Vec<TestEvent> = self
                .events
                .iter()
                .filter(|event| {
                    event.ts > cursor.timestamp_ns
                        || (event.ts == cursor.timestamp_ns
                            && event.id.as_str() > cursor.event_id.as_str())
                })
                .cloned()
                .collect();
            out.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.id.cmp(&b.id)));
            out.truncate(limit);
            Ok(out)
        }
    }

    #[derive(Debug, Default)]
    struct DeterministicReplayDomain {
        seen: HashSet<String>,
        pending: VecDeque<String>,
        applied_order: Vec<String>,
        executed_order: Vec<String>,
    }

    impl OrchestratorDomain<TestEvent, String, String, String> for DeterministicReplayDomain {
        type Error = String;

        fn intent_key(&self, intent: &String) -> String {
            intent.clone()
        }

        async fn apply_events(&mut self, events: &[TestEvent]) -> Result<(), Self::Error> {
            for event in events {
                if self.seen.insert(event.id.clone()) {
                    self.applied_order.push(event.id.clone());
                    self.pending.push_back(event.id.clone());
                }
            }
            Ok(())
        }

        async fn plan(&mut self) -> Result<Vec<String>, Self::Error> {
            Ok(self.pending.drain(..).collect())
        }

        async fn execute(
            &mut self,
            intent: &String,
        ) -> Result<ExecutionOutcome<String>, Self::Error> {
            self.executed_order.push(intent.clone());
            Ok(ExecutionOutcome::Completed {
                receipts: vec![format!("receipt-{intent}")],
            })
        }
    }

    #[derive(Debug, Default)]
    struct CountingNoPlanDomain {
        executions: usize,
    }

    impl OrchestratorDomain<TestEvent, String, String, String> for CountingNoPlanDomain {
        type Error = String;

        fn intent_key(&self, intent: &String) -> String {
            intent.clone()
        }

        async fn apply_events(&mut self, _events: &[TestEvent]) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn plan(&mut self) -> Result<Vec<String>, Self::Error> {
            Ok(Vec::new())
        }

        async fn execute(
            &mut self,
            intent: &String,
        ) -> Result<ExecutionOutcome<String>, Self::Error> {
            self.executions = self.executions.saturating_add(1);
            Ok(ExecutionOutcome::Completed {
                receipts: vec![format!("receipt-{intent}")],
            })
        }
    }

    #[tokio::test]
    async fn run_tick_enforces_execute_limit() {
        let mut domain = TestDomain;
        let ledger = TestLedgerReader {
            events: vec![
                TestEvent {
                    ts: 10,
                    id: "a".to_string(),
                },
                TestEvent {
                    ts: 10,
                    id: "b".to_string(),
                },
            ],
        };
        let cursor_store = TestCursorStore::default();
        let intent_store = Arc::new(TestIntentStore::default());
        let journal = TestJournal::default();
        let receipts = TestReceiptWriter::default();

        let report = run_tick(
            &mut domain,
            &ledger,
            &cursor_store,
            intent_store.as_ref(),
            &journal,
            &receipts,
            TickConfig {
                observe_limit: 8,
                execute_limit: 2,
            },
        )
        .await
        .expect("tick should succeed");

        assert_eq!(report.dequeued_intents, 2);
        assert_eq!(report.completed_intents, 2);
        assert_eq!(report.persisted_receipts, 2);
        assert!(report.cursor_advanced);
    }

    #[tokio::test]
    async fn run_tick_blocks_unknown_without_resolution() {
        let mut domain = NoPlanDomain;
        let ledger = TestLedgerReader::default();
        let cursor_store = TestCursorStore::default();
        let intent_store = TestIntentStore::default();
        let journal = TestJournal {
            states: Mutex::new(HashMap::from([(
                "intent-a".to_string(),
                EffectExecutionState::Unknown,
            )])),
            unknown_deny: true,
        };
        let receipts = TestReceiptWriter::default();

        intent_store
            .enqueue_many(&["intent-a".to_string()])
            .await
            .expect("enqueue should succeed");

        let report = run_tick(
            &mut domain,
            &ledger,
            &cursor_store,
            &intent_store,
            &journal,
            &receipts,
            TickConfig {
                observe_limit: 0,
                execute_limit: 4,
            },
        )
        .await
        .expect("tick should succeed");

        assert_eq!(report.blocked_intents, 1);
        assert_eq!(report.completed_intents, 0);
        assert_eq!(report.persisted_receipts, 0);
    }

    #[tokio::test]
    async fn run_tick_requeues_retry_outcomes() {
        let mut domain = RetryThenCompleteDomain::default();
        let ledger = TestLedgerReader::default();
        let cursor_store = TestCursorStore::default();
        let intent_store = TestIntentStore::default();
        let journal = TestJournal::default();
        let receipts = TestReceiptWriter::default();

        intent_store
            .enqueue_many(&["intent-a".to_string()])
            .await
            .expect("enqueue should succeed");

        let first_report = run_tick(
            &mut domain,
            &ledger,
            &cursor_store,
            &intent_store,
            &journal,
            &receipts,
            TickConfig {
                observe_limit: 0,
                execute_limit: 1,
            },
        )
        .await
        .expect("first tick should succeed");

        assert_eq!(first_report.retryable_intents, 1);
        assert_eq!(first_report.blocked_intents, 0);
        assert_eq!(first_report.completed_intents, 0);
        assert_eq!(first_report.persisted_receipts, 0);
        {
            let retryable = intent_store
                .retryable
                .lock()
                .expect("retryable lock should not be poisoned");
            assert_eq!(retryable.len(), 1);
            assert_eq!(retryable[0].0, "intent-a");
        }
        {
            let blocked = intent_store
                .blocked
                .lock()
                .expect("blocked lock should not be poisoned");
            assert!(blocked.is_empty());
        }
        {
            let first_receipts = receipts
                .receipts
                .lock()
                .expect("first receipts lock should not be poisoned");
            assert!(first_receipts.is_empty());
        }

        let second_report = run_tick(
            &mut domain,
            &ledger,
            &cursor_store,
            &intent_store,
            &journal,
            &receipts,
            TickConfig {
                observe_limit: 0,
                execute_limit: 1,
            },
        )
        .await
        .expect("second tick should succeed");

        assert_eq!(second_report.retryable_intents, 0);
        assert_eq!(second_report.completed_intents, 1);
        assert_eq!(second_report.persisted_receipts, 1);
        let second_receipts = receipts
            .receipts
            .lock()
            .expect("second receipts lock should not be poisoned");
        assert_eq!(
            second_receipts.as_slice(),
            &["receipt-intent-a".to_string()]
        );
    }

    #[tokio::test]
    async fn run_tick_does_not_mark_done_when_receipt_persistence_fails() {
        let mut domain = NoPlanDomain;
        let ledger = TestLedgerReader::default();
        let cursor_store = TestCursorStore::default();
        let intent_store = TestIntentStore::default();
        let journal = TestJournal::default();
        let receipts = FailingReceiptWriter;

        intent_store
            .enqueue_many(&["intent-a".to_string()])
            .await
            .expect("enqueue should succeed");

        let error = run_tick(
            &mut domain,
            &ledger,
            &cursor_store,
            &intent_store,
            &journal,
            &receipts,
            TickConfig {
                observe_limit: 0,
                execute_limit: 1,
            },
        )
        .await
        .expect_err("tick should fail when receipt persistence fails");

        assert!(matches!(error, ControllerLoopError::PersistReceipts(_)));
        let done = intent_store
            .done
            .lock()
            .expect("done lock should not be poisoned");
        assert!(done.is_empty());
    }

    #[tokio::test]
    async fn run_tick_replay_determinism_matches_full_replay_and_checkpoint_delta() {
        let events = vec![
            TestEvent {
                ts: 1,
                id: "event-a".to_string(),
            },
            TestEvent {
                ts: 1,
                id: "event-b".to_string(),
            },
            TestEvent {
                ts: 2,
                id: "event-c".to_string(),
            },
            TestEvent {
                ts: 3,
                id: "event-d".to_string(),
            },
        ];

        let mut full_domain = DeterministicReplayDomain::default();
        let full_ledger = CursorAwareLedgerReader {
            events: events.clone(),
        };
        let full_cursor = TestCursorStore::default();
        let full_intents = PersistentIntentStore::default();
        let full_journal = RestartableJournal::default();
        let full_receipts = TestReceiptWriter::default();

        let full_report = run_tick(
            &mut full_domain,
            &full_ledger,
            &full_cursor,
            &full_intents,
            &full_journal,
            &full_receipts,
            TickConfig {
                observe_limit: 16,
                execute_limit: 16,
            },
        )
        .await
        .expect("full replay tick should succeed");
        assert_eq!(full_report.completed_intents, 4);
        let full_applied = full_domain.applied_order.clone();
        let full_executed = full_domain.executed_order.clone();
        let full_receipt_rows = full_receipts
            .receipts
            .lock()
            .expect("full receipts lock should not be poisoned")
            .clone();

        let mut delta_domain = DeterministicReplayDomain::default();
        let delta_ledger = CursorAwareLedgerReader {
            events: events.clone(),
        };
        let delta_cursor = TestCursorStore::default();
        let delta_intents = PersistentIntentStore::default();
        let delta_journal = RestartableJournal::default();
        let delta_receipts = TestReceiptWriter::default();

        for _ in 0..3 {
            run_tick(
                &mut delta_domain,
                &delta_ledger,
                &delta_cursor,
                &delta_intents,
                &delta_journal,
                &delta_receipts,
                TickConfig {
                    observe_limit: 2,
                    execute_limit: 2,
                },
            )
            .await
            .expect("checkpoint+delta tick should succeed");
        }

        assert_eq!(delta_domain.applied_order, full_applied);
        assert_eq!(delta_domain.executed_order, full_executed);
        let delta_receipt_rows = delta_receipts
            .receipts
            .lock()
            .expect("delta receipts lock should not be poisoned")
            .clone();
        assert_eq!(delta_receipt_rows, full_receipt_rows);
    }

    #[tokio::test]
    async fn run_tick_crash_replay_fail_closed_prevents_duplicate_effects() {
        let mut domain = CountingNoPlanDomain::default();
        let ledger = CursorAwareLedgerReader::default();
        let cursor_store = TestCursorStore::default();
        let intent_store = PersistentIntentStore::default();
        let journal = RestartableJournal::default();
        let receipts = FailOnceReceiptWriter::new_fail_once();
        journal.set_allow_reexecution(false);

        intent_store
            .enqueue_many(&["intent-a".to_string()])
            .await
            .expect("enqueue should succeed");

        let first_error = run_tick(
            &mut domain,
            &ledger,
            &cursor_store,
            &intent_store,
            &journal,
            &receipts,
            TickConfig {
                observe_limit: 0,
                execute_limit: 1,
            },
        )
        .await
        .expect_err("first tick should fail on forced receipt persistence error");
        assert!(matches!(
            first_error,
            ControllerLoopError::PersistReceipts(_)
        ));
        assert_eq!(domain.executions, 1);

        journal.set_simulate_restart(true);
        let second_report = run_tick(
            &mut domain,
            &ledger,
            &cursor_store,
            &intent_store,
            &journal,
            &receipts,
            TickConfig {
                observe_limit: 0,
                execute_limit: 1,
            },
        )
        .await
        .expect("second tick should fail-closed block unknown effect");

        assert_eq!(second_report.blocked_intents, 1);
        assert_eq!(domain.executions, 1);
        let states = intent_store
            .states
            .lock()
            .expect("states lock should not be poisoned");
        assert_eq!(states.get("intent-a").map(String::as_str), Some("blocked"));
    }
}
