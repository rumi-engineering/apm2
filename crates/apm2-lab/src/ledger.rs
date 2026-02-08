use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use apm2_core::crypto::{EventHasher, Hash, Signer};
use apm2_core::evidence::{ContentAddressedStore, MemoryCas};
use serde::{Deserialize, Serialize};

use crate::event::{EventKind, SignedEvent, hash_hex};

/// Cursor into the append-only lab ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cursor(pub usize);

impl Cursor {
    #[must_use]
    pub const fn start() -> Self {
        Self(0)
    }
}

/// In-memory append-only ledger with optional CAS for artifact references.
#[derive(Debug)]
pub struct LabLedger {
    events: Vec<SignedEvent>,
    cas: MemoryCas,
}

impl Default for LabLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl LabLedger {
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            cas: MemoryCas::new(),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    #[must_use]
    pub fn events(&self) -> &[SignedEvent] {
        &self.events
    }

    #[must_use]
    pub fn last_hash(&self) -> Hash {
        self.events
            .last()
            .map(|e| e.event_hash)
            .unwrap_or(EventHasher::GENESIS_PREV_HASH)
    }

    #[must_use]
    pub fn next_seq(&self) -> u64 {
        (self.events.len() as u64) + 1
    }

    pub fn append(
        &mut self,
        author_id: impl Into<String>,
        signer: &Signer,
        event: EventKind,
    ) -> Result<SignedEvent> {
        let seq = self.next_seq();
        let prev_hash = self.last_hash();
        let signed = SignedEvent::new(
            seq,
            author_id,
            signer,
            prev_hash,
            event,
            SignedEvent::now_ms(),
        )?;
        signed.verify()?;
        self.events.push(signed.clone());
        Ok(signed)
    }

    pub fn append_raw(&mut self, event: SignedEvent) -> Result<()> {
        let expected_seq = self.next_seq();
        if event.seq != expected_seq {
            return Err(anyhow!(
                "seq mismatch: expected {}, got {}",
                expected_seq,
                event.seq
            ));
        }
        let expected_prev = self.last_hash();
        if event.prev_hash != expected_prev {
            return Err(anyhow!(
                "prev_hash mismatch: expected {}, got {}",
                hash_hex(&expected_prev),
                hash_hex(&event.prev_hash)
            ));
        }
        event.verify()?;
        self.events.push(event);
        Ok(())
    }

    #[must_use]
    pub fn read_since(&self, cursor: Cursor) -> &[SignedEvent] {
        &self.events[cursor.0.min(self.events.len())..]
    }

    #[must_use]
    pub fn tail_cursor(&self) -> Cursor {
        Cursor(self.events.len())
    }

    #[must_use]
    pub fn render_for_prompt(&self, cursor: Cursor, max_events: usize) -> String {
        let events = self.read_since(cursor);
        if events.is_empty() {
            return "(no new events)".to_string();
        }

        let start = events.len().saturating_sub(max_events);
        events[start..]
            .iter()
            .map(|event| {
                serde_json::to_string(event).unwrap_or_else(|_| {
                    format!("{{\"seq\":{},\"error\":\"serialize\"}}", event.seq)
                })
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn dump_jsonl(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create parent dir for {}", path.display()))?;
        }

        let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
        let mut writer = BufWriter::new(file);
        for event in &self.events {
            let line = serde_json::to_string(event).context("serialize ledger event")?;
            writer
                .write_all(line.as_bytes())
                .with_context(|| format!("write {}", path.display()))?;
            writer
                .write_all(b"\n")
                .with_context(|| format!("write newline {}", path.display()))?;
        }
        writer
            .flush()
            .with_context(|| format!("flush {}", path.display()))?;
        Ok(())
    }

    pub fn load_jsonl(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let reader = BufReader::new(file);

        let mut ledger = Self::new();
        for (line_no, line) in reader.lines().enumerate() {
            let line = line.with_context(|| format!("read line {}", line_no + 1))?;
            if line.trim().is_empty() {
                continue;
            }
            let event: SignedEvent = serde_json::from_str(&line)
                .with_context(|| format!("parse line {}", line_no + 1))?;
            ledger
                .append_raw(event)
                .with_context(|| format!("append line {}", line_no + 1))?;
        }

        Ok(ledger)
    }

    pub fn store_artifact(&self, content: &[u8]) -> Result<Hash> {
        let result = self.cas.store(content).context("store artifact in cas")?;
        Ok(result.hash)
    }

    pub fn retrieve_artifact(&self, hash: &Hash) -> Result<Vec<u8>> {
        self.cas
            .retrieve(hash)
            .with_context(|| format!("retrieve artifact {}", hash_hex(hash)))
    }
}

#[cfg(test)]
mod tests {
    use apm2_core::crypto::Signer;

    use super::LabLedger;
    use crate::event::{EventKind, WorkType};

    #[test]
    fn append_and_reload_round_trip() {
        let signer = Signer::generate();
        let mut ledger = LabLedger::new();
        ledger
            .append(
                "world",
                &signer,
                EventKind::WorkOpened {
                    work_id: "w-001".to_string(),
                    work_type: WorkType::Analyze,
                    value: 1.0,
                    description: "demo".to_string(),
                },
            )
            .expect("append event");

        let temp = tempfile::NamedTempFile::new().expect("temp file");
        ledger.dump_jsonl(temp.path()).expect("dump");
        let reloaded = LabLedger::load_jsonl(temp.path()).expect("load");

        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded.events()[0].seq, 1);
    }
}
