use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::closure::CompositeView;

#[derive(Debug, Clone)]
pub struct PromptPaths {
    pub system_prompt_files: BTreeMap<String, PathBuf>,
}

pub fn write_system_prompts(
    agents: &BTreeMap<String, crate::spec::AgentSpec>,
    lab_dir: impl AsRef<Path>,
) -> Result<PromptPaths> {
    let lab_dir = lab_dir.as_ref();
    fs::create_dir_all(lab_dir)
        .with_context(|| format!("create lab prompt dir {}", lab_dir.display()))?;

    let mut files = BTreeMap::new();
    for (agent_id, agent) in agents {
        let file_name = format!("agent_{}_system.md", agent_id);
        let path = lab_dir.join(file_name);
        let content = render_system_prompt(agent_id, &agent.domain, &agent.description);
        fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
        files.insert(agent_id.clone(), path);
    }

    Ok(PromptPaths {
        system_prompt_files: files,
    })
}

fn render_system_prompt(agent_id: &str, domain: &str, description: &str) -> String {
    format!(
        "You are agent {agent_id}.\n\
Domain: {domain}.\n\
Strength: {description}.\n\
Protocol: each turn you observe new ledger events and choose exactly ONE action.\n\
Goal: maximize total admitted work value while minimizing token usage and failures.\n\
Constraints: work requires independent verification; budgets are finite; act fail-closed.\n\
Return exactly one JSON object with one of:\n\
{{\"action\":\"claim\",\"work_id\":\"...\"}}\n\
{{\"action\":\"submit\",\"work_id\":\"...\",\"solution\":\"...\"}}\n\
{{\"action\":\"verify\",\"work_id\":\"...\",\"verdict\":\"pass|fail\",\"reasoning\":\"...\"}}\n\
{{\"action\":\"propose_formation\",\"partner_ids\":[\"...\"],\"rationale\":\"...\"}}\n\
{{\"action\":\"attest_formation\",\"composite_id\":\"...\",\"approve\":true|false,\"rationale\":\"...\"}}\n\
{{\"action\":\"delegate\",\"work_id\":\"...\",\"delegate_to\":\"...\",\"sub_task\":\"...\"}}\n\
{{\"action\":\"pass\"}}\n\
No markdown, no prose before or after JSON."
    )
}

pub fn build_tick_prompt(
    tick: u64,
    agent_id: &str,
    budget_remaining: u64,
    ledger_updates: &str,
    open_work: &[String],
    composite: Option<&CompositeView>,
) -> String {
    let composite_note = if let Some(comp) = composite {
        format!(
            "You are in composite {} with members [{}]. Delegation is available.\n",
            comp.composite_id,
            comp.members.join(",")
        )
    } else {
        "No active composite membership.\n".to_string()
    };

    let open_work_lines = if open_work.is_empty() {
        "(none)".to_string()
    } else {
        open_work.join("\n")
    };

    format!(
        "Tick: {tick}\n\
Agent: {agent_id}\n\
Budget remaining (tokens): {budget_remaining}\n\
{composite_note}\n\
Open work items:\n{open_work_lines}\n\
New ledger events (JSONL):\n{ledger_updates}\n\
Choose exactly one valid action JSON object now."
    )
}
