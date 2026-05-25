use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReportDraft {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub program_handle: String,
    pub title: String,
    pub vulnerability_information: String,
    pub weakness_id: Option<u64>,
    pub severity_rating: Option<String>,
    pub impact: Option<String>,
    pub structured_scope_id: Option<u64>,
    pub cvss_vector: Option<String>,
}

fn drafts_dir() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .context("cannot find config dir")?
        .join("h1mcp")
        .join("drafts");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn draft_path(id: &str) -> Result<PathBuf> {
    Ok(drafts_dir()?.join(format!("{id}.json")))
}

pub fn save(draft: &ReportDraft) -> Result<()> {
    let path = draft_path(&draft.id)?;
    let json = serde_json::to_string_pretty(draft)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn load(id: &str) -> Result<ReportDraft> {
    let path = draft_path(id)?;
    let json = std::fs::read_to_string(&path)
        .with_context(|| format!("draft '{id}' not found"))?;
    Ok(serde_json::from_str(&json)?)
}

pub fn list_all() -> Result<Vec<ReportDraft>> {
    let dir = drafts_dir()?;
    let mut drafts = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|e| e.to_str()) == Some("json") {
            if let Ok(json) = std::fs::read_to_string(entry.path()) {
                if let Ok(d) = serde_json::from_str::<ReportDraft>(&json) {
                    drafts.push(d);
                }
            }
        }
    }
    drafts.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    Ok(drafts)
}

pub fn delete(id: &str) -> Result<()> {
    let path = draft_path(id)?;
    std::fs::remove_file(&path)
        .with_context(|| format!("draft '{id}' not found"))?;
    Ok(())
}

pub fn create(
    program_handle: String,
    title: String,
    vulnerability_information: String,
    weakness_id: Option<u64>,
    severity_rating: Option<String>,
    impact: Option<String>,
    structured_scope_id: Option<u64>,
    cvss_vector: Option<String>,
) -> ReportDraft {
    let now = Utc::now();
    ReportDraft {
        id: Uuid::new_v4().to_string(),
        created_at: now,
        updated_at: now,
        program_handle,
        title,
        vulnerability_information,
        weakness_id,
        severity_rating,
        impact,
        structured_scope_id,
        cvss_vector,
    }
}

pub fn to_h1_payload(draft: &ReportDraft) -> serde_json::Value {
    let mut attrs = serde_json::json!({
        "team_handle": draft.program_handle,
        "title": draft.title,
        "vulnerability_information": draft.vulnerability_information,
    });
    if let Some(wid) = draft.weakness_id {
        attrs["weakness_id"] = wid.into();
    }
    if let Some(ref s) = draft.severity_rating {
        attrs["severity_rating"] = s.clone().into();
    }
    if let Some(ref i) = draft.impact {
        attrs["impact"] = i.clone().into();
    }
    if let Some(sid) = draft.structured_scope_id {
        attrs["structured_scope_id"] = sid.into();
    }
    serde_json::json!({
        "data": {
            "type": "report",
            "attributes": attrs
        }
    })
}
