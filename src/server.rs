use anyhow::Result;
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    tool, tool_handler, tool_router,
};
use serde_json::Value;
use std::sync::Arc;

use crate::drafts;
use crate::h1_client::H1Client;
use crate::params::*;

/// Recursively drop nulls, empty containers, and known-noise keys to reduce the
/// token cost of tool output. Lossless for anything an LLM needs (absence of a
/// field reads the same as an explicit null).
fn prune(v: &Value) -> Value {
    const NOISE_KEYS: &[&str] = &["profile_picture"];
    match v {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, val) in map {
                if NOISE_KEYS.contains(&k.as_str()) || val.is_null() {
                    continue;
                }
                let pv = prune(val);
                let empty = matches!(&pv, Value::Array(a) if a.is_empty())
                    || matches!(&pv, Value::Object(o) if o.is_empty());
                if !empty {
                    out.insert(k.clone(), pv);
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(prune).collect()),
        _ => v.clone(),
    }
}

#[derive(Clone)]
pub struct H1Server {
    client: Arc<H1Client>,
    tool_router: ToolRouter<Self>,
}

impl H1Server {
    pub fn new(client: H1Client) -> Self {
        Self {
            client: Arc::new(client),
            tool_router: Self::tool_router(),
        }
    }

    // Token-efficient output: prune noise, then serialize compact (no pretty
    // whitespace). The result is consumed by an LLM, not a human, so dropping
    // null/empty fields and avatar URLs cuts input tokens with no real loss.
    fn ok(v: Value) -> String {
        serde_json::to_string(&prune(&v)).unwrap_or_else(|e| format!("serialize error: {e}"))
    }

    fn err(e: anyhow::Error) -> String {
        format!("Error: {e:#}")
    }
}

#[tool_router]
impl H1Server {
    // ── Report read ───────────────────────────────────────────────────────

    #[tool(description = "Search your submitted HackerOne reports. Filter by keyword, program, severity, or state.")]
    async fn search_reports(&self, Parameters(p): Parameters<SearchReportsParams>) -> String {
        match self.client.search_reports(
            p.keyword.as_deref(),
            p.program.as_deref(),
            p.severity.as_deref(),
            p.state.as_deref(),
            p.page_size,
            p.page_number,
            p.sort.as_deref(),
        ).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Get full details of a single HackerOne report by numeric ID.")]
    async fn get_report(&self, Parameters(p): Parameters<ReportIdParam>) -> String {
        match self.client.get_report(p.report_id).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Get a report bundled with its full triage conversation and activity timeline.")]
    async fn get_report_with_conversation(&self, Parameters(p): Parameters<ReportIdParam>) -> String {
        let (r, a) = tokio::join!(
            self.client.get_report(p.report_id),
            self.client.get_report_activities(p.report_id, Some(100)),
        );
        match (r, a) {
            (Ok(report), Ok(activities)) => Self::ok(serde_json::json!({
                "report": report,
                "activities": activities
            })),
            (Err(e), _) | (_, Err(e)) => Self::err(e),
        }
    }

    #[tool(description = "Get the activity timeline (comments, state changes, bounty awards) for a report. Note: the hacker API returns activities nested inside get_report; this standalone call uses the program API and needs a program-scoped token.")]
    async fn get_report_activities(&self, Parameters(p): Parameters<ReportActivitiesParam>) -> String {
        match self.client.get_report_activities(p.report_id, p.page_size).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    // ── Report write ──────────────────────────────────────────────────────

    #[tool(description = "Submit a vulnerability report directly to a HackerOne program. Prefer draft_report + submit_draft for review before submission.")]
    async fn submit_report(&self, Parameters(p): Parameters<SubmitReportParams>) -> String {
        let mut attrs = serde_json::json!({
            "team_handle": p.program_handle,
            "title": p.title,
            "vulnerability_information": p.vulnerability_information,
        });
        if let Some(wid) = p.weakness_id { attrs["weakness_id"] = wid.into(); }
        if let Some(ref s) = p.severity_rating { attrs["severity_rating"] = s.clone().into(); }
        if let Some(ref i) = p.impact { attrs["impact"] = i.clone().into(); }
        if let Some(sid) = p.structured_scope_id { attrs["structured_scope_id"] = sid.into(); }
        let body = serde_json::json!({ "data": { "type": "report", "attributes": attrs } });
        match self.client.submit_report(body).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Add a comment to a HackerOne report. Set internal=true for team-only notes. Requires a program-scoped API token (not part of the hacker API).")]
    async fn add_comment(&self, Parameters(p): Parameters<AddCommentParams>) -> String {
        match self.client.add_comment(p.report_id, &p.message, p.internal.unwrap_or(false)).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Close/withdraw a HackerOne report with an optional message. Requires a program-scoped API token (not part of the hacker API).")]
    async fn close_report(&self, Parameters(p): Parameters<CloseReportParams>) -> String {
        match self.client.close_report(p.report_id, &p.message).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Update the severity rating of a report. Rating: none, low, medium, high, critical. Requires a program-scoped API token (not part of the hacker API).")]
    async fn update_report_severity(&self, Parameters(p): Parameters<UpdateSeverityParams>) -> String {
        match self.client.update_severity(p.report_id, &p.rating, p.score).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Request public disclosure for a resolved report. Kind: 'full' (default) or 'limited'. Requires a program-scoped API token (not part of the hacker API).")]
    async fn request_disclosure(&self, Parameters(p): Parameters<RequestDisclosureParams>) -> String {
        let kind = p.kind.as_deref().unwrap_or("full");
        match self.client.request_disclosure(p.report_id, kind).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    // ── Report intents ────────────────────────────────────────────────────

    #[tool(description = "Create a report intent: send a free-text vulnerability description to a program and have HackerOne's assistant pre-validate it before filing a full report. The first step of assisted submission.")]
    async fn create_report_intent(&self, Parameters(p): Parameters<CreateReportIntentParams>) -> String {
        match self.client.create_report_intent(&p.program_handle, &p.description).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "List your report intents (assisted-submission drafts) and their assistant status.")]
    async fn list_report_intents(&self, Parameters(p): Parameters<PageSizeParam>) -> String {
        match self.client.list_report_intents(p.page_size).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Get a single report intent by ID, including the assistant_response and job status. Poll this after create_report_intent.")]
    async fn get_report_intent(&self, Parameters(p): Parameters<ReportIntentIdParam>) -> String {
        match self.client.get_report_intent(p.report_intent_id).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    // ── Programs ──────────────────────────────────────────────────────────

    #[tool(description = "List all HackerOne programs you have access to (auto-paginated).")]
    async fn list_programs(&self, Parameters(p): Parameters<ListProgramsParam>) -> String {
        match self.client.list_programs(p.page_size).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Get full details of a HackerOne program including bounty table, policy, and contact info.")]
    async fn get_program_details(&self, Parameters(p): Parameters<ProgramHandleParam>) -> String {
        match self.client.get_program(&p.program_handle).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Get in-scope assets for a program. Returns asset type, identifier, and bounty eligibility.")]
    async fn get_program_scope(&self, Parameters(p): Parameters<ProgramPageParam>) -> String {
        match self.client.get_program_scope(&p.program_handle, p.page_size).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Get accepted weakness types (CWE categories) for a program. Use to pick the correct weakness_id when submitting.")]
    async fn get_program_weaknesses(&self, Parameters(p): Parameters<ProgramPageParam>) -> String {
        match self.client.get_program_weaknesses(&p.program_handle, p.page_size).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Get everything needed to submit to a program in one call: submittable structured_scope_id options and accepted weakness_id options. Use before submit_report or draft_report.")]
    async fn get_submission_options(&self, Parameters(p): Parameters<ProgramHandleParam>) -> String {
        match self.client.get_submission_options(&p.program_handle).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    // ── Hacker profile ────────────────────────────────────────────────────

    #[tool(description = "Get your hacker identity (username, name, bio) derived from your reports. Note: the hacker API has no standalone profile endpoint, so reputation/signal/impact are not available and this returns nothing if you have no reports.")]
    async fn get_hacker_profile(&self) -> String {
        match self.client.get_profile().await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Get your current HackerOne balance.")]
    async fn get_balance(&self) -> String {
        match self.client.get_balance().await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Get your HackerOne earnings history.")]
    async fn get_earnings(&self, Parameters(p): Parameters<PageSizeParam>) -> String {
        match self.client.get_earnings(p.page_size).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    // ── Hacktivity ────────────────────────────────────────────────────────

    #[tool(description = "Search publicly disclosed HackerOne reports (hacktivity). Filter by keyword or program handle.")]
    async fn search_disclosed_reports(&self, Parameters(p): Parameters<SearchDisclosedParams>) -> String {
        match self.client.search_disclosed(p.query.as_deref(), p.program.as_deref(), p.page_size).await {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Analyze patterns across your recent reports: severity distribution, state breakdown, top programs.")]
    async fn analyze_report_patterns(&self, Parameters(p): Parameters<PageSizeParam>) -> String {
        match self.client.search_reports(None, None, None, None, p.page_size.or(Some(100)), None, None).await {
            Ok(v) => {
                let empty = vec![];
                let data = v["data"].as_array().unwrap_or(&empty);
                let mut by_severity = std::collections::HashMap::<String, usize>::new();
                let mut by_state = std::collections::HashMap::<String, usize>::new();
                let mut by_program = std::collections::HashMap::<String, usize>::new();
                for r in data {
                    let attrs = &r["attributes"];
                    *by_severity.entry(attrs["severity_rating"].as_str().unwrap_or("none").to_string()).or_default() += 1;
                    *by_state.entry(attrs["state"].as_str().unwrap_or("unknown").to_string()).or_default() += 1;
                    *by_program.entry(r["relationships"]["team"]["data"]["id"].as_str().unwrap_or("?").to_string()).or_default() += 1;
                }
                Self::ok(serde_json::json!({
                    "total_reports": data.len(),
                    "by_severity": by_severity,
                    "by_state": by_state,
                    "by_program": by_program,
                }))
            }
            Err(e) => Self::err(e),
        }
    }

    // ── Draft management (local storage, no H1 API call) ─────────────────

    #[tool(description = "Save a report draft locally without submitting. Returns a draft_id for later review and submission.")]
    async fn draft_report(&self, Parameters(p): Parameters<DraftCreateParams>) -> String {
        let draft = drafts::create(
            p.program_handle,
            p.title,
            p.vulnerability_information,
            p.weakness_id,
            p.severity_rating,
            p.impact,
            p.structured_scope_id,
            p.cvss_vector,
        );
        match drafts::save(&draft) {
            Ok(()) => Self::ok(serde_json::json!({
                "draft_id": draft.id,
                "message": "Draft saved. Review with get_draft, edit with update_draft, submit with submit_draft."
            })),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "List all saved local report drafts (not yet submitted to HackerOne).")]
    async fn list_drafts(&self) -> String {
        match drafts::list_all() {
            Ok(ds) => Self::ok(serde_json::json!({ "count": ds.len(), "drafts": ds })),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Get the full contents of a saved draft by draft_id.")]
    async fn get_draft(&self, Parameters(p): Parameters<DraftIdParam>) -> String {
        match drafts::load(&p.draft_id) {
            Ok(d) => Self::ok(serde_json::to_value(d).unwrap()),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Update fields of an existing draft. Only provided fields are changed.")]
    async fn update_draft(&self, Parameters(p): Parameters<DraftUpdateParams>) -> String {
        match drafts::load(&p.draft_id) {
            Ok(mut d) => {
                if let Some(t) = p.title { d.title = t; }
                if let Some(vi) = p.vulnerability_information { d.vulnerability_information = vi; }
                if let Some(wid) = p.weakness_id { d.weakness_id = Some(wid); }
                if let Some(s) = p.severity_rating { d.severity_rating = Some(s); }
                if let Some(i) = p.impact { d.impact = Some(i); }
                if let Some(sid) = p.structured_scope_id { d.structured_scope_id = Some(sid); }
                if let Some(cv) = p.cvss_vector { d.cvss_vector = Some(cv); }
                d.updated_at = chrono::Utc::now();
                match drafts::save(&d) {
                    Ok(()) => Self::ok(serde_json::json!({ "draft_id": d.id, "message": "Draft updated." })),
                    Err(e) => Self::err(e),
                }
            }
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Permanently delete a saved draft.")]
    async fn delete_draft(&self, Parameters(p): Parameters<DraftIdParam>) -> String {
        match drafts::delete(&p.draft_id) {
            Ok(()) => format!("Draft '{}' deleted.", p.draft_id),
            Err(e) => Self::err(e),
        }
    }

    #[tool(description = "Submit a saved draft to HackerOne. The draft is deleted locally after successful submission.")]
    async fn submit_draft(&self, Parameters(p): Parameters<DraftIdParam>) -> String {
        let draft = match drafts::load(&p.draft_id) {
            Ok(d) => d,
            Err(e) => return Self::err(e),
        };
        let payload = drafts::to_h1_payload(&draft);
        match self.client.submit_report(payload).await {
            Ok(v) => {
                let _ = drafts::delete(&p.draft_id);
                Self::ok(serde_json::json!({
                    "message": "Report submitted. Draft deleted.",
                    "report": v
                }))
            }
            Err(e) => Self::err(e),
        }
    }
}

#[tool_handler(name = "h1mcp", version = "0.1.4", router = self.tool_router)]
impl ServerHandler for H1Server {}

pub async fn run() -> Result<()> {
    let client = H1Client::from_env()?;
    let server = H1Server::new(client);
    let transport = (tokio::io::stdin(), tokio::io::stdout());
    let service = server.serve(transport).await?;
    service.waiting().await?;
    Ok(())
}
