use schemars::JsonSchema;
use serde::Deserialize;

// ── Report params ─────────────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct SearchReportsParams {
    /// Keyword to search in title/body
    pub keyword: Option<String>,
    /// Program handle (e.g. "twilio")
    pub program: Option<String>,
    /// Severity: none, low, medium, high, critical
    pub severity: Option<String>,
    /// State: new, triaged, needs-more-info, resolved, not-applicable, informative, duplicate, spam
    pub state: Option<String>,
    /// Number of results (1-100, default 25)
    pub page_size: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ReportIdParam {
    /// Numeric report ID
    pub report_id: u64,
}

#[derive(Deserialize, JsonSchema)]
pub struct ReportActivitiesParam {
    pub report_id: u64,
    pub page_size: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SubmitReportParams {
    pub program_handle: String,
    pub title: String,
    pub vulnerability_information: String,
    pub weakness_id: Option<u64>,
    /// none, low, medium, high, critical
    pub severity_rating: Option<String>,
    pub impact: Option<String>,
    pub structured_scope_id: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct AddCommentParams {
    pub report_id: u64,
    pub message: String,
    /// If true, only visible to program team
    pub internal: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct CloseReportParams {
    pub report_id: u64,
    pub message: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct UpdateSeverityParams {
    pub report_id: u64,
    /// none, low, medium, high, critical
    pub rating: String,
    /// Optional CVSS score (0.0-10.0)
    pub score: Option<f64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct RequestDisclosureParams {
    pub report_id: u64,
    /// "full" or "limited"
    pub kind: Option<String>,
}

// ── Program params ────────────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct ProgramHandleParam {
    pub program_handle: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ProgramPageParam {
    pub program_handle: String,
    pub page_size: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ListProgramsParam {
    pub page_size: Option<u32>,
}

// ── Hacker / misc params ──────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct PageSizeParam {
    pub page_size: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SearchDisclosedParams {
    pub query: Option<String>,
    pub program: Option<String>,
    pub page_size: Option<u32>,
}

// ── Draft params ──────────────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct DraftCreateParams {
    pub program_handle: String,
    pub title: String,
    pub vulnerability_information: String,
    pub weakness_id: Option<u64>,
    /// none, low, medium, high, critical
    pub severity_rating: Option<String>,
    pub impact: Option<String>,
    pub structured_scope_id: Option<u64>,
    /// CVSS 3.1 vector string
    pub cvss_vector: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct DraftIdParam {
    /// Draft UUID (from list_drafts)
    pub draft_id: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct DraftUpdateParams {
    pub draft_id: String,
    pub title: Option<String>,
    pub vulnerability_information: Option<String>,
    pub weakness_id: Option<u64>,
    pub severity_rating: Option<String>,
    pub impact: Option<String>,
    pub structured_scope_id: Option<u64>,
    pub cvss_vector: Option<String>,
}
