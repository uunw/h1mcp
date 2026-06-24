use anyhow::{Context, Result};
use reqwest::{Client, RequestBuilder};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const BASE_URL: &str = "https://api.hackerone.com/v1";
const CACHE_TTL: Duration = Duration::from_secs(60);

pub struct H1Client {
    client: Client,
    username: String,
    api_key: String,
    cache: Mutex<HashMap<String, (Value, Instant)>>,
}

impl H1Client {
    pub fn from_env() -> Result<Self> {
        let username = std::env::var("H1_USERNAME")
            .context("H1_USERNAME env var not set")?;
        let api_key = std::env::var("H1_API_KEY")
            .context("H1_API_KEY env var not set")?;
        Ok(Self {
            client: Client::new(),
            username,
            api_key,
            cache: Mutex::new(HashMap::new()),
        })
    }

    fn auth_get(&self, url: &str) -> RequestBuilder {
        self.client
            .get(url)
            .basic_auth(&self.username, Some(&self.api_key))
            .header("Accept", "application/json")
    }

    fn post(&self, path: &str) -> RequestBuilder {
        self.client
            .post(format!("{BASE_URL}{path}"))
            .basic_auth(&self.username, Some(&self.api_key))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
    }

    async fn exec<T: DeserializeOwned>(&self, rb: RequestBuilder) -> Result<T> {
        const MAX_RETRIES: u32 = 3;
        let mut attempt = 0u32;
        loop {
            let req = rb.try_clone().context("request body not retryable")?;
            let resp = req.send().await?;
            let status = resp.status();

            if status == 429 {
                let wait = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(5);
                if attempt < MAX_RETRIES {
                    attempt += 1;
                    tracing::warn!("rate limited, waiting {wait}s (attempt {attempt}/{MAX_RETRIES})");
                    tokio::time::sleep(Duration::from_secs(wait)).await;
                    continue;
                }
                anyhow::bail!("H1 API rate limited after {MAX_RETRIES} retries");
            }

            if status.is_server_error() && attempt < MAX_RETRIES {
                attempt += 1;
                let wait = 2u64.pow(attempt);
                tracing::warn!("server error {status}, retrying in {wait}s (attempt {attempt}/{MAX_RETRIES})");
                tokio::time::sleep(Duration::from_secs(wait)).await;
                continue;
            }

            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("H1 API error {status}: {body}");
            }

            return Ok(resp.json::<T>().await?);
        }
    }

    // Cache-aware GET — key is the full URL.
    async fn cached_get(&self, url: &str) -> Result<Value> {
        {
            let cache = self.cache.lock().unwrap();
            if let Some((val, at)) = cache.get(url) {
                if at.elapsed() < CACHE_TTL {
                    return Ok(val.clone());
                }
            }
        }
        let val: Value = self.exec(self.auth_get(url)).await?;
        self.cache.lock().unwrap().insert(url.to_string(), (val.clone(), Instant::now()));
        Ok(val)
    }

    // ── Reports ──────────────────────────────────────────────────────────

    pub async fn search_reports(
        &self,
        keyword: Option<&str>,
        program: Option<&str>,
        severity: Option<&str>,
        state: Option<&str>,
        page_size: Option<u32>,
        page_number: Option<u32>,
        sort: Option<&str>,
    ) -> Result<Value> {
        // Hacker API exposes only your own reports, under /hackers/me/reports.
        let mut url = format!("{BASE_URL}/hackers/me/reports?");
        if let Some(k) = keyword { url.push_str(&format!("filter[keyword]={k}&")); }
        if let Some(p) = program { url.push_str(&format!("filter[program][]={p}&")); }
        if let Some(s) = severity { url.push_str(&format!("filter[severity][]={s}&")); }
        if let Some(st) = state { url.push_str(&format!("filter[state][]={st}&")); }
        if let Some(n) = page_number { url.push_str(&format!("page[number]={n}&")); }
        if let Some(s) = sort { url.push_str(&format!("sort={s}&")); }
        url.push_str(&format!("page[size]={}", page_size.unwrap_or(25).min(100)));
        self.cached_get(&url).await
    }

    pub async fn get_report(&self, id: u64) -> Result<Value> {
        self.cached_get(&format!("{BASE_URL}/hackers/reports/{id}")).await
    }

    // The hacker API has no standalone activities endpoint — activities are
    // nested inside GET /hackers/reports/{id}. Extract them from the report.
    pub async fn get_report_activities(&self, id: u64, _page_size: Option<u32>) -> Result<Value> {
        let report = self.get_report(id).await?;
        Ok(report["data"]["relationships"]["activities"].clone())
    }

    pub async fn submit_report(&self, body: Value) -> Result<Value> {
        self.exec(self.post("/hackers/reports").json(&body)).await
    }

    // NOTE: add_comment / close_report / update_severity / request_disclosure are
    // customer/program API operations. They are not part of the hacker API and
    // require a program-scoped token; with a hacker token they return 401.
    // These methods return a descriptive error immediately rather than hitting the API.
    pub async fn add_comment(&self, id: u64, _message: &str, _internal: bool) -> Result<Value> {
        anyhow::bail!(
            "add_comment is not supported by the HackerOne hacker API. \
             To add a comment to report #{id}, visit https://hackerone.com/reports/{id} \
             and use the web interface."
        )
    }

    pub async fn close_report(&self, id: u64, _message: &str) -> Result<Value> {
        anyhow::bail!(
            "close_report is not supported by the HackerOne hacker API. \
             To close report #{id}, visit https://hackerone.com/reports/{id} \
             and use the web interface."
        )
    }

    pub async fn update_severity(&self, id: u64, _rating: &str, _score: Option<f64>) -> Result<Value> {
        anyhow::bail!(
            "update_report_severity is not supported by the HackerOne hacker API. \
             To update severity for report #{id}, visit https://hackerone.com/reports/{id} \
             and use the web interface."
        )
    }

    pub async fn request_disclosure(&self, id: u64, _kind: &str) -> Result<Value> {
        anyhow::bail!(
            "request_disclosure is not supported by the HackerOne hacker API. \
             To request disclosure for report #{id}, visit https://hackerone.com/reports/{id} \
             and use the web interface."
        )
    }

    // ── Report intents (hacker API) ──────────────────────────────────────
    // A report intent is the first step of the assisted submission flow: you
    // send a free-text description and HackerOne's assistant pre-validates it.

    pub async fn create_report_intent(&self, team_handle: &str, description: &str) -> Result<Value> {
        let body = serde_json::json!({
            "data": {
                "type": "report-intent",
                "attributes": { "team_handle": team_handle, "description": description }
            }
        });
        self.exec(self.post("/hackers/report_intents").json(&body)).await
    }

    pub async fn list_report_intents(&self, page_size: Option<u32>) -> Result<Value> {
        let size = page_size.unwrap_or(25).min(100);
        self.cached_get(&format!("{BASE_URL}/hackers/report_intents?page[size]={size}")).await
    }

    pub async fn get_report_intent(&self, id: u64) -> Result<Value> {
        self.cached_get(&format!("{BASE_URL}/hackers/report_intents/{id}")).await
    }

    // ── Programs ─────────────────────────────────────────────────────────

    pub async fn list_programs(&self, page_size: Option<u32>) -> Result<Value> {
        let size = page_size.unwrap_or(25).min(100);
        let mut all_data: Vec<Value> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut url = format!("{BASE_URL}/hackers/programs?page[size]={size}");
            if let Some(ref c) = cursor { url.push_str(&format!("&page[cursor]={c}")); }
            let resp: Value = self.cached_get(&url).await?;
            if let Some(data) = resp["data"].as_array() {
                all_data.extend(data.clone());
            }
            cursor = resp["links"]["next"].as_str()
                .and_then(|u| url::Url::parse(u).ok())
                .and_then(|u| u.query_pairs().find(|(k, _)| k == "page[cursor]").map(|(_, v)| v.to_string()));
            if cursor.is_none() { break; }
        }
        Ok(serde_json::json!({ "data": all_data, "total": all_data.len() }))
    }

    pub async fn get_program(&self, handle: &str) -> Result<Value> {
        self.cached_get(&format!("{BASE_URL}/hackers/programs/{handle}")).await
    }

    pub async fn get_program_scope(&self, handle: &str, page_size: Option<u32>) -> Result<Value> {
        let size = page_size.unwrap_or(25).min(100);
        self.cached_get(&format!("{BASE_URL}/hackers/programs/{handle}/structured_scopes?page[size]={size}")).await
    }

    pub async fn get_program_weaknesses(&self, handle: &str, page_size: Option<u32>) -> Result<Value> {
        let size = page_size.unwrap_or(100).min(100);
        self.cached_get(&format!("{BASE_URL}/hackers/programs/{handle}/weaknesses?page[size]={size}")).await
    }

    // Bundle the IDs needed to submit a report to a program: submittable
    // structured scopes (structured_scope_id) and accepted weaknesses (weakness_id).
    pub async fn get_submission_options(&self, handle: &str) -> Result<Value> {
        let (scopes, weaknesses) = tokio::join!(
            self.get_program_scope(handle, Some(100)),
            self.get_program_weaknesses(handle, Some(100)),
        );
        let scopes = scopes?;
        let weaknesses = weaknesses?;
        let empty = vec![];
        let scope_opts: Vec<Value> = scopes["data"].as_array().unwrap_or(&empty).iter()
            .filter(|s| s["attributes"]["eligible_for_submission"].as_bool().unwrap_or(false))
            .map(|s| serde_json::json!({
                "structured_scope_id": s["id"],
                "asset_identifier": s["attributes"]["asset_identifier"],
                "asset_type": s["attributes"]["asset_type"],
                "eligible_for_bounty": s["attributes"]["eligible_for_bounty"],
            }))
            .collect();
        let weakness_opts: Vec<Value> = weaknesses["data"].as_array().unwrap_or(&empty).iter()
            .map(|w| serde_json::json!({
                "weakness_id": w["id"],
                "name": w["attributes"]["name"],
            }))
            .collect();
        Ok(serde_json::json!({
            "program": handle,
            "structured_scopes": scope_opts,
            "weaknesses": weakness_opts,
        }))
    }

    // ── Hacker ───────────────────────────────────────────────────────────

    // The hacker API has no standalone self-profile endpoint (/hackers/me -> 401).
    // Derive identity from the reporter object embedded in your own reports.
    pub async fn get_profile(&self) -> Result<Value> {
        let reports = self
            .cached_get(&format!("{BASE_URL}/hackers/me/reports?page[size]=1"))
            .await?;
        let reporter = &reports["data"][0]["relationships"]["reporter"]["data"];
        if reporter.is_object() {
            Ok(reporter.clone())
        } else {
            anyhow::bail!(
                "Profile is not exposed by the hacker API; it can only be derived \
                 from an existing report, and you have no reports yet."
            )
        }
    }

    pub async fn get_balance(&self) -> Result<Value> {
        self.cached_get(&format!("{BASE_URL}/hackers/payments/balance")).await
    }

    pub async fn get_earnings(&self, page_size: Option<u32>) -> Result<Value> {
        let size = page_size.unwrap_or(25).min(100);
        self.cached_get(&format!("{BASE_URL}/hackers/payments/earnings?page[size]={size}")).await
    }

    // ── Hacktivity ───────────────────────────────────────────────────────

    pub async fn search_disclosed(&self, query: Option<&str>, program: Option<&str>, page_size: Option<u32>) -> Result<Value> {
        self.cached_get(&hacktivity_url(query, program, page_size)).await
    }
}

// ── Hacktivity URL builder ───────────────────────────────────────────────
// The hacktivity endpoint does NOT accept JSON-API `filter[...]` params (those
// belong to /reports). It takes a single Apache Lucene `queryString`: filter a
// program with `team:<handle>`, while a bare term is a full-text keyword search.
// Unknown params are silently ignored — which is why the old `filter[program][]`
// returned the unfiltered global feed. Values are URL-encoded by `url` crate.
// Ref: https://api.hackerone.com/hacker-resources (GET /hackers/hacktivity)
fn hacktivity_url(query: Option<&str>, program: Option<&str>, page_size: Option<u32>) -> String {
    let size = page_size.unwrap_or(25).min(100);
    let mut clauses: Vec<String> = Vec::new();
    if let Some(p) = program {
        clauses.push(format!("team:{p}"));
    }
    if let Some(q) = query.map(str::trim).filter(|q| !q.is_empty()) {
        // Group the keyword so multi-word input stays intact when AND-combined.
        clauses.push(if clauses.is_empty() { q.to_string() } else { format!("({q})") });
    }
    let mut params: Vec<(&str, String)> = vec![("page[size]", size.to_string())];
    if !clauses.is_empty() {
        params.push(("queryString", clauses.join(" AND ")));
    }
    url::Url::parse_with_params(&format!("{BASE_URL}/hackers/hacktivity"), &params)
        .expect("hacktivity base URL is valid")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Decode a single query param back to its logical value (handles `+`/`%XX`).
    fn qs(url: &str, key: &str) -> Option<String> {
        url::Url::parse(url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }

    #[test]
    fn program_filter_uses_team_lucene_field() {
        let url = hacktivity_url(None, Some("unico_idtech"), None);
        assert_eq!(qs(&url, "queryString").as_deref(), Some("team:unico_idtech"));
        // Regression guard: the old broken JSON-API filter must never reappear.
        assert!(!url.contains("filter"), "must not emit filter[] params: {url}");
    }

    #[test]
    fn keyword_only_is_bare_term() {
        let url = hacktivity_url(Some("idor"), None, None);
        assert_eq!(qs(&url, "queryString").as_deref(), Some("idor"));
    }

    #[test]
    fn program_and_keyword_anded_and_grouped() {
        let url = hacktivity_url(Some("sql injection"), Some("curl"), None);
        assert_eq!(qs(&url, "queryString").as_deref(), Some("team:curl AND (sql injection)"));
    }

    #[test]
    fn blank_keyword_ignored() {
        let url = hacktivity_url(Some("   "), None, None);
        assert_eq!(qs(&url, "queryString"), None);
    }

    #[test]
    fn page_size_clamped_to_100() {
        let url = hacktivity_url(None, None, Some(9999));
        assert_eq!(qs(&url, "page[size]").as_deref(), Some("100"));
    }

    #[test]
    fn default_page_size_and_no_query() {
        let url = hacktivity_url(None, None, None);
        assert_eq!(qs(&url, "page[size]").as_deref(), Some("25"));
        assert_eq!(qs(&url, "queryString"), None);
    }
}
