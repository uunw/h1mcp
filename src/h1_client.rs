use anyhow::{Context, Result};
use reqwest::{Client, RequestBuilder};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::time::Duration;

const BASE_URL: &str = "https://api.hackerone.com/v1";

pub struct H1Client {
    client: Client,
    username: String,
    api_key: String,
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
        })
    }

    fn get(&self, path: &str) -> RequestBuilder {
        self.client
            .get(format!("{BASE_URL}{path}"))
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

    // ── Reports ──────────────────────────────────────────────────────────

    pub async fn search_reports(
        &self,
        keyword: Option<&str>,
        program: Option<&str>,
        severity: Option<&str>,
        state: Option<&str>,
        page_size: Option<u32>,
    ) -> Result<Value> {
        let mut url = format!("{BASE_URL}/reports?");
        if let Some(k) = keyword { url.push_str(&format!("filter[keyword]={k}&")); }
        if let Some(p) = program { url.push_str(&format!("filter[program][]={p}&")); }
        if let Some(s) = severity { url.push_str(&format!("filter[severity][]={s}&")); }
        if let Some(st) = state { url.push_str(&format!("filter[state][]={st}&")); }
        let size = page_size.unwrap_or(25).min(100);
        url.push_str(&format!("page[size]={size}"));
        let rb = self.client.get(&url)
            .basic_auth(&self.username, Some(&self.api_key))
            .header("Accept", "application/json");
        self.exec(rb).await
    }

    pub async fn get_report(&self, id: u64) -> Result<Value> {
        self.exec(self.get(&format!("/reports/{id}"))).await
    }

    pub async fn get_report_activities(&self, id: u64, page_size: Option<u32>) -> Result<Value> {
        let size = page_size.unwrap_or(25);
        self.exec(self.get(&format!("/reports/{id}/activities?page[size]={size}"))).await
    }

    pub async fn submit_report(&self, body: Value) -> Result<Value> {
        self.exec(self.post("/reports").json(&body)).await
    }

    pub async fn add_comment(&self, id: u64, message: &str, internal: bool) -> Result<Value> {
        let body = serde_json::json!({
            "data": {
                "type": "activity-comment",
                "attributes": {
                    "message": message,
                    "internal": internal
                }
            }
        });
        self.exec(self.post(&format!("/reports/{id}/activities")).json(&body)).await
    }

    pub async fn close_report(&self, id: u64, message: &str) -> Result<Value> {
        let body = serde_json::json!({
            "data": {
                "type": "activity-close-report",
                "attributes": { "message": message }
            }
        });
        self.exec(self.post(&format!("/reports/{id}/activities")).json(&body)).await
    }

    pub async fn update_severity(&self, id: u64, rating: &str, score: Option<f64>) -> Result<Value> {
        let mut attrs = serde_json::json!({ "rating": rating });
        if let Some(s) = score { attrs["score"] = s.into(); }
        let body = serde_json::json!({
            "data": { "type": "severity", "attributes": attrs }
        });
        self.exec(self.post(&format!("/reports/{id}/severities")).json(&body)).await
    }

    pub async fn request_disclosure(&self, id: u64, kind: &str) -> Result<Value> {
        let body = serde_json::json!({
            "data": {
                "type": "disclosure-request",
                "attributes": { "type": kind }
            }
        });
        self.exec(self.post(&format!("/reports/{id}/disclosure_requests")).json(&body)).await
    }

    // ── Programs ─────────────────────────────────────────────────────────

    pub async fn list_programs(&self, page_size: Option<u32>) -> Result<Value> {
        let size = page_size.unwrap_or(25).min(100);
        let mut all_data: Vec<Value> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut url = format!("{BASE_URL}/hackers/programs?page[size]={size}");
            if let Some(ref c) = cursor { url.push_str(&format!("&page[cursor]={c}")); }
            let rb = self.client.get(&url)
                .basic_auth(&self.username, Some(&self.api_key))
                .header("Accept", "application/json");
            let resp: Value = self.exec(rb).await?;
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
        self.exec(self.get(&format!("/programs/{handle}"))).await
    }

    pub async fn get_program_scope(&self, handle: &str, page_size: Option<u32>) -> Result<Value> {
        let size = page_size.unwrap_or(25).min(100);
        self.exec(self.get(&format!("/programs/{handle}/structured_scopes?page[size]={size}"))).await
    }

    pub async fn get_program_weaknesses(&self, handle: &str, page_size: Option<u32>) -> Result<Value> {
        let size = page_size.unwrap_or(100).min(100);
        self.exec(self.get(&format!("/programs/{handle}/weaknesses?page[size]={size}"))).await
    }

    // ── Hacker ───────────────────────────────────────────────────────────

    pub async fn get_profile(&self) -> Result<Value> {
        self.exec(self.get("/hackers/me")).await
    }

    pub async fn get_balance(&self) -> Result<Value> {
        self.exec(self.get("/hackers/me/payments")).await
    }

    pub async fn get_earnings(&self, page_size: Option<u32>) -> Result<Value> {
        let size = page_size.unwrap_or(25).min(100);
        self.exec(self.get(&format!("/hackers/me/payments?page[size]={size}"))).await
    }

    // ── Hacktivity ───────────────────────────────────────────────────────

    pub async fn search_disclosed(&self, query: Option<&str>, program: Option<&str>, page_size: Option<u32>) -> Result<Value> {
        let size = page_size.unwrap_or(25).min(100);
        let mut url = format!("{BASE_URL}/hacktivity?page[size]={size}");
        if let Some(q) = query { url.push_str(&format!("&filter[keyword]={q}")); }
        if let Some(p) = program { url.push_str(&format!("&filter[program][]={p}")); }
        let rb = self.client.get(&url)
            .basic_auth(&self.username, Some(&self.api_key))
            .header("Accept", "application/json");
        self.exec(rb).await
    }
}
