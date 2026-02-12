use anyhow::{Context, Result};
use std::collections::HashMap;

/// Cache for fetched remote schemas.
pub struct FetchCache {
    cache: HashMap<String, serde_json::Value>,
}

impl FetchCache {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Fetch a schema from GitHub. Returns cached value if available.
    ///
    /// URL: `https://raw.githubusercontent.com/{org}/{repo}/main/schemas/{name}.json`
    pub fn fetch(&mut self, org: &str, repo: &str, name: &str) -> Result<serde_json::Value> {
        let key = format!("@{}/{}/{}", org, repo, name);
        if let Some(val) = self.cache.get(&key) {
            return Ok(val.clone());
        }

        let url = format!(
            "https://raw.githubusercontent.com/{}/{}/main/schemas/{}.json",
            org, repo, name
        );

        let resp = ureq::get(&url)
            .call()
            .with_context(|| format!("failed to fetch schema {}: {}", key, url))?;

        let value: serde_json::Value = resp
            .into_json()
            .with_context(|| format!("failed to parse JSON from {}", url))?;

        self.cache.insert(key, value.clone());
        Ok(value)
    }
}
