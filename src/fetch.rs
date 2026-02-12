use anyhow::{bail, Context, Result};
use std::collections::HashMap;

/// Central schema registry on GitHub — fallback when the source repo
/// doesn't contain a `schemas/` directory.
const REGISTRY_ORG: &str = "wormholelabs-xyz";
const REGISTRY_REPO: &str = "wormhole-schemas";

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
    /// Resolution order:
    /// 1. Try the source repo: `{org}/{repo}/main/schemas/{name}.json`
    /// 2. Fall back to the central registry: `wormholelabs-xyz/wormhole-schemas/main/schemas/@{org}/{repo}/{name}.json`
    pub fn fetch(&mut self, org: &str, repo: &str, name: &str) -> Result<serde_json::Value> {
        let key = format!("@{}/{}/{}", org, repo, name);
        if let Some(val) = self.cache.get(&key) {
            return Ok(val.clone());
        }

        // Try the source repo first
        let source_url = format!(
            "https://raw.githubusercontent.com/{}/{}/main/schemas/{}.json",
            org, repo, name
        );
        if let Ok(value) = fetch_json(&source_url) {
            self.cache.insert(key, value.clone());
            return Ok(value);
        }

        // Fall back to the central registry
        let registry_url = format!(
            "https://raw.githubusercontent.com/{}/{}/main/schemas/@{}/{}/{}.json",
            REGISTRY_ORG, REGISTRY_REPO, org, repo, name
        );
        match fetch_json(&registry_url) {
            Ok(value) => {
                self.cache.insert(key, value.clone());
                Ok(value)
            }
            Err(e) => bail!(
                "schema {} not found in source repo ({}) or central registry ({}): {}",
                key,
                source_url,
                registry_url,
                e
            ),
        }
    }
}

fn fetch_json(url: &str) -> Result<serde_json::Value> {
    let resp = ureq::get(url)
        .call()
        .with_context(|| format!("fetching {}", url))?;
    let value: serde_json::Value = resp
        .into_json()
        .with_context(|| format!("parsing JSON from {}", url))?;
    Ok(value)
}
