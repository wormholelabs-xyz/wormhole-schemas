use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;

/// Central schema registry on GitHub — fallback when the source repo
/// doesn't contain a `schemas/` directory.
pub(crate) const REGISTRY_ORG: &str = "wormholelabs-xyz";
pub(crate) const REGISTRY_REPO: &str = "wormhole-schemas";
/// Branch names to try, in order.
pub(crate) const BRANCHES: &[&str] = &["main", "master"];

/// Return the persistent disk cache directory.
///
/// Checks `$WORMHOLE_SCHEMAS_CACHE` first, then falls back to
/// `$HOME/.wormhole-schemas/`.
pub(crate) fn cache_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("WORMHOLE_SCHEMAS_CACHE") {
        return Some(PathBuf::from(dir));
    }
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".wormhole-schemas"))
}

/// Read a cached schema from disk.
pub(crate) fn read_cached(
    cache: &Option<PathBuf>,
    org: &str,
    repo: &str,
    name: &str,
) -> Option<serde_json::Value> {
    let dir = cache.as_ref()?;
    let path = dir
        .join(format!("@{}", org))
        .join(repo)
        .join(format!("{}.json", name));
    let contents = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&contents).ok()
}

/// Write a schema to the disk cache. Errors are silently ignored.
pub(crate) fn write_cached(
    cache: &Option<PathBuf>,
    org: &str,
    repo: &str,
    name: &str,
    value: &serde_json::Value,
) {
    let Some(dir) = cache.as_ref() else { return };
    let parent = dir.join(format!("@{}", org)).join(repo);
    if std::fs::create_dir_all(&parent).is_err() {
        return;
    }
    let target = parent.join(format!("{}.json", name));
    let tmp = parent.join(format!(".{}.json.tmp", name));
    let Ok(json) = serde_json::to_string_pretty(value) else {
        return;
    };
    if std::fs::write(&tmp, json).is_ok() {
        let _ = std::fs::rename(&tmp, &target);
    }
}

/// Cache for fetched remote schemas.
pub struct FetchCache {
    cache: HashMap<String, serde_json::Value>,
    disk_cache: Option<PathBuf>,
}

impl FetchCache {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            disk_cache: cache_dir(),
        }
    }

    /// Fetch a schema from GitHub. Returns cached value if available.
    ///
    /// Resolution order:
    /// 1. In-memory cache
    /// 2. Persistent disk cache
    /// 3. Source repo (trying main, then master)
    /// 4. Central registry (trying main, then master)
    ///
    /// Network fetches write through to the disk cache.
    pub fn fetch(&mut self, org: &str, repo: &str, name: &str) -> Result<serde_json::Value> {
        let key = format!("@{}/{}/{}", org, repo, name);
        if let Some(val) = self.cache.get(&key) {
            return Ok(val.clone());
        }

        // Try persistent disk cache
        if let Some(val) = read_cached(&self.disk_cache, org, repo, name) {
            self.cache.insert(key, val.clone());
            return Ok(val);
        }

        // Try the source repo first (main, then master)
        for branch in BRANCHES {
            let url = format!(
                "https://raw.githubusercontent.com/{}/{}/{}/schemas/{}.json",
                org, repo, branch, name
            );
            if let Ok(value) = fetch_json(&url) {
                write_cached(&self.disk_cache, org, repo, name, &value);
                self.cache.insert(key, value.clone());
                return Ok(value);
            }
        }

        // Fall back to the central registry (main, then master)
        for branch in BRANCHES {
            let url = format!(
                "https://raw.githubusercontent.com/{}/{}/{}/schemas/@{}/{}/{}.json",
                REGISTRY_ORG, REGISTRY_REPO, branch, org, repo, name
            );
            if let Ok(value) = fetch_json(&url) {
                write_cached(&self.disk_cache, org, repo, name, &value);
                self.cache.insert(key, value.clone());
                return Ok(value);
            }
        }

        bail!(
            "schema {} not found in source repo or central registry",
            key,
        )
    }
}

pub(crate) fn fetch_json(url: &str) -> Result<serde_json::Value> {
    let mut req = ureq::get(url).set("User-Agent", "wsch");
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        req = req.set("Authorization", &format!("Bearer {}", token));
    }
    // GitHub API endpoints need Accept header
    if url.contains("api.github.com") {
        req = req.set("Accept", "application/vnd.github+json");
    }
    let resp = req.call().with_context(|| format!("fetching {}", url))?;
    let value: serde_json::Value = resp
        .into_json()
        .with_context(|| format!("parsing JSON from {}", url))?;
    Ok(value)
}
