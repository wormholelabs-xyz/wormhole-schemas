use anyhow::Result;
use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;

use crate::fetch::{
    cache_dir, fetch_json, read_cached, write_cached, BRANCHES, REGISTRY_ORG, REGISTRY_REPO,
};

/// Sync all schemas to the local disk cache.
///
/// 1. Fetches the central registry tree and downloads every schema it lists.
/// 2. Scans the existing cache for schemas that weren't in the registry
///    (i.e. previously fetched on-demand from a source repo) and refreshes
///    them from `raw.githubusercontent.com/{org}/{repo}/`.
///
/// Returns the total number of schemas synced.
pub fn sync(verbose: bool) -> Result<usize> {
    let dir = cache_dir().ok_or_else(|| {
        anyhow::anyhow!("cannot determine cache directory: set $WORMHOLE_SCHEMAS_CACHE or $HOME")
    })?;

    let cache = Some(dir.clone());
    let mut synced: HashSet<String> = HashSet::new();
    let mut count = 0;
    // Estimate total from existing cache size (will be adjusted when we know better)
    let cached_entries = scan_cache(&dir);
    let mut progress = Progress::new(cached_entries.len());

    // --- Phase 1: central registry ---
    if let Some((branch, tree)) = resolve_registry_tree() {
        let entries = tree["tree"].as_array();
        let schema_paths: Vec<&str> = entries
            .iter()
            .flat_map(|a| a.iter())
            .filter_map(|e| {
                let path = e["path"].as_str()?;
                if path.starts_with("schemas/@") && path.ends_with(".json") {
                    Some(path)
                } else {
                    None
                }
            })
            .collect();

        // We know the registry count; extras from cache will be added after phase 1
        progress.set_total(schema_paths.len());

        for path in &schema_paths {
            let Some((org, repo, name)) = parse_schema_path(path) else {
                if verbose {
                    progress.log(&format!("  skip: {}", path));
                }
                continue;
            };

            let key = format!("@{}/{}/{}", org, repo, name);
            progress.tick(&key);

            let url = format!(
                "https://raw.githubusercontent.com/{}/{}/{}/{}",
                REGISTRY_ORG, REGISTRY_REPO, branch, path
            );

            match fetch_json(&url) {
                Ok(value) => {
                    let status = write_and_diff(&cache, org, repo, name, &value);
                    synced.insert(key.clone());
                    count += 1;
                    progress.advance();
                    match status {
                        SyncStatus::New => progress.log(&format!("  + {}", key)),
                        SyncStatus::Modified => progress.log(&format!("  ~ {}", key)),
                        SyncStatus::Unchanged => {
                            if verbose {
                                progress.log(&format!("  = {}", key));
                            }
                        }
                    }
                }
                Err(e) => {
                    progress.advance();
                    if verbose {
                        progress.log(&format!("  WARN: {}: {}", path, e));
                    }
                }
            }
        }

        // Adjust total: registry schemas + non-registry cached schemas
        let extra: usize = cached_entries
            .iter()
            .filter(|(o, r, n)| !synced.contains(&format!("@{}/{}/{}", o, r, n)))
            .count();
        progress.set_total(schema_paths.len() + extra);
    } else {
        if verbose {
            progress
                .log("  WARN: could not reach central registry, refreshing cached schemas only");
        }
        progress.set_total(cached_entries.len());
    }

    // --- Phase 2: refresh cached schemas not in the central registry ---
    for (org, repo, name) in &cached_entries {
        let key = format!("@{}/{}/{}", org, repo, name);
        if synced.contains(&key) {
            continue;
        }

        progress.tick(&key);

        // Try fetching from the source repo (main, then master)
        let mut ok = false;
        for branch in BRANCHES {
            let url = format!(
                "https://raw.githubusercontent.com/{}/{}/{}/schemas/{}.json",
                org, repo, branch, name
            );
            if let Ok(value) = fetch_json(&url) {
                let status = write_and_diff(&cache, org, repo, name, &value);
                count += 1;
                ok = true;
                progress.advance();
                match status {
                    SyncStatus::New => progress.log(&format!("  + {} (source repo)", key)),
                    SyncStatus::Modified => progress.log(&format!("  ~ {} (source repo)", key)),
                    SyncStatus::Unchanged => {
                        if verbose {
                            progress.log(&format!("  = {} (source repo)", key));
                        }
                    }
                }
                break;
            }
        }
        if !ok {
            progress.advance();
            if verbose {
                progress.log(&format!("  WARN: could not refresh {}", key));
            }
        }
    }

    progress.finish();
    write_sync_metadata(&cache, count);
    Ok(count)
}

// ---------------------------------------------------------------------------
// Progress bar
// ---------------------------------------------------------------------------

struct Progress {
    done: usize,
    total: usize,
    term_width: usize,
}

impl Progress {
    fn new(estimated_total: usize) -> Self {
        Self {
            done: 0,
            total: estimated_total.max(1),
            term_width: terminal_width(),
        }
    }

    fn set_total(&mut self, total: usize) {
        self.total = total.max(1);
    }

    fn advance(&mut self) {
        self.done += 1;
        if self.done > self.total {
            self.total = self.done;
        }
    }

    /// Show the current item being fetched on the progress line.
    fn tick(&self, label: &str) {
        let bar = self.render_bar(label);
        eprint!("\r{}", bar);
        let _ = std::io::stderr().flush();
    }

    /// Print a permanent line (new/modified/warning), then redraw progress.
    fn log(&self, msg: &str) {
        // Clear the current line, print the message, then redraw progress
        eprint!("\r{}\r{}\n", " ".repeat(self.term_width.min(120)), msg);
        let bar = self.render_bar("");
        eprint!("{}", bar);
        let _ = std::io::stderr().flush();
    }

    /// Clear the progress line.
    fn finish(&self) {
        eprint!("\r{}\r", " ".repeat(self.term_width.min(120)));
        let _ = std::io::stderr().flush();
    }

    fn render_bar(&self, label: &str) -> String {
        let pct = if self.total > 0 {
            self.done * 100 / self.total
        } else {
            0
        };
        let counter = format!(" {}/{} ", self.done, self.total);

        // [####    ] 12/29  @org/repo/name
        let bar_width: usize = 20;
        let filled = if self.total > 0 {
            (self.done * bar_width) / self.total
        } else {
            0
        };
        let empty = bar_width - filled;
        let bar = format!("[{}{}]", "#".repeat(filled), " ".repeat(empty));

        let prefix = format!("{}{}", bar, counter);
        // Truncate label to fit terminal
        let max_label = self.term_width.saturating_sub(prefix.len() + 1);
        let truncated = if label.len() > max_label {
            &label[..max_label]
        } else {
            label
        };

        let _ = pct; // used implicitly via filled
        format!("{}{}", prefix, truncated)
    }
}

fn terminal_width() -> usize {
    // Try COLUMNS env, fall back to 80
    std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Try to resolve the central registry tree, returning (branch, tree_json).
fn resolve_registry_tree() -> Option<(&'static str, serde_json::Value)> {
    for branch in BRANCHES {
        let url = format!(
            "https://api.github.com/repos/{}/{}/git/trees/{}?recursive=1",
            REGISTRY_ORG, REGISTRY_REPO, branch
        );
        if let Ok(val) = fetch_json(&url) {
            return Some((branch, val));
        }
    }
    None
}

/// Parse `schemas/@org/repo/name.json` into (org, repo, name).
fn parse_schema_path(path: &str) -> Option<(&str, &str, &str)> {
    let rel = path.strip_prefix("schemas/")?;
    let parts: Vec<&str> = rel.splitn(3, '/').collect();
    if parts.len() != 3 {
        return None;
    }
    let org = parts[0].strip_prefix('@')?;
    let name = parts[2].strip_suffix(".json")?;
    Some((org, parts[1], name))
}

/// Walk the cache directory and return (org, repo, name) for each cached schema.
fn scan_cache(dir: &std::path::Path) -> Vec<(String, String, String)> {
    let mut result = Vec::new();
    let Ok(orgs) = std::fs::read_dir(dir) else {
        return result;
    };
    for org_entry in orgs.flatten() {
        let org_path = org_entry.path();
        let Some(org_name) = org_path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !org_name.starts_with('@') || !org_path.is_dir() {
            continue;
        }
        let org = &org_name[1..];
        let Ok(repos) = std::fs::read_dir(&org_path) else {
            continue;
        };
        for repo_entry in repos.flatten() {
            let repo_path = repo_entry.path();
            if !repo_path.is_dir() {
                continue;
            }
            let repo = repo_entry.file_name().to_string_lossy().to_string();
            let Ok(schemas) = std::fs::read_dir(&repo_path) else {
                continue;
            };
            for schema_entry in schemas.flatten() {
                let sp = schema_entry.path();
                if sp.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                if let Some(name) = sp.file_stem().and_then(|s| s.to_str()) {
                    result.push((org.to_string(), repo.clone(), name.to_string()));
                }
            }
        }
    }
    result
}

enum SyncStatus {
    New,
    Modified,
    Unchanged,
}

/// Compare fetched value with cache, write it, and return the status.
fn write_and_diff(
    cache: &Option<PathBuf>,
    org: &str,
    repo: &str,
    name: &str,
    value: &serde_json::Value,
) -> SyncStatus {
    let existing = read_cached(cache, org, repo, name);
    write_cached(cache, org, repo, name, value);
    match existing {
        None => SyncStatus::New,
        Some(old) if old == *value => SyncStatus::Unchanged,
        Some(_) => SyncStatus::Modified,
    }
}

fn write_sync_metadata(cache: &Option<PathBuf>, count: usize) {
    let Some(dir) = cache.as_ref() else { return };
    let meta = serde_json::json!({
        "synced_at": chrono_timestamp(),
        "schema_count": count,
    });
    let _ = std::fs::write(
        dir.join(".sync"),
        serde_json::to_string_pretty(&meta).unwrap_or_default(),
    );
}

fn chrono_timestamp() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", dur.as_secs())
}
