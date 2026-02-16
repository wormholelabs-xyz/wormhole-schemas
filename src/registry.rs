use anyhow::{bail, Context, Result};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

#[cfg(feature = "fetch")]
use crate::fetch::FetchCache;
use crate::parse::{self, Cursor};
use crate::refs::{self, ParsedRef, Scope};
use crate::schema::{self, Field, OptionInner, Schema};
use crate::serialize::{self, ArgInfo};

/// Maximum nesting depth for schema resolution (prevents stack overflow from
/// malicious or deeply nested schema chains).
const MAX_NESTING_DEPTH: usize = 32;

/// Maximum repeat count when parsing untrusted binary input.
const MAX_REPEAT_COUNT: usize = 256;

/// Synthetic schema name used as a greedy catch-all during inference.
const CATCHALL_KEY: &str = "__catchall__";
/// Field name in the catch-all schema that captures raw bytes.
const CATCHALL_FIELD: &str = "__payload__";

/// Cache for schemas loaded on-demand (local overrides discovered after
/// initial load, and optionally remote fetches from GitHub).
struct RuntimeCache {
    schemas: HashMap<String, Schema>,
    #[cfg(feature = "fetch")]
    fetch: FetchCache,
}

/// Registry of loaded schemas with lazy reference resolution.
pub struct Registry {
    schema_dir: Option<PathBuf>,
    /// Schemas loaded at init time — immutable after construction.
    schemas: HashMap<String, Schema>,
    /// Schemas fetched on-demand from GitHub or discovered later.
    runtime_cache: RefCell<RuntimeCache>,
}

impl Registry {
    /// Create a registry from the persistent disk cache (if available).
    pub fn new() -> Result<Self> {
        #[cfg(feature = "fetch")]
        let schemas = match crate::fetch::cache_dir() {
            Some(dir) if dir.exists() => Self::load_dir(&dir).unwrap_or_default(),
            _ => HashMap::new(),
        };
        #[cfg(not(feature = "fetch"))]
        let schemas = HashMap::new();
        Self::finish(None, schemas)
    }

    /// Load all `.json` schemas from a directory.
    ///
    /// Reads root-level `.json` files as `@this` schemas, and files under
    /// `@org/repo/*.json` subdirectories as scoped schemas keyed by
    /// `@org/repo/name`.
    pub fn load(schema_dir: &Path) -> Result<Self> {
        let schemas = Self::load_dir(schema_dir)?;
        Self::finish(Some(schema_dir.to_path_buf()), schemas)
    }

    /// Load from the disk cache, then layer on overrides from a directory.
    pub fn with_overrides(schema_dir: &Path) -> Result<Self> {
        #[cfg(feature = "fetch")]
        let mut schemas = match crate::fetch::cache_dir() {
            Some(dir) if dir.exists() => Self::load_dir(&dir).unwrap_or_default(),
            _ => HashMap::new(),
        };
        #[cfg(not(feature = "fetch"))]
        let mut schemas = HashMap::new();
        // Directory schemas override cache
        let dir_schemas = Self::load_dir(schema_dir)?;
        schemas.extend(dir_schemas);
        Self::finish(Some(schema_dir.to_path_buf()), schemas)
    }

    fn load_dir(schema_dir: &Path) -> Result<HashMap<String, Schema>> {
        let mut schemas = HashMap::new();

        let entries = std::fs::read_dir(schema_dir).with_context(|| {
            format!("failed to read schema directory: {}", schema_dir.display())
        })?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json") {
                // Root-level schema → @this namespace
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| anyhow::anyhow!("invalid filename: {}", path.display()))?
                    .to_string();
                let s = Self::load_schema_file(&path)?;
                schemas.insert(name, s);
            } else if path.is_dir() {
                let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if !dir_name.starts_with('@') {
                    continue;
                }
                let org = &dir_name[1..];

                // Scan repo directories inside @org/
                let repo_entries = std::fs::read_dir(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                for repo_entry in repo_entries {
                    let repo_entry = repo_entry?;
                    let repo_path = repo_entry.path();
                    if !repo_path.is_dir() {
                        continue;
                    }
                    let repo = repo_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                    // Scan .json files inside @org/repo/
                    let schema_entries = std::fs::read_dir(&repo_path)
                        .with_context(|| format!("failed to read {}", repo_path.display()))?;
                    for schema_entry in schema_entries {
                        let schema_entry = schema_entry?;
                        let schema_path = schema_entry.path();
                        if schema_path.extension().and_then(|e| e.to_str()) != Some("json") {
                            continue;
                        }
                        let name = schema_path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .ok_or_else(|| {
                                anyhow::anyhow!("invalid filename: {}", schema_path.display())
                            })?;
                        let key = format!("@{}/{}/{}", org, repo, name);
                        let s = Self::load_schema_file(&schema_path)?;
                        schemas.insert(key, s);
                    }
                }
            }
        }

        Ok(schemas)
    }

    fn finish(schema_dir: Option<PathBuf>, mut schemas: HashMap<String, Schema>) -> Result<Self> {
        // Synthetic catch-all schema for inference (single hex field eats all bytes)
        schemas.insert(
            CATCHALL_KEY.to_string(),
            Schema {
                about: None,
                params: vec![],
                fields: Some(vec![Field::Named {
                    name: CATCHALL_FIELD.to_string(),
                    field_type: schema::FieldType::Hex,
                    help: None,
                }]),
                ref_: None,
            },
        );

        Ok(Self {
            schema_dir,
            schemas,
            runtime_cache: RefCell::new(RuntimeCache {
                schemas: HashMap::new(),
                #[cfg(feature = "fetch")]
                fetch: FetchCache::new(),
            }),
        })
    }

    fn load_schema_file(path: &Path) -> Result<Schema> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse JSON in {}", path.display()))?;
        schema::parse_schema(value).with_context(|| format!("invalid schema in {}", path.display()))
    }

    /// List all loaded schema names.
    pub fn schemas(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .schemas
            .keys()
            .filter(|k| k.as_str() != CATCHALL_KEY)
            .map(|s| s.as_str())
            .collect();
        names.sort();
        names
    }

    /// Get a schema by name.
    pub fn get(&self, name: &str) -> Option<&Schema> {
        self.schemas.get(name)
    }

    /// Return schema names that have no type parameters (ground schemas).
    /// These are the schemas that can be used for inference.
    pub fn ground_schemas(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .schemas
            .iter()
            .filter(|(k, s)| s.params.is_empty() && k.as_str() != CATCHALL_KEY)
            .map(|(k, _)| k.as_str())
            .collect();
        names.sort();
        names
    }

    /// Try to infer the schema from raw binary data.
    ///
    /// Uses a greedy+recursive approach:
    /// 1. Try non-catch-all ground schemas directly.
    /// 2. Try each single-param schema with a synthetic catch-all inner type.
    ///    If it parses, extract the captured inner bytes and recursively infer.
    /// 3. Fall back to catch-all ground schemas (hex-payload, etc.).
    pub fn infer(&self, data: &[u8]) -> Result<(String, serde_json::Value)> {
        self.infer_recursive(data, 0)
    }

    /// Maximum recursion depth for inference (prevents infinite loops).
    const MAX_INFER_DEPTH: usize = 8;

    fn infer_recursive(&self, data: &[u8], depth: usize) -> Result<(String, serde_json::Value)> {
        if depth > Self::MAX_INFER_DEPTH {
            bail!(
                "inference exceeded maximum depth of {}",
                Self::MAX_INFER_DEPTH
            );
        }

        let ground = self.ground_schemas();

        // Partition: specific vs catch-all
        let mut specific = Vec::new();
        let mut catchall = Vec::new();
        for name in &ground {
            if self.is_catchall(name) {
                catchall.push(*name);
            } else {
                specific.push(*name);
            }
        }

        // Pass 1: try specific ground schemas
        for name in &specific {
            if let Ok(parsed) = self.parse(name, data) {
                return Ok((name.to_string(), parsed));
            }
        }

        // Pass 2: try single-param schemas with the synthetic catch-all
        let mut parameterized: Vec<&str> = self
            .schemas
            .iter()
            .filter(|(k, s)| s.params.len() == 1 && k.as_str() != CATCHALL_KEY)
            .map(|(k, _)| k.as_str())
            .collect();
        parameterized.sort();

        for outer in &parameterized {
            let greedy_ref = format!("{}<{}>", outer, CATCHALL_KEY);
            let greedy_parsed = match self.parse(&greedy_ref, data) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Extract the captured inner bytes from __payload__
            let inner_hex = match find_field(&greedy_parsed, CATCHALL_FIELD) {
                Some(h) => h,
                None => continue,
            };
            let inner_bytes = match hex::decode(&inner_hex) {
                Ok(b) => b,
                Err(_) => continue,
            };

            // Recursively infer the inner payload
            if let Ok((inner_name, _)) = self.infer_recursive(&inner_bytes, depth + 1) {
                // Construct the fully-qualified ref and do a real parse
                let full_ref = format!("{}<{}>", outer, inner_name);
                if let Ok(final_parsed) = self.parse(&full_ref, data) {
                    return Ok((full_ref, final_parsed));
                }
            }

            // If recursive refinement failed, the outer still matched with catch-all.
            // We could return outer<hex-payload> but that's not very useful — keep trying
            // other outers.
        }

        // Pass 3: catch-all ground schemas as last resort
        for name in &catchall {
            if let Ok(parsed) = self.parse(name, data) {
                return Ok((name.to_string(), parsed));
            }
        }

        bail!(
            "could not infer schema: no schema matched the {} byte payload",
            data.len()
        )
    }

    /// True if the schema is a catch-all (single hex field, or empty fields).
    fn is_catchall(&self, name: &str) -> bool {
        let Some(schema) = self.schemas.get(name) else {
            return false;
        };
        let Some(fields) = &schema.fields else {
            return false;
        };
        match fields.len() {
            0 => true, // empty schema
            1 => matches!(
                &fields[0],
                Field::Named {
                    field_type: schema::FieldType::Hex,
                    ..
                }
            ),
            _ => false,
        }
    }

    /// Collect all named fields (arguments) for a schema ref string.
    ///
    /// The `ref_str` can be:
    /// - A plain name: `"onboard"`
    /// - A parameterized ref: `"transceiver-message<ntt-manager-message<native-token-transfer>>"`
    /// - A full scoped ref: `"@this/route"`
    pub fn args(&self, ref_str: &str) -> Result<Vec<ArgInfo>> {
        let parsed = self.normalize_ref(ref_str)?;
        let mut visited = HashSet::new();
        self.collect_args_recursive(&parsed, &BTreeMap::new(), &mut visited)
    }

    /// Serialize a schema's payload given field values as a JSON object.
    pub fn serialize(&self, ref_str: &str, values: &serde_json::Value) -> Result<Vec<u8>> {
        let parsed = self.normalize_ref(ref_str)?;

        // Pre-validate: collect all missing fields across the entire schema tree
        let mut missing = Vec::new();
        let mut visited = HashSet::new();
        self.collect_missing_recursive(
            &parsed,
            &BTreeMap::new(),
            values,
            &mut visited,
            &mut missing,
        )?;
        if !missing.is_empty() {
            bail!("missing fields: {}", missing.join(", "));
        }

        visited.clear();
        let mut output = Vec::new();
        self.serialize_recursive(&parsed, &BTreeMap::new(), values, &mut output, &mut visited)?;
        Ok(output)
    }

    /// Normalize a user-supplied ref string into a ParsedRef.
    /// Bare names (no `@` prefix) are resolved by searching loaded schemas
    /// for a unique match on the trailing name segment. Falls back to `@this/name`.
    /// All `Param` nodes are converted to `@this/` refs since user-facing
    /// strings never contain type variables — those only appear in schema files.
    fn normalize_ref(&self, ref_str: &str) -> Result<ParsedRef> {
        let ref_str = ref_str.trim();
        let resolved = if ref_str.starts_with('@') {
            ref_str.to_string()
        } else {
            self.resolve_short_name(ref_str)
        };
        let parsed = refs::parse_ref(&resolved)?;
        Ok(Self::params_to_this(parsed))
    }

    /// Resolve a bare name (like `onboard` or `vaa<onboard>`) to a fully
    /// scoped ref string by matching against loaded schema names.
    fn resolve_short_name(&self, name: &str) -> String {
        // Already fully qualified — return as-is
        if name.starts_with('@') {
            return name.to_string();
        }

        // Extract the base name (before any angle brackets)
        let base = name.split('<').next().unwrap_or(name);

        // Search for loaded schemas whose last path segment matches
        let matches: Vec<&str> = self
            .schemas
            .keys()
            .filter(|k| k.rsplit('/').next() == Some(base))
            .map(|k| k.as_str())
            .collect();

        if matches.len() == 1 {
            // Unique match: replace the bare base name with the full scoped name
            let full_base = matches[0];
            if name.contains('<') {
                // Has angle brackets — replace just the base part, recursively
                // resolving the inner args too
                let scope = &full_base[..full_base.rfind('/').unwrap()];
                self.resolve_short_ref_recursive(name, scope)
            } else {
                full_base.to_string()
            }
        } else {
            // Ambiguous or not found — fall back to @this/ prefix
            format!("@this/{}", name)
        }
    }

    /// Recursively resolve bare names in a ref string like `vaa<onboard>`.
    fn resolve_short_ref_recursive(&self, ref_str: &str, _default_scope: &str) -> String {
        // Split into base<args>
        if let Some(open) = ref_str.find('<') {
            let base = &ref_str[..open];
            // Find matching close bracket
            let inner = &ref_str[open + 1..ref_str.len() - 1];
            let resolved_base = self.resolve_short_name(base);

            // Resolve inner args (split by top-level commas)
            let resolved_args = self.resolve_short_name(inner);
            format!("{}<{}>", resolved_base, resolved_args)
        } else {
            self.resolve_short_name(ref_str)
        }
    }

    /// Recursively convert all Param nodes to @this/ Concrete refs.
    /// Used for user-facing API where bare names are schema refs, not type variables.
    fn params_to_this(parsed: ParsedRef) -> ParsedRef {
        match parsed {
            ParsedRef::Param(name) => {
                // If the param name contains '<', it was a bare ref with args
                // that the parser couldn't handle without scope. Re-parse with @this/.
                if name.contains('<') {
                    let full = format!("@this/{}", name);
                    match refs::parse_ref(&full) {
                        Ok(reparsed) => Self::params_to_this(reparsed),
                        Err(_) => ParsedRef::Concrete {
                            scope: Scope::This,
                            name,
                            args: vec![],
                        },
                    }
                } else {
                    ParsedRef::Concrete {
                        scope: Scope::This,
                        name,
                        args: vec![],
                    }
                }
            }
            ParsedRef::Concrete { scope, name, args } => ParsedRef::Concrete {
                scope,
                name,
                args: args.into_iter().map(Self::params_to_this).collect(),
            },
        }
    }

    /// Rewrite `@this/` ref strings inside field-level refs to a remote scope.
    fn rewrite_field_this_scope(fields: &[Field], org: &str, repo: &str) -> Vec<Field> {
        fields
            .iter()
            .map(|f| match f {
                Field::Ref { ref_, name } => Field::Ref {
                    ref_: Self::rewrite_ref_str(ref_, org, repo),
                    name: name.clone(),
                },
                Field::Repeat {
                    name,
                    count_field,
                    ref_,
                } => Field::Repeat {
                    name: name.clone(),
                    count_field: count_field.clone(),
                    ref_: Self::rewrite_ref_str(ref_, org, repo),
                },
                Field::Option {
                    name,
                    inner,
                    compact,
                    help,
                } => {
                    let inner = match inner {
                        OptionInner::Fields(fields) => {
                            OptionInner::Fields(Self::rewrite_field_this_scope(fields, org, repo))
                        }
                        other => other.clone(),
                    };
                    Field::Option {
                        name: name.clone(),
                        inner,
                        compact: *compact,
                        help: help.clone(),
                    }
                }
                other => other.clone(),
            })
            .collect()
    }

    /// Rewrite a ref string's `@this/` prefix to `@org/repo/`, handling
    /// nested angle-bracket args via parse/rewrite/format.
    fn rewrite_ref_str(s: &str, org: &str, repo: &str) -> String {
        if !s.contains("@this/") {
            return s.to_string();
        }
        match refs::parse_ref(s) {
            Ok(parsed) => {
                let rewritten = refs::rewrite_this_scope(&parsed, org, repo);
                refs::format_ref(&rewritten)
            }
            Err(_) => s.to_string(),
        }
    }

    /// Recursively replace Param nodes with their bindings.
    fn substitute_params(parsed: &ParsedRef, bindings: &BTreeMap<String, ParsedRef>) -> ParsedRef {
        match parsed {
            ParsedRef::Param(name) => {
                if let Some(bound) = bindings.get(name) {
                    bound.clone()
                } else {
                    parsed.clone()
                }
            }
            ParsedRef::Concrete { scope, name, args } => ParsedRef::Concrete {
                scope: scope.clone(),
                name: name.clone(),
                args: args
                    .iter()
                    .map(|a| Self::substitute_params(a, bindings))
                    .collect(),
            },
        }
    }

    /// Resolve a ParsedRef to its fields, applying param bindings.
    ///
    /// The `visited` set tracks currently-being-resolved refs for cycle detection.
    /// It is created fresh per top-level call (args/serialize/parse), so entries
    /// from failed inner calls are discarded when the top-level call fails.
    fn resolve_fields(
        &self,
        parsed: &ParsedRef,
        bindings: &BTreeMap<String, ParsedRef>,
        visited: &mut HashSet<String>,
    ) -> Result<(Vec<Field>, BTreeMap<String, ParsedRef>)> {
        match parsed {
            ParsedRef::Param(name) => {
                if let Some(bound) = bindings.get(name) {
                    self.resolve_fields(bound, bindings, visited)
                } else {
                    bail!("unbound type parameter: {}", name);
                }
            }
            ParsedRef::Concrete { scope, name, args } => {
                let visit_key = refs::format_ref(parsed);
                if visited.contains(&visit_key) {
                    bail!("circular reference detected: {}", visit_key);
                }
                visited.insert(visit_key.clone());

                if visited.len() > MAX_NESTING_DEPTH {
                    bail!(
                        "maximum schema nesting depth ({}) exceeded",
                        MAX_NESTING_DEPTH
                    );
                }

                let schema = self.load_schema(scope, name)?;

                // Bind params to args
                if args.len() != schema.params.len() {
                    bail!(
                        "schema '{}' expects {} params, got {}",
                        name,
                        schema.params.len(),
                        args.len()
                    );
                }
                let mut new_bindings = bindings.clone();
                for (param, arg) in schema.params.iter().zip(args.iter()) {
                    // Rewrite @this/ scope for remote schemas
                    let rewritten = match scope {
                        Scope::Remote { org, repo } => refs::rewrite_this_scope(arg, org, repo),
                        Scope::This => arg.clone(),
                    };
                    // Resolve any param refs in the arg against current bindings,
                    // so that e.g. vaa-body<A> where A is already bound to @this/onboard
                    // correctly binds vaa-body's A to @this/onboard, not to Param("A").
                    let resolved = Self::substitute_params(&rewritten, bindings);
                    new_bindings.insert(param.clone(), resolved);
                }

                // Get fields: either inline or from ref
                let (fields, result_bindings) = if let Some(ref ref_str) = schema.ref_ {
                    let mut inner_ref = refs::parse_ref(ref_str)?;
                    // Rewrite @this/ in the ref for remote schemas
                    if let Scope::Remote { org, repo } = scope {
                        inner_ref = refs::rewrite_this_scope(&inner_ref, org, repo);
                    }
                    self.resolve_fields(&inner_ref, &new_bindings, visited)?
                } else if let Some(ref fields) = schema.fields {
                    // Rewrite @this/ in field-level refs for remote schemas
                    let fields = match scope {
                        Scope::Remote { org, repo } => {
                            Self::rewrite_field_this_scope(fields, org, repo)
                        }
                        Scope::This => fields.clone(),
                    };
                    (fields, new_bindings)
                } else {
                    bail!("schema '{}' has neither fields nor ref", name);
                };

                visited.remove(&visit_key);
                Ok((fields, result_bindings))
            }
        }
    }

    /// Load a schema by scope and name.
    ///
    /// For remote refs (`@org/repo/name`), checks init-time schemas first,
    /// then the runtime cache, then falls back to fetching from GitHub.
    fn load_schema(&self, scope: &Scope, name: &str) -> Result<Schema> {
        // Synthetic catch-all lives in local scope regardless of how it's referenced
        if name == CATCHALL_KEY {
            return self
                .schemas
                .get(CATCHALL_KEY)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("schema not found: {}", name));
        }
        match scope {
            Scope::This => self
                .schemas
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("schema not found: {}", name)),
            Scope::Remote { org, repo } => {
                let cache_key = format!("@{}/{}/{}", org, repo, name);

                // Check init-time schemas (locally bundled remote schemas)
                if let Some(schema) = self.schemas.get(&cache_key) {
                    return Ok(schema.clone());
                }

                // Check runtime cache
                {
                    let cache = self.runtime_cache.borrow();
                    if let Some(schema) = cache.schemas.get(&cache_key) {
                        return Ok(schema.clone());
                    }
                }

                // Try local file: schema_dir/@org/repo/name.json
                let local_path = self.schema_dir.as_ref().map(|d| {
                    d.join(format!("@{}", org))
                        .join(repo)
                        .join(format!("{}.json", name))
                });

                let value = if local_path.as_ref().is_some_and(|p| p.exists()) {
                    let lp = local_path.unwrap();
                    let contents = std::fs::read_to_string(&lp)
                        .with_context(|| format!("failed to read {}", lp.display()))?;
                    serde_json::from_str::<serde_json::Value>(&contents)
                        .with_context(|| format!("failed to parse JSON in {}", lp.display()))?
                } else {
                    #[cfg(feature = "fetch")]
                    {
                        self.runtime_cache
                            .borrow_mut()
                            .fetch
                            .fetch(org, repo, name)?
                    }
                    #[cfg(not(feature = "fetch"))]
                    {
                        bail!(
                            "remote schema {} not found locally and network fetching is disabled \
                             (enable the `fetch` feature to fetch from GitHub)",
                            cache_key
                        )
                    }
                };

                let schema = schema::parse_schema(value)
                    .with_context(|| format!("invalid remote schema: {}", cache_key))?;
                self.runtime_cache
                    .borrow_mut()
                    .schemas
                    .insert(cache_key, schema.clone());
                Ok(schema)
            }
        }
    }

    /// Recursively collect argument info from a parsed ref.
    fn collect_args_recursive(
        &self,
        parsed: &ParsedRef,
        bindings: &BTreeMap<String, ParsedRef>,
        visited: &mut HashSet<String>,
    ) -> Result<Vec<ArgInfo>> {
        let (fields, new_bindings) = self.resolve_fields(parsed, bindings, visited)?;

        let mut args = Vec::new();
        let mut i = 0;
        while i < fields.len() {
            match &fields[i] {
                Field::Named {
                    name,
                    field_type,
                    help,
                } => {
                    args.push(ArgInfo {
                        name: name.clone(),
                        field_type: field_type.to_string(),
                        help: help.clone(),
                        enum_values: None,
                    });
                }
                Field::Enum {
                    name,
                    encoding,
                    values,
                    help,
                } => {
                    let variant_names: Vec<String> =
                        values.iter().map(|(n, _)| n.clone()).collect();
                    args.push(ArgInfo {
                        name: name.clone(),
                        field_type: format!("enum({})", encoding),
                        help: help.clone(),
                        enum_values: Some(variant_names),
                    });
                }
                Field::Ref { ref_, .. } => {
                    let inner = if ref_.starts_with('@') {
                        refs::parse_ref(ref_)?
                    } else {
                        // Could be a param
                        ParsedRef::Param(ref_.clone())
                    };
                    let inner_args = self.collect_args_recursive(&inner, &new_bindings, visited)?;
                    args.extend(inner_args);
                }
                Field::LengthPrefix(_) => {
                    // Skip — the next field (ref) will handle collection
                }
                Field::Repeat { name, .. } => {
                    // Array field — user provides concatenated hex blob
                    args.push(ArgInfo {
                        name: name.clone(),
                        field_type: "hex".to_string(),
                        help: None,
                        enum_values: None,
                    });
                }
                Field::Option {
                    name, inner, help, ..
                } => {
                    let type_str = match inner {
                        OptionInner::Type(ft) => format!("option({})", ft),
                        OptionInner::Fields(_) => "option(struct)".to_string(),
                    };
                    args.push(ArgInfo {
                        name: name.clone(),
                        field_type: type_str,
                        help: help.clone(),
                        enum_values: None,
                    });
                }
                Field::Const { .. } | Field::Zeros(_) => {
                    // No user input needed
                }
            }
            i += 1;
        }

        Ok(args)
    }

    /// Walk the schema tree and collect names of missing Named fields.
    fn collect_missing_recursive(
        &self,
        parsed: &ParsedRef,
        bindings: &BTreeMap<String, ParsedRef>,
        values: &serde_json::Value,
        visited: &mut HashSet<String>,
        missing: &mut Vec<String>,
    ) -> Result<()> {
        let (fields, new_bindings) = self.resolve_fields(parsed, bindings, visited)?;
        self.collect_missing_fields(&fields, &new_bindings, values, visited, missing)
    }

    fn collect_missing_fields(
        &self,
        fields: &[Field],
        bindings: &BTreeMap<String, ParsedRef>,
        values: &serde_json::Value,
        visited: &mut HashSet<String>,
        missing: &mut Vec<String>,
    ) -> Result<()> {
        let mut i = 0;
        while i < fields.len() {
            match &fields[i] {
                Field::Named { name, .. } | Field::Enum { name, .. } => {
                    if values.get(name).and_then(|v| v.as_str()).is_none() {
                        missing.push(name.clone());
                    }
                }
                Field::LengthPrefix(_) => {
                    i += 1;
                    if i >= fields.len() {
                        break;
                    }
                    if let Field::Ref { ref_, name } = &fields[i] {
                        let inner = if ref_.starts_with('@') {
                            refs::parse_ref(ref_)?
                        } else {
                            ParsedRef::Param(ref_.clone())
                        };
                        let inner_values = if let Some(name) = name {
                            values.get(name).unwrap_or(values)
                        } else {
                            values
                        };
                        self.collect_missing_recursive(
                            &inner,
                            bindings,
                            inner_values,
                            visited,
                            missing,
                        )?;
                    }
                }
                Field::Ref { ref_, name } => {
                    let inner = if ref_.starts_with('@') {
                        refs::parse_ref(ref_)?
                    } else {
                        ParsedRef::Param(ref_.clone())
                    };
                    let inner_values = if let Some(name) = name {
                        values.get(name).unwrap_or(values)
                    } else {
                        values
                    };
                    self.collect_missing_recursive(
                        &inner,
                        bindings,
                        inner_values,
                        visited,
                        missing,
                    )?;
                }
                Field::Option { .. } => {
                    // Option fields are never required
                }
                Field::Const { .. } | Field::Zeros(_) | Field::Repeat { .. } => {}
            }
            i += 1;
        }
        Ok(())
    }

    /// Recursively serialize fields from a parsed ref.
    fn serialize_recursive(
        &self,
        parsed: &ParsedRef,
        bindings: &BTreeMap<String, ParsedRef>,
        values: &serde_json::Value,
        output: &mut Vec<u8>,
        visited: &mut HashSet<String>,
    ) -> Result<()> {
        let (fields, new_bindings) = self.resolve_fields(parsed, bindings, visited)?;
        self.serialize_fields(&fields, &new_bindings, values, output, visited)
    }

    /// Serialize a list of fields.
    fn serialize_fields(
        &self,
        fields: &[Field],
        bindings: &BTreeMap<String, ParsedRef>,
        values: &serde_json::Value,
        output: &mut Vec<u8>,
        visited: &mut HashSet<String>,
    ) -> Result<()> {
        let mut i = 0;
        while i < fields.len() {
            match &fields[i] {
                Field::Const { name, value } => {
                    let bytes = hex::decode(value)
                        .with_context(|| format!("invalid const hex for '{}': {}", name, value))?;
                    output.extend_from_slice(&bytes);
                }
                Field::Zeros(n) => {
                    output.extend(std::iter::repeat_n(0u8, *n));
                }
                Field::Named {
                    name, field_type, ..
                } => {
                    let val = values
                        .get(name)
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("missing value for field '{}'", name))?;
                    serialize::serialize_field(field_type, val, output)
                        .with_context(|| format!("serializing field '{}'", name))?;
                }
                Field::Enum {
                    name,
                    encoding,
                    values: variants,
                    ..
                } => {
                    let variant_name =
                        values.get(name).and_then(|v| v.as_str()).ok_or_else(|| {
                            anyhow::anyhow!("missing value for enum field '{}'", name)
                        })?;
                    let disc = variants
                        .iter()
                        .find(|(n, _)| n == variant_name)
                        .map(|(_, v)| *v)
                        .ok_or_else(|| {
                            let valid: Vec<&str> =
                                variants.iter().map(|(n, _)| n.as_str()).collect();
                            anyhow::anyhow!(
                                "unknown variant '{}' for enum field '{}' (valid: {})",
                                variant_name,
                                name,
                                valid.join(", ")
                            )
                        })?;
                    serialize::serialize_field(encoding, &disc.to_string(), output)
                        .with_context(|| format!("serializing enum field '{}'", name))?;
                }
                Field::LengthPrefix(size_type) => {
                    // Next field must be a ref; serialize it into a temp buffer to get the length
                    i += 1;
                    if i >= fields.len() {
                        bail!("length_prefix at end of fields with no following ref");
                    }
                    let next = &fields[i];
                    let mut inner_buf = Vec::new();
                    match next {
                        Field::Ref { ref_, name } => {
                            let inner = if ref_.starts_with('@') {
                                refs::parse_ref(ref_)?
                            } else {
                                ParsedRef::Param(ref_.clone())
                            };
                            // If the ref has a name, look up the nested object; otherwise use same values
                            let inner_values = if let Some(name) = name {
                                values.get(name).unwrap_or(values)
                            } else {
                                values
                            };
                            self.serialize_recursive(
                                &inner,
                                bindings,
                                inner_values,
                                &mut inner_buf,
                                visited,
                            )?;
                        }
                        _ => bail!("length_prefix must be followed by a ref field"),
                    }

                    // Write the length
                    match size_type.as_str() {
                        "u16be" => {
                            let len: u16 = inner_buf.len().try_into().with_context(|| {
                                format!(
                                    "payload too large for u16 length prefix: {}",
                                    inner_buf.len()
                                )
                            })?;
                            output.extend_from_slice(&len.to_be_bytes());
                        }
                        other => bail!("unsupported length_prefix type: {}", other),
                    }
                    output.extend_from_slice(&inner_buf);
                }
                Field::Ref { ref_, name } => {
                    let inner = if ref_.starts_with('@') {
                        refs::parse_ref(ref_)?
                    } else {
                        ParsedRef::Param(ref_.clone())
                    };
                    // If the ref has a name, look up the nested object; otherwise use same values
                    let inner_values = if let Some(name) = name {
                        values.get(name).unwrap_or(values)
                    } else {
                        values
                    };
                    self.serialize_recursive(&inner, bindings, inner_values, output, visited)?;
                }
                Field::Repeat {
                    name,
                    count_field,
                    ref_,
                } => {
                    let arr = values
                        .get(name)
                        .and_then(|v| v.as_array())
                        .map(|a| a.as_slice())
                        .unwrap_or(&[]);

                    // Validate array length matches the count field
                    let expected_count: usize = values
                        .get(count_field)
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    if arr.len() != expected_count {
                        bail!(
                            "repeat '{}': array has {} items but '{}' is {}",
                            name,
                            arr.len(),
                            count_field,
                            expected_count,
                        );
                    }

                    let inner = if ref_.starts_with('@') {
                        refs::parse_ref(ref_)?
                    } else {
                        ParsedRef::Param(ref_.clone())
                    };
                    for (idx, item) in arr.iter().enumerate() {
                        self.serialize_recursive(&inner, bindings, item, output, visited)
                            .with_context(|| {
                                format!("serializing repeat '{}' item {}", name, idx)
                            })?;
                    }
                }
                Field::Option {
                    name,
                    inner,
                    compact,
                    ..
                } => {
                    let val = values.get(name);
                    let is_none = val.is_none() || val == Some(&serde_json::Value::Null);

                    if is_none {
                        // Write None tag
                        output.push(0x00);
                        // In fixed mode, pad with zeros to match inner size
                        if !compact {
                            let pad = schema::option_inner_size(inner)
                                .expect("non-compact option must have fixed size");
                            output.extend(std::iter::repeat_n(0u8, pad));
                        }
                    } else {
                        // Write Some tag
                        output.push(0x01);
                        match inner {
                            OptionInner::Type(ft) => {
                                let s = val.unwrap().as_str().ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "option field '{}': expected string value",
                                        name
                                    )
                                })?;
                                serialize::serialize_field(ft, s, output).with_context(|| {
                                    format!("serializing option field '{}'", name)
                                })?;
                            }
                            OptionInner::Fields(fields) => {
                                let obj = val.unwrap();
                                self.serialize_fields(fields, bindings, obj, output, visited)
                                    .with_context(|| {
                                        format!("serializing option field '{}'", name)
                                    })?;
                            }
                        }
                    }
                }
            }
            i += 1;
        }
        Ok(())
    }

    // ----- Parsing (binary → JSON) -----

    /// Parse a binary payload back into a JSON object using a schema ref string.
    pub fn parse(&self, ref_str: &str, data: &[u8]) -> Result<serde_json::Value> {
        let parsed = self.normalize_ref(ref_str)?;
        let mut cursor = Cursor::new(data);
        let mut visited = HashSet::new();
        let map = self.parse_recursive(&parsed, &BTreeMap::new(), &mut cursor, &mut visited)?;
        cursor
            .assert_exhausted()
            .context("trailing bytes after parsing")?;
        Ok(serde_json::Value::Object(map))
    }

    /// Recursively resolve a ref to its fields and parse them from the cursor.
    fn parse_recursive(
        &self,
        parsed: &ParsedRef,
        bindings: &BTreeMap<String, ParsedRef>,
        cursor: &mut Cursor,
        visited: &mut HashSet<String>,
    ) -> Result<serde_json::Map<String, serde_json::Value>> {
        let (fields, new_bindings) = self.resolve_fields(parsed, bindings, visited)?;
        self.parse_fields(&fields, &new_bindings, cursor, visited)
    }

    /// Walk a field list sequentially, parsing each field from the cursor.
    fn parse_fields(
        &self,
        fields: &[Field],
        bindings: &BTreeMap<String, ParsedRef>,
        cursor: &mut Cursor,
        visited: &mut HashSet<String>,
    ) -> Result<serde_json::Map<String, serde_json::Value>> {
        let mut map = serde_json::Map::new();
        let mut i = 0;
        while i < fields.len() {
            match &fields[i] {
                Field::Const { name, value } => {
                    let expected = hex::decode(value)
                        .with_context(|| format!("invalid const hex for '{}': {}", name, value))?;
                    let actual = cursor
                        .read_bytes(expected.len())
                        .with_context(|| format!("reading const field '{}'", name))?;
                    if actual != expected.as_slice() {
                        bail!(
                            "const field '{}' mismatch at offset {}: expected {}, got {}",
                            name,
                            cursor.position() - expected.len(),
                            value,
                            hex::encode(actual)
                        );
                    }
                }
                Field::Zeros(n) => {
                    let actual = cursor
                        .read_bytes(*n)
                        .with_context(|| format!("reading {} zero bytes", n))?;
                    if actual.iter().any(|&b| b != 0) {
                        bail!(
                            "expected {} zero bytes at offset {}, got {}",
                            n,
                            cursor.position() - n,
                            hex::encode(actual)
                        );
                    }
                }
                Field::Named {
                    name, field_type, ..
                } => {
                    let val = parse::parse_field(field_type, cursor)
                        .with_context(|| format!("parsing field '{}'", name))?;
                    map.insert(name.clone(), serde_json::Value::String(val));
                }
                Field::Enum {
                    name,
                    encoding,
                    values: variants,
                    ..
                } => {
                    let raw = parse::parse_field(encoding, cursor)
                        .with_context(|| format!("parsing enum field '{}'", name))?;
                    let disc: u64 = raw.parse().with_context(|| {
                        format!("enum field '{}': invalid discriminant '{}'", name, raw)
                    })?;
                    let variant_name = variants
                        .iter()
                        .find(|(_, v)| *v == disc)
                        .map(|(n, _)| n.as_str())
                        .ok_or_else(|| {
                            let valid: Vec<String> = variants
                                .iter()
                                .map(|(n, v)| format!("{}={}", n, v))
                                .collect();
                            anyhow::anyhow!(
                                "unknown discriminant {} for enum field '{}' (valid: {})",
                                disc,
                                name,
                                valid.join(", ")
                            )
                        })?;
                    map.insert(
                        name.clone(),
                        serde_json::Value::String(variant_name.to_string()),
                    );
                }
                Field::LengthPrefix(size_type) => {
                    // Read the length, create a sub-cursor, parse the next Ref within it
                    let len: usize = match size_type.as_str() {
                        "u16be" => {
                            let b = cursor.read_bytes(2)?;
                            u16::from_be_bytes([b[0], b[1]]) as usize
                        }
                        other => bail!("unsupported length_prefix type: {}", other),
                    };
                    i += 1;
                    if i >= fields.len() {
                        bail!("length_prefix at end of fields with no following ref");
                    }
                    let next = &fields[i];
                    match next {
                        Field::Ref { ref_, name } => {
                            let mut sub = cursor.sub_cursor(len).with_context(|| {
                                format!("creating sub-cursor for length-prefixed ref '{}'", ref_)
                            })?;
                            let inner = if ref_.starts_with('@') {
                                refs::parse_ref(ref_)?
                            } else {
                                ParsedRef::Param(ref_.clone())
                            };
                            let inner_map =
                                self.parse_recursive(&inner, bindings, &mut sub, visited)?;
                            sub.assert_exhausted().with_context(|| {
                                format!(
                                    "length-prefixed ref '{}' did not consume all {} bytes",
                                    ref_, len
                                )
                            })?;
                            if let Some(name) = name {
                                map.insert(name.clone(), serde_json::Value::Object(inner_map));
                            } else {
                                for (k, v) in inner_map {
                                    map.insert(k, v);
                                }
                            }
                        }
                        _ => bail!("length_prefix must be followed by a ref field"),
                    }
                }
                Field::Ref { ref_, name } => {
                    let inner = if ref_.starts_with('@') {
                        refs::parse_ref(ref_)?
                    } else {
                        ParsedRef::Param(ref_.clone())
                    };
                    let inner_map = self.parse_recursive(&inner, bindings, cursor, visited)?;
                    if let Some(name) = name {
                        map.insert(name.clone(), serde_json::Value::Object(inner_map));
                    } else {
                        for (k, v) in inner_map {
                            map.insert(k, v);
                        }
                    }
                }
                Field::Repeat {
                    name,
                    count_field,
                    ref_,
                } => {
                    // Look up the count from a previously-parsed field
                    let count_val =
                        map.get(count_field)
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "repeat field '{}' references count field '{}' not yet parsed",
                                    name,
                                    count_field
                                )
                            })?;
                    let count: usize = count_val.parse().with_context(|| {
                        format!(
                            "count field '{}' is not a valid integer: {}",
                            count_field, count_val
                        )
                    })?;
                    if count > MAX_REPEAT_COUNT {
                        bail!(
                            "repeat count {} exceeds maximum of {} for field '{}'",
                            count,
                            MAX_REPEAT_COUNT,
                            name
                        );
                    }
                    let inner = if ref_.starts_with('@') {
                        refs::parse_ref(ref_)?
                    } else {
                        ParsedRef::Param(ref_.clone())
                    };
                    let mut items = Vec::with_capacity(count);
                    for idx in 0..count {
                        let item_map = self
                            .parse_recursive(&inner, bindings, cursor, visited)
                            .with_context(|| {
                                format!("parsing repeat '{}' item {}/{}", name, idx + 1, count)
                            })?;
                        items.push(serde_json::Value::Object(item_map));
                    }
                    map.insert(name.clone(), serde_json::Value::Array(items));
                }
                Field::Option {
                    name,
                    inner,
                    compact,
                    ..
                } => {
                    let tag = cursor
                        .read_bytes(1)
                        .with_context(|| format!("reading option tag for '{}'", name))?[0];

                    match tag {
                        0 => {
                            // None — skip padding in fixed mode
                            if !compact {
                                let pad = schema::option_inner_size(inner)
                                    .expect("non-compact option must have fixed size");
                                cursor.read_bytes(pad).with_context(|| {
                                    format!("skipping option padding for '{}'", name)
                                })?;
                            }
                            map.insert(name.clone(), serde_json::Value::Null);
                        }
                        1 => {
                            // Some — parse inner
                            match inner {
                                OptionInner::Type(ft) => {
                                    let val =
                                        parse::parse_field(ft, cursor).with_context(|| {
                                            format!("parsing option field '{}'", name)
                                        })?;
                                    map.insert(name.clone(), serde_json::Value::String(val));
                                }
                                OptionInner::Fields(fields) => {
                                    let inner_map = self
                                        .parse_fields(fields, bindings, cursor, visited)
                                        .with_context(|| {
                                            format!("parsing option field '{}'", name)
                                        })?;
                                    map.insert(name.clone(), serde_json::Value::Object(inner_map));
                                }
                            }
                        }
                        other => {
                            bail!(
                                "invalid option tag {} for field '{}' (expected 0 or 1)",
                                other,
                                name
                            );
                        }
                    }
                }
            }
            i += 1;
        }
        Ok(map)
    }
}

/// Recursively search a JSON value for a field with the given key.
/// Returns the string value if found.
fn find_field(value: &serde_json::Value, key: &str) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(v) = map.get(key) {
                return v.as_str().map(|s| s.to_string());
            }
            for v in map.values() {
                if let Some(found) = find_field(v, key) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                if let Some(found) = find_field(v, key) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}
