use anyhow::{bail, Context, Result};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

#[cfg(feature = "fetch")]
use crate::fetch::FetchCache;
use crate::parse::{self, Cursor};
use crate::refs::{self, ParsedRef, Scope};
use crate::schema::{self, Field, Schema};
use crate::serialize::{self, ArgInfo};

/// Maximum nesting depth for schema resolution (prevents stack overflow from
/// malicious or deeply nested schema chains).
const MAX_NESTING_DEPTH: usize = 32;

/// Maximum repeat count when parsing untrusted binary input.
const MAX_REPEAT_COUNT: usize = 256;

/// Cache for schemas loaded on-demand (local overrides discovered after
/// initial load, and optionally remote fetches from GitHub).
struct RuntimeCache {
    schemas: HashMap<String, Schema>,
    #[cfg(feature = "fetch")]
    fetch: FetchCache,
}

/// Registry of loaded schemas with lazy reference resolution.
pub struct Registry {
    schema_dir: PathBuf,
    /// Schemas loaded at init time — immutable after construction.
    schemas: HashMap<String, Schema>,
    /// Schemas fetched on-demand from GitHub or discovered later.
    runtime_cache: RefCell<RuntimeCache>,
}

impl Registry {
    /// Load all `.json` schemas from a directory.
    ///
    /// Reads root-level `.json` files as `@this` schemas, and files under
    /// `@org/repo/*.json` subdirectories as scoped schemas keyed by
    /// `@org/repo/name`.
    pub fn load(schema_dir: &Path) -> Result<Self> {
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
                let schema = Self::load_schema_file(&path)?;
                schemas.insert(name, schema);
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
                        let schema = Self::load_schema_file(&schema_path)?;
                        schemas.insert(key, schema);
                    }
                }
            }
        }

        Ok(Self {
            schema_dir: schema_dir.to_path_buf(),
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
        let mut names: Vec<&str> = self.schemas.keys().map(|s| s.as_str()).collect();
        names.sort();
        names
    }

    /// Get a schema by name.
    pub fn get(&self, name: &str) -> Option<&Schema> {
        self.schemas.get(name)
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
    pub fn serialize(
        &self,
        ref_str: &str,
        values: &serde_json::Value,
    ) -> Result<Vec<u8>> {
        let parsed = self.normalize_ref(ref_str)?;
        let mut visited = HashSet::new();
        let mut output = Vec::new();
        self.serialize_recursive(&parsed, &BTreeMap::new(), values, &mut output, &mut visited)?;
        Ok(output)
    }

    /// Normalize a user-supplied ref string into a ParsedRef.
    /// Bare names (no `@` prefix) are treated as `@this/name`.
    /// All `Param` nodes are converted to `@this/` refs since user-facing
    /// strings never contain type variables — those only appear in schema files.
    fn normalize_ref(&self, ref_str: &str) -> Result<ParsedRef> {
        let ref_str = ref_str.trim();
        let parsed = if ref_str.starts_with('@') {
            refs::parse_ref(ref_str)?
        } else {
            // Treat as bare name, possibly with angle brackets
            let full = format!("@this/{}", ref_str);
            refs::parse_ref(&full)?
        };
        Ok(Self::params_to_this(parsed))
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
                let local_path = self
                    .schema_dir
                    .join(format!("@{}", org))
                    .join(repo)
                    .join(format!("{}.json", name));

                let value = if local_path.exists() {
                    let contents = std::fs::read_to_string(&local_path)
                        .with_context(|| format!("failed to read {}", local_path.display()))?;
                    serde_json::from_str::<serde_json::Value>(&contents).with_context(|| {
                        format!("failed to parse JSON in {}", local_path.display())
                    })?
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
                        "u16" => {
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
                    count_field: _,
                    ref_,
                } => {
                    // Look up the array in JSON; serialize each item against the ref schema
                    if let Some(arr) = values.get(name).and_then(|v| v.as_array()) {
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
                    // If no array present, emit nothing (count=0)
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
                Field::LengthPrefix(size_type) => {
                    // Read the length, create a sub-cursor, parse the next Ref within it
                    let len: usize = match size_type.as_str() {
                        "u16" => {
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
            }
            i += 1;
        }
        Ok(map)
    }
}
