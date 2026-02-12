use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use wormhole_schemas::Registry;

/// Wormhole schema tool — parse, build, and inspect binary payloads.
#[derive(Parser)]
#[command(name = "wsch")]
struct Cli {
    /// Path to the schemas directory
    #[arg(long, default_value = "schemas")]
    schemas: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse a binary payload to JSON.
    Parse {
        /// Schema ref (e.g. "onboard", "vaa<onboard>"). Inferred if omitted.
        #[arg(long, short)]
        schema: Option<String>,

        /// Hex string or @file to read raw bytes from. Reads stdin if omitted.
        payload: Option<String>,
    },
    /// Build a binary payload from JSON.
    Build {
        /// Schema ref. Required unless JSON contains $schema.
        #[arg(long, short)]
        schema: Option<String>,

        /// JSON file to load base values from. Use - for stdin.
        #[arg(long)]
        json: Option<String>,

        /// Field overrides as key=value (dot notation for nested: payload.amount=500).
        overrides: Vec<String>,
    },
    /// List all available schemas.
    Schemas,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {:#}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let reg = Registry::load(&cli.schemas)
        .with_context(|| format!("loading schemas from {}", cli.schemas.display()))?;

    match cli.command {
        Command::Parse { schema, payload } => cmd_parse(&reg, schema.as_deref(), payload),
        Command::Build {
            schema,
            json,
            overrides,
        } => cmd_build(&reg, schema.as_deref(), json, &overrides),
        Command::Schemas => cmd_schemas(&reg),
    }
}

fn cmd_schemas(reg: &Registry) -> Result<()> {
    for name in reg.schemas() {
        let schema = reg.get(name).unwrap();
        let params = if schema.params.is_empty() {
            String::new()
        } else {
            format!("<{}>", schema.params.join(", "))
        };
        let about = schema.about.as_deref().unwrap_or("");
        println!("{}{}\t{}", name, params, about);
    }
    Ok(())
}

fn cmd_parse(reg: &Registry, schema: Option<&str>, payload_arg: Option<String>) -> Result<()> {
    let data = read_payload(payload_arg)?;

    let (schema_name, parsed) = if let Some(s) = schema {
        let parsed = reg.parse(s, &data)?;
        (s.to_string(), parsed)
    } else {
        reg.infer(&data)?
    };

    // Inject $schema at the beginning of the output
    let fields = match parsed {
        serde_json::Value::Object(m) => m,
        other => {
            let mut m = serde_json::Map::new();
            m.insert("value".to_string(), other);
            m
        }
    };
    let mut out = serde_json::Map::new();
    out.insert(
        "$schema".to_string(),
        serde_json::Value::String(schema_name),
    );
    out.extend(fields);

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::Value::Object(out))?
    );
    Ok(())
}

fn cmd_build(
    reg: &Registry,
    schema: Option<&str>,
    json_source: Option<String>,
    overrides: &[String],
) -> Result<()> {
    // Load base JSON
    let mut values = if let Some(src) = json_source {
        let text = if src == "-" {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        } else {
            std::fs::read_to_string(&src).with_context(|| format!("reading {}", src))?
        };
        serde_json::from_str::<serde_json::Value>(&text).context("parsing JSON input")?
    } else if io::stdin().is_terminal() {
        // Interactive terminal — start with empty object
        serde_json::Value::Object(serde_json::Map::new())
    } else {
        // Read JSON from piped stdin (overrides applied on top)
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            serde_json::Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_str::<serde_json::Value>(trimmed).context("parsing JSON from stdin")?
        }
    };

    // Apply field overrides
    for ov in overrides {
        let (key, val) = ov
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("invalid override (expected key=value): {}", ov))?;
        let parts: Vec<&str> = key.split('.').collect();
        set_nested(&mut values, &parts, val)?;
    }

    // Determine schema
    let schema_name = if let Some(s) = schema {
        s.to_string()
    } else if let Some(s) = values.get("$schema").and_then(|v| v.as_str()) {
        s.to_string()
    } else {
        bail!("no schema specified: use --schema or include $schema in JSON");
    };

    let bytes = reg.serialize(&schema_name, &values)?;
    println!("{}", hex::encode(&bytes));
    Ok(())
}

/// Read payload data from argument, @file reference, or stdin.
fn read_payload(arg: Option<String>) -> Result<Vec<u8>> {
    match arg {
        Some(s) if s.starts_with('@') => {
            // Read raw bytes from file
            let path = &s[1..];
            std::fs::read(path).with_context(|| format!("reading file: {}", path))
        }
        Some(s) => {
            // Treat as hex string
            hex::decode(s.trim()).context("decoding hex payload")
        }
        None => {
            // Read from stdin
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;

            // If it looks like hex (all ASCII hex chars, possibly with whitespace), decode it
            let text = String::from_utf8_lossy(&buf);
            let trimmed = text.trim();
            if !trimmed.is_empty()
                && trimmed
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || b.is_ascii_whitespace())
            {
                let clean: String = trimmed
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect();
                hex::decode(&clean).context("decoding hex from stdin")
            } else {
                // Treat as raw bytes
                Ok(buf)
            }
        }
    }
}

/// Set a value in a nested JSON object using a dotted path.
fn set_nested(value: &mut serde_json::Value, path: &[&str], val: &str) -> Result<()> {
    if path.is_empty() {
        bail!("empty path in field override");
    }
    if path.len() == 1 {
        value
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("cannot set field on non-object"))?
            .insert(
                path[0].to_string(),
                serde_json::Value::String(val.to_string()),
            );
        return Ok(());
    }

    let obj = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("cannot navigate into non-object"))?;
    let entry = obj
        .entry(path[0].to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    set_nested(entry, &path[1..], val)
}
