use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use wormhole_schemas::Registry;

/// Wormhole schema tool — parse, build, and inspect binary payloads.
#[derive(Parser)]
#[command(name = "wsch")]
struct Cli {
    /// Path to additional schemas directory (layered on top of built-in schemas)
    #[arg(long)]
    schemas: Option<PathBuf>,

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

    /// Sign an unsigned VAA with a guardian key.
    #[cfg(feature = "sign")]
    Sign {
        /// Guardian secret key (hex-encoded secp256k1)
        #[arg(long, env = "GUARDIAN_KEY")]
        guardian_key: String,

        /// Guardian index in the set
        #[arg(long, default_value = "0")]
        guardian_index: u8,

        /// Output format: hex or base64
        #[arg(long, default_value = "hex")]
        format: String,

        /// Unsigned VAA as hex string, @file, or stdin
        vaa: Option<String>,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {:#}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let reg = match &cli.schemas {
        Some(dir) => Registry::builtin_with_overrides(dir)
            .with_context(|| format!("loading schemas from {}", dir.display()))?,
        None => Registry::builtin().context("loading built-in schemas")?,
    };

    match cli.command {
        Command::Parse { schema, payload } => cmd_parse(&reg, schema.as_deref(), payload),
        Command::Build {
            schema,
            json,
            overrides,
        } => cmd_build(&reg, schema.as_deref(), json, &overrides),
        Command::Schemas => cmd_schemas(&reg),
        #[cfg(feature = "sign")]
        Command::Sign {
            guardian_key,
            guardian_index,
            format,
            vaa,
        } => cmd_sign(&guardian_key, guardian_index, &format, vaa),
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

/// Decode a text payload as hex or base64.
///
/// Tries hex first (if all chars are hex digits), then base64.
fn decode_text_payload(text: &str) -> Result<Vec<u8>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        bail!("empty payload");
    }

    // Strip whitespace for both decoders
    let clean: String = trimmed
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();

    // Pure hex chars → hex
    if clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return hex::decode(&clean).context("decoding hex payload");
    }

    // Try base64 (standard or URL-safe, with or without padding)
    use base64::Engine;
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&clean) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(&clean) {
        return Ok(bytes);
    }

    // Fall back to hex decode for the error message
    hex::decode(&clean).context("payload is not valid hex or base64")
}

/// Read payload data from argument, @file reference, or stdin.
fn read_payload(arg: Option<String>) -> Result<Vec<u8>> {
    match arg {
        Some(s) if s.starts_with('@') => {
            // Read raw bytes from file
            let path = &s[1..];
            std::fs::read(path).with_context(|| format!("reading file: {}", path))
        }
        Some(s) => decode_text_payload(&s),
        None => {
            // Read from stdin
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;

            // If it looks like text, try hex/base64 decoding
            let text = String::from_utf8_lossy(&buf);
            let trimmed = text.trim();
            if !trimmed.is_empty()
                && trimmed
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b.is_ascii_whitespace())
            {
                decode_text_payload(trimmed)
            } else {
                // Treat as raw bytes
                Ok(buf)
            }
        }
    }
}

#[cfg(feature = "sign")]
fn cmd_sign(
    guardian_key: &str,
    guardian_index: u8,
    format: &str,
    vaa_arg: Option<String>,
) -> Result<()> {
    let raw = read_payload(vaa_arg)?;

    // Parse unsigned VAA header
    if raw.is_empty() {
        bail!("empty VAA");
    }
    if raw[0] != 1 {
        bail!("unsupported VAA version: {}", raw[0]);
    }
    if raw.len() < 6 {
        bail!("VAA too short to contain header");
    }

    let guardian_set_index = u32::from_be_bytes(raw[1..5].try_into().unwrap());
    let sig_count = raw[5] as usize;
    let body_offset = 6 + sig_count * 66;

    if raw.len() < body_offset {
        bail!(
            "VAA truncated: expected at least {} bytes for {} signatures, got {}",
            body_offset,
            sig_count,
            raw.len()
        );
    }

    let body = &raw[body_offset..];
    let signature = sign_vaa_body(guardian_key, guardian_index, body)?;

    // Collect existing signatures + new one
    let mut signatures: Vec<[u8; 66]> = Vec::with_capacity(sig_count + 1);
    for i in 0..sig_count {
        let start = 6 + i * 66;
        let mut sig = [0u8; 66];
        sig.copy_from_slice(&raw[start..start + 66]);
        signatures.push(sig);
    }
    signatures.push(signature);

    // Sort by guardian index (first byte)
    signatures.sort_by_key(|s| s[0]);

    // Build signed VAA
    let mut signed = Vec::new();
    signed.push(1u8); // version
    signed.extend_from_slice(&guardian_set_index.to_be_bytes());
    signed.push(signatures.len() as u8);
    for sig in &signatures {
        signed.extend_from_slice(sig);
    }
    signed.extend_from_slice(body);

    match format {
        "base64" | "b64" => {
            use base64::Engine;
            println!(
                "{}",
                base64::engine::general_purpose::STANDARD.encode(&signed)
            );
        }
        _ => {
            println!("{}", hex::encode(&signed));
        }
    }

    Ok(())
}

#[cfg(feature = "sign")]
fn sign_vaa_body(key_hex: &str, index: u8, body: &[u8]) -> Result<[u8; 66]> {
    use sha3::Digest;

    let key_hex = key_hex.trim_start_matches("0x");
    let key_bytes: [u8; 32] = hex::decode(key_hex)
        .context("invalid guardian key hex")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("guardian key must be 32 bytes, got {}", v.len()))?;

    let secret = libsecp256k1::SecretKey::parse(&key_bytes)
        .map_err(|e| anyhow::anyhow!("invalid secp256k1 key: {}", e))?;

    let hash1 = sha3::Keccak256::digest(body);
    let digest: [u8; 32] = sha3::Keccak256::digest(hash1).into();
    let msg = libsecp256k1::Message::parse(&digest);
    let (sig, rec) = libsecp256k1::sign(&msg, &secret);

    let mut result = [0u8; 66];
    result[0] = index;
    result[1..65].copy_from_slice(&sig.serialize());
    result[65] = rec.serialize();
    Ok(result)
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
