//! CLI integration tests for the `wsch` binary.
//!
//! These tests run the binary as a subprocess, piping data between invocations
//! to verify round-trip correctness, schema inference, and incremental builds.

use std::process::{Command, Stdio};

fn wsch() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wsch"))
}

/// Run wsch with args, piping `stdin_data` in, and return stdout as a String.
fn run(args: &[&str], stdin_data: Option<&str>) -> String {
    let mut cmd = wsch();
    cmd.args(args);
    cmd.stdin(match stdin_data {
        Some(_) => Stdio::piped(),
        None => Stdio::null(),
    });
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn wsch");

    if let Some(data) = stdin_data {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(data.as_bytes())
            .expect("failed to write stdin");
    }

    let output = child.wait_with_output().expect("failed to wait on wsch");
    assert!(
        output.status.success(),
        "wsch {} failed with stderr: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("non-utf8 stdout")
}

/// Run wsch expecting failure; return stderr.
fn run_err(args: &[&str], stdin_data: Option<&str>) -> String {
    let mut cmd = wsch();
    cmd.args(args);
    cmd.stdin(match stdin_data {
        Some(_) => Stdio::piped(),
        None => Stdio::null(),
    });
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn wsch");

    if let Some(data) = stdin_data {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(data.as_bytes())
            .expect("failed to write stdin");
    }

    let output = child.wait_with_output().expect("failed to wait on wsch");
    assert!(
        !output.status.success(),
        "expected wsch to fail but it succeeded"
    );
    String::from_utf8(output.stderr).expect("non-utf8 stderr")
}

// ---------------------------------------------------------------------------
// wsch schemas
// ---------------------------------------------------------------------------

#[test]
fn schemas_lists_all() {
    let out = run(&["schemas"], None);
    assert!(out.contains("onboard"), "should list onboard");
    assert!(out.contains("register-peer"), "should list register-peer");
    assert!(out.contains("route"), "should list route");
    assert!(out.contains("vaa<A>"), "should list vaa<A>");
    assert!(!out.contains("__catchall__"), "should not expose catchall");
}

// ---------------------------------------------------------------------------
// wsch build + parse round-trips
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_onboard() {
    let hex = run(
        &[
            "build",
            "--schema",
            "onboard",
            "admin=0000000000000000000000000000000000000001",
            "app-type=NTT",
            "initial-ticket=1",
            "ticket-count=10",
            "init-data=",
        ],
        None,
    );
    let json = run(&["parse", "--schema", "onboard", hex.trim()], None);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["$schema"], "onboard");
    assert_eq!(v["admin"], "0000000000000000000000000000000000000001");
    assert_eq!(v["app-type"], "NTT");
    assert_eq!(v["initial-ticket"], "1");
    assert_eq!(v["ticket-count"], "10");
    assert_eq!(v["init-data"], "");
}

#[test]
fn roundtrip_register_peer() {
    let hex = run(
        &[
            "build",
            "--schema",
            "register-peer",
            "target-account=9a327fdb08b05f049e206ca974915d1d3ea5a11f",
            "chain-id=1",
            "peer-address=305e53530fb264d2cb5ecebb2c97538c70d7b76846858e1247980bec62f1020b",
        ],
        None,
    );
    let json = run(&["parse", "--schema", "register-peer", hex.trim()], None);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        v["target-account"],
        "9a327fdb08b05f049e206ca974915d1d3ea5a11f"
    );
    assert_eq!(v["chain-id"], "1");
}

#[test]
fn roundtrip_vaa_from_json() {
    let input = serde_json::json!({
        "$schema": "vaa<register-peer>",
        "guardian-set-index": "4",
        "signature-count": "2",
        "signatures": [
            {"guardian-index": "0", "signature": "aa".repeat(65)},
            {"guardian-index": "1", "signature": "bb".repeat(65)},
        ],
        "timestamp": "1700000000",
        "nonce": "42",
        "emitter-chain": "66",
        "emitter-address": "0000000000000000000000000000000000000000000000000000000000000001",
        "sequence": "100",
        "consistency-level": "200",
        "payload": {
            "target-account": "9a327fdb08b05f049e206ca974915d1d3ea5a11f",
            "chain-id": "1",
            "peer-address": "305e53530fb264d2cb5ecebb2c97538c70d7b76846858e1247980bec62f1020b",
        },
    });
    let hex = run(&["build"], Some(&input.to_string()));
    let json = run(
        &["parse", "--schema", "vaa<register-peer>", hex.trim()],
        None,
    );
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["guardian-set-index"], "4");
    assert_eq!(v["signature-count"], "2");
    assert_eq!(v["payload"]["chain-id"], "1");
}

// ---------------------------------------------------------------------------
// Schema inference
// ---------------------------------------------------------------------------

#[test]
fn infer_ground_schema() {
    let hex = run(
        &[
            "build",
            "--schema",
            "onboard",
            "admin=0000000000000000000000000000000000000001",
            "app-type=NTT",
            "initial-ticket=1",
            "ticket-count=10",
            "init-data=",
        ],
        None,
    );
    // parse without --schema: should infer onboard
    let json = run(&["parse", hex.trim()], None);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let schema = v["$schema"].as_str().unwrap();
    assert!(schema.contains("onboard"), "inferred: {}", schema);
}

#[test]
fn infer_parameterized_vaa() {
    let input = serde_json::json!({
        "$schema": "vaa<onboard>",
        "guardian-set-index": "4",
        "signature-count": "0",
        "timestamp": "1700000000",
        "nonce": "0",
        "emitter-chain": "66",
        "emitter-address": "0000000000000000000000000000000000000000000000000000000000000001",
        "sequence": "1",
        "consistency-level": "200",
        "payload": {
            "admin": "0000000000000000000000000000000000000001",
            "app-type": "NTT",
            "initial-ticket": "100",
            "ticket-count": "10",
            "init-data": "",
        },
    });
    let hex = run(&["build"], Some(&input.to_string()));
    // parse without --schema: should infer vaa<..onboard..>
    let json = run(&["parse", hex.trim()], None);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let schema = v["$schema"].as_str().unwrap();
    assert!(
        schema.contains("vaa") && schema.contains("onboard"),
        "inferred: {}",
        schema
    );
    assert_eq!(v["payload"]["app-type"], "NTT");
}

#[test]
fn infer_parameterized_vaa_with_signatures() {
    let input = serde_json::json!({
        "$schema": "vaa<register-peer>",
        "guardian-set-index": "4",
        "signature-count": "2",
        "signatures": [
            {"guardian-index": "0", "signature": "aa".repeat(65)},
            {"guardian-index": "1", "signature": "bb".repeat(65)},
        ],
        "timestamp": "1700000000",
        "nonce": "42",
        "emitter-chain": "66",
        "emitter-address": "0000000000000000000000000000000000000000000000000000000000000001",
        "sequence": "100",
        "consistency-level": "200",
        "payload": {
            "target-account": "9a327fdb08b05f049e206ca974915d1d3ea5a11f",
            "chain-id": "1",
            "peer-address": "305e53530fb264d2cb5ecebb2c97538c70d7b76846858e1247980bec62f1020b",
        },
    });
    let hex = run(&["build"], Some(&input.to_string()));
    let json = run(&["parse", hex.trim()], None);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let schema = v["$schema"].as_str().unwrap();
    assert!(
        schema.contains("vaa") && schema.contains("register-peer"),
        "inferred: {}",
        schema
    );
    assert_eq!(v["signature-count"], "2");
    let sigs = v["signatures"].as_array().unwrap();
    assert_eq!(sigs.len(), 2);
}

// ---------------------------------------------------------------------------
// Incremental build (pipe JSON in + apply overrides)
// ---------------------------------------------------------------------------

#[test]
fn incremental_build_override_field() {
    let input = serde_json::json!({
        "$schema": "register-peer",
        "target-account": "9a327fdb08b05f049e206ca974915d1d3ea5a11f",
        "chain-id": "1",
        "peer-address": "305e53530fb264d2cb5ecebb2c97538c70d7b76846858e1247980bec62f1020b",
    });
    // Build with override: chain-id=42
    let hex = run(&["build", "chain-id=42"], Some(&input.to_string()));
    let json = run(&["parse", "--schema", "register-peer", hex.trim()], None);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["chain-id"], "42");
    // Other fields unchanged
    assert_eq!(
        v["target-account"],
        "9a327fdb08b05f049e206ca974915d1d3ea5a11f"
    );
}

#[test]
fn incremental_build_nested_override() {
    let input = serde_json::json!({
        "$schema": "vaa<register-peer>",
        "guardian-set-index": "4",
        "signature-count": "0",
        "timestamp": "1700000000",
        "nonce": "42",
        "emitter-chain": "66",
        "emitter-address": "0000000000000000000000000000000000000000000000000000000000000001",
        "sequence": "100",
        "consistency-level": "200",
        "payload": {
            "target-account": "9a327fdb08b05f049e206ca974915d1d3ea5a11f",
            "chain-id": "1",
            "peer-address": "305e53530fb264d2cb5ecebb2c97538c70d7b76846858e1247980bec62f1020b",
        },
    });
    // Override nested field with dot notation
    let hex = run(&["build", "payload.chain-id=99"], Some(&input.to_string()));
    let json = run(
        &["parse", "--schema", "vaa<register-peer>", hex.trim()],
        None,
    );
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["payload"]["chain-id"], "99");
    // Rest unchanged
    assert_eq!(v["guardian-set-index"], "4");
    assert_eq!(v["timestamp"], "1700000000");
}

#[test]
fn full_pipeline_parse_modify_rebuild() {
    // Build an onboard payload
    let hex1 = run(
        &[
            "build",
            "--schema",
            "onboard",
            "admin=0000000000000000000000000000000000000001",
            "app-type=NTT",
            "initial-ticket=1",
            "ticket-count=10",
            "init-data=",
        ],
        None,
    );
    // Parse it (with inference)
    let json = run(&["parse", hex1.trim()], None);
    // Rebuild with a changed field
    let hex2 = run(&["build", "ticket-count=99"], Some(&json));
    // Parse again and verify
    let json2 = run(&["parse", "--schema", "onboard", hex2.trim()], None);
    let v: serde_json::Value = serde_json::from_str(&json2).unwrap();
    assert_eq!(v["ticket-count"], "99");
    assert_eq!(v["initial-ticket"], "1"); // unchanged
}

// ---------------------------------------------------------------------------
// Stdin hex parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_hex_from_stdin() {
    let hex = run(
        &[
            "build",
            "--schema",
            "onboard",
            "admin=0000000000000000000000000000000000000001",
            "app-type=NTT",
            "initial-ticket=1",
            "ticket-count=10",
            "init-data=",
        ],
        None,
    );
    // Pipe hex into parse via stdin
    let json = run(&["parse", "--schema", "onboard"], Some(hex.trim()));
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["app-type"], "NTT");
}

// ---------------------------------------------------------------------------
// Base64 input
// ---------------------------------------------------------------------------

#[test]
fn parse_base64_arg() {
    // Build an onboard payload as hex, convert to base64, and parse it
    let hex = run(
        &[
            "build",
            "--schema",
            "onboard",
            "admin=0000000000000000000000000000000000000001",
            "app-type=NTT",
            "initial-ticket=1",
            "ticket-count=10",
            "init-data=",
        ],
        None,
    );
    let bytes = hex::decode(hex.trim()).unwrap();
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

    let json = run(&["parse", "--schema", "onboard", &b64], None);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["app-type"], "NTT");
    assert_eq!(v["initial-ticket"], "1");
}

#[test]
fn parse_base64_stdin() {
    let hex = run(
        &[
            "build",
            "--schema",
            "onboard",
            "admin=0000000000000000000000000000000000000001",
            "app-type=NTT",
            "initial-ticket=1",
            "ticket-count=10",
            "init-data=",
        ],
        None,
    );
    let bytes = hex::decode(hex.trim()).unwrap();
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

    let json = run(&["parse", "--schema", "onboard"], Some(&b64));
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["app-type"], "NTT");
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

#[test]
fn build_no_schema_errors() {
    let err = run_err(
        &["build", "admin=0000000000000000000000000000000000000001"],
        Some("{}"),
    );
    assert!(err.contains("no schema"), "stderr: {}", err);
}

#[test]
fn parse_bad_hex_errors() {
    let err = run_err(&["parse", "--schema", "onboard", "not_hex!!"], None);
    assert!(err.contains("error"), "stderr: {}", err);
}

#[test]
fn build_repeat_count_mismatch_errors() {
    let err = run_err(
        &[
            "build",
            "--schema",
            "vaa<onboard>",
            "guardian-set-index=0",
            "signature-count=1",
            "timestamp=0",
            "nonce=0",
            "emitter-chain=66",
            "emitter-address=0000000000000000000000000000000000000000000000000000000000000001",
            "sequence=1",
            "consistency-level=1",
            "admin=0000000000000000000000000000000000000001",
            "app-type=NTT",
            "initial-ticket=1",
            "ticket-count=10",
            "init-data=",
        ],
        None,
    );
    assert!(
        err.contains("signatures") && err.contains("0 items") && err.contains("1"),
        "stderr: {}",
        err
    );
}
