use std::path::PathBuf;
use tempfile::TempDir;
use wormhole_schemas::Registry;

const ZERO_ADDR: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const XRPL: &str = "@wormholelabs-xyz/ripple";
const NTT: &str = "@wormhole-foundation/native-token-transfers";
const WH: &str = "@wormhole-foundation/wormhole";
const TB: &str = "@wormhole-foundation/token-bridge";

fn schema_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schemas")
}

#[test]
fn load_all_schemas() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let names = reg.schemas();
    assert!(names.contains(&format!("{XRPL}/onboard").as_str()));
    assert!(names.contains(&format!("{XRPL}/register-peer").as_str()));
    assert!(names.contains(&format!("{XRPL}/route").as_str()));
    assert!(names.contains(&format!("{NTT}/native-token-transfer").as_str()));
    assert!(names.contains(&format!("{NTT}/ntt-manager-message").as_str()));
    assert!(names.contains(&format!("{NTT}/transceiver-message").as_str()));
    assert!(names.contains(&format!("{WH}/vaa").as_str()));
    assert!(names.contains(&format!("{WH}/vaa-body").as_str()));
    assert!(names.contains(&format!("{WH}/vaa-header").as_str()));
    assert!(names.contains(&format!("{WH}/guardian-signature").as_str()));
    assert!(names.contains(&format!("{NTT}/ntt-with-payload").as_str()));
    assert!(names.contains(&format!("{NTT}/empty").as_str()));
    assert!(names.contains(&format!("{NTT}/hex-payload").as_str()));
    assert!(names.contains(&format!("{NTT}/ntt").as_str()));
    // Ripple: release, ticket-refill
    assert!(names.contains(&format!("{XRPL}/release").as_str()));
    assert!(names.contains(&format!("{XRPL}/ticket-refill").as_str()));
    // Token Bridge
    assert!(names.contains(&format!("{TB}/transfer").as_str()));
    assert!(names.contains(&format!("{TB}/attest-meta").as_str()));
    assert!(names.contains(&format!("{TB}/transfer-with-payload").as_str()));
    assert!(names.contains(&format!("{TB}/register-chain").as_str()));
    assert!(names.contains(&format!("{TB}/upgrade-contract").as_str()));
    // Core governance
    assert!(names.contains(&format!("{WH}/guardian-key").as_str()));
    assert!(names.contains(&format!("{WH}/contract-upgrade").as_str()));
    assert!(names.contains(&format!("{WH}/guardian-set-update").as_str()));
    assert!(names.contains(&format!("{WH}/set-message-fee").as_str()));
    assert!(names.contains(&format!("{WH}/transfer-fees").as_str()));
    // NTT transceiver
    assert!(names.contains(&format!("{NTT}/wormhole-transceiver-init").as_str()));
    assert!(names.contains(&format!("{NTT}/wormhole-peer-registration").as_str()));
    assert!(names.contains(&format!("{XRPL}/ticket-range").as_str()));
    assert_eq!(names.len(), 31);
}

#[test]
fn schema_metadata() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let onboard = reg.get(&format!("{XRPL}/onboard")).unwrap();
    assert_eq!(
        onboard.about.as_deref(),
        Some("Initialize a new XRPL account")
    );
    assert!(onboard.params.is_empty());

    let route = reg.get(&format!("{XRPL}/route")).unwrap();
    assert_eq!(route.about.as_deref(), Some("Send an NTT transfer to XRPL"));
    assert!(route.ref_.is_some());

    let transceiver = reg.get(&format!("{NTT}/transceiver-message")).unwrap();
    assert_eq!(transceiver.params, vec!["A"]);

    let vaa = reg.get(&format!("{WH}/vaa")).unwrap();
    assert_eq!(
        vaa.about.as_deref(),
        Some("Complete Wormhole VAA (header + body)")
    );
    assert_eq!(vaa.params, vec!["A"]);

    let vaa_body = reg.get(&format!("{WH}/vaa-body")).unwrap();
    assert_eq!(
        vaa_body.about.as_deref(),
        Some("Wormhole VAA body (the part that gets signed)")
    );
    assert_eq!(vaa_body.params, vec!["A"]);

    let vaa_header = reg.get(&format!("{WH}/vaa-header")).unwrap();
    assert!(vaa_header.params.is_empty());
}

#[test]
fn args_onboard() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let args = reg.args(&format!("{XRPL}/onboard")).unwrap();
    let names: Vec<&str> = args.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "admin",
            "app-type",
            "initial-ticket",
            "ticket-count",
            "init-data"
        ]
    );
    let init_data = args.iter().find(|a| a.name == "init-data").unwrap();
    assert_eq!(init_data.field_type, "hex");
}

#[test]
fn args_register_peer() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let args = reg.args(&format!("{XRPL}/register-peer")).unwrap();
    let names: Vec<&str> = args.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, vec!["target-account", "chain-id", "peer-address"]);
}

#[test]
fn args_route_through_parameterized_chain() {
    let reg = Registry::load(&schema_dir()).unwrap();
    // route → transceiver-message<ntt-manager-message<native-token-transfer>>
    let args = reg.args(&format!("{XRPL}/route")).unwrap();
    let names: Vec<&str> = args.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "source-ntt-manager",
            "custody-account",
            "id",
            "sender",
            "decimals",
            "amount",
            "source-token",
            "recipient",
            "recipient-chain",
        ]
    );
    let rc = args.iter().find(|a| a.name == "recipient-chain").unwrap();
    assert_eq!(rc.field_type, "u16be");
}

#[test]
fn serialize_onboard() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "admin": "0000000000000000000000000000000000000001",
        "app-type": "NTT",
        "initial-ticket": "100",
        "ticket-count": "10",
        "init-data": "",
    });

    let payload = reg.serialize(&format!("{XRPL}/onboard"), &values).unwrap();

    // Verify structure:
    // const "5852504C" (4 bytes)
    assert_eq!(&payload[0..4], &hex::decode("5852504C").unwrap());
    // admin bytes20 (20 bytes)
    assert_eq!(payload[4..23], [0u8; 19]);
    assert_eq!(payload[23], 1);
    // app-type string32 (32 bytes) — left-zero-padded "NTT"
    assert_eq!(&payload[24..53], &[0u8; 29]);
    assert_eq!(&payload[53..56], b"NTT");
    // initial-ticket u64 (8 bytes) = 100
    assert_eq!(&payload[56..64], &100u64.to_be_bytes());
    // ticket-count u64 (8 bytes) = 10
    assert_eq!(&payload[64..72], &10u64.to_be_bytes());
    // init-data hex (0 bytes from default "")
    assert_eq!(payload.len(), 72);
}

#[test]
fn serialize_register_peer() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "target-account": "0000000000000000000000000000000000000001",
        "chain-id": "1",
        "peer-address": "0000000000000000000000000000000000000000000000000000000000000002",
    });

    let payload = reg
        .serialize(&format!("{XRPL}/register-peer"), &values)
        .unwrap();

    // const "5841444D" (4 bytes)
    assert_eq!(&payload[0..4], &hex::decode("5841444D").unwrap());
    // const "01" (1 byte)
    assert_eq!(payload[4], 0x01);
    // target-account bytes20 (20 bytes)
    assert_eq!(payload[5..24], [0u8; 19]);
    assert_eq!(payload[24], 1);
    // chain-id u16 (2 bytes)
    assert_eq!(&payload[25..27], &1u16.to_be_bytes());
    // peer-address address (32 bytes)
    assert_eq!(payload[27..58], [0u8; 31]);
    assert_eq!(payload[58], 2);
    assert_eq!(payload.len(), 59);
}

#[test]
fn serialize_native_token_transfer() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "decimals": "8",
        "amount": "1000000",
        "source-token": "0000000000000000000000000000000000000000000000000000000000000001",
        "recipient": "0000000000000000000000000000000000000000000000000000000000000002",
        "recipient-chain": "66",
    });

    let payload = reg
        .serialize(&format!("{NTT}/native-token-transfer"), &values)
        .unwrap();

    // const "994E5454" (4 bytes)
    assert_eq!(&payload[0..4], &hex::decode("994E5454").unwrap());
    // decimals u8 (1 byte) = 8
    assert_eq!(payload[4], 8);
    // amount u64 (8 bytes) = 1000000
    assert_eq!(&payload[5..13], &1000000u64.to_be_bytes());
    // source-token address (32 bytes)
    assert_eq!(payload[13..44], [0u8; 31]);
    assert_eq!(payload[44], 1);
    // recipient address (32 bytes)
    assert_eq!(payload[45..76], [0u8; 31]);
    assert_eq!(payload[76], 2);
    // recipient-chain u16 (2 bytes) = 66
    assert_eq!(&payload[77..79], &66u16.to_be_bytes());
    // No trailing bytes — EmptyPayload is implicit, no additional_payload_len
    assert_eq!(payload.len(), 79);
}

#[test]
fn serialize_route_full_ntt_payload() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "source-ntt-manager": ZERO_ADDR,
        "custody-account": "0000000000000000000000000000000000000000000000000000000000000099",
        "payload": {
            "id": ZERO_ADDR,
            "sender": ZERO_ADDR,
            "payload": {
                "decimals": "8",
                "amount": "500",
                "source-token": "0000000000000000000000000000000000000000000000000000000000000001",
                "recipient": "0000000000000000000000000000000000000000000000000000000000000002",
                "recipient-chain": "66",
            },
        },
    });

    let payload = reg.serialize(&format!("{XRPL}/route"), &values).unwrap();

    // NTT = 79 bytes (no additional_payload_len with EmptyPayload)
    // mgr = 32 + 32 + 2 + 79 = 145 bytes
    // Total = 4 + 32 + 32 + 2 + 145 + 2 = 217

    assert_eq!(payload.len(), 217);

    // Verify transceiver prefix
    assert_eq!(&payload[0..4], &hex::decode("9945FF10").unwrap());
    // source-ntt-manager = zeros
    assert_eq!(&payload[4..36], &[0u8; 32]);
    // custody-account
    assert_eq!(payload[67], 0x99);
    // ntt-manager-message length = 145
    assert_eq!(&payload[68..70], &145u16.to_be_bytes());
    // id + sender = zeros
    assert_eq!(&payload[70..134], &[0u8; 64]);
    // native-token-transfer length = 79
    assert_eq!(&payload[134..136], &79u16.to_be_bytes());
    // NTT prefix at 136
    assert_eq!(&payload[136..140], &hex::decode("994E5454").unwrap());
    // decimals
    assert_eq!(payload[140], 8);
    // amount = 500
    assert_eq!(&payload[141..149], &500u64.to_be_bytes());
    // trailing 0000 (transceiver_payload_len)
    assert_eq!(&payload[215..217], &[0u8; 2]);
}

#[test]
fn serialize_route_via_explicit_ref_string() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "source-ntt-manager": ZERO_ADDR,
        "custody-account": "0000000000000000000000000000000000000000000000000000000000000099",
        "payload": {
            "id": ZERO_ADDR,
            "sender": ZERO_ADDR,
            "payload": {
                "decimals": "8",
                "amount": "500",
                "source-token": "0000000000000000000000000000000000000000000000000000000000000001",
                "recipient": "0000000000000000000000000000000000000000000000000000000000000002",
                "recipient-chain": "66",
            },
        },
    });

    // Using explicit parameterized ref instead of "route" name
    let payload = reg
        .serialize(
            &format!(
                "{NTT}/transceiver-message<{NTT}/ntt-manager-message<{NTT}/native-token-transfer>>"
            ),
            &values,
        )
        .unwrap();

    // Should produce the exact same output as "route"
    let reg2 = Registry::load(&schema_dir()).unwrap();
    let payload2 = reg2.serialize(&format!("{XRPL}/route"), &values).unwrap();
    assert_eq!(payload, payload2);
}

#[test]
fn serialize_with_base58_address() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "source-ntt-manager": ZERO_ADDR,
        // Use base58 for custody-account (Solana system program = all zeros)
        "custody-account": "11111111111111111111111111111111",
        "payload": {
            "id": ZERO_ADDR,
            "sender": ZERO_ADDR,
            "payload": {
                "decimals": "8",
                "amount": "1",
                "source-token": "0000000000000000000000000000000000000000000000000000000000000001",
                "recipient": "0000000000000000000000000000000000000000000000000000000000000002",
                "recipient-chain": "66",
            },
        },
    });

    let payload = reg.serialize(&format!("{XRPL}/route"), &values).unwrap();
    // base58 "11111111111111111111111111111111" = 32 zero bytes
    // custody-account starts at offset 36
    assert_eq!(&payload[36..68], &[0u8; 32]);
}

#[test]
fn missing_required_field_errors() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({}); // empty — missing required fields
    let result = reg.serialize(&format!("{XRPL}/onboard"), &values);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("missing fields"), "error was: {}", err);
    // All five onboard fields should be listed
    assert!(err.contains("admin"), "error was: {}", err);
    assert!(err.contains("app-type"), "error was: {}", err);
    assert!(err.contains("ticket-count"), "error was: {}", err);
}

#[test]
fn circular_ref_detected() {
    // Create a temporary directory with schemas that reference each other
    let dir = tempfile::tempdir().unwrap();

    std::fs::write(dir.path().join("a.json"), r#"{"ref": "@this/b"}"#).unwrap();
    std::fs::write(dir.path().join("b.json"), r#"{"ref": "@this/a"}"#).unwrap();

    let reg = Registry::load(dir.path()).unwrap();
    let result = reg.args("a");
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("circular"), "error was: {}", err);
}

#[test]
fn param_binding_through_chain() {
    // Test that parameters correctly propagate through the chain:
    // transceiver-message<ntt-manager-message<native-token-transfer>>
    let reg = Registry::load(&schema_dir()).unwrap();

    // The args should come from all three levels:
    // transceiver-message contributes: source-ntt-manager, custody-account
    // ntt-manager-message contributes: id, sender
    // native-token-transfer contributes: decimals, amount, source-token, recipient, recipient-chain
    let args = reg
        .args(&format!(
            "{NTT}/transceiver-message<{NTT}/ntt-manager-message<{NTT}/native-token-transfer>>"
        ))
        .unwrap();
    let names: Vec<&str> = args.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "source-ntt-manager",
            "custody-account",
            "id",
            "sender",
            "decimals",
            "amount",
            "source-token",
            "recipient",
            "recipient-chain",
        ]
    );
}

#[test]
fn args_vaa_body_with_onboard_payload() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let args = reg.args(&format!("{WH}/vaa-body<{XRPL}/onboard>")).unwrap();
    let names: Vec<&str> = args.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "timestamp",
            "nonce",
            "emitter-chain",
            "emitter-address",
            "sequence",
            "consistency-level",
            "admin",
            "app-type",
            "initial-ticket",
            "ticket-count",
            "init-data",
        ]
    );
}

#[test]
fn args_vaa_full_with_onboard_payload() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let args = reg.args(&format!("{WH}/vaa<{XRPL}/onboard>")).unwrap();
    let names: Vec<&str> = args.iter().map(|a| a.name.as_str()).collect();
    // header fields + body fields + payload fields
    assert_eq!(
        names,
        vec![
            "guardian-set-index",
            "signature-count",
            "signatures",
            "timestamp",
            "nonce",
            "emitter-chain",
            "emitter-address",
            "sequence",
            "consistency-level",
            "admin",
            "app-type",
            "initial-ticket",
            "ticket-count",
            "init-data",
        ]
    );
}

#[test]
fn args_vaa_full_with_route_payload() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let args = reg.args(&format!("{WH}/vaa<{XRPL}/route>")).unwrap();
    let names: Vec<&str> = args.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "guardian-set-index",
            "signature-count",
            "signatures",
            "timestamp",
            "nonce",
            "emitter-chain",
            "emitter-address",
            "sequence",
            "consistency-level",
            "source-ntt-manager",
            "custody-account",
            "id",
            "sender",
            "decimals",
            "amount",
            "source-token",
            "recipient",
            "recipient-chain",
        ]
    );
}

#[test]
fn serialize_vaa_body_onboard() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "timestamp": "1700000000",
        "nonce": "42",
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

    let payload = reg
        .serialize(&format!("{WH}/vaa-body<{XRPL}/onboard>"), &values)
        .unwrap();

    // VAA body: 4+4+2+32+8+1 = 51 bytes
    // onboard payload: 4+20+32+8+8+0 = 72 bytes
    // Total: 123 bytes
    assert_eq!(payload.len(), 123);

    // timestamp u32 BE
    assert_eq!(&payload[0..4], &1700000000u32.to_be_bytes());
    // nonce u32 BE
    assert_eq!(&payload[4..8], &42u32.to_be_bytes());
    // emitter-chain u16 BE = 66
    assert_eq!(&payload[8..10], &66u16.to_be_bytes());
    // emitter-address (32 bytes)
    assert_eq!(payload[41], 1);
    // sequence u64 BE = 1
    assert_eq!(&payload[42..50], &1u64.to_be_bytes());
    // consistency-level u8 = 200
    assert_eq!(payload[50], 200);
    // onboard prefix starts at 51
    assert_eq!(&payload[51..55], &hex::decode("5852504C").unwrap());
}

#[test]
fn serialize_full_vaa_onboard() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
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

    let vaa = reg
        .serialize(&format!("{WH}/vaa<{XRPL}/onboard>"), &values)
        .unwrap();

    // Header: version(1) + guardian-set-index(4) + signature-count(1) + signatures(0) = 6
    // Body: 51 + onboard(72) = 123
    // Total: 129
    assert_eq!(vaa.len(), 129);

    // version const = 0x01
    assert_eq!(vaa[0], 0x01);
    // guardian-set-index u32 BE = 4
    assert_eq!(&vaa[1..5], &4u32.to_be_bytes());
    // signature-count = 0
    assert_eq!(vaa[5], 0);
    // body starts at offset 6
    // timestamp at offset 6
    assert_eq!(&vaa[6..10], &1700000000u32.to_be_bytes());
    // onboard prefix at offset 6+51 = 57
    assert_eq!(&vaa[57..61], &hex::decode("5852504C").unwrap());
}

#[test]
fn serialize_vaa_with_qualified_arg() {
    // Regression: `vaa<@wormholelabs-xyz/ripple/onboard>` used to fail with
    // "invalid ref format: @this/@wormholelabs-xyz/ripple/onboard" because
    // resolve_short_name blindly prepended @this/ to already-qualified refs.
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
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

    // Short base name + fully-qualified arg
    let a = reg
        .serialize("vaa<@wormholelabs-xyz/ripple/onboard>", &values)
        .unwrap();
    // Fully-qualified everything
    let b = reg
        .serialize(&format!("{WH}/vaa<{XRPL}/onboard>"), &values)
        .unwrap();
    assert_eq!(a, b);
}

#[test]
fn serialize_vaa_with_signatures() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "guardian-set-index": "4",
        "signature-count": "2",
        "signatures": [
            {"guardian-index": "0", "signature": "AA".repeat(65)},
            {"guardian-index": "1", "signature": "BB".repeat(65)},
        ],
        "timestamp": "0",
        "nonce": "0",
        "emitter-chain": "1",
        "emitter-address": "0000000000000000000000000000000000000000000000000000000000000001",
        "sequence": "0",
        "consistency-level": "0",
        "payload": {
            "target-account": "0000000000000000000000000000000000000001",
            "chain-id": "1",
            "peer-address": "0000000000000000000000000000000000000000000000000000000000000002",
        },
    });

    let vaa = reg
        .serialize(&format!("{WH}/vaa<{XRPL}/register-peer>"), &values)
        .unwrap();

    // Header: version(1) + gsi(4) + sig_count(1) + sigs(132) = 138
    // Body: 51 + register-peer(59) = 110
    // Total: 248
    assert_eq!(vaa.len(), 248);

    // version
    assert_eq!(vaa[0], 0x01);
    // guardian-set-index
    assert_eq!(&vaa[1..5], &4u32.to_be_bytes());
    // signature-count
    assert_eq!(vaa[5], 2);
    // first sig starts at 6: guardian_index = 0
    assert_eq!(vaa[6], 0x00);
    assert_eq!(vaa[7], 0xAA); // first byte of sig
                              // second sig starts at 6+66=72: guardian_index = 1
    assert_eq!(vaa[72], 0x01);
    assert_eq!(vaa[73], 0xBB);
    // body starts at 6+132=138
    assert_eq!(&vaa[138..142], &0u32.to_be_bytes()); // timestamp
}

// ---------------------------------------------------------------------------
// Parse (binary → JSON) tests
// ---------------------------------------------------------------------------

#[test]
fn parse_roundtrip_onboard() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "admin": "0000000000000000000000000000000000000001",
        "app-type": "NTT",
        "initial-ticket": "100",
        "ticket-count": "10",
        "init-data": "aabb",
    });

    let ref_str = format!("{XRPL}/onboard");
    let payload = reg.serialize(&ref_str, &values).unwrap();
    let parsed = reg.parse(&ref_str, &payload).unwrap();
    let obj = parsed.as_object().unwrap();

    assert_eq!(
        obj["admin"].as_str().unwrap(),
        "0000000000000000000000000000000000000001"
    );
    assert_eq!(obj["app-type"].as_str().unwrap(), "NTT");
    assert_eq!(obj["initial-ticket"].as_str().unwrap(), "100");
    assert_eq!(obj["ticket-count"].as_str().unwrap(), "10");
    assert_eq!(obj["init-data"].as_str().unwrap(), "aabb");
}

#[test]
fn parse_roundtrip_onboard_empty_hex() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "admin": "0000000000000000000000000000000000000001",
        "app-type": "NTT",
        "initial-ticket": "100",
        "ticket-count": "10",
        "init-data": "",
    });

    let ref_str = format!("{XRPL}/onboard");
    let payload = reg.serialize(&ref_str, &values).unwrap();
    let parsed = reg.parse(&ref_str, &payload).unwrap();
    let obj = parsed.as_object().unwrap();

    assert_eq!(obj["init-data"].as_str().unwrap(), "");
}

#[test]
fn parse_roundtrip_register_peer() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "target-account": "0000000000000000000000000000000000000001",
        "chain-id": "1",
        "peer-address": "0000000000000000000000000000000000000000000000000000000000000002",
    });

    let ref_str = format!("{XRPL}/register-peer");
    let payload = reg.serialize(&ref_str, &values).unwrap();
    let parsed = reg.parse(&ref_str, &payload).unwrap();
    let obj = parsed.as_object().unwrap();

    assert_eq!(
        obj["target-account"].as_str().unwrap(),
        "0000000000000000000000000000000000000001"
    );
    assert_eq!(obj["chain-id"].as_str().unwrap(), "1");
    assert_eq!(
        obj["peer-address"].as_str().unwrap(),
        "0000000000000000000000000000000000000000000000000000000000000002"
    );
}

#[test]
fn parse_roundtrip_route() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "source-ntt-manager": ZERO_ADDR,
        "custody-account": "0000000000000000000000000000000000000000000000000000000000000099",
        "payload": {
            "id": ZERO_ADDR,
            "sender": ZERO_ADDR,
            "payload": {
                "decimals": "8",
                "amount": "500",
                "source-token": "0000000000000000000000000000000000000000000000000000000000000001",
                "recipient": "0000000000000000000000000000000000000000000000000000000000000002",
                "recipient-chain": "66",
            },
        },
    });

    let ref_str = format!("{XRPL}/route");
    let payload = reg.serialize(&ref_str, &values).unwrap();
    let parsed = reg.parse(&ref_str, &payload).unwrap();
    let obj = parsed.as_object().unwrap();

    assert_eq!(obj["source-ntt-manager"].as_str().unwrap(), ZERO_ADDR);
    assert_eq!(
        obj["custody-account"].as_str().unwrap(),
        "0000000000000000000000000000000000000000000000000000000000000099"
    );
    let mgr = obj["payload"].as_object().unwrap();
    assert_eq!(mgr["id"].as_str().unwrap(), ZERO_ADDR);
    assert_eq!(mgr["sender"].as_str().unwrap(), ZERO_ADDR);
    let ntt = mgr["payload"].as_object().unwrap();
    assert_eq!(ntt["decimals"].as_str().unwrap(), "8");
    assert_eq!(ntt["amount"].as_str().unwrap(), "500");
    assert_eq!(
        ntt["source-token"].as_str().unwrap(),
        "0000000000000000000000000000000000000000000000000000000000000001"
    );
    assert_eq!(
        ntt["recipient"].as_str().unwrap(),
        "0000000000000000000000000000000000000000000000000000000000000002"
    );
    assert_eq!(ntt["recipient-chain"].as_str().unwrap(), "66");
}

#[test]
fn parse_roundtrip_vaa_body_onboard() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "timestamp": "1700000000",
        "nonce": "42",
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

    let ref_str = format!("{WH}/vaa-body<{XRPL}/onboard>");
    let payload = reg.serialize(&ref_str, &values).unwrap();
    let parsed = reg.parse(&ref_str, &payload).unwrap();
    let obj = parsed.as_object().unwrap();

    assert_eq!(obj["timestamp"].as_str().unwrap(), "1700000000");
    assert_eq!(obj["nonce"].as_str().unwrap(), "42");
    assert_eq!(obj["emitter-chain"].as_str().unwrap(), "66");
    assert_eq!(obj["sequence"].as_str().unwrap(), "1");
    assert_eq!(obj["consistency-level"].as_str().unwrap(), "200");
    let payload = obj["payload"].as_object().unwrap();
    assert_eq!(payload["app-type"].as_str().unwrap(), "NTT");
    assert_eq!(payload["initial-ticket"].as_str().unwrap(), "100");
}

#[test]
fn parse_roundtrip_vaa_with_signatures() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "guardian-set-index": "4",
        "signature-count": "2",
        "signatures": [
            {"guardian-index": "0", "signature": "AA".repeat(65)},
            {"guardian-index": "1", "signature": "BB".repeat(65)},
        ],
        "timestamp": "0",
        "nonce": "0",
        "emitter-chain": "1",
        "emitter-address": "0000000000000000000000000000000000000000000000000000000000000001",
        "sequence": "0",
        "consistency-level": "0",
        "payload": {
            "target-account": "0000000000000000000000000000000000000001",
            "chain-id": "1",
            "peer-address": "0000000000000000000000000000000000000000000000000000000000000002",
        },
    });

    let ref_str = format!("{WH}/vaa<{XRPL}/register-peer>");
    let vaa_bytes = reg.serialize(&ref_str, &values).unwrap();
    let parsed = reg.parse(&ref_str, &vaa_bytes).unwrap();
    let obj = parsed.as_object().unwrap();

    assert_eq!(obj["guardian-set-index"].as_str().unwrap(), "4");
    assert_eq!(obj["signature-count"].as_str().unwrap(), "2");

    // signatures is an array of objects
    let sigs = obj["signatures"].as_array().unwrap();
    assert_eq!(sigs.len(), 2);
    assert_eq!(
        sigs[0].as_object().unwrap()["guardian-index"]
            .as_str()
            .unwrap(),
        "0"
    );
    assert_eq!(
        sigs[1].as_object().unwrap()["guardian-index"]
            .as_str()
            .unwrap(),
        "1"
    );
    // Check signature bytes
    let sig0 = sigs[0].as_object().unwrap()["signature"].as_str().unwrap();
    assert_eq!(sig0, "aa".repeat(65));
    let sig1 = sigs[1].as_object().unwrap()["signature"].as_str().unwrap();
    assert_eq!(sig1, "bb".repeat(65));

    assert_eq!(obj["timestamp"].as_str().unwrap(), "0");
    let payload = obj["payload"].as_object().unwrap();
    assert_eq!(
        payload["target-account"].as_str().unwrap(),
        "0000000000000000000000000000000000000001"
    );
    assert_eq!(payload["chain-id"].as_str().unwrap(), "1");
}

#[test]
fn parse_trailing_bytes_rejected() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "target-account": "0000000000000000000000000000000000000001",
        "chain-id": "1",
        "peer-address": "0000000000000000000000000000000000000000000000000000000000000002",
    });

    let ref_str = format!("{XRPL}/register-peer");
    let mut payload = reg.serialize(&ref_str, &values).unwrap();
    payload.push(0xFF); // extra byte
    let result = reg.parse(&ref_str, &payload);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("trailing"), "error was: {}", err);
}

#[test]
fn parse_truncated_data_rejected() {
    let reg = Registry::load(&schema_dir()).unwrap();
    // register-peer is 59 bytes; give it only 10
    let data = vec![0u8; 10];
    let result = reg.parse(&format!("{XRPL}/register-peer"), &data);
    assert!(result.is_err());
}

#[test]
fn parse_const_mismatch_rejected() {
    let reg = Registry::load(&schema_dir()).unwrap();
    // register-peer starts with const "5841444D" then const "01"
    // Corrupt the first byte
    let values = serde_json::json!({
        "target-account": "0000000000000000000000000000000000000001",
        "chain-id": "1",
        "peer-address": "0000000000000000000000000000000000000000000000000000000000000002",
    });
    let ref_str = format!("{XRPL}/register-peer");
    let mut payload = reg.serialize(&ref_str, &values).unwrap();
    payload[0] = 0xFF; // corrupt prefix
    let result = reg.parse(&ref_str, &payload);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("mismatch"), "error was: {}", err);
}

#[test]
fn infer_ground_onboard() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "admin": "0000000000000000000000000000000000000001",
        "app-type": "NTT",
        "initial-ticket": "100",
        "ticket-count": "10",
        "init-data": "",
    });
    let ref_str = format!("{XRPL}/onboard");
    let payload = reg.serialize(&ref_str, &values).unwrap();
    let (name, _parsed) = reg.infer(&payload).unwrap();
    assert_eq!(name, format!("{XRPL}/onboard"));
}

#[test]
fn infer_vaa_onboard() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
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
    let ref_str = format!("{WH}/vaa<{XRPL}/onboard>");
    let payload = reg.serialize(&ref_str, &values).unwrap();
    let (name, parsed) = reg.infer(&payload).unwrap();
    assert!(
        name.contains("vaa") && name.contains("onboard"),
        "expected vaa<...onboard...>, got: {}",
        name
    );
    let obj = parsed.as_object().unwrap();
    assert_eq!(obj["guardian-set-index"].as_str().unwrap(), "4");
    let inner = obj["payload"].as_object().unwrap();
    assert_eq!(inner["app-type"].as_str().unwrap(), "NTT");
}

// ---------------------------------------------------------------------------
// Builtin + layering tests
// ---------------------------------------------------------------------------

#[test]
fn new_loads_from_disk_cache() {
    // Registry::new() loads from disk cache; with no cache dir, it's empty
    // We test via load() which is the same path used by all other tests
    let reg = Registry::load(&schema_dir()).unwrap();
    let names = reg.schemas();
    assert!(names.contains(&format!("{XRPL}/onboard").as_str()));
    assert!(names.contains(&format!("{WH}/vaa").as_str()));
    assert!(names.contains(&format!("{TB}/transfer").as_str()));
    assert!(names.contains(&format!("{NTT}/native-token-transfer").as_str()));
    assert_eq!(names.len(), 31);
}

#[test]
fn load_serialize_roundtrip() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "admin": "0000000000000000000000000000000000000001",
        "app-type": "NTT",
        "initial-ticket": "100",
        "ticket-count": "10",
        "init-data": "",
    });
    let ref_str = format!("{XRPL}/onboard");
    let payload = reg.serialize(&ref_str, &values).unwrap();
    let parsed = reg.parse(&ref_str, &payload).unwrap();
    assert_eq!(parsed["app-type"].as_str().unwrap(), "NTT");
}

#[test]
fn with_overrides_adds_new_schema() {
    let tmp = TempDir::new().unwrap();

    // Copy real schemas as the base, then add a custom overlay
    copy_dir_recursive(&schema_dir(), tmp.path());

    let org_dir = tmp.path().join("@custom").join("project");
    std::fs::create_dir_all(&org_dir).unwrap();
    std::fs::write(
        org_dir.join("my-payload.json"),
        r#"[{"name": "tag", "const": "CAFE"}, {"name": "value", "type": "u32be"}]"#,
    )
    .unwrap();

    let reg = Registry::load(tmp.path()).unwrap();
    let names = reg.schemas();

    // All originals still present
    assert!(names.contains(&format!("{XRPL}/onboard").as_str()));
    assert!(names.contains(&format!("{WH}/vaa").as_str()));
    // Plus the new one
    assert!(names.contains(&"@custom/project/my-payload"));
    assert_eq!(names.len(), 32);

    // The new schema works
    let values = serde_json::json!({"value": "42"});
    let payload = reg
        .serialize("@custom/project/my-payload", &values)
        .unwrap();
    assert_eq!(&payload[0..2], &hex::decode("CAFE").unwrap());
    assert_eq!(&payload[2..6], &42u32.to_be_bytes());
}

#[test]
fn with_overrides_shadows_base_schema() {
    let tmp = TempDir::new().unwrap();
    // Override the onboard schema with a different "about" and simpler fields
    let org_dir = tmp.path().join("@wormholelabs-xyz").join("ripple");
    std::fs::create_dir_all(&org_dir).unwrap();
    std::fs::write(
        org_dir.join("onboard.json"),
        r#"{
            "about": "Overridden onboard schema",
            "fields": [
                {"name": "prefix", "const": "5852504C"},
                {"name": "value",  "type": "u64be"}
            ]
        }"#,
    )
    .unwrap();

    // Copy real schemas into the same temp dir so we can load them together
    copy_dir_recursive(&schema_dir(), tmp.path());

    // Now write the override on top (overwriting the copied original)
    std::fs::write(
        tmp.path()
            .join("@wormholelabs-xyz")
            .join("ripple")
            .join("onboard.json"),
        r#"{
            "about": "Overridden onboard schema",
            "fields": [
                {"name": "prefix", "const": "5852504C"},
                {"name": "value",  "type": "u64be"}
            ]
        }"#,
    )
    .unwrap();

    let reg = Registry::load(tmp.path()).unwrap();

    // The override should replace the original
    let schema = reg.get(&format!("{XRPL}/onboard")).unwrap();
    assert_eq!(schema.about.as_deref(), Some("Overridden onboard schema"));

    // It should serialize with the overridden layout (4 prefix + 8 u64 = 12 bytes)
    let values = serde_json::json!({"value": "99"});
    let payload = reg.serialize(&format!("{XRPL}/onboard"), &values).unwrap();
    assert_eq!(payload.len(), 12);
    assert_eq!(&payload[0..4], &hex::decode("5852504C").unwrap());
    assert_eq!(&payload[4..12], &99u64.to_be_bytes());

    // Other schemas still work
    let names = reg.schemas();
    assert!(names.contains(&format!("{WH}/vaa").as_str()));
    assert!(names.contains(&format!("{TB}/transfer").as_str()));
}

/// Helper: recursively copy a directory tree.
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let ty = entry.file_type().unwrap();
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&src_path, &dst_path);
        } else {
            std::fs::copy(&src_path, &dst_path).unwrap();
        }
    }
}

// ---- Enum field tests ----

#[test]
fn enum_roundtrip() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[
            {"name": "mode", "enum": {"type": "u8", "values": {"Fast": 0, "Slow": 1, "Turbo": 2}}},
            {"name": "count", "type": "u8"}
        ]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    // Serialize with variant name
    let values = serde_json::json!({"mode": "Turbo", "count": "5"});
    let payload = reg.serialize("test", &values).unwrap();
    assert_eq!(payload, vec![2, 5]); // Turbo=2, count=5

    // Parse back — should get variant name, not number
    let parsed = reg.parse("test", &payload).unwrap();
    assert_eq!(parsed["mode"], "Turbo");
    assert_eq!(parsed["count"], "5");
}

#[test]
fn enum_unknown_variant_on_build() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[{"name": "x", "enum": {"type": "u8", "values": {"A": 0, "B": 1}}}]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    let values = serde_json::json!({"x": "C"});
    let err = reg.serialize("test", &values).unwrap_err().to_string();
    assert!(err.contains("unknown variant"), "error was: {}", err);
}

#[test]
fn enum_unknown_discriminant_on_parse() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[{"name": "x", "enum": {"type": "u8", "values": {"A": 0, "B": 1}}}]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    let err = reg.parse("test", &[99]).unwrap_err().to_string();
    assert!(err.contains("unknown discriminant"), "error was: {}", err);
}

#[test]
fn enum_u16be_encoding() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[{"name": "chain", "enum": {"type": "u16be", "values": {"Solana": 1, "Ethereum": 2, "XRPL": 1000}}}]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    let values = serde_json::json!({"chain": "XRPL"});
    let payload = reg.serialize("test", &values).unwrap();
    assert_eq!(payload, vec![0x03, 0xe8]); // 1000 in big-endian u16

    let parsed = reg.parse("test", &payload).unwrap();
    assert_eq!(parsed["chain"], "XRPL");
}

#[test]
fn enum_args_shows_variants() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[{"name": "mode", "enum": {"type": "u8", "values": {"Fast": 0, "Slow": 1}}}]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();
    let args = reg.args("test").unwrap();
    assert_eq!(args.len(), 1);
    assert_eq!(args[0].name, "mode");
    assert!(args[0].field_type.contains("enum"));
    let ev = args[0].enum_values.as_ref().unwrap();
    assert!(ev.contains(&"Fast".to_string()));
    assert!(ev.contains(&"Slow".to_string()));
}

// ---- Option field tests ----

#[test]
fn option_fixed_single_type_some_roundtrip() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[
            {"name": "tag", "type": "u8"},
            {"name": "val", "option": {"type": "u64le"}}
        ]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    let values = serde_json::json!({"tag": "1", "val": "42"});
    let payload = reg.serialize("test", &values).unwrap();
    // tag(1) + option_tag(1) + u64le(8) = 10 bytes
    assert_eq!(payload.len(), 10);
    assert_eq!(payload[0], 1); // tag
    assert_eq!(payload[1], 1); // option: Some
    assert_eq!(&payload[2..10], &42u64.to_le_bytes());

    let parsed = reg.parse("test", &payload).unwrap();
    assert_eq!(parsed["tag"], "1");
    assert_eq!(parsed["val"], "42");
}

#[test]
fn option_fixed_single_type_none_roundtrip() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[
            {"name": "tag", "type": "u8"},
            {"name": "val", "option": {"type": "u64le"}}
        ]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    // null → None
    let values = serde_json::json!({"tag": "1", "val": null});
    let payload = reg.serialize("test", &values).unwrap();
    // Same total size: tag(1) + option_tag(1) + padding(8) = 10
    assert_eq!(payload.len(), 10);
    assert_eq!(payload[0], 1); // tag
    assert_eq!(payload[1], 0); // option: None
    assert_eq!(&payload[2..10], &[0u8; 8]); // zero padding

    let parsed = reg.parse("test", &payload).unwrap();
    assert_eq!(parsed["tag"], "1");
    assert!(parsed["val"].is_null());
}

#[test]
fn option_fixed_single_type_missing_is_none() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[{"name": "val", "option": {"type": "u8"}}]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    // Missing field → None
    let values = serde_json::json!({});
    let payload = reg.serialize("test", &values).unwrap();
    // 1 tag + 1 padding = 2
    assert_eq!(payload.len(), 2);
    assert_eq!(payload[0], 0); // None
    assert_eq!(payload[1], 0); // padding
}

#[test]
fn option_fixed_fields_some_roundtrip() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[
            {"name": "range", "option": {"fields": [
                {"name": "next", "type": "u64le"},
                {"name": "last", "type": "u64le"}
            ]}}
        ]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    let values = serde_json::json!({"range": {"next": "100", "last": "200"}});
    let payload = reg.serialize("test", &values).unwrap();
    // 1 tag + 8 + 8 = 17
    assert_eq!(payload.len(), 17);
    assert_eq!(payload[0], 1); // Some

    let parsed = reg.parse("test", &payload).unwrap();
    let range = parsed["range"].as_object().unwrap();
    assert_eq!(range["next"], "100");
    assert_eq!(range["last"], "200");
}

#[test]
fn option_fixed_fields_none_roundtrip() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[
            {"name": "range", "option": {"fields": [
                {"name": "next", "type": "u64le"},
                {"name": "last", "type": "u64le"}
            ]}}
        ]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    let values = serde_json::json!({"range": null});
    let payload = reg.serialize("test", &values).unwrap();
    // Same total size: 1 tag + 16 padding = 17
    assert_eq!(payload.len(), 17);
    assert_eq!(payload[0], 0); // None
    assert_eq!(&payload[1..17], &[0u8; 16]);

    let parsed = reg.parse("test", &payload).unwrap();
    assert!(parsed["range"].is_null());
}

#[test]
fn option_compact_single_type_some_roundtrip() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[
            {"name": "val", "option": {"type": "u64be", "compact": true}},
            {"name": "tail", "type": "u8"}
        ]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    let values = serde_json::json!({"val": "99", "tail": "7"});
    let payload = reg.serialize("test", &values).unwrap();
    // 1 tag + 8 inner + 1 tail = 10
    assert_eq!(payload.len(), 10);
    assert_eq!(payload[0], 1); // Some

    let parsed = reg.parse("test", &payload).unwrap();
    assert_eq!(parsed["val"], "99");
    assert_eq!(parsed["tail"], "7");
}

#[test]
fn option_compact_single_type_none_roundtrip() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[
            {"name": "val", "option": {"type": "u64be", "compact": true}},
            {"name": "tail", "type": "u8"}
        ]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    let values = serde_json::json!({"val": null, "tail": "7"});
    let payload = reg.serialize("test", &values).unwrap();
    // 1 tag (no padding!) + 1 tail = 2
    assert_eq!(payload.len(), 2);
    assert_eq!(payload[0], 0); // None
    assert_eq!(payload[1], 7); // tail

    let parsed = reg.parse("test", &payload).unwrap();
    assert!(parsed["val"].is_null());
    assert_eq!(parsed["tail"], "7");
}

#[test]
fn option_compact_fields_roundtrip() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[
            {"name": "data", "option": {"fields": [
                {"name": "a", "type": "u8"},
                {"name": "b", "type": "u8"}
            ], "compact": true}},
            {"name": "end", "type": "u8"}
        ]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    // Some
    let values = serde_json::json!({"data": {"a": "1", "b": "2"}, "end": "99"});
    let payload = reg.serialize("test", &values).unwrap();
    assert_eq!(payload, vec![1, 1, 2, 99]); // tag + a + b + end

    let parsed = reg.parse("test", &payload).unwrap();
    let data = parsed["data"].as_object().unwrap();
    assert_eq!(data["a"], "1");
    assert_eq!(data["b"], "2");
    assert_eq!(parsed["end"], "99");

    // None
    let values = serde_json::json!({"data": null, "end": "99"});
    let payload = reg.serialize("test", &values).unwrap();
    assert_eq!(payload, vec![0, 99]); // tag + end (no padding)

    let parsed = reg.parse("test", &payload).unwrap();
    assert!(parsed["data"].is_null());
    assert_eq!(parsed["end"], "99");
}

#[test]
fn option_collect_missing_skips_option_fields() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[
            {"name": "required", "type": "u8"},
            {"name": "optional", "option": {"type": "u8"}}
        ]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    // Empty values → only "required" is missing, not "optional"
    let values = serde_json::json!({});
    let err = reg.serialize("test", &values).unwrap_err().to_string();
    assert!(err.contains("required"), "error was: {}", err);
    assert!(!err.contains("optional"), "error was: {}", err);
}

#[test]
fn option_args_shows_type() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[
            {"name": "a", "option": {"type": "u64le"}},
            {"name": "b", "option": {"fields": [{"name": "x", "type": "u8"}]}}
        ]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();
    let args = reg.args("test").unwrap();
    assert_eq!(args.len(), 2);
    assert_eq!(args[0].name, "a");
    assert_eq!(args[0].field_type, "option(u64le)");
    assert_eq!(args[1].name, "b");
    assert_eq!(args[1].field_type, "option(struct)");
}

#[test]
fn option_xrpl_account_schema_loads() {
    // Verify the updated xrpl-account schema loads and the option field is recognized
    let reg = Registry::load(&schema_dir()).unwrap();
    let schema = reg.get(&format!("{XRPL}/xrpl-account")).unwrap();
    assert!(schema.about.is_some());
    let args = reg.args(&format!("{XRPL}/xrpl-account")).unwrap();
    let names: Vec<&str> = args.iter().map(|a| a.name.as_str()).collect();
    assert!(names.contains(&"next-range"), "args: {:?}", names);
}

#[test]
fn option_xrpl_account_roundtrip_some() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let ref_str = format!("{XRPL}/xrpl-account");

    // Build binary with Some next-range
    // discriminator(8) + xrpl-address(20) + admin(20) + app-type(1) + xrpl-token-decimals(1) +
    // xrpl-token-id(42) + current-range{next(8)+last(8)} +
    // next-range: tag(1) + next(8) + last(8) +
    // refill-pending(1) + refill-nonce(8) + bump(1)
    // Total: 8+20+20+1+1+42+8+8+1+8+8+1+8+1 = 135
    let mut data = vec![0u8; 135];
    // discriminator
    let disc = hex::decode("1432f4993cef2ea8").unwrap();
    data[..8].copy_from_slice(&disc);
    // next-range tag at offset 108 (8+20+20+1+1+42+8+8)
    data[108] = 1; // Some
                   // next = 100 (u64le)
    data[109..117].copy_from_slice(&100u64.to_le_bytes());
    // last = 200 (u64le)
    data[117..125].copy_from_slice(&200u64.to_le_bytes());

    let parsed = reg.parse(&ref_str, &data).unwrap();
    let obj = parsed.as_object().unwrap();
    // current-range is now a named ref to ticket-range
    let current = obj["current-range"].as_object().unwrap();
    assert_eq!(current["next"], "0");
    assert_eq!(current["last"], "0");
    // next-range is an option with ref
    let range = obj["next-range"].as_object().unwrap();
    assert_eq!(range["next"], "100");
    assert_eq!(range["last"], "200");
}

#[test]
fn option_xrpl_account_roundtrip_none() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let ref_str = format!("{XRPL}/xrpl-account");

    let mut data = vec![0u8; 135];
    let disc = hex::decode("1432f4993cef2ea8").unwrap();
    data[..8].copy_from_slice(&disc);
    // next-range tag at offset 108
    data[108] = 0; // None — padding is already zeros

    let parsed = reg.parse(&ref_str, &data).unwrap();
    let obj = parsed.as_object().unwrap();
    assert!(obj["next-range"].is_null());
}

#[test]
fn option_invalid_tag_rejected() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[{"name": "val", "option": {"type": "u8"}}]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    // Tag byte = 2 (invalid)
    let result = reg.parse("test", &[2, 0]);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("invalid option tag"), "error was: {}", err);
}

#[test]
fn option_ref_fixed_roundtrip() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("inner.json"),
        r#"[{"name": "x", "type": "u32le"}, {"name": "y", "type": "u32le"}]"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[
            {"name": "tag", "type": "u8"},
            {"name": "data", "option": {"ref": "@this/inner"}}
        ]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    // Some
    let values = serde_json::json!({"tag": "1", "data": {"x": "10", "y": "20"}});
    let payload = reg.serialize("test", &values).unwrap();
    // tag(1) + option_tag(1) + x(4) + y(4) = 10
    assert_eq!(payload.len(), 10);
    assert_eq!(payload[1], 1); // Some

    let parsed = reg.parse("test", &payload).unwrap();
    let data = parsed["data"].as_object().unwrap();
    assert_eq!(data["x"], "10");
    assert_eq!(data["y"], "20");

    // None
    let values = serde_json::json!({"tag": "1", "data": null});
    let payload = reg.serialize("test", &values).unwrap();
    // tag(1) + option_tag(1) + padding(8) = 10 (fixed size preserved)
    assert_eq!(payload.len(), 10);
    assert_eq!(payload[1], 0); // None
    assert_eq!(&payload[2..10], &[0u8; 8]);

    let parsed = reg.parse("test", &payload).unwrap();
    assert!(parsed["data"].is_null());
}

#[test]
fn option_ref_compact_roundtrip() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("inner.json"),
        r#"[{"name": "x", "type": "u16be"}]"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("test.json"),
        r#"[
            {"name": "data", "option": {"ref": "@this/inner", "compact": true}},
            {"name": "end", "type": "u8"}
        ]"#,
    )
    .unwrap();
    let reg = Registry::load(dir.path()).unwrap();

    // Some
    let values = serde_json::json!({"data": {"x": "999"}, "end": "7"});
    let payload = reg.serialize("test", &values).unwrap();
    assert_eq!(payload.len(), 4); // tag(1) + x(2) + end(1)

    let parsed = reg.parse("test", &payload).unwrap();
    assert_eq!(parsed["data"]["x"], "999");
    assert_eq!(parsed["end"], "7");

    // None — compact, no padding
    let values = serde_json::json!({"data": null, "end": "7"});
    let payload = reg.serialize("test", &values).unwrap();
    assert_eq!(payload.len(), 2); // tag(1) + end(1)
    assert_eq!(payload[0], 0);
    assert_eq!(payload[1], 7);

    let parsed = reg.parse("test", &payload).unwrap();
    assert!(parsed["data"].is_null());
    assert_eq!(parsed["end"], "7");
}
