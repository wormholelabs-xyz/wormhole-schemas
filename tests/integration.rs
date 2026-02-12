use std::path::PathBuf;
use wormhole_schemas::Registry;

const ZERO_ADDR: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const XRPL: &str = "@wormholelabs-xyz/ripple";
const NTT: &str = "@wormhole-foundation/native-token-transfers";
const WH: &str = "@wormhole-foundation/wormhole";

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
    assert_eq!(names.len(), 14);
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
    assert_eq!(rc.field_type, "u16");
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
