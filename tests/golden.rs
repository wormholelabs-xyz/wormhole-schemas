//! Golden tests: serialize known inputs and compare byte-for-byte against
//! payloads from the NTT repo and the XRPL sequencer test suite.

use std::path::PathBuf;
use wormhole_schemas::Registry;

const XRPL: &str = "@wormholelabs-xyz/ripple";
const NTT: &str = "@wormhole-foundation/native-token-transfers";
const WH: &str = "@wormhole-foundation/wormhole";

fn schema_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schemas")
}

// ---------------------------------------------------------------------------
// NTT upstream golden vectors from wormhole-foundation/native-token-transfers
// Source: evm/test/payloads/
//
// All three transceiver_message variants share the same NTT field values.
// They differ only in the NativeTokenTransfer additional payload:
//
//   _1:                  NTT<EmptyPayload>     → no additional_payload_len (79-byte NTT)
//   _with_empty_payload: NTT<EmptyMockPayload> → additional_payload_len=0  (81-byte NTT)
//   _with_32byte_payload:NTT<MockPayload>      → additional_payload_len=32 (113-byte NTT)
//
// EmptyPayload has SIZE=Some(0) which causes the length prefix to be skipped.
// The XRPL codebase uses EmptyPayload, so `route` matches _1.
// ---------------------------------------------------------------------------

/// Shared field values for all three upstream test vectors.
fn ntt_upstream_values() -> serde_json::Value {
    serde_json::json!({
        "source-ntt-manager": "042942fafabe0000000000000000000000000000000000000000000000000000",
        "custody-account": "042942fababe0000000000000000000000000000000000000000000000000000",
        "payload": {
            "id": "128434bafe23430000000000000000000000000000000000ce00aa0000000000",
            "sender": "4667921341234300000000000000000000000000000000000000000000000000",
            "payload": {
                "decimals": "7",
                "amount": "1234567",
                "source-token": "beefface00000000000000000000000000000000000000000000000000000000",
                "recipient": "feebcafe00000000000000000000000000000000000000000000000000000000",
                "recipient-chain": "2",
            },
        },
    })
}

/// transceiver_message_1.txt — NTT<EmptyPayload> (no additional_payload_len).
/// This is the format the XRPL codebase uses. `route` schema matches byte-for-byte.
#[test]
fn golden_ntt_transceiver_message_1() {
    let golden = hex::decode(concat!(
        "9945ff10",                                                         // transceiver prefix
        "042942fafabe0000000000000000000000000000000000000000000000000000", // source_ntt_manager
        "042942fababe0000000000000000000000000000000000000000000000000000", // recipient_ntt_manager
        "0091",                                                             // mgr_payload_len = 145
        "128434bafe23430000000000000000000000000000000000ce00aa0000000000", // id
        "4667921341234300000000000000000000000000000000000000000000000000", // sender
        "004f",                                                             // ntt_payload_len = 79
        "994e5454",                                                         // NTT prefix
        "07",                                                               // decimals = 7
        "000000000012d687",                                                 // amount = 1234567
        "beefface00000000000000000000000000000000000000000000000000000000", // source_token
        "feebcafe00000000000000000000000000000000000000000000000000000000", // recipient
        "0002",                                                             // recipient_chain = 2
        "0000", // transceiver_payload_len = 0
    ))
    .unwrap();

    assert_eq!(golden.len(), 217);

    let reg = Registry::load(&schema_dir()).unwrap();
    let ours = reg
        .serialize(&format!("{XRPL}/route"), &ntt_upstream_values())
        .unwrap();
    assert_eq!(ours, golden);
}

/// transceiver_message_with_empty_payload.txt — NTT with additional_payload_len=0.
/// Uses ntt-with-payload<empty> to add the length-prefixed empty payload.
#[test]
fn golden_ntt_transceiver_message_with_empty_payload() {
    let golden = hex::decode(concat!(
        "9945ff10",                                                         // transceiver prefix
        "042942fafabe0000000000000000000000000000000000000000000000000000", // source_ntt_manager
        "042942fababe0000000000000000000000000000000000000000000000000000", // recipient_ntt_manager
        "0093",                                                             // mgr_payload_len = 147
        "128434bafe23430000000000000000000000000000000000ce00aa0000000000", // id
        "4667921341234300000000000000000000000000000000000000000000000000", // sender
        "0051",                                                             // ntt_payload_len = 81
        "994e5454",                                                         // NTT prefix
        "07",                                                               // decimals = 7
        "000000000012d687",                                                 // amount = 1234567
        "beefface00000000000000000000000000000000000000000000000000000000", // source_token
        "feebcafe00000000000000000000000000000000000000000000000000000000", // recipient
        "0002",                                                             // recipient_chain = 2
        "0000", // additional_payload_len = 0
        "0000", // transceiver_payload_len = 0
    ))
    .unwrap();

    assert_eq!(golden.len(), 219);

    let reg = Registry::load(&schema_dir()).unwrap();
    // ntt-with-payload<empty> adds the additional_payload length prefix
    // The inner values are flat here since the refs are unnamed
    let values = serde_json::json!({
        "source-ntt-manager": "042942fafabe0000000000000000000000000000000000000000000000000000",
        "custody-account": "042942fababe0000000000000000000000000000000000000000000000000000",
        "payload": {
            "id": "128434bafe23430000000000000000000000000000000000ce00aa0000000000",
            "sender": "4667921341234300000000000000000000000000000000000000000000000000",
            "payload": {
                "decimals": "7",
                "amount": "1234567",
                "source-token": "beefface00000000000000000000000000000000000000000000000000000000",
                "recipient": "feebcafe00000000000000000000000000000000000000000000000000000000",
                "recipient-chain": "2",
            },
        },
    });
    let ours = reg
        .serialize(
            &format!("{NTT}/transceiver-message<{NTT}/ntt-manager-message<{NTT}/ntt-with-payload<{NTT}/empty>>>"),
            &values,
        )
        .unwrap();
    assert_eq!(ours, golden);
}

/// transceiver_message_with_32byte_payload.txt — NTT with 32-byte additional payload.
/// Uses ntt-with-payload<hex-payload> to add the length-prefixed payload.
#[test]
fn golden_ntt_transceiver_message_with_32byte_payload() {
    let golden = hex::decode(concat!(
        "9945ff10",                                                         // transceiver prefix
        "042942fafabe0000000000000000000000000000000000000000000000000000", // source_ntt_manager
        "042942fababe0000000000000000000000000000000000000000000000000000", // recipient_ntt_manager
        "00b3",                                                             // mgr_payload_len = 179
        "128434bafe23430000000000000000000000000000000000ce00aa0000000000", // id
        "4667921341234300000000000000000000000000000000000000000000000000", // sender
        "0071",                                                             // ntt_payload_len = 113
        "994e5454",                                                         // NTT prefix
        "07",                                                               // decimals = 7
        "000000000012d687",                                                 // amount = 1234567
        "beefface00000000000000000000000000000000000000000000000000000000", // source_token
        "feebcafe00000000000000000000000000000000000000000000000000000000", // recipient
        "0002",                                                             // recipient_chain = 2
        "0020", // additional_payload_len = 32
        "deadbeef000000000000000000000000000000000000000000000000deadbeef", // additional_payload
        "0000", // transceiver_payload_len = 0
    ))
    .unwrap();

    assert_eq!(golden.len(), 251);

    let reg = Registry::load(&schema_dir()).unwrap();
    let values = serde_json::json!({
        "source-ntt-manager": "042942fafabe0000000000000000000000000000000000000000000000000000",
        "custody-account": "042942fababe0000000000000000000000000000000000000000000000000000",
        "payload": {
            "id": "128434bafe23430000000000000000000000000000000000ce00aa0000000000",
            "sender": "4667921341234300000000000000000000000000000000000000000000000000",
            "payload": {
                "decimals": "7",
                "amount": "1234567",
                "source-token": "beefface00000000000000000000000000000000000000000000000000000000",
                "recipient": "feebcafe00000000000000000000000000000000000000000000000000000000",
                "recipient-chain": "2",
                "additional-payload": "deadbeef000000000000000000000000000000000000000000000000deadbeef",
            },
        },
    });
    let ours = reg
        .serialize(
            &format!("{NTT}/transceiver-message<{NTT}/ntt-manager-message<{NTT}/ntt-with-payload<{NTT}/hex-payload>>>"),
            &values,
        )
        .unwrap();
    assert_eq!(ours, golden);
}

// ---------------------------------------------------------------------------
// NTT upstream: transceiver_registration_1.txt
// ---------------------------------------------------------------------------

#[test]
fn golden_ntt_transceiver_registration() {
    let golden = hex::decode(concat!(
        "18fc67c2", // transceiver registration prefix
        "0017",     // chain_id = 23
        "bababafefe000000000000000000000000000000000000000000000000000000", // transceiver_address
    ))
    .unwrap();

    assert_eq!(golden.len(), 38);
    assert_eq!(&golden[4..6], &23u16.to_be_bytes());
}

// ---------------------------------------------------------------------------
// XRPL onboarding: test_xrpl_address(1) with known fields
// Source: xrpl-sequencer/tests/common/xrpl.rs test_onboarding_payload
// ---------------------------------------------------------------------------

#[test]
fn golden_xrpl_onboard() {
    let admin_hex = "01deadbeef000000000000000000000000000000";

    let reg = Registry::load(&schema_dir()).unwrap();
    let payload = reg
        .serialize(
            &format!("{XRPL}/onboard"),
            &serde_json::json!({
                "admin": admin_hex,
                "app-type": "NTT",
                "initial-ticket": "100",
                "ticket-count": "150",
                "init-data": "010203",
            }),
        )
        .unwrap();

    // Total: 4 + 20 + 32 + 8 + 8 + 3 = 75
    assert_eq!(payload.len(), 75);

    // prefix "XRPL"
    assert_eq!(&payload[0..4], b"XRPL");

    // admin (20 bytes)
    assert_eq!(&payload[4..24], &hex::decode(admin_hex).unwrap());

    // app_type "NTT" in 32 bytes, left-zero-padded
    assert_eq!(&payload[24..53], &[0u8; 29]);
    assert_eq!(&payload[53..56], b"NTT");

    // initial_ticket = 100
    assert_eq!(&payload[56..64], &100u64.to_be_bytes());

    // ticket_count = 150
    assert_eq!(&payload[64..72], &150u64.to_be_bytes());

    // init_data = [1, 2, 3]
    assert_eq!(&payload[72..75], &[1, 2, 3]);
}

// ---------------------------------------------------------------------------
// XRPL register-peer: test_xrpl_address(1), chain=2, peer=[0xAB; 32]
// Source: xrpl-sequencer/tests/common/xrpl.rs test_register_peer_payload
// ---------------------------------------------------------------------------

#[test]
fn golden_xrpl_register_peer() {
    let target_hex = "01deadbeef000000000000000000000000000000";
    let peer_hex = "abababababababababababababababababababababababababababababababab";

    let reg = Registry::load(&schema_dir()).unwrap();
    let payload = reg
        .serialize(
            &format!("{XRPL}/register-peer"),
            &serde_json::json!({
                "target-account": target_hex,
                "chain-id": "2",
                "peer-address": peer_hex,
            }),
        )
        .unwrap();

    // Total: 4 + 1 + 20 + 2 + 32 = 59
    assert_eq!(payload.len(), 59);

    // prefix "XADM"
    assert_eq!(&payload[0..4], b"XADM");

    // action = 0x01
    assert_eq!(payload[4], 0x01);

    // target_account
    assert_eq!(&payload[5..25], &hex::decode(target_hex).unwrap());

    // chain_id = 2
    assert_eq!(&payload[25..27], &2u16.to_be_bytes());

    // peer_address
    assert_eq!(&payload[27..59], &[0xAB; 32]);
}

// ---------------------------------------------------------------------------
// E2E fixture: onboarding from xrpl-client/fixtures/e2e-xrp/onboarding.json
// Real field values from a testnet transaction
// ---------------------------------------------------------------------------

#[test]
fn golden_e2e_onboard() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let payload = reg
        .serialize(
            &format!("{XRPL}/onboard"),
            &serde_json::json!({
                "admin": "e1307c2234835da6d831a9b3422f7d067520a914",
                "app-type": "NTT",
                "initial-ticket": "5",
                "ticket-count": "48",
                "init-data": "06000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            }),
        )
        .unwrap();

    // 4 + 20 + 32 + 8 + 8 + 43 = 115
    assert_eq!(payload.len(), 115);

    // prefix "XRPL"
    assert_eq!(&payload[0..4], b"XRPL");

    // admin
    assert_eq!(
        &payload[4..24],
        &hex::decode("e1307c2234835da6d831a9b3422f7d067520a914").unwrap()
    );

    // initial_ticket = 5
    assert_eq!(&payload[56..64], &5u64.to_be_bytes());

    // ticket_count = 48
    assert_eq!(&payload[64..72], &48u64.to_be_bytes());

    // init_data = 06 + 42 zero bytes
    assert_eq!(payload[72], 0x06);
    assert_eq!(&payload[73..115], &[0u8; 42]);
}

// ---------------------------------------------------------------------------
// E2E fixture: register-peer from xrpl-client/fixtures/e2e-xrp/register-peer.json
// Real field values from a testnet transaction
// ---------------------------------------------------------------------------

#[test]
fn golden_e2e_register_peer() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let payload = reg
        .serialize(
            &format!("{XRPL}/register-peer"),
            &serde_json::json!({
                "target-account": "9a327fdb08b05f049e206ca974915d1d3ea5a11f",
                "chain-id": "66",
                "peer-address": "305e53530fb264d2cb5ecebb2c97538c70d7b76846858e1247980bec62f1020b",
            }),
        )
        .unwrap();

    assert_eq!(payload.len(), 59);

    // prefix "XADM"
    assert_eq!(&payload[0..4], b"XADM");
    // action
    assert_eq!(payload[4], 0x01);
    // target_account
    assert_eq!(
        &payload[5..25],
        &hex::decode("9a327fdb08b05f049e206ca974915d1d3ea5a11f").unwrap()
    );
    // chain_id = 66
    assert_eq!(&payload[25..27], &66u16.to_be_bytes());
    // peer_address
    assert_eq!(
        &payload[27..59],
        &hex::decode("305e53530fb264d2cb5ecebb2c97538c70d7b76846858e1247980bec62f1020b").unwrap()
    );
}

// ---------------------------------------------------------------------------
// E2E: full VAA body wrapping an onboarding payload, with fields from fixture
// ---------------------------------------------------------------------------

#[test]
fn golden_e2e_vaa_body_onboard() {
    let reg = Registry::load(&schema_dir()).unwrap();
    let payload = reg
        .serialize(
            &format!("{WH}/vaa-body<{XRPL}/onboard>"),
            &serde_json::json!({
                "timestamp": "1700000000",
                "nonce": "0",
                "emitter-chain": "66",
                "emitter-address": "0000000000000000000000009a327fdb08b05f049e206ca974915d1d3ea5a11f",
                "sequence": "655360",
                "consistency-level": "200",
                "payload": {
                    "admin": "e1307c2234835da6d831a9b3422f7d067520a914",
                    "app-type": "NTT",
                    "initial-ticket": "5",
                    "ticket-count": "48",
                    "init-data": "06000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                },
            }),
        )
        .unwrap();

    // VAA body: 4+4+2+32+8+1 = 51, payload: 115
    // Total: 166
    assert_eq!(payload.len(), 166);

    // VAA body fields
    assert_eq!(&payload[0..4], &1700000000u32.to_be_bytes());
    assert_eq!(&payload[4..8], &0u32.to_be_bytes());
    assert_eq!(&payload[8..10], &66u16.to_be_bytes());
    // emitter address — XRPL address right-aligned in 32 bytes
    assert_eq!(&payload[10..22], &[0u8; 12]);
    assert_eq!(
        &payload[22..42],
        &hex::decode("9a327fdb08b05f049e206ca974915d1d3ea5a11f").unwrap()
    );
    assert_eq!(&payload[42..50], &655360u64.to_be_bytes());
    assert_eq!(payload[50], 200);

    // Onboarding prefix starts at 51
    assert_eq!(&payload[51..55], b"XRPL");
}

// ---------------------------------------------------------------------------
// Golden parse tests: parse known binary payloads and verify field values
// ---------------------------------------------------------------------------

/// Parse the transceiver_message_1 golden vector (217 bytes) via `route` schema.
#[test]
fn golden_parse_transceiver_message_1() {
    let golden = hex::decode(concat!(
        "9945ff10",                                                         // transceiver prefix
        "042942fafabe0000000000000000000000000000000000000000000000000000", // source_ntt_manager
        "042942fababe0000000000000000000000000000000000000000000000000000", // recipient_ntt_manager
        "0091",                                                             // mgr_payload_len = 145
        "128434bafe23430000000000000000000000000000000000ce00aa0000000000", // id
        "4667921341234300000000000000000000000000000000000000000000000000", // sender
        "004f",                                                             // ntt_payload_len = 79
        "994e5454",                                                         // NTT prefix
        "07",                                                               // decimals = 7
        "000000000012d687",                                                 // amount = 1234567
        "beefface00000000000000000000000000000000000000000000000000000000", // source_token
        "feebcafe00000000000000000000000000000000000000000000000000000000", // recipient
        "0002",                                                             // recipient_chain = 2
        "0000", // transceiver_payload_len = 0
    ))
    .unwrap();

    let reg = Registry::load(&schema_dir()).unwrap();
    let parsed = reg.parse(&format!("{XRPL}/route"), &golden).unwrap();

    assert_eq!(
        parsed,
        serde_json::json!({
            "source-ntt-manager": "042942fafabe0000000000000000000000000000000000000000000000000000",
            "custody-account":    "042942fababe0000000000000000000000000000000000000000000000000000",
            "payload": {
                "id":              "128434bafe23430000000000000000000000000000000000ce00aa0000000000",
                "sender":          "4667921341234300000000000000000000000000000000000000000000000000",
                "payload": {
                    "decimals":        "7",
                    "amount":          "1234567",
                    "source-token":    "beefface00000000000000000000000000000000000000000000000000000000",
                    "recipient":       "feebcafe00000000000000000000000000000000000000000000000000000000",
                    "recipient-chain": "2",
                },
            },
        })
    );
}

/// Parse a known onboard payload and verify all fields.
#[test]
fn golden_parse_xrpl_onboard() {
    let payload = hex::decode(concat!(
        "5852504c",                                                         // "XRPL" prefix
        "01deadbeef000000000000000000000000000000",                         // admin (20 bytes)
        "00000000000000000000000000000000000000000000000000000000004e5454", // app-type "NTT" (32 bytes)
        "0000000000000064",                                                 // initial-ticket = 100
        "0000000000000096",                                                 // ticket-count = 150
        "010203",                                                           // init-data
    ))
    .unwrap();

    let reg = Registry::load(&schema_dir()).unwrap();
    let parsed = reg.parse(&format!("{XRPL}/onboard"), &payload).unwrap();

    assert_eq!(
        parsed,
        serde_json::json!({
            "admin":          "01deadbeef000000000000000000000000000000",
            "app-type":       "NTT",
            "initial-ticket": "100",
            "ticket-count":   "150",
            "init-data":      "010203",
        })
    );
}

/// Parse a register-peer payload from known hex.
#[test]
fn golden_parse_register_peer() {
    let payload = hex::decode(concat!(
        "5841444d",                                                         // "XADM"
        "01",                                                               // action
        "9a327fdb08b05f049e206ca974915d1d3ea5a11f",                         // target-account
        "0042",                                                             // chain-id = 66
        "305e53530fb264d2cb5ecebb2c97538c70d7b76846858e1247980bec62f1020b", // peer-address
    ))
    .unwrap();

    let reg = Registry::load(&schema_dir()).unwrap();
    let parsed = reg
        .parse(&format!("{XRPL}/register-peer"), &payload)
        .unwrap();

    assert_eq!(
        parsed,
        serde_json::json!({
            "target-account": "9a327fdb08b05f049e206ca974915d1d3ea5a11f",
            "chain-id":       "66",
            "peer-address":   "305e53530fb264d2cb5ecebb2c97538c70d7b76846858e1247980bec62f1020b",
        })
    );
}

/// Parse a full VAA with 2 signatures wrapping a register-peer payload.
#[test]
fn golden_parse_vaa_with_signatures() {
    let reg = Registry::load(&schema_dir()).unwrap();

    let ref_str = format!("{WH}/vaa<{XRPL}/register-peer>");

    // Build via serialize so we have a known-good payload
    let vaa_bytes = reg
        .serialize(
            &ref_str,
            &serde_json::json!({
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
            }),
        )
        .unwrap();

    let parsed = reg.parse(&ref_str, &vaa_bytes).unwrap();

    assert_eq!(
        parsed,
        serde_json::json!({
            "guardian-set-index": "4",
            "signature-count":   "2",
            "signatures": [
                { "guardian-index": "0", "signature": "aa".repeat(65) },
                { "guardian-index": "1", "signature": "bb".repeat(65) },
            ],
            "timestamp":         "1700000000",
            "nonce":             "42",
            "emitter-chain":     "66",
            "emitter-address":   "0000000000000000000000000000000000000000000000000000000000000001",
            "sequence":          "100",
            "consistency-level": "200",
            "payload": {
                "target-account":    "9a327fdb08b05f049e206ca974915d1d3ea5a11f",
                "chain-id":          "1",
                "peer-address":      "305e53530fb264d2cb5ecebb2c97538c70d7b76846858e1247980bec62f1020b",
            },
        })
    );
}

// ---------------------------------------------------------------------------
// Structural match: our route schema produces a valid NTT transceiver message
// that has the same structure as the NTT upstream test vector.
// ---------------------------------------------------------------------------

#[test]
fn golden_route_structural_match() {
    let zero = "0000000000000000000000000000000000000000000000000000000000000000";
    let reg = Registry::load(&schema_dir()).unwrap();
    let payload = reg
        .serialize(
            &format!("{XRPL}/route"),
            &serde_json::json!({
                "source-ntt-manager": zero,
                "custody-account": "042942fababe0000000000000000000000000000000000000000000000000000",
                "payload": {
                    "id": zero,
                    "sender": zero,
                    "payload": {
                        "decimals": "7",
                        "amount": "1234567",
                        "source-token": "beefface00000000000000000000000000000000000000000000000000000000",
                        "recipient": "feebcafe00000000000000000000000000000000000000000000000000000000",
                        "recipient-chain": "2",
                    },
                },
            }),
        )
        .unwrap();

    // NTT=79 (no additional_payload_len), mgr=32+32+2+79=145
    // 4 + 32 + 32 + 2 + 145 + 2 = 217
    assert_eq!(payload.len(), 217);

    // Transceiver prefix
    assert_eq!(&payload[0..4], &hex::decode("9945ff10").unwrap());

    // NttManagerMessage length prefix
    let mgr_len = u16::from_be_bytes([payload[68], payload[69]]);
    assert_eq!(mgr_len, 145);

    // NativeTokenTransfer length prefix
    let ntt_len = u16::from_be_bytes([payload[134], payload[135]]);
    assert_eq!(ntt_len, 79);

    // NTT prefix
    assert_eq!(&payload[136..140], &hex::decode("994e5454").unwrap());

    // trailing 0000 (transceiver_payload_len = 0)
    assert_eq!(&payload[215..217], &[0u8; 2]);
}
