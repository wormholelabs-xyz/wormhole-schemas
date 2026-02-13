use anyhow::{bail, Context, Result};

use crate::schema::FieldType;

/// Information about a named argument in a schema.
#[derive(Debug, Clone)]
pub struct ArgInfo {
    pub name: String,
    pub field_type: String,
    pub help: Option<String>,
}

/// Serialize a single field value to bytes based on its type.
pub fn serialize_field(field_type: &FieldType, value: &str, output: &mut Vec<u8>) -> Result<()> {
    match field_type {
        FieldType::U8 => {
            let n: u8 = value
                .parse()
                .with_context(|| format!("invalid u8: {}", value))?;
            output.push(n);
        }
        FieldType::U16Be => {
            let n: u16 = value
                .parse()
                .with_context(|| format!("invalid u16be: {}", value))?;
            output.extend_from_slice(&n.to_be_bytes());
        }
        FieldType::U16Le => {
            let n: u16 = value
                .parse()
                .with_context(|| format!("invalid u16le: {}", value))?;
            output.extend_from_slice(&n.to_le_bytes());
        }
        FieldType::U32Be => {
            let n: u32 = value
                .parse()
                .with_context(|| format!("invalid u32be: {}", value))?;
            output.extend_from_slice(&n.to_be_bytes());
        }
        FieldType::U32Le => {
            let n: u32 = value
                .parse()
                .with_context(|| format!("invalid u32le: {}", value))?;
            output.extend_from_slice(&n.to_le_bytes());
        }
        FieldType::U64Be => {
            let n: u64 = value
                .parse()
                .with_context(|| format!("invalid u64be: {}", value))?;
            output.extend_from_slice(&n.to_be_bytes());
        }
        FieldType::U64Le => {
            let n: u64 = value
                .parse()
                .with_context(|| format!("invalid u64le: {}", value))?;
            output.extend_from_slice(&n.to_le_bytes());
        }
        FieldType::U256Be => {
            let n: ethnum::U256 = value
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid u256be: {}", value))?;
            output.extend_from_slice(&n.to_be_bytes());
        }
        FieldType::U256Le => {
            let n: ethnum::U256 = value
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid u256le: {}", value))?;
            output.extend_from_slice(&n.to_le_bytes());
        }
        FieldType::Address => {
            let bytes = parse_address(value)?;
            output.extend_from_slice(&bytes);
        }
        FieldType::String32 => {
            let ascii = value.as_bytes();
            if ascii.len() > 32 {
                bail!("string32 value too long: {} bytes", ascii.len());
            }
            // Left-zero-padded: zeros first, then the string
            let padding = 32 - ascii.len();
            output.extend(std::iter::repeat_n(0u8, padding));
            output.extend_from_slice(ascii);
        }
        FieldType::Hex => {
            if value.is_empty() {
                // Empty hex is valid — zero bytes
                return Ok(());
            }
            let bytes =
                hex::decode(value).with_context(|| format!("invalid hex value: {}", value))?;
            output.extend_from_slice(&bytes);
        }
        FieldType::Bytes(n) => {
            let bytes = hex::decode(value)
                .with_context(|| format!("invalid hex for bytes{}: {}", n, value))?;
            if bytes.len() != *n {
                bail!(
                    "bytes{} requires exactly {} bytes, got {}",
                    n,
                    n,
                    bytes.len()
                );
            }
            output.extend_from_slice(&bytes);
        }
    }
    Ok(())
}

/// Parse an address value into a 32-byte array.
///
/// Accepts:
/// - 64-char hex (32 bytes) — used directly
/// - 40-char hex (20 bytes) — left-zero-padded to 32 bytes
/// - Base58 string — decoded and zero-padded if needed
fn parse_address(value: &str) -> Result<[u8; 32]> {
    let mut result = [0u8; 32];

    // Try hex first — only if the length matches 40 (20 bytes) or 64 (32 bytes) chars
    if (value.len() == 40 || value.len() == 64) && value.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(value) {
            match bytes.len() {
                32 => {
                    result.copy_from_slice(&bytes);
                    return Ok(result);
                }
                20 => {
                    // Left-zero-pad: 12 zeros + 20 bytes
                    result[12..].copy_from_slice(&bytes);
                    return Ok(result);
                }
                _ => {}
            }
        }
    }

    // Try base58
    let decoded = bs58::decode(value)
        .into_vec()
        .with_context(|| format!("invalid address (not hex or base58): {}", value))?;

    match decoded.len() {
        32 => {
            result.copy_from_slice(&decoded);
        }
        20 => {
            result[12..].copy_from_slice(&decoded);
        }
        n if n < 32 => {
            // Zero-pad on the left
            let offset = 32 - n;
            result[offset..].copy_from_slice(&decoded);
        }
        _ => bail!(
            "base58 address decoded to {} bytes, expected ≤32",
            decoded.len()
        ),
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_u8() {
        let mut out = Vec::new();
        serialize_field(&FieldType::U8, "8", &mut out).unwrap();
        assert_eq!(out, vec![8]);
    }

    #[test]
    fn serialize_u16be() {
        let mut out = Vec::new();
        serialize_field(&FieldType::U16Be, "256", &mut out).unwrap();
        assert_eq!(out, vec![1, 0]);
    }

    #[test]
    fn serialize_u16le() {
        let mut out = Vec::new();
        serialize_field(&FieldType::U16Le, "256", &mut out).unwrap();
        assert_eq!(out, vec![0, 1]);
    }

    #[test]
    fn serialize_u32le() {
        let mut out = Vec::new();
        serialize_field(&FieldType::U32Le, "1", &mut out).unwrap();
        assert_eq!(out, vec![1, 0, 0, 0]);
    }

    #[test]
    fn serialize_u64be() {
        let mut out = Vec::new();
        serialize_field(&FieldType::U64Be, "1", &mut out).unwrap();
        assert_eq!(out, vec![0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn serialize_u64le() {
        let mut out = Vec::new();
        serialize_field(&FieldType::U64Le, "1", &mut out).unwrap();
        assert_eq!(out, vec![1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn serialize_bytes20() {
        let mut out = Vec::new();
        serialize_field(
            &FieldType::Bytes(20),
            "0000000000000000000000000000000000000001",
            &mut out,
        )
        .unwrap();
        assert_eq!(out.len(), 20);
        assert_eq!(out[19], 1);
    }

    #[test]
    fn serialize_address_32_hex() {
        let mut out = Vec::new();
        let hex_32 = "0000000000000000000000000000000000000000000000000000000000000001";
        serialize_field(&FieldType::Address, hex_32, &mut out).unwrap();
        assert_eq!(out.len(), 32);
        assert_eq!(out[31], 1);
    }

    #[test]
    fn serialize_address_20_hex() {
        let mut out = Vec::new();
        let hex_20 = "0000000000000000000000000000000000000001";
        serialize_field(&FieldType::Address, hex_20, &mut out).unwrap();
        assert_eq!(out.len(), 32);
        // 12 zero-pad + 20 bytes
        assert_eq!(out[31], 1);
        assert_eq!(out[0..12], [0u8; 12]);
    }

    #[test]
    fn serialize_string32() {
        let mut out = Vec::new();
        serialize_field(&FieldType::String32, "NTT", &mut out).unwrap();
        assert_eq!(out.len(), 32);
        // Left-zero-padded: 29 zeros + "NTT"
        assert_eq!(&out[29..], b"NTT");
        assert_eq!(&out[..29], &[0u8; 29]);
    }

    #[test]
    fn serialize_hex_empty() {
        let mut out = Vec::new();
        serialize_field(&FieldType::Hex, "", &mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn serialize_hex_nonempty() {
        let mut out = Vec::new();
        serialize_field(&FieldType::Hex, "AABB", &mut out).unwrap();
        assert_eq!(out, vec![0xAA, 0xBB]);
    }

    #[test]
    fn serialize_u256be_zero() {
        let mut out = Vec::new();
        serialize_field(&FieldType::U256Be, "0", &mut out).unwrap();
        assert_eq!(out, vec![0u8; 32]);
    }

    #[test]
    fn serialize_u256be_small() {
        let mut out = Vec::new();
        serialize_field(&FieldType::U256Be, "100000000", &mut out).unwrap();
        assert_eq!(out.len(), 32);
        // 100000000 = 0x05f5e100
        assert_eq!(&out[28..], &[0x05, 0xf5, 0xe1, 0x00]);
        assert_eq!(&out[..28], &[0u8; 28]);
    }

    #[test]
    fn serialize_u256be_max() {
        let mut out = Vec::new();
        serialize_field(
            &FieldType::U256Be,
            "115792089237316195423570985008687907853269984665640564039457584007913129639935",
            &mut out,
        )
        .unwrap();
        assert_eq!(out, vec![0xFF; 32]);
    }

    #[test]
    fn serialize_u256be_invalid() {
        let mut out = Vec::new();
        assert!(serialize_field(&FieldType::U256Be, "not_a_number", &mut out).is_err());
    }

    #[test]
    fn serialize_u256le_small() {
        let mut out = Vec::new();
        serialize_field(&FieldType::U256Le, "100000000", &mut out).unwrap();
        assert_eq!(out.len(), 32);
        // 100000000 = 0x05f5e100 — LE: least significant byte first
        assert_eq!(&out[..4], &[0x00, 0xe1, 0xf5, 0x05]);
        assert_eq!(&out[4..], &[0u8; 28]);
    }

    #[test]
    fn address_base58() {
        // A known Solana pubkey in base58
        let result = parse_address("11111111111111111111111111111111").unwrap();
        assert_eq!(result, [0u8; 32]);
    }
}
