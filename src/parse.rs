use anyhow::{bail, Context, Result};

use crate::schema::FieldType;

/// A cursor over a byte slice for sequential parsing.
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            bail!(
                "unexpected end of data at offset {}: need {} bytes, have {}",
                self.pos,
                n,
                self.remaining()
            );
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    pub fn read_remaining(&mut self) -> &'a [u8] {
        let slice = &self.data[self.pos..];
        self.pos = self.data.len();
        slice
    }

    /// Carve out the next `n` bytes as a new bounded cursor.
    pub fn sub_cursor(&mut self, n: usize) -> Result<Cursor<'a>> {
        let bytes = self.read_bytes(n)?;
        Ok(Cursor::new(bytes))
    }

    pub fn assert_exhausted(&self) -> Result<()> {
        if self.remaining() > 0 {
            bail!(
                "{} unexpected trailing bytes at offset {}",
                self.remaining(),
                self.pos
            );
        }
        Ok(())
    }
}

/// Parse a single typed field from the cursor, returning a string representation.
pub fn parse_field(field_type: &FieldType, cursor: &mut Cursor) -> Result<String> {
    match field_type {
        FieldType::U8 => {
            let b = cursor.read_bytes(1)?;
            Ok(b[0].to_string())
        }
        FieldType::U16Be => {
            let b = cursor.read_bytes(2)?;
            Ok(u16::from_be_bytes([b[0], b[1]]).to_string())
        }
        FieldType::U16Le => {
            let b = cursor.read_bytes(2)?;
            Ok(u16::from_le_bytes([b[0], b[1]]).to_string())
        }
        FieldType::U32Be => {
            let b = cursor.read_bytes(4)?;
            Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]).to_string())
        }
        FieldType::U32Le => {
            let b = cursor.read_bytes(4)?;
            Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]).to_string())
        }
        FieldType::U64Be => {
            let b = cursor.read_bytes(8)?;
            Ok(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]).to_string())
        }
        FieldType::U64Le => {
            let b = cursor.read_bytes(8)?;
            Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]).to_string())
        }
        FieldType::U256Be => {
            let b = cursor.read_bytes(32)?;
            let n = ethnum::U256::from_be_bytes(b.try_into().unwrap());
            Ok(n.to_string())
        }
        FieldType::U256Le => {
            let b = cursor.read_bytes(32)?;
            let n = ethnum::U256::from_le_bytes(b.try_into().unwrap());
            Ok(n.to_string())
        }
        FieldType::Address => {
            let b = cursor.read_bytes(32)?;
            Ok(hex::encode(b))
        }
        FieldType::String32 => {
            let b = cursor.read_bytes(32)?;
            // Strip left zero-padding, return ASCII
            let start = b.iter().position(|&x| x != 0).unwrap_or(32);
            let s = std::str::from_utf8(&b[start..]).context("string32 contains non-UTF8 bytes")?;
            Ok(s.to_string())
        }
        FieldType::Hex => {
            let b = cursor.read_remaining();
            Ok(hex::encode(b))
        }
        FieldType::Bytes(n) => {
            let b = cursor.read_bytes(*n)?;
            Ok(hex::encode(b))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_read_bytes() {
        let mut c = Cursor::new(&[1, 2, 3, 4]);
        assert_eq!(c.read_bytes(2).unwrap(), &[1, 2]);
        assert_eq!(c.position(), 2);
        assert_eq!(c.remaining(), 2);
        assert_eq!(c.read_bytes(2).unwrap(), &[3, 4]);
        c.assert_exhausted().unwrap();
    }

    #[test]
    fn cursor_read_past_end() {
        let mut c = Cursor::new(&[1]);
        assert!(c.read_bytes(2).is_err());
    }

    #[test]
    fn cursor_sub_cursor() {
        let mut c = Cursor::new(&[1, 2, 3, 4, 5]);
        let mut sub = c.sub_cursor(3).unwrap();
        assert_eq!(sub.read_bytes(2).unwrap(), &[1, 2]);
        assert_eq!(sub.remaining(), 1);
        // outer cursor advanced past the 3 bytes
        assert_eq!(c.remaining(), 2);
    }

    #[test]
    fn parse_u8() {
        let mut c = Cursor::new(&[42]);
        assert_eq!(parse_field(&FieldType::U8, &mut c).unwrap(), "42");
    }

    #[test]
    fn parse_u16be() {
        let mut c = Cursor::new(&[1, 0]);
        assert_eq!(parse_field(&FieldType::U16Be, &mut c).unwrap(), "256");
    }

    #[test]
    fn parse_u16le() {
        let mut c = Cursor::new(&[1, 0]);
        assert_eq!(parse_field(&FieldType::U16Le, &mut c).unwrap(), "1");
    }

    #[test]
    fn parse_u32le() {
        let mut c = Cursor::new(&[1, 0, 0, 0]);
        assert_eq!(parse_field(&FieldType::U32Le, &mut c).unwrap(), "1");
    }

    #[test]
    fn parse_u64be() {
        let mut c = Cursor::new(&[0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(parse_field(&FieldType::U64Be, &mut c).unwrap(), "1");
    }

    #[test]
    fn parse_u64le() {
        let mut c = Cursor::new(&[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(parse_field(&FieldType::U64Le, &mut c).unwrap(), "1");
    }

    #[test]
    fn parse_address() {
        let mut data = [0u8; 32];
        data[31] = 0xAB;
        let mut c = Cursor::new(&data);
        let s = parse_field(&FieldType::Address, &mut c).unwrap();
        assert_eq!(s.len(), 64);
        assert!(s.ends_with("ab"));
        assert!(s.starts_with("000000"));
    }

    #[test]
    fn parse_string32() {
        let mut data = [0u8; 32];
        data[29] = b'N';
        data[30] = b'T';
        data[31] = b'T';
        let mut c = Cursor::new(&data);
        assert_eq!(parse_field(&FieldType::String32, &mut c).unwrap(), "NTT");
    }

    #[test]
    fn parse_hex_empty() {
        let mut c = Cursor::new(&[]);
        assert_eq!(parse_field(&FieldType::Hex, &mut c).unwrap(), "");
    }

    #[test]
    fn parse_hex_nonempty() {
        let mut c = Cursor::new(&[0xAA, 0xBB]);
        assert_eq!(parse_field(&FieldType::Hex, &mut c).unwrap(), "aabb");
    }

    #[test]
    fn parse_bytes20() {
        let data = [0u8; 20];
        let mut c = Cursor::new(&data);
        let s = parse_field(&FieldType::Bytes(20), &mut c).unwrap();
        assert_eq!(s.len(), 40);
    }

    #[test]
    fn parse_u256be_zero() {
        let mut c = Cursor::new(&[0u8; 32]);
        assert_eq!(parse_field(&FieldType::U256Be, &mut c).unwrap(), "0");
    }

    #[test]
    fn parse_u256be_small() {
        let mut data = [0u8; 32];
        data[31] = 100;
        let mut c = Cursor::new(&data);
        assert_eq!(parse_field(&FieldType::U256Be, &mut c).unwrap(), "100");
    }

    #[test]
    fn parse_u256be_large() {
        // 100000000 = 0x05f5e100
        let mut data = [0u8; 32];
        data[28] = 0x05;
        data[29] = 0xf5;
        data[30] = 0xe1;
        data[31] = 0x00;
        let mut c = Cursor::new(&data);
        assert_eq!(
            parse_field(&FieldType::U256Be, &mut c).unwrap(),
            "100000000"
        );
    }

    #[test]
    fn parse_u256be_max() {
        let mut c = Cursor::new(&[0xFF; 32]);
        assert_eq!(
            parse_field(&FieldType::U256Be, &mut c).unwrap(),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
    }

    #[test]
    fn parse_u256le_small() {
        let mut data = [0u8; 32];
        data[0] = 100;
        let mut c = Cursor::new(&data);
        assert_eq!(parse_field(&FieldType::U256Le, &mut c).unwrap(), "100");
    }

    #[test]
    fn parse_u256le_large() {
        // 100000000 = 0x05f5e100 — in LE the least significant byte comes first
        let mut data = [0u8; 32];
        data[0] = 0x00;
        data[1] = 0xe1;
        data[2] = 0xf5;
        data[3] = 0x05;
        let mut c = Cursor::new(&data);
        assert_eq!(
            parse_field(&FieldType::U256Le, &mut c).unwrap(),
            "100000000"
        );
    }
}
