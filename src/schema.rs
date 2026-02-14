use anyhow::{bail, Result};
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;

/// Parsed representation of a field type string (e.g. "u8", "address", "bytes20").
///
/// Parsed once during deserialization so that parse/serialize can dispatch on
/// the enum instead of re-matching strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    U8,
    U16Be,
    U16Le,
    U32Be,
    U32Le,
    U64Be,
    U64Le,
    U256Be,
    U256Le,
    Address,
    String32,
    Hex,
    Bytes(usize),
}

impl FieldType {
    /// True for numeric types that can back an enum discriminant.
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            FieldType::U8
                | FieldType::U16Be
                | FieldType::U16Le
                | FieldType::U32Be
                | FieldType::U32Le
                | FieldType::U64Be
                | FieldType::U64Le
                | FieldType::U256Be
                | FieldType::U256Le
        )
    }

    pub fn from_type_str(s: &str) -> Result<Self, String> {
        match s {
            "u8" => Ok(FieldType::U8),
            "u16be" => Ok(FieldType::U16Be),
            "u16le" => Ok(FieldType::U16Le),
            "u32be" => Ok(FieldType::U32Be),
            "u32le" => Ok(FieldType::U32Le),
            "u64be" => Ok(FieldType::U64Be),
            "u64le" => Ok(FieldType::U64Le),
            "u256be" => Ok(FieldType::U256Be),
            "u256le" => Ok(FieldType::U256Le),
            "address" => Ok(FieldType::Address),
            "string32" => Ok(FieldType::String32),
            "hex" => Ok(FieldType::Hex),
            other if other.starts_with("bytes") => {
                let n: usize = other[5..]
                    .parse()
                    .map_err(|_| format!("invalid bytesN type: {}", other))?;
                Ok(FieldType::Bytes(n))
            }
            other => Err(format!("unknown field type: {}", other)),
        }
    }
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FieldType::U8 => write!(f, "u8"),
            FieldType::U16Be => write!(f, "u16be"),
            FieldType::U16Le => write!(f, "u16le"),
            FieldType::U32Be => write!(f, "u32be"),
            FieldType::U32Le => write!(f, "u32le"),
            FieldType::U64Be => write!(f, "u64be"),
            FieldType::U64Le => write!(f, "u64le"),
            FieldType::U256Be => write!(f, "u256be"),
            FieldType::U256Le => write!(f, "u256le"),
            FieldType::Address => write!(f, "address"),
            FieldType::String32 => write!(f, "string32"),
            FieldType::Hex => write!(f, "hex"),
            FieldType::Bytes(n) => write!(f, "bytes{}", n),
        }
    }
}

/// A single field in a schema.
#[derive(Debug, Clone)]
pub enum Field {
    Const {
        name: String,
        value: String,
    },
    Zeros(usize),
    /// A reference to another schema. If `name` is Some, the parsed result is
    /// nested under that key instead of merged flat.
    Ref {
        ref_: String,
        name: Option<String>,
    },
    LengthPrefix(String),
    Named {
        name: String,
        field_type: FieldType,
        help: Option<String>,
    },
    /// An enum field: named variants mapped to numeric discriminant values.
    /// JSON: `{"name": "app-type", "enum": {"type": "u8", "values": {"Core": 0, "Ntt": 2}}}`
    Enum {
        name: String,
        encoding: FieldType,
        values: Vec<(String, u64)>,
        help: Option<String>,
    },
    /// An array of schemas, repeated `count_field` times.
    /// JSON: `{"name": "sigs", "repeat": "sig-count", "ref": "@this/guardian-signature"}`
    Repeat {
        name: String,
        count_field: String,
        ref_: String,
    },
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldVisitor;

        impl<'de> Visitor<'de> for FieldVisitor {
            type Value = Field;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a field object")
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<Field, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut const_val: Option<String> = None;
                let mut zeros_val: Option<usize> = None;
                let mut ref_val: Option<String> = None;
                let mut length_prefix_val: Option<String> = None;
                let mut repeat_val: Option<String> = None;
                let mut enum_val: Option<serde_json::Value> = None;
                let mut anchor_val: Option<String> = None;
                let mut name_val: Option<String> = None;
                let mut type_val: Option<String> = None;
                let mut help_val: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "const" => const_val = Some(map.next_value()?),
                        "zeros" => zeros_val = Some(map.next_value()?),
                        "ref" => ref_val = Some(map.next_value()?),
                        "length_prefix" => length_prefix_val = Some(map.next_value()?),
                        "repeat" => repeat_val = Some(map.next_value()?),
                        "enum" => enum_val = Some(map.next_value()?),
                        "anchor" => anchor_val = Some(map.next_value()?),
                        "name" => name_val = Some(map.next_value()?),
                        "type" => type_val = Some(map.next_value()?),
                        "help" => help_val = Some(map.next_value()?),
                        _ => {
                            let _ = map.next_value::<serde_json::Value>()?;
                        }
                    }
                }

                if let Some(anchor) = anchor_val {
                    let name = name_val
                        .ok_or_else(|| de::Error::custom("anchor field requires a 'name'"))?;
                    Ok(Field::Const {
                        name,
                        value: anchor_discriminator(&anchor),
                    })
                } else if let Some(c) = const_val {
                    let name = name_val
                        .ok_or_else(|| de::Error::custom("const field requires a 'name'"))?;
                    Ok(Field::Const { name, value: c })
                } else if let Some(z) = zeros_val {
                    Ok(Field::Zeros(z))
                } else if let Some(repeat) = repeat_val {
                    let name = name_val
                        .ok_or_else(|| de::Error::custom("repeat field requires a 'name'"))?;
                    let ref_ = ref_val
                        .ok_or_else(|| de::Error::custom("repeat field requires a 'ref'"))?;
                    Ok(Field::Repeat {
                        name,
                        count_field: repeat,
                        ref_,
                    })
                } else if let Some(enum_obj) = enum_val {
                    let name = name_val
                        .ok_or_else(|| de::Error::custom("enum field requires a 'name'"))?;
                    parse_enum_field(name, enum_obj, help_val).map_err(de::Error::custom)
                } else if let Some(r) = ref_val {
                    Ok(Field::Ref {
                        ref_: r,
                        name: name_val,
                    })
                } else if let Some(lp) = length_prefix_val {
                    Ok(Field::LengthPrefix(lp))
                } else if let (Some(name), Some(ty)) = (name_val, type_val) {
                    let field_type = FieldType::from_type_str(&ty).map_err(de::Error::custom)?;
                    Ok(Field::Named {
                        name,
                        field_type,
                        help: help_val,
                    })
                } else {
                    Err(de::Error::custom("unrecognized field shape"))
                }
            }
        }

        deserializer.deserialize_map(FieldVisitor)
    }
}

/// A schema loaded from a file. Supports two JSON shapes:
/// - Bare array: `[{...}, {...}]` → fields only
/// - Object: `{ "about": ..., "params": [...], "fields": [...], "ref": "..." }`
#[derive(Debug, Clone)]
pub struct Schema {
    pub about: Option<String>,
    pub params: Vec<String>,
    pub fields: Option<Vec<Field>>,
    pub ref_: Option<String>,
}

impl<'de> Deserialize<'de> for Schema {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SchemaVisitor;

        impl<'de> Visitor<'de> for SchemaVisitor {
            type Value = Schema;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a schema (array or object)")
            }

            // Bare array shape
            fn visit_seq<A>(self, seq: A) -> std::result::Result<Schema, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let fields: Vec<Field> =
                    Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
                Ok(Schema {
                    about: None,
                    params: vec![],
                    fields: Some(fields),
                    ref_: None,
                })
            }

            // Object shape
            fn visit_map<M>(self, mut map: M) -> std::result::Result<Schema, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut about: Option<String> = None;
                let mut params: Option<Vec<String>> = None;
                let mut fields: Option<Vec<Field>> = None;
                let mut ref_: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "about" => about = Some(map.next_value()?),
                        "params" => params = Some(map.next_value()?),
                        "fields" => fields = Some(map.next_value()?),
                        "ref" => ref_ = Some(map.next_value()?),
                        _ => {
                            let _ = map.next_value::<serde_json::Value>()?;
                        }
                    }
                }

                Ok(Schema {
                    about,
                    params: params.unwrap_or_default(),
                    fields,
                    ref_,
                })
            }
        }

        deserializer.deserialize_any(SchemaVisitor)
    }
}

/// Get the user-visible name of a field, if it has one.
fn field_name(field: &Field) -> Option<&str> {
    match field {
        Field::Named { name, .. }
        | Field::Const { name, .. }
        | Field::Enum { name, .. }
        | Field::Repeat { name, .. } => Some(name.as_str()),
        Field::Ref {
            name: Some(name), ..
        } => Some(name.as_str()),
        _ => None,
    }
}

/// Compute an Anchor discriminator: `sha256(input)[..8]` as hex.
///
/// The input is the full discriminator string, e.g. `"account:XrplAccount"`.
fn anchor_discriminator(input: &str) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(input.as_bytes());
    hex::encode(&hash[..8])
}

/// Parse the `"enum"` object from a field JSON into a `Field::Enum`.
fn parse_enum_field(
    name: String,
    enum_obj: serde_json::Value,
    help: Option<String>,
) -> Result<Field, String> {
    let obj = enum_obj.as_object().ok_or("enum must be an object")?;

    let type_str = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or("enum requires a 'type' string")?;
    let encoding = FieldType::from_type_str(type_str)?;
    if !encoding.is_numeric() {
        return Err(format!(
            "enum encoding must be a numeric type, got '{}'",
            type_str
        ));
    }

    let values_obj = obj
        .get("values")
        .and_then(|v| v.as_object())
        .ok_or("enum requires a 'values' object")?;

    if values_obj.is_empty() {
        return Err("enum 'values' must not be empty".to_string());
    }

    let mut values = Vec::with_capacity(values_obj.len());
    let mut seen_names = HashSet::new();
    let mut seen_values = HashSet::new();

    for (variant_name, disc_val) in values_obj {
        if !seen_names.insert(variant_name.clone()) {
            return Err(format!("duplicate enum variant name: '{}'", variant_name));
        }
        let disc = disc_val.as_u64().ok_or_else(|| {
            format!(
                "enum variant '{}' value must be a non-negative integer",
                variant_name
            )
        })?;
        if !seen_values.insert(disc) {
            return Err(format!("duplicate enum discriminant value: {}", disc));
        }
        values.push((variant_name.clone(), disc));
    }

    Ok(Field::Enum {
        name,
        encoding,
        values,
        help,
    })
}

/// Maximum value representable by an encoding type.
fn encoding_max(encoding: &FieldType) -> Option<u64> {
    match encoding {
        FieldType::U8 => Some(u8::MAX as u64),
        FieldType::U16Be | FieldType::U16Le => Some(u16::MAX as u64),
        FieldType::U32Be | FieldType::U32Le => Some(u32::MAX as u64),
        FieldType::U64Be | FieldType::U64Le => Some(u64::MAX),
        // U256 always fits in u64 range since discriminants are u64
        FieldType::U256Be | FieldType::U256Le => Some(u64::MAX),
        _ => None,
    }
}

/// Validate structural invariants of a schema's field list.
fn validate_schema(schema: &Schema) -> Result<()> {
    if let Some(ref fields) = schema.fields {
        // Check for duplicate field names
        let mut names = HashSet::new();
        for field in fields {
            if let Some(name) = field_name(field) {
                if !names.insert(name) {
                    bail!("duplicate field name: '{}'", name);
                }
            }
        }

        // Check LengthPrefix is followed by a Ref
        for (i, field) in fields.iter().enumerate() {
            if matches!(field, Field::LengthPrefix(_)) {
                match fields.get(i + 1) {
                    Some(Field::Ref { .. }) => {} // OK
                    _ => bail!("length_prefix must be followed by a ref field"),
                }
            }
        }

        // Check enum discriminant values fit in their encoding type
        for field in fields {
            if let Field::Enum {
                name,
                encoding,
                values,
                ..
            } = field
            {
                if let Some(max) = encoding_max(encoding) {
                    for (variant, disc) in values {
                        if *disc > max {
                            bail!(
                                "enum field '{}': variant '{}' value {} exceeds {} max ({})",
                                name,
                                variant,
                                disc,
                                encoding,
                                max
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Parse a schema from a JSON value.
pub fn parse_schema(value: serde_json::Value) -> Result<Schema> {
    let schema: Schema = serde_json::from_value(value)?;
    if schema.fields.is_none() && schema.ref_.is_none() {
        bail!("schema must have at least `fields` or `ref`");
    }
    validate_schema(&schema)?;
    Ok(schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_array() {
        let json = serde_json::json!([
            {"name": "prefix", "const": "AABB"},
            {"name": "x", "type": "u8"}
        ]);
        let schema = parse_schema(json).unwrap();
        assert!(schema.about.is_none());
        assert!(schema.params.is_empty());
        assert!(schema.ref_.is_none());
        let fields = schema.fields.unwrap();
        assert_eq!(fields.len(), 2);
        assert!(
            matches!(&fields[0], Field::Const { name, value } if name == "prefix" && value == "AABB")
        );
        assert!(
            matches!(&fields[1], Field::Named { name, field_type, .. } if name == "x" && *field_type == FieldType::U8)
        );
    }

    #[test]
    fn const_requires_name() {
        let json = serde_json::json!([
            {"const": "AABB"}
        ]);
        assert!(parse_schema(json).is_err());
    }

    #[test]
    fn parse_object_with_ref() {
        let json = serde_json::json!({
            "about": "test",
            "ref": "@this/foo<@this/bar>"
        });
        let schema = parse_schema(json).unwrap();
        assert_eq!(schema.about.as_deref(), Some("test"));
        assert_eq!(schema.ref_.as_deref(), Some("@this/foo<@this/bar>"));
    }

    #[test]
    fn parse_parameterized() {
        let json = serde_json::json!({
            "params": ["A"],
            "fields": [
                {"zeros": 32},
                {"ref": "A"}
            ]
        });
        let schema = parse_schema(json).unwrap();
        assert_eq!(schema.params, vec!["A"]);
        let fields = schema.fields.unwrap();
        assert_eq!(fields.len(), 2);
        assert!(matches!(&fields[0], Field::Zeros(32)));
        assert!(matches!(&fields[1], Field::Ref { ref_, name: None } if ref_ == "A"));
    }

    #[test]
    fn reject_empty_schema() {
        let json = serde_json::json!({"about": "empty"});
        assert!(parse_schema(json).is_err());
    }

    #[test]
    fn reject_duplicate_field_names() {
        let json = serde_json::json!([
            {"name": "x", "type": "u8"},
            {"name": "x", "type": "u16be"}
        ]);
        let err = parse_schema(json).unwrap_err().to_string();
        assert!(err.contains("duplicate field name"), "error was: {}", err);
    }

    #[test]
    fn reject_length_prefix_at_end() {
        let json = serde_json::json!([
            {"length_prefix": "u16be"}
        ]);
        let err = parse_schema(json).unwrap_err().to_string();
        assert!(
            err.contains("length_prefix must be followed"),
            "error was: {}",
            err
        );
    }

    #[test]
    fn reject_unknown_field_type() {
        let json = serde_json::json!([
            {"name": "x", "type": "float64"}
        ]);
        assert!(parse_schema(json).is_err());
    }

    #[test]
    fn anchor_produces_const() {
        let json = serde_json::json!([
            {"name": "disc", "anchor": "account:XrplAccount"}
        ]);
        let schema = parse_schema(json).unwrap();
        let fields = schema.fields.unwrap();
        assert_eq!(fields.len(), 1);
        match &fields[0] {
            Field::Const { name, value } => {
                assert_eq!(name, "disc");
                assert_eq!(value, "1432f4993cef2ea8");
            }
            other => panic!("expected Const, got {:?}", other),
        }
    }

    #[test]
    fn anchor_requires_name() {
        let json = serde_json::json!([
            {"anchor": "account:Foo"}
        ]);
        assert!(parse_schema(json).is_err());
    }

    #[test]
    fn parse_enum_field_valid() {
        let json = serde_json::json!([
            {"name": "app-type", "enum": {"type": "u8", "values": {"Core": 0, "Wtt": 1, "Ntt": 2}}}
        ]);
        let schema = parse_schema(json).unwrap();
        let fields = schema.fields.unwrap();
        assert_eq!(fields.len(), 1);
        match &fields[0] {
            Field::Enum {
                name,
                encoding,
                values,
                help,
            } => {
                assert_eq!(name, "app-type");
                assert_eq!(*encoding, FieldType::U8);
                assert_eq!(values.len(), 3);
                assert!(help.is_none());
            }
            other => panic!("expected Enum, got {:?}", other),
        }
    }

    #[test]
    fn parse_enum_with_help() {
        let json = serde_json::json!([
            {"name": "mode", "enum": {"type": "u16be", "values": {"Fast": 0, "Slow": 1}}, "help": "transfer mode"}
        ]);
        let schema = parse_schema(json).unwrap();
        let fields = schema.fields.unwrap();
        match &fields[0] {
            Field::Enum { help, .. } => {
                assert_eq!(help.as_deref(), Some("transfer mode"));
            }
            other => panic!("expected Enum, got {:?}", other),
        }
    }

    #[test]
    fn enum_requires_name() {
        let json = serde_json::json!([
            {"enum": {"type": "u8", "values": {"A": 0}}}
        ]);
        assert!(parse_schema(json).is_err());
    }

    #[test]
    fn enum_rejects_non_numeric_encoding() {
        let json = serde_json::json!([
            {"name": "x", "enum": {"type": "address", "values": {"A": 0}}}
        ]);
        let err = parse_schema(json).unwrap_err().to_string();
        assert!(err.contains("numeric"), "error was: {}", err);
    }

    #[test]
    fn enum_rejects_empty_values() {
        let json = serde_json::json!([
            {"name": "x", "enum": {"type": "u8", "values": {}}}
        ]);
        let err = parse_schema(json).unwrap_err().to_string();
        assert!(err.contains("empty"), "error was: {}", err);
    }

    #[test]
    fn enum_rejects_duplicate_discriminant() {
        let json = serde_json::json!([
            {"name": "x", "enum": {"type": "u8", "values": {"A": 0, "B": 0}}}
        ]);
        let err = parse_schema(json).unwrap_err().to_string();
        assert!(err.contains("duplicate"), "error was: {}", err);
    }

    #[test]
    fn enum_rejects_overflow() {
        let json = serde_json::json!([
            {"name": "x", "enum": {"type": "u8", "values": {"A": 256}}}
        ]);
        let err = parse_schema(json).unwrap_err().to_string();
        assert!(err.contains("exceeds"), "error was: {}", err);
    }
}
